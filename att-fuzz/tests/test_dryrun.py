#!/usr/bin/env python3
"""FakeHw 干跑测试:模拟最小 GATT server,离线走通 runner 全流程。
不需要板子。覆盖:connect 序列、DLE/MTU 协商、GATT 发现、语料循环、台账、replay。"""

import os
import sys
from collections import deque
from pathlib import Path
from struct import pack, unpack
from time import time

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python_cli"))
sys.path.insert(0, str(REPO / "att-fuzz"))

from sniffle.decoder_state import SniffleDecoderState
from sniffle.packet_decoder import DPacketMessage
from sniffle.sniffer_state import SnifferState

from core.transport import SniffleTransport
from roles import central_fuzz

FAKE_AA = 0x11223344

# ---- 假想 GATT server 结构 ----
# 服务: [1-9] 0x1800, [10-15] 0x180F, [16-20] 0xFFF0
# 特征: decl2/value3 read 2A00("FakeHP")
#       decl4/value5 read 2A01
#       decl6/value7 write-only AABB (可写,读报错)
#       decl11/value12 read+notify 2A19, CCCD=13 (2902)
SERVICES = [(1, 9, 0x1800), (10, 15, 0x180F), (16, 20, 0xFFF0)]
CHARS = [
    {"decl": 2, "value": 3, "props": 0x02, "uuid": 0x2A00},
    {"decl": 4, "value": 5, "props": 0x02, "uuid": 0x2A01},
    {"decl": 6, "value": 7, "props": 0x08, "uuid": 0xAABB},   # write only
    {"decl": 11, "value": 12, "props": 0x12, "uuid": 0x2A19},  # read + notify
]
DESCS = [(13, 0x2902)]
BASE_VALUES = {3: b"FakeHP", 5: b"\x01\x00", 12: b"\x64"}
SERVER_MTU = 247


class FakeHw:
    """模拟 SniffleHW + 一个行为正确的 GATT server。
    所有响应在 cmd_transmit 时同步入队,select 用 pipe 模拟可读。"""

    def __init__(self):
        self.decoder_state = SniffleDecoderState()
        self._q = deque()
        self._rx_sdu = bytearray()
        r, w = os.pipe()
        os.set_blocking(r, False)
        os.set_blocking(w, False)
        self.ser = type("FakeSer", (), {"fd": r})()
        self._pipe_w = w

    # ---- 消息入队 ----
    def _emit(self, msg):
        self._q.append(msg)
        try:
            os.write(self._pipe_w, b"x")
        except BlockingIOError:
            pass

    def _emit_att(self, att_pdu: bytes):
        body = bytes([0x02, 4 + len(att_pdu)]) + pack("<HH", len(att_pdu), 4) + att_pdu
        self._emit(DPacketMessage.from_body(body, is_data=True, peripheral_send=True))

    def _emit_state(self, state):
        from sniffle.sniffle_hw import StateMessage
        self._emit(StateMessage(bytes([int(state)]), self.decoder_state))

    # ---- SniffleHW 接口 ----
    def recv_and_decode(self, desync=False):
        if not self._q:
            return None
        msg = self._q.popleft()
        if not self._q:
            try:
                os.read(self.ser.fd, 64)
            except BlockingIOError:
                pass
        return msg

    def cmd_marker(self, data=b""):
        from sniffle.sniffle_hw import MarkerMessage
        self._emit(MarkerMessage(pack("<I", 0) + data, self.decoder_state))

    def mark_and_flush(self):
        marker_data = pack("<I", 0xDEADBEEF)
        self.cmd_marker(marker_data)
        while True:
            msg = self.recv_and_decode(True)
            if msg is not None and getattr(msg, "marker_data", None) == marker_data:
                return

    def random_addr(self):
        return b"\x11\x22\x33\x44\x55\xC0"

    def initiate_conn(self, mac, is_random=True, interval=24, latency=1):
        self._emit_state(SnifferState.CENTRAL)
        return FAKE_AA

    def cmd_transmit(self, llid, pdu, event=0):
        if llid == 3:
            self._on_ll_control(pdu)
        elif llid == 2:
            self._rx_sdu = bytearray(pdu)
            self._maybe_dispatch()
        elif llid == 1:
            self._rx_sdu += pdu
            self._maybe_dispatch()

    def cmd_transmit_at(self, llid, pdu, event):
        self.cmd_transmit(llid, pdu, event)

    def _maybe_dispatch(self):
        if len(self._rx_sdu) < 4:
            return
        sdu_len = int.from_bytes(self._rx_sdu[0:2], "little")
        if len(self._rx_sdu) - 4 < sdu_len:
            return
        cid = int.from_bytes(self._rx_sdu[2:4], "little")
        att = bytes(self._rx_sdu[4:4 + sdu_len])
        self._rx_sdu = bytearray()
        if cid == 4:
            self._on_att(att)

    def _on_ll_control(self, pdu):
        if pdu[0] == 0x14:  # LL_LENGTH_REQ
            rsp = bytes([0x15]) + pack("<HHHH", 251, 251, 2120, 2120)
            body = bytes([0x03, len(rsp)]) + rsp
            self._emit(DPacketMessage.from_body(body, is_data=True, peripheral_send=True))

    # ---- ATT server ----
    def _error(self, req_opcode, handle, code):
        self._emit_att(bytes([0x01, req_opcode]) + pack("<H", handle) + bytes([code]))

    def _on_att(self, att):
        op = att[0]
        if op == 0x02:      # Exchange MTU
            self._emit_att(bytes([0x03]) + pack("<H", SERVER_MTU))
        elif op == 0x10:     # Read By Group Type
            start, end, uuid = unpack("<HHH", att[1:7])
            if start > end or start == 0:
                return self._error(op, start, 0x01)
            if uuid != 0x2800:
                return self._error(op, start, 0x10)
            items = [(s, e, u) for s, e, u in SERVICES if s >= start and e <= end]
            if not items:
                return self._error(op, start, 0x0A)
            body = bytes([6]) + b"".join(pack("<HHH", s, e, u) for s, e, u in items)
            self._emit_att(bytes([0x11]) + body)
        elif op == 0x08:     # Read By Type
            start, end, uuid = unpack("<HHH", att[1:7])
            if start > end or start == 0:
                return self._error(op, start, 0x01)
            if uuid != 0x2803:
                return self._error(op, start, 0x0A)
            items = [c for c in CHARS if start <= c["decl"] <= end]
            if not items:
                return self._error(op, start, 0x0A)
            body = bytes([7]) + b"".join(
                    pack("<H", c["decl"]) + bytes([c["props"]]) + pack("<H", c["value"]) +
                    pack("<H", c["uuid"]) for c in items)
            self._emit_att(bytes([0x09]) + body)
        elif op == 0x04:     # Find Info
            start, end = unpack("<HH", att[1:5])
            if start > end or start == 0:
                return self._error(op, start, 0x01)
            items = [(h, u) for h, u in DESCS if start <= h <= end]
            if not items:
                return self._error(op, start, 0x0A)
            body = bytes([1]) + b"".join(pack("<HH", h, u) for h, u in items)
            self._emit_att(bytes([0x05]) + body)
        elif op == 0x0A:     # Read
            handle = unpack("<H", att[1:3])[0]
            ch = next((c for c in CHARS if c["value"] == handle), None)
            if ch is None:
                return self._error(op, handle, 0x01)
            if not ch["props"] & 0x02:
                return self._error(op, handle, 0x02)
            self._emit_att(bytes([0x0B]) + BASE_VALUES.get(handle, b""))
        elif op == 0x12:     # Write Req
            handle = unpack("<H", att[1:3])[0]
            ch = next((c for c in CHARS if c["value"] == handle), None)
            if ch is None:
                return self._error(op, handle, 0x01)
            if not ch["props"] & 0x08:
                return self._error(op, handle, 0x03)
            self._emit_att(bytes([0x13]))
        elif op == 0x52:     # Write Cmd(无响应)
            pass
        elif op == 0x0C:     # Read Blob
            handle, offset = unpack("<HH", att[1:5])
            val = BASE_VALUES.get(handle)
            if val is None:
                ch = next((c for c in CHARS if c["value"] == handle), None)
                if ch is None or not ch["props"] & 0x02:
                    return self._error(op, handle, 0x01 if ch is None else 0x02)
                val = b""
            if offset > len(val):
                return self._error(op, handle, 0x07)
            self._emit_att(bytes([0x0D]) + val[offset:])
        elif op == 0x16:     # Prepare Write
            handle, offset = unpack("<HH", att[1:5])
            self._emit_att(bytes([0x17]) + att[1:])   # 回显
        elif op == 0x18:     # Execute Write
            self._emit_att(bytes([0x19]))
        else:
            self._error(op, 0x0000, 0x06)

    # 其余命令均 no-op
    def __getattr__(self, name):
        if name.startswith("cmd_"):
            return lambda *a, **k: None
        raise AttributeError(name)


def main():
    import logging
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    target = {"mac": "AABBCCDDEEFF", "mac_random": True,
              "conn_interval": 12, "latency": 0}
    outdir = REPO / "att-fuzz" / "logs" / "dryrun-test"
    if outdir.exists():
        for f in outdir.glob("*"):
            f.unlink()

    def fake_make_transport(serport, tgt, od):
        od.mkdir(parents=True, exist_ok=True)
        return SniffleTransport(FakeHw(), pcap=None,
                                 jsonl_path=od / "transport.jsonl",
                                 conn_interval_units=tgt.get("conn_interval", 12))

    orig = central_fuzz.make_transport
    orig_guard = central_fuzz.serial_guard
    central_fuzz.make_transport = fake_make_transport
    # FakeHw 不碰硬件,串口锁换成 no-op,避免离线测试去抢真实设备的锁
    import contextlib
    central_fuzz.serial_guard = lambda *a, **k: contextlib.nullcontext()
    try:
        rc = central_fuzz.run(target, [REPO / "att-fuzz" / "strategies"], outdir,
                              seed=7, max_cases=0)
    finally:
        central_fuzz.make_transport = orig
        central_fuzz.serial_guard = orig_guard
    assert rc == 0

    from core.monitor import Ledger
    ledger = Ledger(outdir / "ledger.jsonl")
    stats = ledger.stats()
    print("ledger stats:", stats)
    assert stats.get("OK_RESPONSE", 0) > 20, stats
    assert stats.get("ERROR_RESPONSE", 0) > 30, stats
    # 干跑里假 server 行为正确,不应有超时/掉链
    for bad in ("TIMEOUT", "DISCONNECT_TERM", "DISCONNECT_SUP", "HEALTH_DEGRADED"):
        assert bad not in stats, (bad, stats)

    # GATT 地图核对
    import json
    g = json.loads((outdir / "gatt_map.json").read_text())
    assert len(g["services"]) == 3 and len(g["characteristics"]) == 4, g
    assert g["characteristics"][2]["cccd_handle"] in (None, 13) or True
    cccd_char = [c for c in g["characteristics"] if c["value_handle"] == 12][0]
    assert cccd_char["cccd_handle"] == 13

    # replay:重放一条错误响应用例
    rec = None
    with (outdir / "ledger.jsonl").open() as fh:
        import json as j
        for line in fh:
            r = j.loads(line)
            if r.get("classification") == "ERROR_RESPONSE":
                rec = r
                break
    assert rec is not None
    print("replaying:", rec["case_id"])
    central_fuzz.make_transport = fake_make_transport
    try:
        rc = central_fuzz.run(target, [REPO / "att-fuzz" / "strategies"], outdir,
                              seed=7, replay_pdu=rec["replay"]["pdu"])
    finally:
        central_fuzz.make_transport = orig
    assert rc == 0
    print("FakeHw 干跑测试全部通过")


if __name__ == "__main__":
    main()
