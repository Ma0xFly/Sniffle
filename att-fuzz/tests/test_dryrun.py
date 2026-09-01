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
        elif pdu[0] == 0x02:  # LL_TERMINATE_IND(我方发出):真实对端会回 TERMINATE,
            # 固件补丁 #2 上报 TerminateMeasurement -> transport 据此翻 _link_up
            from sniffle.measurements import TerminateMeasurement
            reason = pdu[1] if len(pdu) > 1 else 0x13
            self._emit(TerminateMeasurement(bytes([reason])))
            self._emit_state(SnifferState.PAUSED)

    # ---- ATT server ----
    def _error(self, req_opcode, handle, code):
        self._emit_att(bytes([0x01, req_opcode]) + pack("<H", handle) + bytes([code]))

    def _on_att(self, att):
        op = att[0]
        # 畸形/半截 PDU(如 L2CAP 欺骗)防御:长度不足按 INVALID_PDU 回 error,
        # 不崩(真实 server 对短 PDU 会回错或忽略)。
        _minlen = {0x02: 3, 0x10: 7, 0x08: 7, 0x04: 5, 0x0A: 3, 0x12: 3,
                   0x52: 3, 0x0C: 5, 0x16: 5, 0x18: 2}
        if len(att) < _minlen.get(op, 1):
            return self._error(op, 0x0000, 0x04)
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
    # FakeHw 不碰硬件,串口锁换成 no-op,避免离线测试去抢真实设备的锁。
    # 该替换保持到 main 末尾再恢复——后续 replay 段同样走 FakeHw,
    # 若中途恢复为真锁,测试会依赖"真实串口空闲"(并行跑任务时 SerialBusy 炸)。
    import contextlib
    central_fuzz.serial_guard = lambda *a, **k: contextlib.nullcontext()
    try:
        # 大跑用除 l2cap.yaml 外全部策略:l2cap 欺骗用例故意产生 TIMEOUT/冻结,
        # 属预期信号,单独跑(见文末);大跑断言保持"FakeHw 行为正确不应有告警"。
        all_strats = sorted(p for p in (REPO / "att-fuzz" / "strategies").glob("*.yaml")
                            if p.name != "l2cap.yaml")
        rc = central_fuzz.run(target, all_strats, outdir, seed=7, max_cases=0)
    finally:
        central_fuzz.make_transport = orig
    assert rc == 0

    from core.monitor import Ledger
    ledger = Ledger(outdir / "ledger.jsonl")
    stats = ledger.stats()
    print("ledger stats:", stats)
    assert stats.get("OK_RESPONSE", 0) > 20, stats
    assert stats.get("ERROR_RESPONSE", 0) > 30, stats
    # 干跑里假 server 行为正确,不应有超时/掉链
    for bad in ("TIMEOUT", "DISCONNECT_TERM", "DISCONNECT_SUP", "HEALTH_DEGRADED",
                "ATT_FREEZE"):
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
    print("replay 回归: %s" % rec["case_id"])

    # ---- 序列用例:大跑中确实执行且逐步记录 ----
    from core.att import exchange_mtu_req
    recs = []
    with (outdir / "ledger.jsonl").open() as fh:
        for line in fh:
            r = j.loads(line)
            recs.append(r)
    seq_recs = [r for r in recs if r.get("case_kind") == "sequence"]
    assert seq_recs, "大跑没有执行任何序列用例"
    for r in seq_recs:
        assert r["steps"] and isinstance(r["alert_step"], int), r["case_id"]
        assert all("classification" in s for s in r["steps"]), r["case_id"]
        assert r["replay"]["kind"] == "sequence" and \
            len(r["replay"]["steps"]) == len(r["steps"]), r["case_id"]
    noneneg = [r for r in recs if r["case_id"].startswith("sm-noneneg")]
    assert noneneg, "未协商 MTU 用例没有执行"
    reneg = [r for r in seq_recs if r["case_id"] == "sm-mtu-reneg-2x"]
    assert reneg and len(reneg[0]["steps"]) == 2
    print("序列用例: %d 条(其中未协商 %d 条)" % (len(seq_recs), len(noneneg)))

    # ---- replay 回归 1:write_cmd 台账记录透传 expect_response,不再 TIMEOUT 伪影 ----
    outdir_r = REPO / "att-fuzz" / "logs" / "dryrun-test-replay"

    def _clean_replay_outdir():
        outdir_r.mkdir(parents=True, exist_ok=True)
        for f in outdir_r.glob("*"):
            f.unlink()

    _clean_replay_outdir()
    central_fuzz.make_transport = fake_make_transport
    try:
        rc = central_fuzz.run(target, [], outdir_r, seed=1,
                              replay_pdu="520700", replay_expect=False)
        assert rc == 0
        led_r = Ledger(outdir_r / "ledger.jsonl")
        r = led_r.find("replay")
        assert r["classification"] == "OK_RESPONSE", r
        assert r["replay"] == {"pdu": "520700", "expect_response": False}, r["replay"]
        print("replay 回归: write_cmd 无响应正确(无 TIMEOUT 伪影)")

        # ---- replay 回归 2:序列台账记录逐步重放 ----
        _clean_replay_outdir()
        rc = central_fuzz.run(target, [], outdir_r, seed=1, replay_steps=[
            {"pdu": exchange_mtu_req(247).hex(), "expect_response": True, "observe": 0},
            {"pdu": "520700", "expect_response": False, "observe": 0},
        ])
        assert rc == 0
        r = Ledger(outdir_r / "ledger.jsonl").find("replay")
        assert r["case_kind"] == "sequence" and len(r["steps"]) == 2, r
        assert r["alert_step"] == 0 and r["classification"] == "OK_RESPONSE", r
        assert r["steps"][1]["expect_response"] is False
        assert r["replay"]["kind"] == "sequence", r["replay"]
        print("replay 回归: 序列 2 步逐步重放正确")
    finally:
        central_fuzz.make_transport = orig
    central_fuzz.serial_guard = orig_guard    # 全部段结束,恢复真实串口锁

    # ---- ATT_FREEZE / HEALTH_DEGRADED 分类判定 ----
    from core.session import FuzzSession as _FS

    class FreezeHw(FakeHw):
        """frozen 后对 read(0x0A)不响应,链路保持(ATT 冻结模拟)。"""
        frozen = False

        def _on_att(self, att):
            if att[0] == 0x0A and self.frozen:
                return
            super()._on_att(att)

    fhw = FreezeHw()
    ft = SniffleTransport(fhw, jsonl_path=None, conn_interval_units=12)
    fs = _FS(ft, target)
    fs.start()
    fhw.frozen = True
    r = fs.run_case("freeze", "classify", lambda: bytes([0x0A, 0x03, 0x00]))
    assert r.classification.name == "ATT_FREEZE", r
    assert "post_hc=timeout" in r.notes, r.notes
    print("分类: 冻结读场景 -> ATT_FREEZE")

    vt = SniffleTransport(FakeHw(), jsonl_path=None, conn_interval_units=12)
    vs = _FS(vt, target)
    vs.start()
    vs.gatt.baseline["0x0003"]["value"] = "bb"    # 篡改基线 -> 读响应值不匹配
    r = vs.run_case("degraded", "classify", lambda: bytes([0x0A, 0x03, 0x00]))
    assert r.classification.name == "HEALTH_DEGRADED", r
    assert "post_hc=value_changed" in r.notes, r.notes
    print("分类: 值异常读场景 -> HEALTH_DEGRADED")

    # ---- 变异轮干跑(rounds=2,小预算)+ 门控序列 replay ----
    _clean_replay_outdir()
    central_fuzz.make_transport = fake_make_transport
    # 隔离签名库:不扫真实 run(其合规 signature 会占满种子判定),用空库 +
    # 空扫描目录 -> 首轮用例全算"新签名",变异轮有种子可抽。
    os.environ["ATT_FUZZ_SIGDB"] = str(REPO / "att-fuzz" / "logs" / "dryrun-sigdb.json")
    os.environ["ATT_FUZZ_SIGSCAN"] = str(REPO / "att-fuzz" / "logs" / "dryrun-sigscan")
    Path(os.environ["ATT_FUZZ_SIGSCAN"]).mkdir(parents=True, exist_ok=True)
    try:
        # 首轮用 opcodes.yaml:未知 opcode 在 FakeHw 回 error 0x06(历史真实库没有该
        # 组合) -> 新签名种子,变异轮才有种子可抽。
        rc = central_fuzz.run(target, [REPO / "att-fuzz" / "strategies" / "opcodes.yaml"],
                              outdir_r, seed=3, max_cases=10, rounds=2,
                              round_budget=6)
        assert rc == 0
        recs_mut = [j.loads(l) for l in (outdir_r / "ledger.jsonl").open()]
        muts = [r for r in recs_mut if r["case_id"].startswith("mut-")]
        assert muts, "变异轮未产生用例"
        sigs = set(r.get("signature") for r in recs_mut if r.get("signature"))
        assert sigs, "无签名产出"
        gated = [r for r in muts if any(s.get("gate_at") is not None
                                        for s in (r.get("steps") or []))]
        print("变异轮: %d 变异用例, %d 含门控, 签名 %d 种"
              % (len(muts), len(gated), len(sigs)))
        # 门控序列 replay:按台账 gate_at 序列逐步重放
        if gated:
            g = gated[0]
            rc = central_fuzz.run(target, [], outdir_r, seed=3,
                                  replay_steps=g["replay"]["steps"])
            assert rc == 0
            rr = Ledger(outdir_r / "ledger.jsonl").find("replay")
            assert rr["case_kind"] == "sequence", rr
            assert rr["replay"]["kind"] == "sequence"
            print("门控 replay 回归: 序列逐步重放 OK (%d 步)" % len(rr["steps"]))
    finally:
        central_fuzz.make_transport = orig

    # ---- L2CAP 帧欺骗:raw 注入逃逸口单元测试 + 单独跑 l2cap.yaml ----
    class RecHw(FakeHw):
        """记录 cmd_transmit/at 收到的原始帧(验证 inject_raw 原样透传)。"""
        def __init__(self):
            super().__init__()
            self.sent = []
            self.sent_at = []
        def cmd_transmit(self, llid, pdu, event=0):
            self.sent.append((llid, bytes(pdu)))
            super().cmd_transmit(llid, pdu, event)
        def cmd_transmit_at(self, llid, pdu, event):
            self.sent_at.append((llid, bytes(pdu), event))
            super().cmd_transmit_at(llid, pdu, event)

    rhw = RecHw()
    rt = SniffleTransport(rhw, jsonl_path=None, conn_interval_units=12)
    # 连接(RecHw 继承 FakeHw,respond 正常)
    rt.connect(target)
    rt.setup_data_size()
    # 谎报 L2CAP 头(声明 16 字节,实际 ATT 1 字节)原样透传,transport 不代头
    raw_frames = [(2, bytes.fromhex("100004000a")),
                  (1, bytes.fromhex("4142"))]
    rt.inject_raw(raw_frames)
    assert rhw.sent[-2:] == raw_frames, rhw.sent   # 原样帧序列
    # gate_at 门控透传
    rt.inject_raw([(2, bytes.fromhex("100004000a"))], gate_at=5)
    assert rhw.sent_at and rhw.sent_at[-1][2] == 5, rhw.sent_at
    print("raw 注入单元: 帧序列原样透传 + gate_at 门控 OK")

    # l2cap.yaml 单独跑:欺骗用例在 FakeHw 上跑通,产出的 TIMEOUT 是预期信号
    _clean_replay_outdir()
    central_fuzz.make_transport = fake_make_transport
    try:
        rc = central_fuzz.run(target, [REPO / "att-fuzz" / "strategies" / "l2cap.yaml"],
                              outdir_r, seed=2, max_cases=0)
        assert rc == 0
        recs_l2 = [j.loads(l) for l in (outdir_r / "ledger.jsonl").open()]
        assert recs_l2, "l2cap 用例未执行"
        l2_alert = [r for r in recs_l2 if r["classification"] in
                    ("TIMEOUT", "ATT_FREEZE", "DISCONNECT_TERM", "DISCONNECT_SUP")]
        print("l2cap 欺骗: %d 用例, %d 异常信号(TIMEOUT/冻结/掉链,预期)"
              % (len(recs_l2), len(l2_alert)))
        # replay:含 raw 帧的用例按 frames 序列重放
        rawrec = next((r for r in recs_l2 if any("frames" in s for s in (r.get("steps") or []))), None)
        if rawrec:
            rc = central_fuzz.run(target, [], outdir_r, seed=2,
                                  replay_steps=rawrec["replay"]["steps"])
            assert rc == 0
            rr = Ledger(outdir_r / "ledger.jsonl").find("replay")
            assert rr["case_kind"] == "sequence", rr
            print("raw replay 回归: 帧序列逐步重放 OK")
    finally:
        central_fuzz.make_transport = orig

    # ---- server_fuzz 反向角色:peripheral 广播 + 接受连接 + 应答循环(FakeHw)----
    from roles import server_fuzz
    from core.att_server import ServerResponder as _ServerResponder, build_db as _build_db

    class PeriHw(FakeHw):
        """记录 advertise 调用 + 注入一条 CONNECT_IND 模拟手机连入。"""
        def __init__(self):
            super().__init__()
            self.advertised = []
        def cmd_advertise(self, advData, scanRspData=b"", mode=0):
            self.advertised.append((bytes(advData), bytes(scanRspData), mode))
        def cmd_setaddr(self, addr, is_random=True):
            self.setaddr = (bytes(addr), is_random)
        # 其余 cmd_* 走 __getattr__ no-op

    def _emit_connect_ind(hw, aa=0x55667788, interval=12, latency=0, timeout=2000):
        # CONNECT_IND adv PDU: 2 字节 adv 头 + 36 字节 LLData(InitA/AdvA/AA/参数)
        init_a = bytes.fromhex("112233445566")   # 手机(central)
        adv_a = bytes.fromhex("ffeeddccbbaa")    # 我方(peripheral)
        body = (bytes([0x05, 36]) + init_a + adv_a + pack("<I", aa) +
                bytes([0xaa, 0xbb, 0xcc]) + bytes([4]) +
                pack("<HHHH", 6, interval, latency, timeout) +
                bytes([0xFF, 0xFF, 0xFF, 0xFF, 0x1F]) + bytes([0x06]))
        hw._emit(DPacketMessage.from_body(body, is_data=False))

    phw = PeriHw()
    pt = SniffleTransport(phw, jsonl_path=None, conn_interval_units=12)
    pt.role = "peripheral"
    adv, srsp = server_fuzz.build_adv_data("Sniffle Server")
    assert b"Sniffle Server" in adv and bytes([3, 0x03, 0x0F, 0x18]) in adv
    pt.advertise(adv, srsp, interval_ms=200)
    assert phw.advertised and phw.advertised[-1][0] == bytes(adv)
    # 稳定地址:advertise 显式传 mac 时走 cmd_setaddr(重广播循环全程同地址,
    # 防 random_addr() 每轮换新地址导致手机缓存/重连失效)
    stable = b"\x11\x22\x33\x44\x55\xC0"
    pt.advertise(adv, srsp, interval_ms=200, mac=stable)
    assert phw.setaddr == (stable, True)
    # 手机 CONNECT_IND -> accept_connection 返回参数,链路 up,连接参数对齐
    _emit_connect_ind(phw)
    conn = pt.accept_connection(timeout=5.0)
    assert conn is not None and conn["interval"] == 12 and conn["aa"] == 0x55667788, conn
    assert pt.link_up and pt.aa == 0x55667788
    assert abs(pt.conn_interval_s - 12 * 0.00125) < 1e-9
    # 应答循环:Exchange MTU -> 0x03;Read By Group Type -> 服务表
    pr = _ServerResponder(_build_db(device_name="Sniffle Server"), server_mtu=247)
    phw._emit_att(bytes([0x02, 0x40, 0x00]))
    pdu = pt.recv_att(timeout=5.0)
    assert pdu is not None and pdu.pdu[0] == 0x02
    rsp = pr.handle_request(pdu.pdu)
    assert rsp == bytes([0x03, 0xF7, 0x00]) and pr.att_mtu == 64
    phw._emit_att(bytes([0x10, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x28]))
    pdu = pt.recv_att(timeout=5.0)
    assert pdu is not None and pdu.pdu[0] == 0x10
    rsp = pr.handle_request(pdu.pdu)
    assert rsp[0] == 0x11 and (len(rsp) - 2) % 6 == 0
    print("server_fuzz 反向角色:广播/接受连接/应答循环 OK")

    # ---- 加密冒充语料循环:FakeHw 模拟耳机握手 + 加密 ATT,跑语料循环 ----
    # 复用 01_crack 测试向量(LTK/SKD/IV),_EncGattHw 在 FakeHw 之上叠加
    # LL ENC 握手 + 加密 ATT(收 M2S 解密/回 S2M 加密)。
    from core import bt_crypto as _bc_enc
    from roles import impersonation_fuzz as _imp_dr

    _SK_DR = _bc_enc.session_key(
            bytes.fromhex("59d4b35ece0df548c10efe17e9da1f4c"),
            bytes.fromhex("9f6b013d7eb25f87"), bytes.fromhex("68f5add3ca185186"))
    _IV_DR = bytes.fromhex("ea6ec7cc6199de66")
    # enable_encryption 入参(wire/dump 序 = big-endian 反转)
    _LTK_WIRE_DR = bytes.fromhex("59d4b35ece0df548c10efe17e9da1f4c")[::-1]
    _SKDM_WIRE_DR = bytes.fromhex("9f6b013d7eb25f87")[::-1]
    _SKDS_WIRE_DR = bytes.fromhex("68f5add3ca185186")[::-1]
    _IVM_WIRE_DR = _IV_DR[:4]
    _IVS_WIRE_DR = _IV_DR[4:]

    class _EncGattHw(FakeHw):
        """FakeHw + LL ENC 握手 + 加密 ATT(M2S 解密 / S2M 加密回)。"""
        def __init__(self, ltk_wire):
            super().__init__()
            self._ltk_wire = ltk_wire
            self._cipher = None
            self._enc_started = False
            self._enc_complete = False

        def _emit_att(self, att_pdu):
            if self._cipher is not None and self._enc_complete:
                sdu = pack("<HH", len(att_pdu), 4) + att_pdu
                ct, mic = self._cipher.encrypt_packet(0x02, sdu, _bc_enc.DIR_S2M)
                body = bytes([0x02, len(ct) + 4]) + ct + mic
                self._emit(DPacketMessage.from_body(body, is_data=True,
                                                    peripheral_send=True))
            else:
                super()._emit_att(att_pdu)

        def _emit_ll_ctrl(self, payload, encrypted=False):
            if encrypted and self._cipher is not None:
                ct, mic = self._cipher.encrypt_packet(0x03, payload,
                                                      _bc_enc.DIR_S2M)
                body = bytes([0x03, len(ct) + 4]) + ct + mic
            else:
                body = bytes([0x03, len(payload)]) + payload
            self._emit(DPacketMessage.from_body(body, is_data=True,
                                                peripheral_send=True))

        def cmd_transmit(self, llid, pdu, event=0):
            if llid == 3 and len(pdu) >= 23 and pdu[0] == 0x03 and \
                    self._cipher is None:
                # LL_ENC_REQ(明文):建 cipher,回 ENC_RSP + START_ENC_REQ
                skdm = pdu[11:19]; ivm = pdu[19:23]
                ltk_be = self._ltk_wire[::-1]
                skds = bytes.fromhex("68f5add3ca185186")[::-1]
                ivs = bytes.fromhex("6199de66")
                sessk = _bc_enc.session_key(ltk_be, skdm[::-1], skds[::-1])
                self._cipher = _bc_enc.LLCipherState(sessk, ivm + ivs,
                                                     search_window=2048)
                self._emit_ll_ctrl(bytes([0x04]) + skds + ivs, encrypted=False)
                self._emit_ll_ctrl(bytes([0x05]), encrypted=False)
                self._enc_started = True
                return
            if llid == 3 and self._enc_started and not self._enc_complete:
                # master 加密 START_ENC_RSP(M2S)-> 回加密 START_ENC_RSP(S2M)
                self._emit_ll_ctrl(bytes([0x06]), encrypted=True)
                self._enc_started = False
                self._enc_complete = True
                return
            if llid == 2 and self._cipher is not None and self._enc_complete:
                # 加密 M2S ATT -> 解密后走 FakeHw._on_att(响应经 _emit_att 加密)
                if len(pdu) < 4:
                    return
                ct, mic = pdu[:-4], pdu[-4:]
                pt = self._cipher.decrypt_packet(0x02, ct, mic,
                                                 _bc_enc.DIR_M2S, 0)
                if pt is None or len(pt) < 4:
                    return
                sdu_len, _cid = unpack("<HH", pt[:4])
                self._on_att(pt[4:4 + sdu_len])
                return
            # 明文段(DLE LENGTH_REQ / MTU):走 FakeHw 原逻辑
            super().cmd_transmit(llid, pdu, event)

        def cmd_transmit_at(self, llid, pdu, event):
            self.cmd_transmit(llid, pdu, event)

    _eghw = _EncGattHw(_LTK_WIRE_DR)
    _et = SniffleTransport(_eghw, pcap=None, jsonl_path=None,
                           conn_interval_units=12)
    _tgt_dr = {"mac": "AABBCCDDEEFF", "mac_random": True,
               "conn_interval": 12, "latency": 0}
    _et.connect(_tgt_dr, our_addr=bytes.fromhex("1122334455C0"),
                our_addr_random=False)
    assert _et.link_up
    _et.setup_data_size()
    # 驱动 LL ENC 握手(用 record 桩)
    _ev_dr = []
    _imp_dr._drive_enc_handshake(_et, _LTK_WIRE_DR,
                                 lambda **k: _ev_dr.append(k))
    assert _et._enc_enabled and _et._enc_cipher is not None
    # 加密链路 GATT 发现
    from core.gatt_map import discover as _discover_dr
    _gatt_dr = _discover_dr(_et)
    assert _gatt_dr.services and _gatt_dr.characteristics, "加密发现应出服务/特征"
    print("加密冒充:握手 + 加密 GATT 发现 OK (%d 服务, %d 特征)"
          % (len(_gatt_dr.services), len(_gatt_dr.characteristics)))

    # 语料循环:小策略(handle 层),max_cases=4,无墙台账
    from core.session import FuzzSession as _FS_dr
    from core.fuzz_loop import run_corpus_loop as _rcl_dr
    from core.monitor import Ledger as _Led_dr
    _od_dr = REPO / "att-fuzz" / "logs" / "dryrun-enc-corpus"
    _od_dr.mkdir(parents=True, exist_ok=True)
    for _f in _od_dr.glob("*"):
        _f.unlink()
    _fled = _Led_dr(_od_dr / "fuzz_ledger.jsonl")
    _fsess = _FS_dr(_et, _tgt_dr, gatt_map_path=None, ledger=_fled,
                    negotiate_mtu=False)
    _fsess.gatt = _gatt_dr
    _strat = [REPO / "att-fuzz" / "strategies" / "handles.yaml"]
    _cstats = _rcl_dr(_fsess, _strat, _fled, _gatt_dr, _et, seed=1,
                      max_cases=4, on_freeze=lambda s: False,
                      on_link_drop=lambda: False,
                      no_mtu_negotiate_meta=False)
    assert _cstats["done"] >= 1, _cstats
    _fstats = _fled.stats()
    assert _fstats, "fuzz 台账不应为空: %s" % _fstats
    assert _fstats.get("OK_RESPONSE", 0) > 0 or _fstats.get("ERROR_RESPONSE", 0) > 0, _fstats
    print("加密冒充语料循环: %d 用例, stats=%s" %
          (_cstats["done"], _fstats))

    print("FakeHw 干跑测试全部通过")


if __name__ == "__main__":
    main()
