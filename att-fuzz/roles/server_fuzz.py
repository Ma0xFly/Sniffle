#!/usr/bin/env python3
# att-fuzz/roles/server_fuzz.py
"""
模式二驱动:反向角色 -- 伪装恶意 GATT server 打手机 client(攻击面⑧)。

Sniffle 以可连接 peripheral 身份广播,手机连入后对手机的 ATT 请求回
可配置响应。本任务交付:正常模式 + 假 GATT 数据库(应答引擎在
core/att_server.py);恶意响应策略是下一任务(替换生成器行为即可)。
角色 = central_fuzz 的对偶:central 是"打外设",这里是"被打"。

运行流程(每轮连接循环):
  广播(ADVERTISING) -> 等手机 CONNECT_IND(PERIPHERAL)
  -> ATT 应答循环(手机请求 -> ServerResponder 生成响应 -> inject)
  -> 手机断开 -> 重新广播,等待下一次连接

台账(server_ledger.jsonl)记录"手机请求 -> 我方响应"对,服务发现序列是
后续最小化崩溃复现的证据链。logcat oracle(core/adb_oracle.py)随应答循环
周期检查手机侧崩溃,崩溃事件携带当前 context(连接号+请求序号+opcode)
做时间对齐归因。

用法(经 runner.py):
  python3 att-fuzz/runner.py --target targets/xisem鼠标.json --server \
        --server-name "Sniffle Server" --server-duration 120 --adb-serial ZD9...
  (target 档案主要提供 serport/conn_interval;地址是广播方的,由我们自选随机地址)

设计边界:Sniffle 无 SMP,作为 server 不发起也不响应配对,只应答 ATT;
手机系统蓝牙扫描/连接 BLE 外设默认不需要配对(除非特征权限触发 SMP,
由我们的响应内容控制 -- 那是恶意策略任务的事)。
"""

import json
import logging
import time
from pathlib import Path

from sniffle.pcap import PcapBleWriter
from sniffle.sniffle_hw import SniffleHW

from core.adb_oracle import AdbOracle
from core.att import AttOpcode
from core.att_server import ServerResponder, build_db
from core.serial_lock import guard as serial_guard
from core.transport import LinkDrop, SniffleTransport

log = logging.getLogger("att-fuzz.server")

REPO = Path(__file__).resolve().parents[2]

_OPCODE_NAMES = {int(o): o.name for o in AttOpcode}


def op_name(op: int) -> str:
    return _OPCODE_NAMES.get(op, "UNKNOWN_0x%02X" % op)


def build_adv_data(name: str) -> tuple:
    """可连接广播 + 扫描响应。含 flags、完整本地名、Battery(0x180F)服务 UUID
    -- 诱导手机系统蓝牙做服务发现。"""
    name_b = name.encode("utf-8")[:20]
    adv = bytes([2, 0x01, 0x06])                    # LE General Discoverable + BR/EDR Not Supported
    adv += bytes([len(name_b) + 1, 0x09]) + name_b  # Complete Local Name
    adv += bytes([3, 0x03, 0x0F, 0x18])             # 16-bit Service UUID: Battery(0x180F)
    scan_rsp = bytes([2, 0x01, 0x06])
    mfr = b"Sniffle"
    scan_rsp += bytes([len(mfr) + 1, 0xFF]) + mfr   # Manufacturer Specific Data
    return adv, scan_rsp


def make_transport(serport, outdir: Path, conn_interval: int = 12) -> SniffleTransport:
    hw = SniffleHW(serport=serport)
    pcap = PcapBleWriter(str(outdir / "capture.pcap"))
    t = SniffleTransport(hw, pcap=pcap, jsonl_path=outdir / "transport.jsonl",
                         conn_interval_units=conn_interval)
    t.role = "peripheral"
    return t


def run(target: dict | None, outdir: Path, serport=None, duration: float = 0.0,
        name: str = "Sniffle Server", interval_ms: int = 200,
        adb_serial: str | None = None, adb_path: str | None = None) -> int:
    """反向角色主入口。duration>0 为运行秒数上限;0 表示一直跑到 Ctrl-C。"""
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    conn_interval = (target or {}).get("conn_interval", 12)
    serport = serport or (target or {}).get("serport")
    with serial_guard(serport, "CLI server_fuzz(反向角色)"):
        return _run_locked(outdir, serport, duration, name, interval_ms,
                           conn_interval, adb_serial, adb_path)


def _drain_oracle(record, oracle):
    """把 oracle 已排队的崩溃事件落台账(带归因 context)。"""
    for ev in oracle.poll():
        record(kind="oracle_crash", name=ev.name, context=ev.context,
               line=ev.line)
        log.warning("logcat oracle hit: %s (context=%r)", ev.name, ev.context)


def _run_locked(outdir: Path, serport, duration: float, name: str,
                interval_ms: int, conn_interval: int,
                adb_serial: str | None, adb_path: str | None) -> int:
    t = make_transport(serport, outdir, conn_interval)
    responder = ServerResponder(build_db(device_name=name), server_mtu=247)
    oracle = AdbOracle(serial=adb_serial or "ZD9L8H454HDY7DEU",
                       adb_path=adb_path, outdir=outdir)
    oracle.start()

    adv_data, scan_rsp = build_adv_data(name)
    # MAC 只生成一次并全程复用:random_addr() 每次调用都换新地址,若在重广播
    # 循环里反复调用,手机每次看到的都是"新设备" -- 缓存/重连全失效
    # (实测:手机把同名不同地址记成多个设备,nRF Connect 再连必失败)。
    our_mac = t.hw.random_addr()
    log.info("our static random address: %s", our_mac.hex())
    ledger_path = outdir / "server_ledger.jsonl"
    started = time.time()
    conn_no = 0

    def record(**fields):
        rec = {"ts": round(time.time(), 6), "conn": conn_no}
        rec.update(fields)
        with open(ledger_path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    try:
        while True:
            if duration and time.time() - started >= duration:
                log.info("duration reached, stopping")
                break
            t.advertise(adv_data, scan_rsp, interval_ms=interval_ms, mac=our_mac)
            log.info("advertising as %r ... (手机扫描连接)", name)
            conn = t.accept_connection(timeout=duration if duration else None)
            if conn is None:
                continue
            conn_no += 1
            conn_ts = time.time()
            log.info("phone connected #%d: %s aa=%08X interval=%d",
                     conn_no, conn["init_addr"], conn["aa"], conn["interval"])
            record(kind="conn_start", init_addr=conn["init_addr"],
                   init_random=conn["init_random"], aa="%08X" % conn["aa"],
                   interval=conn["interval"], latency=conn["latency"],
                   timeout=conn["timeout"])
            oracle.set_context("conn#%d" % conn_no)
            served = 0
            while True:
                try:
                    pdu = t.recv_att(timeout=1.0)
                except LinkDrop as drop:
                    log.info("link dropped: %s", drop)
                    break
                if pdu is None:
                    # 请求空窗:周期检查 oracle 与运行时长
                    if duration and time.time() - started >= duration:
                        log.info("duration reached inside session")
                        if t.link_up:
                            try:
                                t.disconnect()
                            except Exception as e:
                                log.warning("disconnect during stop: %s", e)
                        break
                    _drain_oracle(record, oracle)
                    continue
                served += 1
                op = pdu.pdu[0]
                rsp = responder.handle_request(pdu.pdu)
                ctx = "conn#%d served=%d op=0x%02X(%s)" % (
                        conn_no, served, op, op_name(op))
                oracle.set_context(ctx)
                record(kind="req", op=op, opname=op_name(op),
                       req=pdu.pdu.hex(),
                       rsp=rsp.hex() if rsp else None,
                       rsp_opcode=rsp[0] if rsp else None,
                       rsp_opname=op_name(rsp[0]) if rsp else None,
                       att_mtu=responder.att_mtu)
                if rsp is not None:
                    try:
                        t.inject(rsp)
                    except Exception as e:
                        log.warning("inject response failed: %s", e)
                        break
                _drain_oracle(record, oracle)
            record(kind="conn_end", served=served,
                   dur_s=round(time.time() - conn_ts, 3))
    except KeyboardInterrupt:
        log.info("interrupted by user")
    finally:
        oracle.stop()
        log.info("server run summary: %d connections, oracle saved %d crash windows",
                 conn_no, oracle.saved)
        log.info("server ledger: %s", ledger_path)
        log.info("pcap:          %s", outdir / "capture.pcap")
    return 0
