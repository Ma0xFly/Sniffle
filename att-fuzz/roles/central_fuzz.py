#!/usr/bin/env python3
# att-fuzz/roles/central_fuzz.py
"""
模式一驱动:直连外设(central),确定性语料逐用例推进。
主循环纪律:前健康检查 -> 注入 -> 等响应 -> 分类 -> 双录 -> 后健康检查。
runner.py 先把 att-fuzz/ 与 python_cli/ 加进 sys.path,本模块用绝对导入。
"""

import logging
import time
from pathlib import Path

from sniffle.pcap import PcapBleWriter
from sniffle.sniffle_hw import SniffleHW

from core.corpus import CaseStep, expand, load_yaml_files
from core.monitor import ALERT_CLASSIFICATIONS, Ledger
from core.serial_lock import guard as serial_guard
from core.session import FuzzSession
from core.transport import SniffleTransport

log = logging.getLogger("att-fuzz.central")


def make_transport(serport, target: dict, outdir: Path) -> SniffleTransport:
    hw = SniffleHW(serport=serport or target.get("serport"))
    pcap = PcapBleWriter(str(outdir / "capture.pcap"))
    return SniffleTransport(hw, pcap=pcap, jsonl_path=outdir / "transport.jsonl",
                            conn_interval_units=target.get("conn_interval", 12))


def run(target: dict, strategy_paths, outdir: Path, serport=None, seed=1,
        max_cases=0, replay_pdu: str | None = None, replay_expect: bool = True,
        replay_steps: list | None = None) -> int:
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    # 串口锁覆盖整个任务窗口(连接+语料循环);GUI 空闲时不持锁,CLI 可用
    with serial_guard(serport or target.get("serport"), "CLI fuzz/replay 任务"):
        return _run_locked(target, strategy_paths, outdir, serport, seed,
                           max_cases, replay_pdu, replay_expect, replay_steps)


def _run_locked(target, strategy_paths, outdir, serport, seed,
                max_cases, replay_pdu, replay_expect, replay_steps) -> int:
    transport = make_transport(serport, target, outdir)
    ledger = Ledger(outdir / "ledger.jsonl")
    session = FuzzSession(transport, target, gatt_map_path=outdir / "gatt_map.json",
                          ledger=ledger)

    log.info("connecting to target...")
    gatt = session.start()
    log.info("negotiated: ll_max=%d att_mtu=%d", transport.ll_max, transport.att_mtu)

    # -- replay 模式:注入指定 PDU/序列(hex),单发即止 --
    if replay_steps:
        steps = [CaseStep(pdu=bytes.fromhex(s["pdu"]),
                          expect_response=bool(s.get("expect_response", True)),
                          observe=float(s.get("observe", 0) or 0))
                 for s in replay_steps]
        log.info("replaying sequence: %d steps", len(steps))
        r = session.run_sequence("replay", "replay", steps,
                                 replay_ctx={"kind": "sequence",
                                             "steps": replay_steps})
        log.info("replay result: %s", r.summary())
        return 0
    if replay_pdu:
        pdu = bytes.fromhex(replay_pdu)
        log.info("replaying %d-byte PDU: %s", len(pdu), pdu.hex())
        r = session.run_case("replay", "replay", lambda: pdu,
                             replay_ctx={"pdu": replay_pdu,
                                         "expect_response": replay_expect},
                             expect_response=replay_expect)
        log.info("replay result: %s", r.summary())
        return 0

    raw_cases = load_yaml_files(strategy_paths)
    cases = expand(raw_cases, gatt, transport.att_mtu, seed)
    if max_cases:
        cases = cases[:max_cases]
    log.info("corpus: %d raw -> %d concrete cases", len(raw_cases), len(cases))

    started = time.time()
    alerts = done = 0
    try:
        for case in cases:
            # 用例可能要求未协商链路(⑤层):按需切换连接协商状态
            session.ensure_negotiation(not case.meta.get("no_mtu_negotiate", False))
            if case.steps is not None:
                r = session.run_sequence(
                        case.id, case.layer, case.steps,
                        replay_ctx={"kind": "sequence",
                                    "steps": [{"pdu": s.pdu.hex(),
                                               "expect_response": s.expect_response,
                                               "observe": s.observe}
                                              for s in case.steps]})
            else:
                expect = case.meta.get("op") != "write_cmd"
                r = session.run_case(case.id, case.layer,
                        lambda c=case: c.pdu,
                        replay_ctx={"pdu": case.pdu.hex(),
                                    "expect_response": expect},
                        expect_response=expect)
            done += 1
            if r.classification in ALERT_CLASSIFICATIONS:
                alerts += 1
            if done % 50 == 0:
                log.info("progress %d/%d (%.1f/min), alerts=%d",
                         done, len(cases),
                         done / max(time.time() - started, 1) * 60, alerts)
    except KeyboardInterrupt:
        log.info("interrupted by user")
    finally:
        stats = ledger.stats()
        log.info("=== run summary ===")
        log.info("cases: %d, elapsed: %.1f min, alerts: %d",
                 done, (time.time() - started) / 60, alerts)
        for cls, n in sorted(stats.items()):
            log.info("  %-20s %d", cls, n)
        log.info("ledger: %s", ledger.path)
        log.info("pcap:   %s", outdir / "capture.pcap")
    return 0
