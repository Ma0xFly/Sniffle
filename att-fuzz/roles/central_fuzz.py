#!/usr/bin/env python3
# att-fuzz/roles/central_fuzz.py
"""
模式一驱动:直连外设(central),确定性语料逐用例推进。
主循环纪律:前健康检查 -> 注入 -> 等响应 -> 分类 -> 双录 -> 后健康检查。
runner.py 先把 att-fuzz/ 与 python_cli/ 加进 sys.path,本模块用绝对导入。
"""

import logging
from pathlib import Path

from sniffle.pcap import PcapBleWriter
from sniffle.sniffle_hw import SniffleHW

from core.corpus import CaseStep
from core.fuzz_loop import run_corpus_loop
from core.monitor import Ledger
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
        replay_steps: list | None = None, rounds: int = 0,
        round_budget: int = 100) -> int:
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    # 串口锁覆盖整个任务窗口(连接+语料循环);GUI 空闲时不持锁,CLI 可用
    with serial_guard(serport or target.get("serport"), "CLI fuzz/replay 任务"):
        return _run_locked(target, strategy_paths, outdir, serport, seed,
                           max_cases, replay_pdu, replay_expect, replay_steps,
                           rounds, round_budget)


def _run_locked(target, strategy_paths, outdir, serport, seed,
                max_cases, replay_pdu, replay_expect, replay_steps,
                rounds, round_budget) -> int:
    transport = make_transport(serport, target, outdir)
    ledger = Ledger(outdir / "ledger.jsonl")
    session = FuzzSession(transport, target, gatt_map_path=outdir / "gatt_map.json",
                          ledger=ledger)

    log.info("connecting to target...")
    gatt = session.start()
    log.info("negotiated: ll_max=%d att_mtu=%d", transport.ll_max, transport.att_mtu)

    # -- replay 模式:注入指定 PDU/序列(hex),单发即止 --
    if replay_steps:
        steps = []
        for s in replay_steps:
            if s.get("frames"):
                steps.append(CaseStep(pdu=b"", expect_response=True,
                                      raw_frames=[(f["llid"],
                                                   bytes.fromhex(f["payload"]))
                                                  for f in s["frames"]]))
            else:
                steps.append(CaseStep(pdu=bytes.fromhex(s.get("pdu", "")),
                                      expect_response=bool(s.get("expect_response", True)),
                                      observe=float(s.get("observe", 0) or 0),
                                      gate_at=int(s["gate_at"])
                                      if s.get("gate_at") is not None else None))
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

    # 确定性语料 + 变异轮循环(主体在 core.fuzz_loop,central 与加密冒充复用)。
    # ATT_FREEZE/LinkDrop 回调:重连(re-negotiate + re-discover)后续跑。
    run_corpus_loop(session, strategy_paths, ledger, gatt, transport,
                    seed=seed, max_cases=max_cases, rounds=rounds,
                    round_budget=round_budget,
                    on_freeze=lambda s: s.start() is not None,
                    on_link_drop=lambda: session.start() is not None)
    log.info("pcap:   %s", outdir / "capture.pcap")
    return 0
