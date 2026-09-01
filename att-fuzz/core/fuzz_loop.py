#!/usr/bin/env python3
# att-fuzz/core/fuzz_loop.py
"""
通用确定性语料 + 变异轮循环。
从 roles/central_fuzz._run_locked 抽出的循环主体,供 central 与加密冒充复用。

- 加载策略 -> expand -> 逐用例 run_case/run_sequence -> 分类 -> 台账 -> 进度
- no_mtu_negotiate meta 开关(⑤层):no_mtu_negotiate_meta=True 时按用例 meta
  切换链路协商状态(MTU=23 vs 已协商);False=不切(加密冒充链路 MTU 已在
  明文段协商,加密后不再断链重协)。
- 变异轮:rounds>0 时,第一轮确定性语料后追加签名驱动变异轮(core.mutator),
  每轮预算 round_budget,预算耗尽进下一轮,签名库跨 run 累积(git 忽略)。
- ATT_FREEZE / LinkDrop 回调:长语料会撞冻结阈值(~1100 事件/连接),
  on_freeze(session)->bool / on_link_drop()->bool:返回 True=重连后续跑,
  False/无回调=停止。LinkDrop/TransportError/SerialException 也走 on_link_drop。
"""

import logging
import os
import time
from pathlib import Path

from .corpus import CaseStep, expand, load_yaml_files
from .monitor import ALERT_CLASSIFICATIONS, Classification
from .transport import LinkDrop, TransportError

log = logging.getLogger("att-fuzz.fuzz_loop")

REPO = Path(__file__).resolve().parents[2]   # 仓库根(core/..)


def run_corpus_loop(session, strategy_paths, ledger, gatt, transport,
                    seed=1, max_cases=0, rounds=0, round_budget=100,
                    on_freeze=None, on_link_drop=None,
                    no_mtu_negotiate_meta=True) -> dict:
    """通用确定性语料 + 变异轮循环。
    返回 {"done": N, "alerts": N, "stats": {cls: count}}。
    on_freeze(session)->bool: ATT_FREEZE 时调用,True=已重连续跑,False/None=停止。
    on_link_drop()->bool: LinkDrop/TransportError/SerialException 时调用,
    True=已重连续跑,False/None=停止。无回调时 ATT_FREEZE/LinkDrop -> break。"""
    try:
        import serial
        _serial_exc = serial.SerialException
    except ImportError:          # pyserial 缺失(不应发生,sniffle 依赖)
        _serial_exc = type("SerialException", (), {})   # 不匹配任何异常

    raw_cases = load_yaml_files(strategy_paths)
    cases = expand(raw_cases, gatt, transport.att_mtu, seed)
    if max_cases:
        cases = cases[:max_cases]
    log.info("corpus: %d raw -> %d concrete cases", len(raw_cases), len(cases))

    # 变异轮生成器:第一轮确定性语料 + 追加变异轮(rounds>0)。
    # 变异轮以"产生新签名的用例 + 告警用例"为种子池,能量加权抽样后变异;
    # 每轮预算 round_budget 个用例,预算耗尽进下一轮。签名库跨 run 累积(git 忽略)。
    def _iter_cases():
        yield from cases
        if not rounds:
            return
        from core.mutator import Mutator, SignatureDb, collect_seeds
        # 签名库路径与扫描目录可用 env 覆盖(离线测试隔离,避免被真实 run 的
        # 合规 signature 占满种子判定);默认跨 run 累积于 logs/signatures.json。
        sigdb_env = os.environ.get("ATT_FUZZ_SIGDB")
        scan_env = os.environ.get("ATT_FUZZ_SIGSCAN")
        sigdb_path = Path(sigdb_env) if sigdb_env else \
            (REPO / "att-fuzz" / "logs" / "signatures.json")
        scan_dir = Path(scan_env) if scan_env else (REPO / "att-fuzz" / "logs")
        db = SignatureDb(sigdb_path)
        db.scan_runs(scan_dir)
        for round_no in range(1, rounds + 1):
            seeds = collect_seeds([ledger.path], db)
            if not seeds:
                log.info("round %d: no seeds (no alerts / no new signatures), stop",
                         round_no)
                break
            mut = Mutator(db, seed * 100 + round_no, transport.att_mtu)
            made = 0
            log.info("round %d: %d seeds, budget %d", round_no, len(seeds),
                     round_budget)
            while made < round_budget:
                seed_case = mut.pick_seed(seeds)
                yield mut.mutate(seed_case, round_no)
                made += 1
            db.scan_runs(scan_dir)   # 本轮新签名/告警入库
            db.save()

    started = time.time()
    alerts = done = 0
    try:
        for case in _iter_cases():
            # 用例可能要求未协商链路(⑤层):按需切换连接协商状态。
            # no_mtu_negotiate_meta=False(加密冒充)时不切,保持当前协商态。
            if no_mtu_negotiate_meta:
                session.ensure_negotiation(
                        not case.meta.get("no_mtu_negotiate", False))
            try:
                if case.steps is not None:
                    step_ctx = []
                    for s in case.steps:
                        if s.raw_frames is not None:
                            step_ctx.append({
                                "frames": [{"llid": llid,
                                            "payload": payload.hex()}
                                           for llid, payload in s.raw_frames],
                                "expect_response": s.expect_response,
                                "observe": s.observe, "gate_at": s.gate_at})
                        else:
                            step_ctx.append({"pdu": s.pdu.hex(),
                                             "expect_response": s.expect_response,
                                             "observe": s.observe,
                                             "gate_at": s.gate_at})
                    r = session.run_sequence(
                            case.id, case.layer, case.steps,
                            replay_ctx={"kind": "sequence", "steps": step_ctx})
                else:
                    expect = case.meta.get("op") != "write_cmd"
                    r = session.run_case(case.id, case.layer,
                            lambda c=case: c.pdu,
                            replay_ctx={"pdu": case.pdu.hex(),
                                        "expect_response": expect},
                            expect_response=expect)
            except (LinkDrop, TransportError) as e:
                # run_case/run_sequence 内部已捕获 LinkDrop 并分类,此处兜底:
                # 极端情况(_recover 自身掉链/串口失联)才冒泡到这里。
                log.warning("link drop during case %s: %s", case.id, e)
                if not _handle_drop(on_link_drop):
                    break
                continue
            except _serial_exc as e:
                log.warning("serial error during case %s: %s", case.id, e)
                if not _handle_drop(on_link_drop):
                    break
                continue
            done += 1
            if r.classification in ALERT_CLASSIFICATIONS:
                alerts += 1
            if r.classification == Classification.ATT_FREEZE:
                if on_freeze is not None:
                    try:
                        ok = on_freeze(session)
                    except Exception as e2:
                        log.warning("on_freeze callback failed: %s", e2)
                        ok = False
                else:
                    ok = False
                if not ok:
                    log.warning("ATT_FREEZE on %s, no reconnect -> stop loop",
                                case.id)
                    break
                # 重连成功:续跑下一用例(transport 已是新加密会话)
                continue
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
    return {"done": done, "alerts": alerts, "stats": stats}


def _handle_drop(on_link_drop) -> bool:
    """调用 on_link_drop 回调;无回调/异常 -> False(停止)。"""
    if on_link_drop is None:
        return False
    try:
        return bool(on_link_drop())
    except Exception as e:
        log.warning("on_link_drop callback failed: %s", e)
        return False
