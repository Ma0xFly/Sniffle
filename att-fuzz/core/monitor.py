#!/usr/bin/env python3
# att-fuzz/core/monitor.py
"""
判定与台账。
- Classification: 每用例的结局分类
- Ledger: JSONL 台账,最小复现单元 + replay
"""

import json
import logging
from dataclasses import dataclass, field, asdict
from enum import IntEnum
from pathlib import Path
from struct import unpack
from time import time

from .att import parse_error_rsp, AttOpcode, ERROR_CODE_NAMES

log = logging.getLogger("att-fuzz.monitor")


class Classification(IntEnum):
    OK_RESPONSE = 0        # 正常(非错误)响应
    ERROR_RESPONSE = 1      # ATT Error Response,记 code
    TIMEOUT = 2            # 响应超时
    DISCONNECT_TERM = 3    # 目标发 TERMINATE(带 reason;0x08=LL Protocol Error 强信号)
    DISCONNECT_SUP = 4     # supervision timeout(静默掉链)
    TX_QUEUE_FULL = 5      # 传输层错误,用例无效
    HEALTH_DEGRADED = 6    # 用例"完成"但健康检查异常(迟滞显现)
    ATT_FREEZE = 7         # ATT 层冻结:post-HC 读无响应但 LL 链路存活(无 TERMINATE/无 supervision)


CLASSIFICATION_NAMES = {int(c): c.name for c in Classification}

# 值得立即人工关注的分类
ALERT_CLASSIFICATIONS = {Classification.TIMEOUT, Classification.DISCONNECT_TERM,
                         Classification.DISCONNECT_SUP, Classification.HEALTH_DEGRADED,
                         Classification.ATT_FREEZE}


def compute_signature(result: "CaseResult") -> str:
    """响应签名:黑盒"伪覆盖"信号。同一签名 = 目标行为无新信息;
    新签名(没见过的错误码/响应 opcode/HC 异常组合) = 值得变异深挖的点。
    供后续变异模式做语料进化与能量调度,此处仅记录。"""
    parts = [result.classification.name]
    if result.response_pdu:
        try:
            parts.append("rsp=0x%02X" % int(result.response_pdu[:2], 16))
        except ValueError:
            pass
    if result.error_code is not None:
        parts.append("err=0x%02X" % result.error_code)
    if result.terminate_reason is not None:
        parts.append("term=0x%02X" % result.terminate_reason)
    if result.health_post and result.health_post != "ok":
        parts.append("hc=%s" % result.health_post)
    return "|".join(parts)


@dataclass
class CaseResult:
    case_id: str
    layer: str
    classification: Classification = Classification.OK_RESPONSE  # 占位,run_case 必覆写
    opcode: int | None = None
    handle: int | None = None
    offset: int | None = None
    value_len: int | None = None
    value_hash: str | None = None
    event: int | None = None
    error_code: int | None = None
    terminate_reason: int | None = None
    response_pdu: str | None = None       # hex
    signature: str | None = None          # 响应签名(见 compute_signature)
    health_pre: str | None = None
    health_post: str | None = None
    notes: list = field(default_factory=list)
    ts: float = field(default_factory=time)

    def summary(self) -> str:
        bits = ["%s" % self.classification.name]
        if self.error_code is not None:
            bits.append("err=0x%02X(%s)" % (self.error_code,
                    ERROR_CODE_NAMES.get(self.error_code, "?")))
        if self.terminate_reason is not None:
            bits.append("term=0x%02X" % self.terminate_reason)
        return "%s [%s] %s" % (self.case_id, self.layer, " ".join(bits))


class Ledger:
    """JSONL 台账。一行一用例,含最小复现单元。"""

    def __init__(self, path):
        self.path = Path(path)
        self._fh = self.path.open("a", encoding="utf-8")

    def record(self, result: CaseResult, case: dict | None = None,
               replayable: dict | None = None, extra: dict | None = None):
        rec = asdict(result)
        rec["classification"] = result.classification.name
        rec["signature"] = result.signature or compute_signature(result)
        if case:
            rec["case"] = case
        if replayable:
            rec["replay"] = replayable
        if extra:
            rec.update(extra)       # 序列用例的 case_kind/steps 等扩展字段
        self._fh.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
        self._fh.flush()

    def find(self, case_id: str):
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("case_id") == case_id:
                    return rec
        return None

    def stats(self) -> dict:
        counts = {}
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                cls = rec.get("classification", "?")
                counts[cls] = counts.get(cls, 0) + 1
        return counts


class ObservableLedger(Ledger):
    """Ledger 子类:record 时额外分发给订阅者(GUI 实时刷新用)。
    不改变 Ledger 的任何写入行为;无订阅者时与 Ledger 等价。"""

    def __init__(self, path):
        super().__init__(path)
        self._listeners = []

    def add_listener(self, fn):
        self._listeners.append(fn)

    def record(self, result: CaseResult, case: dict | None = None,
               replayable: dict | None = None, extra: dict | None = None):
        super().record(result, case=case, replayable=replayable, extra=extra)
        for fn in self._listeners:
            try:
                fn(result, case, replayable)
            except Exception as e:
                log.warning("ledger listener failed: %s", e)
