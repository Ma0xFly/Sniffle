#!/usr/bin/env python3
# att-fuzz/core/mutator.py
"""
签名驱动变异引擎(阶段二)。

黑盒拿不到 coverage,AFL 式反馈换成响应签名当伪覆盖:
signature = 分类|响应opcode|error_code|term_reason|hc异常(台账 signature 列)。

- 轮次结构:第一轮跑确定性语料(不变);之后 --rounds N 追加变异轮。
  每轮预算用例数封顶(round_budget),预算耗尽即进下一轮或停止。
- 种子池:产生新签名的用例 + 全部告警用例。
- 能量调度(AFL 式,反馈源换成签名):签名新颖度(全库没见过)加权 +
  历史告警加权(告警过的 opcode/handle/layer 高能量)+ 永远返回同一错误码的降权。
- 变异算子(不做纯随机字节--乱翻 opcode 退化成未知 opcode 轰炸,与①层重复):
  bit/byte 翻转限参数区、handle/offset/len 边界邻近变异、随机长度插值、
  时序(gate_at 随机化 + 同事件多发)。
"""

import json
import logging
import random
from dataclasses import dataclass, field
from pathlib import Path

from .corpus import Case, CaseStep

log = logging.getLogger("att-fuzz.mutator")


# ---------- 跨 run 签名库 ----------

class SignatureDb:
    """跨 run 累积的签名与告警权重。文件 logs/signatures.json(git 忽略)。"""

    def __init__(self, path):
        self.path = Path(path)
        self.signatures = set()      # 见过的 signature(去重)
        self.repeat = {}             # signature -> 出现次数(降权用)
        self.alert_opcode = {}       # opcode -> 历史告警次数
        self.alert_handle = {}       # handle -> 历史告警次数
        self.alert_layer = {}        # layer -> 历史告警次数
        self._load()

    # ---- 持久化 ----

    def _load(self):
        if not self.path.exists():
            return
        try:
            d = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        self.signatures = set(d.get("signatures", []))
        self.repeat = {str(k): v for k, v in d.get("repeat", {}).items()}
        self.alert_opcode = _to_int_keys(d.get("alert_opcode", {}))
        self.alert_handle = _to_int_keys(d.get("alert_handle", {}))
        self.alert_layer = d.get("alert_layer", {})

    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        d = {
            "signatures": sorted(self.signatures),
            "repeat": self.repeat,
            "alert_opcode": self.alert_opcode,
            "alert_handle": self.alert_handle,
            "alert_layer": self.alert_layer,
        }
        self.path.write_text(json.dumps(d, ensure_ascii=False, indent=1),
                             encoding="utf-8")

    # ---- 查询/更新 ----

    def is_new(self, sig: str) -> bool:
        return sig not in self.signatures

    def add(self, sig: str):
        self.signatures.add(sig)
        self.repeat[str(sig)] = self.repeat.get(str(sig), 0) + 1

    def repeat_penalty(self, sig: str) -> float:
        """同一签名反复出现(永远同一错误码)的降权:重复越多惩罚越大,封顶 3。"""
        return min(self.repeat.get(str(sig), 0), 3) * 0.5

    def scan_runs(self, logs_dir):
        """扫描 logs_dir 下所有 run-*/ledger.jsonl,累积签名库与告警权重。
        幂等:重复扫描只增不减。"""
        logs = Path(logs_dir)
        if not logs.is_dir():
            return
        for led in sorted(logs.glob("*/ledger.jsonl")):
            try:
                recs = [json.loads(l) for l in led.open(encoding="utf-8")
                        if l.strip()]
            except OSError:
                continue
            for r in recs:
                sig = r.get("signature")
                if sig:
                    self.add(sig)
                if r.get("classification") in ("TIMEOUT", "HEALTH_DEGRADED",
                                               "ATT_FREEZE", "DISCONNECT_TERM",
                                               "DISCONNECT_SUP"):
                    if r.get("opcode") is not None:
                        self.alert_opcode[r["opcode"]] = \
                            self.alert_opcode.get(r["opcode"], 0) + 1
                    if r.get("handle") is not None:
                        self.alert_handle[r["handle"]] = \
                            self.alert_handle.get(r["handle"], 0) + 1
                    if r.get("layer"):
                        self.alert_layer[r["layer"]] = \
                            self.alert_layer.get(r["layer"], 0) + 1

    def energy_bonus(self, opcode, handle, layer) -> float:
        """历史告警加权:出过告警的维度给高能量(把时间花在让栈异常的输入周围)。"""
        e = 1.0
        if opcode is not None:
            e += self.alert_opcode.get(opcode, 0) * 0.8
        if handle is not None:
            e += self.alert_handle.get(handle, 0) * 0.6
        if layer:
            e += self.alert_layer.get(layer, 0) * 0.5
        return e


def _to_int_keys(d: dict) -> dict:
    out = {}
    for k, v in d.items():
        try:
            out[int(k)] = v
        except (TypeError, ValueError):
            pass
    return out


# ---------- 种子 ----------

@dataclass
class SeedCase:
    """变异种子:一个已执行过的用例(单 PDU 或序列,steps 统一视图)。"""
    case_id: str
    layer: str
    steps: list = field(default_factory=list)
    signature: str = ""
    opcode: int | None = None
    handle: int | None = None

    @classmethod
    def from_ledger(cls, rec: dict, step_pdus: list | None = None) -> "SeedCase":
        """从台账记录构造种子。种子 PDU 必须来自请求(replay.steps 含请求 pdu);
        台账 steps 只记响应(response_pdu),不能拿来当请求。"""
        rp = rec.get("replay") or {}
        steps = []
        for s in (rp.get("steps") or []):
            if not s.get("pdu"):
                continue
            steps.append(CaseStep(pdu=bytes.fromhex(s["pdu"]),
                                  expect_response=bool(s.get("expect_response", True)),
                                  observe=float(s.get("observe", 0) or 0),
                                  gate_at=int(s["gate_at"])
                                  if s.get("gate_at") is not None else None))
        if not steps and rp.get("pdu"):
            steps = [CaseStep(pdu=bytes.fromhex(rp["pdu"]),
                              expect_response=bool(rp.get("expect_response", True)))]
        if not steps and step_pdus:
            steps = [CaseStep(pdu=p, expect_response=True) for p in step_pdus]
        if not steps:
            # 兜底:从台账步骤的响应 PDU 反推(仅作近似,变异语义弱)
            for s in (rec.get("steps") or []):
                pdu = bytes.fromhex(s.get("response_pdu", ""))
                if pdu:
                    steps.append(CaseStep(pdu=pdu, expect_response=True))
        return cls(case_id=rec.get("case_id", "seed"),
                   layer=rec.get("layer", "?"),
                   steps=steps,
                   signature=rec.get("signature", ""),
                   opcode=rec.get("opcode"),
                   handle=rec.get("handle"))


# ---------- 变异算子 ----------

_PARAM_OPS = ("read_req", "read_blob_req", "write_req", "write_cmd",
              "prepare_write_req", "execute_write_req", "exchange_mtu_req",
              "read_by_type_req", "read_by_group_type_req", "find_info_req")


def _parse_fields(pdu: bytes):
    """从 PDU 解出 (opcode, handle, offset, value_len),解不出为 None。"""
    if not pdu:
        return (None, None, None, None)
    op = pdu[0]
    handle = offset = value_len = None
    if len(pdu) >= 3 and op in (0x0A, 0x0C, 0x12, 0x16, 0x52):
        handle = pdu[1] | (pdu[2] << 8)
    if op in (0x0C, 0x16) and len(pdu) >= 5:
        offset = pdu[3] | (pdu[4] << 8)
    if op in (0x12, 0x52, 0x16) and handle is not None:
        hdr = 5 if op == 0x16 else 3
        value_len = max(0, len(pdu) - hdr)
    return (op, handle, offset, value_len)


def _boundary_values(v: int) -> list:
    """handle/offset 的边界邻近集。"""
    return sorted({0, 1, max(0, v - 2), max(0, v - 1), v, v + 1, v + 2,
                   v * 2, 0x000F, 0x00FF, 0xFFFF})


def _rebuild(pdu: bytes, op: int, handle=None, offset=None, value=b"") -> bytes:
    """按 op 重建 PDU。"""
    from .att import (execute_write_req, prepare_write_req, read_blob_req,
                      read_req, write_cmd, write_req)
    if op == 0x0A:
        return read_req(handle if handle is not None else 1)
    if op == 0x0C:
        return read_blob_req(handle if handle is not None else 1,
                             offset if offset is not None else 0)
    if op in (0x12, 0x52):
        f = write_req if op == 0x12 else write_cmd
        return f(handle if handle is not None else 1, value)
    if op == 0x16:
        return prepare_write_req(handle if handle is not None else 1,
                                 offset if offset is not None else 0, value)
    if op == 0x18:
        return execute_write_req(pdu[1] if len(pdu) > 1 else 1)
    return pdu


class Mutator:
    """签名驱动变异:种子能量加权抽样 + 算子组合。"""

    def __init__(self, db: SignatureDb, seed: int, mtu: int = 512,
                 rng: random.Random | None = None):
        self.db = db
        self.seed = seed
        self.mtu = mtu
        self.rng = rng or random.Random(seed)
        self._case_seq = 0

    # ---- 种子选择(能量加权抽样) ----

    def pick_seed(self, seeds: list) -> SeedCase:
        weights = []
        for s in seeds:
            w = self.db.energy_bonus(s.opcode, s.handle, s.layer)
            if s.signature:
                if self.db.is_new(s.signature):
                    w += 3.0
                w -= self.db.repeat_penalty(s.signature)
            weights.append(max(w, 0.05))
        return self.rng.choices(seeds, weights=weights, k=1)[0]

    # ---- 算子 ----

    def _flip_params(self, pdu: bytes) -> bytes:
        """bit/byte 翻转限参数区(pdu[1:]),不碰 opcode 字节。"""
        if len(pdu) < 2:
            return pdu
        rng = self.rng
        params = bytearray(pdu[1:])
        if rng.random() < 0.5:
            idx = rng.randrange(len(params))
            bit = 1 << rng.randrange(8)
            params[idx] ^= bit
        else:
            for _ in range(rng.randint(1, 3)):
                params[rng.randrange(len(params))] = rng.getrandbits(8)
        return bytes([pdu[0]]) + bytes(params)

    def _boundary(self, pdu: bytes) -> bytes:
        """handle/offset 边界邻近变异(±1/±2/×2/边界间跳)。"""
        op, handle, offset, _ = _parse_fields(pdu)
        if op not in (0x0A, 0x0C, 0x12, 0x16, 0x52):
            return pdu
        value = pdu[5:] if op == 0x16 else (pdu[3:] if op in (0x12, 0x52) else b"")
        if handle is None:
            return pdu
        new_h = self.rng.choice(_boundary_values(handle))
        new_o = offset
        if offset is not None:
            new_o = self.rng.choice(_boundary_values(offset))
        return _rebuild(pdu, op, handle=new_h, offset=new_o, value=value)

    def _random_len(self, pdu: bytes) -> bytes:
        """随机长度插值([0, MTU-3]),值用确定性 incremental。"""
        op, handle, offset, _ = _parse_fields(pdu)
        if op not in (0x12, 0x16, 0x52):
            return pdu
        if handle is None:
            return pdu
        max_len = max(0, self.mtu - 3)
        n = self.rng.randint(0, max_len)
        value = bytes(i & 0xFF for i in range(n))
        return _rebuild(pdu, op, handle=handle, offset=offset, value=value)

    def _apply_params(self, pdu: bytes) -> bytes:
        """组合 1-2 个非时序算子。"""
        rng = self.rng
        ops = [self._flip_params, self._boundary, self._random_len]
        chosen = rng.sample(ops, rng.randint(1, 2))
        for f in chosen:
            pdu = f(pdu)
        return pdu

    # ---- 变异入口 ----

    def mutate(self, seed: SeedCase, round_no: int = 1) -> Case:
        """对一个种子产出变异用例(steps 形式,含 gate_at 时序)。
        时序算子:gate_delay(gate_at 随机打散)或 same_event(两条 PDU 同事件多发)。
        case_id 确定性:mut-r<round>-<n>,同 seed 同 rng 产出逐字节一致。"""
        rng = self.rng
        self._case_seq += 1
        case_id = "mut-r%d-%d" % (round_no, self._case_seq)

        if seed.steps and rng.random() < 0.25:
            # 序列种子:变异某一步 + 打散/同发
            steps = [CaseStep(pdu=s.pdu, expect_response=s.expect_response,
                              observe=s.observe, op=s.op, gate_at=s.gate_at)
                     for s in seed.steps]
            idx = rng.randrange(len(steps))
            steps[idx].pdu = self._apply_params(steps[idx].pdu)
            if rng.random() < 0.5:
                for s in steps:
                    s.gate_at = rng.randint(1, 3)
        else:
            # 单 PDU 变异(单步序列)
            pdu = seed.steps[0].pdu if seed.steps else b"\x0a\x00\x00"
            pdu = self._apply_params(pdu)
            expect = seed.steps[0].expect_response if seed.steps else True
            steps = [CaseStep(pdu=pdu, expect_response=expect, op="mut")]
            if rng.random() < 0.5:
                steps[0].gate_at = rng.randint(1, 3)

        if rng.random() < 0.15:
            # 同事件多发:两条 PDU 排到同一连接事件(SweynTooth 类死锁)
            a = steps[-1].pdu
            b = self._apply_params(bytes([0x0A, 0x01, 0x00]))  # 参数变异读
            gate = max((s.gate_at or 1) for s in steps)
            steps.append(CaseStep(pdu=b, expect_response=True, op="mut",
                                  gate_at=gate))
            for s in steps:
                if s.gate_at is None:
                    s.gate_at = gate
                s.gate_at = gate if s.gate_at == gate else s.gate_at

        return Case(id=case_id, layer=seed.layer or "mut", steps=steps,
                    meta={"mut": True, "ops": [s.op for s in steps],
                          "seed": seed.case_id})


# ---------- 轮次控制 ----------

def collect_seeds(ledger_paths, db: SignatureDb | None = None) -> list:
    """从多个台账收集种子:产生新签名的用例(db 判定)+ 全部告警用例(种子池)。
    返回 [SeedCase]。"""
    seeds = []
    seen_ids = set()
    for lp in ledger_paths:
        lp = Path(lp)
        if not lp.exists():
            continue
        try:
            recs = [json.loads(l) for l in lp.open(encoding="utf-8")
                    if l.strip()]
        except OSError:
            continue
        for r in recs:
            cid = r.get("case_id")
            if not cid or cid in seen_ids:
                continue
            is_alert = r.get("classification") in ("TIMEOUT", "HEALTH_DEGRADED",
                                                   "ATT_FREEZE", "DISCONNECT_TERM",
                                                   "DISCONNECT_SUP")
            sig = r.get("signature") or ""
            is_new = bool(db and sig and db.is_new(sig))
            if not (is_alert or is_new):
                continue
            seen_ids.add(cid)
            seeds.append(SeedCase.from_ledger(r))
    return seeds
