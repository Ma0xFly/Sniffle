#!/usr/bin/env python3
# att-fuzz/core/corpus.py
"""
确定性语料:YAML 模板 -> 针对具体目标展开为具体用例。
- ${each.xxx} 锚点模板:按 GATT 地图逐特征展开
- ${mtu-3} 等标量表达式:按会话上下文解析
- value pattern: zero/ff/incremental/random/fmtstring/ascii(确定性,seed+case_id 驱动)
"""

import logging
import random
import re
from dataclasses import dataclass, field
from pathlib import Path

from .att import (find_info_req, prepare_write_req, raw_opcode_pdu, read_blob_req,
                  read_by_group_type_req, read_by_type_req, read_multiple_req,
                  read_req, write_cmd, write_req, exchange_mtu_req, execute_write_req)
from .gatt_map import Characteristic, GattMap

log = logging.getLogger("att-fuzz.corpus")

VALUE_PATTERNS = ("zero", "ff", "incremental", "random", "fmtstring", "ascii")


def gen_value(pattern: str, length: int, seed, case_id: str) -> bytes:
    length = max(0, int(length))
    if pattern == "zero":
        return bytes(length)
    if pattern == "ff":
        return b"\xFF" * length
    if pattern == "incremental":
        return bytes(i & 0xFF for i in range(length))
    if pattern == "random":
        rng = random.Random("%s|%s" % (seed, case_id))
        return bytes(rng.getrandbits(8) for _ in range(length))
    if pattern == "fmtstring":
        return (b"%s%s%n%p%x%d" * (length // 8 + 1))[:length]
    if pattern == "ascii":
        return (b"ABCD1234" * (length // 8 + 1))[:length]
    raise ValueError("unknown value pattern: %s" % pattern)


_EXPR_RE = re.compile(r"^\$\{([a-zA-Z_][a-zA-Z0-9_.]*)(?:\s*([+\-*])\s*(-?\d+))?\}$")


def eval_expr(expr, variables: dict):
    """支持:整数、${var}、${var+N}、${var-N}、${var*N};结果限 0..0xFFFF。"""
    if isinstance(expr, bool):
        raise ValueError("bool not allowed")
    if isinstance(expr, int):
        val = expr
    elif isinstance(expr, str):
        m = _EXPR_RE.match(expr.strip())
        if not m:
            raise ValueError("bad expression: %r" % expr)
        name, op, operand = m.groups()
        if name not in variables:
            raise ValueError("unknown variable: %r (have %s)" % (name, sorted(variables)))
        val = variables[name]
        if op is not None:
            n = int(operand)
            if op == "+":
                val = val + n
            elif op == "-":
                val = val - n
            else:
                val = val * n
    else:
        raise ValueError("bad expression type: %r" % (expr,))
    if not (0 <= val <= 0xFFFF):
        raise ValueError("expression %r out of handle/length range: %d" % (expr, val))
    return val


@dataclass
class Case:
    """展开后的具体用例"""
    id: str
    layer: str
    pdu: bytes
    expect_response: bool = True
    meta: dict = field(default_factory=dict)

    def __repr__(self):
        return "Case(%s, %s, %s)" % (self.id, self.layer, self.pdu[:8].hex())


# 每种 op 对应的构造器:(case, variables) -> bytes
def _build_pdu(case_raw: dict, v: dict, seed) -> bytes:
    op = case_raw["op"]

    def val_of(field_name, default=None):
        return eval_expr(case_raw.get(field_name, default), v)

    if op == "read_req":
        return read_req(val_of("handle"))
    if op == "read_blob_req":
        return read_blob_req(val_of("handle"), val_of("offset", 0))
    if op == "read_multiple_req":
        # handles 为显式句柄列表(阶段一仅作辅助;逐锚点展开留阶段二)
        return read_multiple_req(case_raw["handles"])
    if op == "write_req":
        value = gen_value(case_raw["value"].get("pattern", "zero"),
                          eval_expr(case_raw["value"].get("len", 0), v), seed, case_raw["id"])
        return write_req(val_of("handle"), value)
    if op == "write_cmd":
        value = gen_value(case_raw["value"].get("pattern", "zero"),
                          eval_expr(case_raw["value"].get("len", 0), v), seed, case_raw["id"])
        return write_cmd(val_of("handle"), value)
    if op == "prepare_write_req":
        value = gen_value(case_raw["value"].get("pattern", "ff"),
                          eval_expr(case_raw["value"].get("len", 4), v), seed, case_raw["id"])
        return prepare_write_req(val_of("handle"), val_of("offset", 0), value)
    if op == "execute_write_req":
        return execute_write_req(val_of("flags", 1))
    if op == "find_info_req":
        return find_info_req(val_of("start", 1), val_of("end", 0xFFFF))
    if op == "read_by_type_req":
        return read_by_type_req(val_of("start", 1), val_of("end", 0xFFFF),
                                val_of("uuid", 0x2803))
    if op == "read_by_group_type_req":
        return read_by_group_type_req(val_of("start", 1), val_of("end", 0xFFFF),
                                      val_of("uuid", 0x2800))
    if op == "exchange_mtu_req":
        return exchange_mtu_req(val_of("mtu", 23))
    raise ValueError("unknown op: %s" % op)


def _char_vars(c: Characteristic, gatt: GattMap, mtu: int) -> dict:
    base_val = gatt.baseline.get("0x%04X" % c.value_handle, {})
    baseline_len = len(base_val.get("value", "")) // 2 if base_val.get("kind") == "value" else 0
    v = {
        "value": c.value_handle,
        "decl": c.decl_handle,
        "cccd": c.cccd_handle or c.value_handle,
        "baseline_len": baseline_len,
        "mtu": mtu,
    }
    # "${each.xxx}" 形式的别名
    v.update({"each." + k: val for k, val in v.items()})
    return v


def _global_vars(gatt: GattMap, mtu: int, anchor_value_handle: int | None) -> dict:
    return {
        "mtu": mtu,
        "value": anchor_value_handle or (gatt.value_handles()[0] if gatt.value_handles() else 1),
    }


def _is_each(expr) -> bool:
    return isinstance(expr, str) and "each" in expr


def expand(raw_cases: list, gatt: GattMap, mtu: int, seed: int,
          per_anchor_cap: int | None = None) -> list:
    """把 YAML 原始用例展开为具体 Case 列表。
    ${each.*} 模板按特征逐个展开;per_anchor_cap 限制每模板展开数(调试用)。"""
    out = []
    chars = gatt.characteristics
    anchor = gatt.known_good_handle()
    gvars = _global_vars(gatt, mtu, anchor)

    for raw in raw_cases:
        layer = raw.get("layer", "?")
        rid = raw.get("id", "case%d" % len(out))

        # ①层:raw opcode,无锚点展开
        if "opcode" in raw and "op" not in raw:
            payload = bytes.fromhex(raw.get("payload", "")) if raw.get("payload") else b""
            pdu = raw_opcode_pdu(raw["opcode"], payload)
            out.append(Case(id=rid, layer=layer, pdu=pdu, meta={"raw": True}))
            continue

        # 需要 ${each.*} 的字段?
        fields = {k: raw.get(k) for k in ("handle", "offset", "start", "end", "mtu", "uuid")}
        value_spec = raw.get("value")
        needs_each = any(_is_each(fv) for fv in fields.values()) or \
                (isinstance(value_spec, dict) and
                 (_is_each(value_spec.get("len")) or _is_each(value_spec.get("handle"))))
        if not needs_each:
            try:
                pdu = _build_pdu(raw, gvars, seed)
                out.append(Case(id=rid, layer=layer, pdu=pdu,
                                meta={"op": raw.get("op")}))
            except ValueError as e:
                log.warning("skip case %s: %s", rid, e)
            continue

        # ${each.*} 展开:逐特征(filter: writable/readable 限定适用面)
        req_filter = raw.get("filter")
        count = 0
        for c in chars:
            if req_filter == "writable" and not (c.has_prop(Characteristic.PROP_WRITE) or
                    c.has_prop(Characteristic.PROP_WRITE_NO_RSP)):
                continue
            if req_filter == "readable" and not c.has_prop(Characteristic.PROP_READ):
                continue
            v = _char_vars(c, gatt, mtu)
            v.update({k: gvars[k] for k in gvars if k not in v})
            try:
                pdu = _build_pdu(raw, v, seed)
            except ValueError as e:
                continue    # 该特征不适用(如不可写),静默跳过
            out.append(Case(id="%s@%04x" % (rid, c.value_handle), layer=layer,
                            pdu=pdu, meta={"op": raw.get("op"),
                                           "handle": c.value_handle}))
            count += 1
            if per_anchor_cap is not None and count >= per_anchor_cap:
                break
        if count == 0:
            log.warning("case %s expanded to 0 cases", rid)

    # PDU 去重:字节相同的用例对目标而言是同一个输入,结果必然相同,
    # 只保留首条(不同模板在边界处常撞出相同字节,白烧健康检查+连接事件)。
    seen, deduped = set(), []
    for c in out:
        key = c.pdu.hex()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(c)
    if len(deduped) < len(out):
        log.info("dedup: %d -> %d cases (removed %d duplicate PDUs)",
                 len(out), len(deduped), len(out) - len(deduped))
    return deduped


def load_yaml_files(paths) -> list:
    import yaml
    raw = []
    for p in sorted(Path(p) for p in paths):
        if p.is_dir():
            raw.extend(load_yaml_files(list(p.glob("*.yaml"))))
            continue
        entries = yaml.safe_load(p.read_text(encoding="utf-8"))
        if entries:
            raw.extend(entries)
    return raw
