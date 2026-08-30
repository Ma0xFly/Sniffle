#!/usr/bin/env python3
# att-fuzz/core/gatt_map.py
"""
GATT 发现引擎与地图。
- Read By Group Type(0x2800) -> 服务
- Read By Type(0x2803) -> 特征声明
- Find Info -> 描述符(0x2902 CCCD)
- 基线读取:每个值 handle 的首读响应/错误码,是后续判定的参照系
发现过程容错:单步超时/错误 -> 记缺口继续,不中断整体。
"""

import json
import logging
from dataclasses import dataclass, field, asdict
from pathlib import Path
from struct import unpack

from .att import (AttError, AttOpcode, parse_error_rsp,
                  find_info_req, read_by_group_type_req, read_by_type_req,
                  read_req)
from .transport import LinkDrop

log = logging.getLogger("att-fuzz.gatt_map")

UUID_PRIMARY_SERVICE = 0x2800
UUID_SECONDARY_SERVICE = 0x2801
UUID_CHAR_DECL = 0x2803
UUID_CCCD = 0x2902


@dataclass
class Service:
    start_handle: int
    end_handle: int
    uuid: str          # hex 字符串("1800" 或 128 位 32 hex)


@dataclass
class Characteristic:
    decl_handle: int
    value_handle: int
    props: int         # 特征属性字节
    uuid: str
    cccd_handle: int | None = None

    def has_prop(self, bit: int) -> bool:
        return bool(self.props & bit)

    PROP_READ = 0x02
    PROP_WRITE_NO_RSP = 0x04
    PROP_WRITE = 0x08
    PROP_NOTIFY = 0x10
    PROP_INDICATE = 0x20


@dataclass
class GattMap:
    services: list = field(default_factory=list)
    characteristics: list = field(default_factory=list)
    baseline: dict = field(default_factory=dict)   # "0xNNNN" -> {"kind": "value"|"error"|..., ...}
    gaps: list = field(default_factory=list)      # 发现期异常记录

    # ---------- 持久化 ----------

    @staticmethod
    def _pretty(d: dict) -> str:
        """人工友好排版:services/characteristics/baseline 大项之间空行,
        每个 service/特征/基线条目之间也空行,缩进 2。
        输出仍是合法 JSON,json.load 可直接读。"""
        def pad(text, n=4):
            return "\n".join((" " * n + l) if l else l
                             for l in text.splitlines())

        sections = []
        for key in ("services", "characteristics", "baseline", "gaps"):
            v = d.get(key, [])
            if isinstance(v, list) and v:
                items = [pad(json.dumps(x, ensure_ascii=False, indent=2))
                         for x in v]
                body = "[\n" + ",\n\n".join(items) + "\n  ]"
            elif isinstance(v, dict) and v:
                items = [pad("\n".join(json.dumps({k: x}, ensure_ascii=False,
                                                   indent=2).splitlines()[1:-1]))
                         for k, x in v.items()]
                body = "{\n" + ",\n\n".join(items) + "\n  }"
            else:
                body = json.dumps(v, ensure_ascii=False)
            sections.append('  "%s": %s' % (key, body))
        return "{\n" + ",\n\n".join(sections) + "\n}\n"

    def save(self, path):
        Path(path).write_text(self._pretty(asdict(self)), encoding="utf-8")

    @classmethod
    def load(cls, path) -> "GattMap":
        d = json.loads(Path(path).read_text(encoding="utf-8"))
        m = cls()
        m.services = [Service(**s) for s in d.get("services", [])]
        m.characteristics = [Characteristic(**c) for c in d.get("characteristics", [])]
        m.baseline = d.get("baseline", {})
        m.gaps = d.get("gaps", [])
        return m

    # ---------- 语料锚点 ----------

    def value_handles(self, writable_only=False, readable_only=False):
        out = []
        for c in self.characteristics:
            if writable_only and not (c.has_prop(Characteristic.PROP_WRITE) or
                    c.has_prop(Characteristic.PROP_WRITE_NO_RSP)):
                continue
            if readable_only and not c.has_prop(Characteristic.PROP_READ):
                continue
            out.append(c.value_handle)
        return out

    def known_good_handle(self):
        """健康检查用:优先 GAP Device Name(0x2A00),其次任何基线可读的值 handle"""
        for c in self.characteristics:
            if c.uuid == "2a00":
                rec = self.baseline.get("0x%04X" % c.value_handle)
                if rec and rec.get("kind") == "value":
                    return c.value_handle
        for c in self.characteristics:
            if c.has_prop(Characteristic.PROP_READ):
                rec = self.baseline.get("0x%04X" % c.value_handle)
                if rec and rec.get("kind") == "value":
                    return c.value_handle
        return None

    def anchor_handles(self):
        """②层语料锚点:真实 handle ±1、服务边界、特殊值"""
        anchors = set()
        for c in self.characteristics:
            anchors.update((c.decl_handle, c.value_handle,
                            c.value_handle - 1, c.value_handle + 1))
            if c.cccd_handle:
                anchors.update((c.cccd_handle, c.cccd_handle + 1))
        for s in self.services:
            anchors.update((s.start_handle, s.end_handle,
                            s.start_handle - 1, s.end_handle + 1))
        anchors.difference_update((0,))          # 0x0000 单独算边界,不作为真实锚点
        return sorted(h for h in anchors if 1 <= h <= 0xFFFF)


# ---------- 发现过程 ----------

class _Discovery:
    def __init__(self, transport):
        self.t = transport

    def _request(self, pdu: bytes, timeout=None):
        """一问一答:返回 (rsp_pdu|None, error:AttError|None)。
        LinkDrop 直接上抛(调用方应中止发现);其余异常记为错误。"""
        self.t.inject(pdu)
        try:
            rsp = self.t.recv_att(timeout)
        except LinkDrop:
            raise
        except Exception as e:
            return None, e
        if rsp is None:
            return None, None
        if rsp.pdu[0] == int(AttOpcode.ERROR_RSP):
            try:
                return rsp.pdu, parse_error_rsp(rsp.pdu[1:])
            except ValueError:
                return rsp.pdu, None
        return rsp.pdu, None


def _uuid_str(raw: bytes) -> str:
    """16 位 UUID 规范化为数值形式("2a00"),128 位保持原样 hex。"""
    if len(raw) == 2:
        return "%04x" % unpack("<H", raw)[0]
    return raw.hex()


def discover(transport, secondary=False, baseline=True) -> GattMap:
    """在已建立连接上做完整 GATT 发现。"""
    m = GattMap()
    d = _Discovery(transport)

    # 1) 服务
    svc_type = UUID_SECONDARY_SERVICE if secondary else UUID_PRIMARY_SERVICE
    start = 1
    while start <= 0xFFFF:
        pdu, err = d._request(read_by_group_type_req(start, 0xFFFF, svc_type))
        if pdu is None or err is not None:
            if err is not None and getattr(err, "error_code", None) != 0x0A:
                m.gaps.append({"step": "service", "start": start,
                               "error": repr(err)})
            break
        item_len = pdu[1]
        if item_len < 6 or (len(pdu) - 2) % item_len != 0:
            m.gaps.append({"step": "service", "start": start, "note": "bad item length"})
            break
        next_start = start
        for i in range(2, len(pdu), item_len):
            s, e = unpack("<HH", pdu[i:i + 4])
            uuid = _uuid_str(pdu[i + 4:i + item_len])
            m.services.append(Service(s, e, uuid))
            next_start = max(next_start, e + 1)
        if next_start <= start:
            break
        start = next_start
        if len(pdu) < 2 + item_len:   # 空响应防御
            break

    # 2) 特征声明(逐服务)
    for svc in m.services:
        cur = svc.start_handle
        while cur <= svc.end_handle:
            pdu, err = d._request(read_by_type_req(cur, svc.end_handle, UUID_CHAR_DECL))
            if pdu is None or err is not None:
                if err is not None and getattr(err, "error_code", None) != 0x0A:
                    m.gaps.append({"step": "char", "service": svc.uuid,
                                   "start": cur, "error": repr(err)})
                break
            if len(pdu) < 2:
                break
            item_len = pdu[1]
            if item_len < 5 or (len(pdu) - 2) % item_len != 0:
                m.gaps.append({"step": "char", "start": cur, "note": "bad item length"})
                break
            next_cur = cur
            for i in range(2, len(pdu), item_len):
                decl = unpack("<H", pdu[i:i + 2])[0]
                props = pdu[i + 2]
                value_handle = unpack("<H", pdu[i + 3:i + 5])[0]
                uuid = _uuid_str(pdu[i + 5:i + item_len])
                m.characteristics.append(Characteristic(decl, value_handle, props, uuid))
                next_cur = max(next_cur, decl + 1)
            if next_cur <= cur:
                break
            cur = next_cur

    # 3) 描述符/CCCD(Find Info,逐特征区间:声明+1 到 下一声明-1)
    chars_sorted = sorted(m.characteristics, key=lambda c: c.decl_handle)
    for idx, c in enumerate(chars_sorted):
        lo = c.value_handle + 1
        hi = (chars_sorted[idx + 1].decl_handle - 1 if idx + 1 < len(chars_sorted)
              else 0xFFFF)
        if lo > hi:
            continue
        cur = lo
        while cur <= hi:
            pdu, err = d._request(find_info_req(cur, hi))
            if pdu is None or err is not None:
                if err is not None and getattr(err, "error_code", None) != 0x0A:
                    m.gaps.append({"step": "desc", "start": cur, "error": repr(err)})
                break
            if len(pdu) < 2:
                break
            fmt = pdu[1]
            item_len = 4 if fmt == 1 else 18
            if (len(pdu) - 2) % item_len != 0:
                m.gaps.append({"step": "desc", "start": cur, "note": "bad format"})
                break
            next_cur = cur
            for i in range(2, len(pdu), item_len):
                h = unpack("<H", pdu[i:i + 2])[0]
                if item_len == 4 and unpack("<H", pdu[i + 2:i + 4])[0] == UUID_CCCD:
                    c.cccd_handle = h
                next_cur = max(next_cur, h + 1)
            if next_cur <= cur:
                break
            cur = next_cur

    # 4) 基线
    if baseline:
        for c in m.characteristics:
            key = "0x%04X" % c.value_handle
            if key in m.baseline:
                continue
            pdu, err = d._request(read_req(c.value_handle))
            if pdu is None:
                m.baseline[key] = {"kind": "timeout"}
            elif err is not None:
                m.baseline[key] = {"kind": "error", "code": err.error_code}
            elif pdu[0] == int(AttOpcode.READ_RSP):
                m.baseline[key] = {"kind": "value", "value": pdu[1:].hex()}
            else:
                m.baseline[key] = {"kind": "unexpected", "pdu": pdu.hex()}

    return m
