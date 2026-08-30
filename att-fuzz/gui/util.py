#!/usr/bin/env python3
# att-fuzz/gui/util.py
"""GUI 共用工具:台账读取、run 目录枚举、GATT 树构建、Markdown 摘要导出。"""

import json
import time
from pathlib import Path

ATT_FUZZ = Path(__file__).resolve().parents[1]
LOGS_DIR = ATT_FUZZ / "logs"
TARGETS_DIR = ATT_FUZZ / "targets"
STRATEGIES_DIR = ATT_FUZZ / "strategies"

RESULT_COLUMNS = [
    {"name": "case_id", "label": "用例", "field": "case_id", "align": "left", "sortable": True},
    {"name": "classification", "label": "分类", "field": "classification", "align": "left", "sortable": True},
    {"name": "layer", "label": "攻击层", "field": "layer", "align": "left", "sortable": True},
    {"name": "opcode", "label": "Opcode", "field": "opcode_str", "align": "left", "sortable": True},
    {"name": "handle", "label": "Handle", "field": "handle_str", "align": "left", "sortable": True},
    {"name": "offset", "label": "Offset", "field": "offset_str", "align": "left", "sortable": True},
    {"name": "value_len", "label": "长度", "field": "value_len", "align": "left", "sortable": True},
    {"name": "error_code", "label": "错误码", "field": "error_str", "align": "left", "sortable": True},
    {"name": "terminate_reason", "label": "Terminate", "field": "term_str", "align": "left", "sortable": True},
    {"name": "health", "label": "健康", "field": "health_str", "align": "left", "sortable": True},
    {"name": "ts_str", "label": "时间", "field": "ts_str", "align": "left", "sortable": True},
]

CLASS_BADGE = {
    "OK_RESPONSE": ("green-7", "OK"),
    "ERROR_RESPONSE": ("blue-6", "ERR"),
    "TIMEOUT": ("orange-7", "TIMEOUT"),
    "DISCONNECT_TERM": ("red-6", "DISC-TERM"),
    "DISCONNECT_SUP": ("red-7", "DISC-SUP"),
    "TX_QUEUE_FULL": ("grey-6", "TXFULL"),
    "HEALTH_DEGRADED": ("deep-orange-6", "DEGRADED"),
}


def _hex(v, width=2):
    return "0x%0*X" % (width, v) if isinstance(v, int) else "—"


def row_to_ui(rec: dict) -> dict:
    """ledger 原始行 -> 表格行(可读化)。"""
    hp, hpst = rec.get("health_pre"), rec.get("health_post")
    return {
        "case_id": rec.get("case_id", ""),
        "classification": rec.get("classification", "?"),
        "layer": rec.get("layer", ""),
        "opcode_str": _hex(rec.get("opcode")),
        "handle_str": _hex(rec.get("handle"), 4),
        "offset_str": _hex(rec.get("offset"), 4),
        "value_len": rec.get("value_len") if rec.get("value_len") is not None else "—",
        "error_str": _hex(rec.get("error_code")),
        "term_str": _hex(rec.get("terminate_reason")),
        "health_str": "%s→%s" % (hp or "?", hpst or "?"),
        "ts_str": rec.get("ts_str") or _fmt_ts(rec.get("ts")),
        "_raw": rec,
    }


def _fmt_ts(ts):
    try:
        return time.strftime("%H:%M:%S", time.localtime(ts)) if ts else ""
    except (TypeError, ValueError):
        return ""


def load_ledger(path) -> list:
    """读整个 ledger.jsonl,返回原始 rec 列表(坏行跳过)。"""
    path = Path(path)
    if not path.exists():
        return []
    out = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


RUN_MARKS = ("ledger.jsonl", "gatt_map.json", "capture.pcap", "transport.jsonl")


def run_dirs() -> list:
    """logs/ 下的会话目录,新→旧。
    目录名不限(改名后仍能识别);含任一会话产物
    (台账/GATT地图/pcap/传输日志)即算会话,纯发现任务也会显示。"""
    if not LOGS_DIR.exists():
        return []
    dirs = [d for d in LOGS_DIR.iterdir()
            if d.is_dir() and any((d / m).exists() for m in RUN_MARKS)]

    def _mtime(d):
        for m in RUN_MARKS:
            p = d / m
            if p.exists():
                return p.stat().st_mtime
        return d.stat().st_mtime

    return sorted(dirs, key=_mtime, reverse=True)


def run_stats(run_dir) -> dict:
    """一个 run 目录的概要:用例数/分类分布/时间。"""
    recs = load_ledger(Path(run_dir) / "ledger.jsonl")
    counts = {}
    for r in recs:
        c = r.get("classification", "?")
        counts[c] = counts.get(c, 0) + 1
    ts = recs[0].get("ts") if recs else None
    if ts is None:               # 纯发现任务没有台账,用目录时间兜底
        ts = Path(run_dir).stat().st_mtime
    gm = Path(run_dir) / "gatt_map.json"
    gatt_str = "—"
    if gm.exists():
        try:
            d = json.loads(gm.read_text(encoding="utf-8"))
            gatt_str = "%d服务/%d特征" % (len(d.get("services", [])),
                                          len(d.get("characteristics", [])))
        except Exception:
            gatt_str = "读取失败"
    return {
        "dir": str(run_dir),
        "name": Path(run_dir).name,
        "cases": len(recs),
        "counts": counts,
        "gatt_str": gatt_str,
        "alerts": sum(1 for r in recs
                      if r.get("classification") in
                      ("TIMEOUT", "DISCONNECT_TERM", "DISCONNECT_SUP", "HEALTH_DEGRADED")),
        "ts_str": _fmt_ts(ts),
    }


def gatt_tree_nodes(gatt: dict) -> list:
    """state.gatt 快照 -> ui.tree 节点。"""
    if not gatt:
        return []
    chars_in = {}
    for c in gatt.get("characteristics", []):
        svc = next((s for s in gatt.get("services", [])
                    if s["start"] <= c["decl"] <= s["end"]), None)
        key = svc["start"] if svc else 0
        chars_in.setdefault(key, []).append(c)

    props_names = {0x02: "read", 0x04: "write-wo-rsp", 0x08: "write",
                   0x10: "notify", 0x20: "indicate"}
    nodes = []
    for s in gatt.get("services", []):
        svc_children = []
        for c in chars_in.get(s["start"], []):
            props = [n for bit, n in props_names.items() if c["props"] & bit]
            line = "0x%04X %s [%s]" % (c["value"], c["uuid"], ",".join(props) or "-")
            base = c.get("baseline")
            if base:
                if base.get("kind") == "value":
                    line += " 基线=%dB" % len(bytes.fromhex(base.get("value", "")))
                elif base.get("kind") == "error":
                    line += " 基线=err 0x%02X" % base.get("code", 0)
            if c["cccd"]:
                line += " CCCD=0x%04X" % c["cccd"]
            svc_children.append({"id": "c%d" % c["value"], "label": line})
        nodes.append({"id": "s%d" % s["start"], "label": "%s [0x%04X-0x%04X]" %
                      (s["uuid"], s["start"], s["end"]), "children": svc_children})
    for gap in gatt.get("gaps", [])[:20]:
        nodes.append({"id": "g%s" % str(gap), "label": "⚠ gap: %s" % gap})
    return nodes


def build_summary_md(run_dir, stats=None) -> str:
    """run 目录 -> Markdown 会话总结。"""
    run_dir = Path(run_dir)
    st = stats or run_stats(run_dir)
    lines = [
        "# Fuzz 会话总结 — %s" % st["name"],
        "",
        "- 时间: %s" % st["ts_str"],
        "- 用例数: %d" % st["cases"],
        "- 告警数: %d" % st["alerts"],
        "",
        "## 分类分布",
        "",
        "| 分类 | 数量 |",
        "|---|---|",
    ]
    for cls, n in sorted(st["counts"].items(), key=lambda kv: -kv[1]):
        lines.append("| %s | %d |" % (cls, n))
    alerts = [r for r in load_ledger(run_dir / "ledger.jsonl")
              if r.get("classification") in
              ("TIMEOUT", "DISCONNECT_TERM", "DISCONNECT_SUP", "HEALTH_DEGRADED")]
    if alerts:
        lines += ["", "## 告警清单", "",
                  "| 用例 | 分类 | opcode | handle | terminate | 备注 |", "|---|---|---|---|---|---|"]
        for r in alerts:
            lines.append("| %s | %s | %s | %s | %s | %s |" % (
                r.get("case_id"), r.get("classification"),
                _hex(r.get("opcode")), _hex(r.get("handle"), 4),
                _hex(r.get("terminate_reason")),
                "; ".join(r.get("notes") or [])[:80]))
    gatt_path = run_dir / "gatt_map.json"
    if gatt_path.exists():
        try:
            g = json.loads(gatt_path.read_text())
            lines += ["", "## GATT 概要", "",
                      "- 服务 %d 个,特征 %d 个,gap %d 条" %
                      (len(g.get("services", [])), len(g.get("characteristics", [])),
                       len(g.get("gaps", [])))]
        except Exception:
            pass
    lines += ["", "产物: `ledger.jsonl` / `capture.pcap` / `transport.jsonl`", ""]
    return "\n".join(lines)
