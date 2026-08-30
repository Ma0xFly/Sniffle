#!/usr/bin/env python3
# att-fuzz/gui/pages/history.py
"""历史会话:run 列表、两次会话分类分布对比、摘要导出。"""

from nicegui import ui

from ..theme import layout
from ..util import CLASS_BADGE, build_summary_md, run_dirs, run_stats


def page():
    layout("历史会话")

    runs = run_dirs()
    if not runs:
        ui.card().classes("w-full")
        with ui.card().classes("w-full"):
            ui.label("logs/ 下还没有会话目录").classes("opacity-60")
            ui.label("先在控制台跑一次 Fuzz(或用 CLI)。产物在 att-fuzz/logs/<会话目录>/,含 ledger.jsonl 的目录都会被识别").classes(
                    "text-xs opacity-40")
        return

    stats = []
    for d in runs[:60]:
        try:
            stats.append(run_stats(d))
        except Exception:
            continue

    # ---- 会话列表 ----
    with ui.card().classes("w-full"):
        ui.label("会话列表(新→旧)").classes("text-sm font-semibold opacity-80")
        cols = [
            {"name": "name", "label": "会话", "field": "name", "align": "left", "sortable": True},
            {"name": "ts_str", "label": "开始时间", "field": "ts_str", "align": "left"},
            {"name": "gatt", "label": "GATT 发现", "field": "gatt_str", "align": "left"},
            {"name": "cases", "label": "用例数", "field": "cases", "align": "left", "sortable": True},
            {"name": "alerts", "label": "告警", "field": "alerts", "align": "left", "sortable": True},
        ]
        tbl = ui.table(columns=cols, rows=[{k: s[k] for k in ("name", "ts_str", "gatt_str",
                                                              "cases", "alerts")}
                                           for s in stats],
                       row_key="name", selection="multiple",
                       pagination={"rowsPerPage": 15}).classes("w-full text-xs")
        tbl.props("dense flat")
        hint = ui.label("勾选两个会话可做分类分布对比").classes("text-xs opacity-50")

    # ---- 对比图 ----
    with ui.card().classes("w-full"):
        ui.label("分类分布对比").classes("text-sm font-semibold opacity-80")
        compare = ui.echart(_compare_options([], [])).classes("h-72 w-full")

        def poll_selection():
            sel = tbl.selected or []
            if len(sel) == 2:
                a = next((s for s in stats if s["name"] == sel[0]), None)
                b = next((s for s in stats if s["name"] == sel[1]), None)
                if a and b:
                    compare.options = _compare_options(a["counts"], b["counts"],
                                                       a["name"], b["name"])
            elif len(sel) == 1:
                a = next((s for s in stats if s["name"] == sel[0]), None)
                if a:
                    compare.options = _compare_options(a["counts"], [], a["name"], None)
        ui.timer(1.0, poll_selection)

    # ---- 单会话摘要导出 ----
    def _export():
        match = next((s for s in stats if s["name"] == sel_run.value), None)
        if not match:
            return
        md = build_summary_md(match["dir"], stats=match)
        import pathlib
        out = pathlib.Path(match["dir"]) / "summary.md"
        out.write_text(md, encoding="utf-8")
        try:
            ui.download(md, filename="summary-%s.md" % match["name"])
        except (TypeError, AttributeError):
            pass
        ui.notify("已写入 %s" % out, type="positive")

    with ui.card().classes("w-full"):
        ui.label("导出摘要").classes("text-sm font-semibold opacity-80")
        with ui.row().classes("items-center gap-3"):
            sel_run = ui.select([s["name"] for s in stats], value=stats[0]["name"],
                                label="会话").classes("w-56").props("dense outlined")
            ui.button("生成 Markdown 摘要", icon="download", on_click=_export) \
                .props("dense color=primary")


def _compare_options(counts_a, counts_b, name_a="", name_b=""):
    classes = sorted(set(counts_a) | set(counts_b))
    legend, series = [], []
    if name_a:
        legend.append(name_a)
        series.append({"name": name_a, "type": "bar",
                       "data": [counts_a.get(c, 0) for c in classes],
                       "itemStyle": {"color": "#38bdf8"}})
    if name_b:
        legend.append(name_b)
        series.append({"name": name_b, "type": "bar",
                       "data": [counts_b.get(c, 0) for c in classes],
                       "itemStyle": {"color": "#f472b6"}})
    return {
        "backgroundColor": "transparent",
        "tooltip": {"trigger": "axis"},
        "legend": {"data": legend, "textStyle": {"color": "#94a3b8"}},
        "grid": {"left": 40, "right": 10, "top": 40, "bottom": 60},
        "xAxis": {"type": "category", "data": classes,
                  "axisLabel": {"color": "#94a3b8", "fontSize": 9,
                                "rotate": 30, "interval": 0}},
        "yAxis": {"type": "value", "axisLabel": {"color": "#94a3b8", "fontSize": 9}},
        "series": series,
    }
