#!/usr/bin/env python3
# att-fuzz/gui/pages/results.py
"""结果浏览 + replay 工作台:台账表格、过滤、用例详情、一键重放、Markdown 导出。"""

import json

from nicegui import ui

from ..controller import controller
from ..state import state
from ..theme import layout
from ..util import (RESULT_COLUMNS, CLASS_BADGE, build_summary_md, find_ledger,
                    load_ledger, row_to_ui, run_dirs)


def page():
    layout("结果与重放")

    recs_all = []          # 当前数据源的全部原始行
    source = {"kind": "live"}   # live / file

    with ui.card().classes("w-full"):
        with ui.row().classes("items-center gap-4 w-full flex-nowrap"):
            ui.label("数据源").classes("text-sm font-semibold opacity-80")
            live_radio = ui.toggle({"live": "当前运行"}, value="live")
            runs = [d.name for d in run_dirs()]
            run_sel = ui.select(runs, value=runs[0] if runs else None,
                                label="历史 run", with_input=True) \
                .classes("w-56").props("dense outlined")
            ui.button(icon="refresh", on_click=lambda: run_sel.set_options(
                [d.name for d in run_dirs()])).props("flat round dense")

        with ui.row().classes("items-center gap-3 w-full flex-nowrap"):
            cls_sel = ui.select(
                ["全部"] + list(CLASS_BADGE.keys()), value="全部",
                label="分类").classes("w-48").props("dense outlined")
            layer_in = ui.input("攻击层", placeholder="如 value/handle") \
                .classes("w-36").props("dense outlined")
            text_in = ui.input("搜索", placeholder="case_id / PDU 片段") \
                .classes("w-44").props("dense outlined")
            only_alerts = ui.checkbox("只看告警", value=False).props("dense")
            n_label = ui.label("").classes("text-xs opacity-60")
            ui.space()
            b_export = ui.button("导出 Markdown 摘要", icon="download",
                                 on_click=lambda: _export())

        table = ui.table(columns=RESULT_COLUMNS, rows=[], row_key="case_id",
                         pagination={"rowsPerPage": 25})
        table.classes("w-full text-xs").props("dense flat")

        def _on_row_click(e):
            row = None
            args = e.args
            if isinstance(args, dict):
                row = args.get("row")
                if row is None and isinstance(args.get("args"), dict):
                    row = args["args"].get("row")
            _show_detail(row)

        table.on("rowClick", _on_row_click)
        ui.label("提示: 点行看详情/重放。告警分类: TIMEOUT/掉链/健康异常").classes(
                "text-[10px] opacity-40")

    # ---------- 详情弹窗 ----------
    with ui.dialog() as dialog, ui.card().classes("w-[560px]"):
        d_title = ui.label("").classes("font-semibold")
        d_grid = ui.column().classes("gap-1 text-xs w-full")
        with ui.row():
            b_replay1 = ui.button("Replay ×1", icon="replay", on_click=lambda: _replay(1)) \
                .props("dense color=primary")
            b_replay5 = ui.button("Replay ×5", icon="fast_rewind", on_click=lambda: _replay(5)) \
                .props("dense")
            ui.space()
            ui.button("关闭", on_click=dialog.close).props("flat dense")
    detail = {"row": None}

    def _replay(n):
        rec = (detail.get("row") or {}).get("_raw")
        if not rec:
            return
        pdu = (rec.get("replay") or {}).get("pdu")
        if not pdu:
            ui.notify("该用例无 replay.pdu", type="warning")
            return
        tgt = _current_target()
        if tgt is None:
            ui.notify("目标档案无效,请到控制台检查", type="warning")
            return
        ok, why = controller.run_replay(pdu, tgt, times=n,
                                        serport=_serport(), demo=state.demo)
        if not ok:
            ui.notify(why, type="warning")
        else:
            ui.notify("已启动重放(占用串口,可在控制台页看进度)", type="info")
            dialog.close()

    def _show_detail(row):
        if not row:
            return
        detail["row"] = row
        rec = row.get("_raw", {})
        d_title.set_text("用例 %s [%s]" % (row["case_id"], row["classification"]))
        # replay 仅对直连 fuzz 台账(ledger.jsonl)有效;加密冒充/反向角色
        # 台账的 PDU 需加密链路或双向角色,通用 replay 不支持。
        replay_ok = source["kind"] == "live" or \
            (source["kind"] == "file" and
             (match := next((x for x in run_dirs() if x.name == run_sel.value), None))
             and (match / "ledger.jsonl").exists())
        b_replay1.disable() if not replay_ok else b_replay1.enable()
        b_replay5.disable() if not replay_ok else b_replay5.enable()
        if not replay_ok:
            b_replay1.tooltip("加密冒充/反向角色台账不支持通用重放")
            b_replay5.tooltip("加密冒充/反向角色台账不支持通用重放")
        d_grid.clear()
        with d_grid:
            base = rec.get("case") or {}
            _kv("layer / op", "%s / %s" % (row["layer"], base.get("op", "—")))
            _kv("handle / offset", "%s / %s" % (row["handle_str"], row["offset_str"]))
            _kv("value_len / hash", "%s / %s" % (row["value_len"], rec.get("value_hash", "—")))
            _kv("error / terminate", "%s / %s" % (row["error_str"], row["term_str"]))
            _kv("健康", row["health_str"])
            _kv("事件号", rec.get("event", "—"))
            _kv("备注", "; ".join(rec.get("notes") or []) or "—")
            _kv("响应 PDU", rec.get("response_pdu") or "—")
            _kv("重放 PDU", (rec.get("replay") or {}).get("pdu") or "—")
        dialog.open()

    def _current_target():
        name = state.demo and "demo"
        # 从目标目录读当前档案:控制台页编辑保存的档案以 name 字段为准,
        # 这里取 targets/ 下最新的一个(重放通常紧随 fuzz 会话)。
        from ..util import TARGETS_DIR
        best = None
        if TARGETS_DIR.exists():
            cands = sorted(TARGETS_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime)
            best = cands[-1] if cands else None
        if best is None:
            return None
        try:
            return json.loads(best.read_text(encoding="utf-8"))
        except Exception:
            return None

    def _serport():
        return None   # 自动探测(与控制台页一致)

    def _export():
        d = state.outdir if source["kind"] == "live" and state.outdir else \
            (str(run_dirs()[0]) if run_dirs() else None)
        if not d:
            ui.notify("没有可导出的会话", type="warning")
            return
        md = build_summary_md(d)
        out = __import__("pathlib").Path(d) / "summary.md"
        out.write_text(md, encoding="utf-8")
        try:
            ui.download(md, filename="summary-%s.md" % out.parent.name)
        except (TypeError, AttributeError):
            pass     # 旧版 NiceGUI 无此 API,文件已落盘
        ui.notify("已写入 %s" % out, type="positive")

    def _refresh_rows():
        nonlocal recs_all
        if source["kind"] == "live":
            with state.lock:
                recs_all = [r for r in state.results]
        else:
            d = run_dirs()
            match = next((x for x in d if x.name == run_sel.value), None)
            ledger_path = find_ledger(match) if match else None
            recs_all = load_ledger(ledger_path) if ledger_path else []
        cls = cls_sel.value
        layer = (layer_in.value or "").strip().lower()
        text = (text_in.value or "").strip().lower()
        rows = []
        for r in recs_all:
            ui_row = row_to_ui(r)
            if cls != "全部" and r.get("classification") != cls:
                continue
            if only_alerts.value and r.get("classification") not in (
                    "TIMEOUT", "DISCONNECT_TERM", "DISCONNECT_SUP",
                    "HEALTH_DEGRADED", "ATT_FREEZE"):
                continue
            if layer and layer not in (r.get("layer") or "").lower():
                continue
            if text and text not in json.dumps(
                    {k: r.get(k) for k in ("case_id", "response_pdu", "notes")},
                    default=str).lower():
                continue
            rows.append(ui_row)
        _colorize(rows)
        table.rows = rows[::-1]     # 新的在前
        table.update()
        n_label.set_text("共 %d 条" % len(rows))

    def _colorize(rows):
        for r in rows:
            badge = CLASS_BADGE.get(r["classification"])
            if badge:
                r["classification"] = r["classification"]  # 保留原值
                r["_cls_color"] = badge[0]

    def poll_live():
        if source["kind"] == "live":
            _refresh_rows()

    def _switch_source(e):
        source["kind"] = e.value
        if e.value == "live":
            live_radio.set_value("live")
        _refresh_rows()

    live_radio.on_value_change(lambda e: _switch_source({"value": e.value or "live"}))
    run_sel.on_value_change(lambda e: _switch_source({"value": "file"})
                            if e.value else None)
    for w in (cls_sel, layer_in, text_in, only_alerts):
        w.on_value_change(lambda *_: _refresh_rows())
    ui.timer(1.0, poll_live)


def _kv(label, value):
    with ui.row().classes("w-full justify-between gap-4 no-wrap"):
        ui.label(label).classes("opacity-50 shrink-0")
        ui.label(str(value)).classes("text-right break-all")
