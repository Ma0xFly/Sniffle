#!/usr/bin/env python3
# att-fuzz/gui/pages/dashboard.py
"""实时仪表盘:进度/分类分布/速率曲线/连接健康/告警流/事件流。"""

from nicegui import ui

from ..state import CLASS_META, RUNNING, state
from ..theme import layout
from ..util import CLASS_BADGE, row_to_ui


def page():
    layout("实时仪表盘")

    # ---- 顶部统计卡 ----
    with ui.row().classes("w-full flex-nowrap gap-3"):
        c_done = _stat_card("用例进度", "—", "play_circle")
        c_alert = _stat_card("告警", "0", "warning", "#f87171")
        c_rate = _stat_card("速率", "—", "speed")
        c_time = _stat_card("已用时", "—", "timer")

    with ui.row().classes("w-full flex-nowrap items-stretch gap-3"):
        # ---- 分类分布 ----
        with ui.card().classes("w-1/3"):
            ui.label("分类分布").classes("text-sm font-semibold opacity-80")
            donut = ui.echart(_donut_options({}), on_click=None).classes("h-64 w-full")
        # ---- 速率曲线 ----
        with ui.card().classes("w-1/3"):
            ui.label("累计用例 / 分钟").classes("text-sm font-semibold opacity-80")
            rate = ui.echart(_rate_options([])).classes("h-64 w-full")
        # ---- 连接健康 ----
        with ui.card().classes("w-1/3"):
            ui.label("连接健康").classes("text-sm font-semibold opacity-80")
            health = ui.column().classes("gap-1 w-full")

            def render_health():
                snap = state.conn_snapshot()
                health.clear()
                with health:
                    _ser = snap.get("serial", "—")
                    _chip("串口", _ser,
                          "green" if _ser == "空闲"
                          else ("grey" if "演示" in _ser else "orange"))
                    _chip("链路", "UP" if snap["link_up"] else "DOWN",
                          "green" if snap["link_up"] else "red")
                    _chip("连接事件", str(snap["cur_event"]))
                    _chip("ATT MTU", str(snap["att_mtu"]))
                    _chip("LL max", str(snap["ll_max"]))
                    _chip("TX 队列满", "是" if snap["tx_queue_full"] else "否",
                          "red" if snap["tx_queue_full"] else "grey")
                    _chip("重连次数", str(snap["reconnects"]))
                    _chip("加密", "加密" if snap.get("encrypted") else "明文",
                          "green" if snap.get("encrypted") else "grey")
                    _chip("ATT 冻结", str(snap.get("att_freeze_count", 0)),
                          "brown" if snap.get("att_freeze_count", 0) else "grey")
                    _chip("固件", str(snap["fw_version"] or "—"))
            ui.timer(1.0, render_health)

    # ---- 告警流 + 事件流 ----
    with ui.row().classes("w-full items-stretch gap-3"):
        with ui.card().classes("w-1/2"):
            with ui.row().classes("items-center gap-2"):
                ui.label("告警用例").classes("text-sm font-semibold opacity-80")
                alert_badge = ui.badge("0", color="red")
            alert_table = ui.table(
                columns=[{"name": "case_id", "label": "用例", "field": "case_id", "align": "left"},
                         {"name": "classification", "label": "分类", "field": "cls_text", "align": "left"},
                         {"name": "handle_str", "label": "Handle", "field": "handle_str", "align": "left"}],
                rows=[], row_key="case_id", pagination=10).classes("w-full text-xs")

        with ui.card().classes("w-1/2"):
            with ui.row().classes("items-center gap-2 w-full"):
                ui.label("传输层事件流").classes("text-sm font-semibold opacity-80")
                kind_filter = ui.select(
                    [None, "inject", "rx_att", "terminate", "state", "connected",
                     "fw_debug", "marker", "data_size", "dle_rsp",
                     "enc_req_sent", "enc_rsp_recv", "enc_engaged",
                     "peer_burst_handled", "gatt_discovered",
                     "wall_handles_loaded", "corpus_done", "read_ok",
                     "read_timeout", "conn_start", "link_drop", "bond_loaded",
                     "setaddr", "impersonation_error"],
                    value=None, label="过滤 kind", with_input=True) \
                    .classes("w-40 text-xs")
            event_log = ui.log(max_lines=300).classes("w-full h-56 text-[11px]")

    _last_event_ts = [0]

    def poll():
        p = state.progress()
        # 统计卡
        total, done = p["total"], p["done"]
        c_done[1].set_text("%d / %s" % (done, total or "∞"))
        c_alert[1].set_text(str(p["alerts"]))
        rate = done / (p["elapsed"] / 60) if p["elapsed"] > 2 else 0
        c_rate[1].set_text("%.1f /分" % rate if rate else "—")
        c_time[1].set_text("%.0f 分 %.0f 秒" % (p["elapsed"] // 60, p["elapsed"] % 60)
                           if p["elapsed"] else "—")
        alert_badge.set_text(str(p["alerts"]))
        # 图
        donut.options = _donut_options(p["counts"])
        rate.options = _rate_options(p["rate"])
        # 告警表
        alert_table.rows = [row_to_ui(r) | {"cls_text": CLASS_BADGE.get(
            r["classification"], ("", r["classification"]))[1]}
            for r in list(state.alerts)[-50:]][::-1]
        alert_table.update()
        # 事件流(增量拉取)
        with state.lock:
            fresh = [e for e in state.events if e.get("ts", 0) > _last_event_ts[0]]
        if fresh:
            _last_event_ts[0] = fresh[-1].get("ts", 0)
            kf = kind_filter.value
            for e in fresh:
                if kf and e.get("kind") != kf:
                    continue
                event_log.push(_fmt_event(e))

    ui.timer(0.5, poll)


def _stat_card(title, value, icon, color="#38bdf8"):
    box = []
    with ui.card().classes("flex-1").style("border-top: 3px solid %s" % color) as card:
        with ui.row().classes("items-center gap-3 w-full flex-nowrap"):
            ui.icon(icon, color=None).style("color:%s;font-size:1.6rem" % color)
            with ui.column().classes("gap-0"):
                ui.label(title).classes("text-[11px] opacity-60")
                v = ui.label(value).classes("text-xl font-bold")
    return card, v


def _chip(label, value, color=None):
    with ui.row().classes("items-center gap-2 w-full justify-between"):
        ui.label(label).classes("text-xs opacity-60")
        ui.badge(value, color=color or "slate").classes("text-xs")


def _donut_options(counts: dict):
    data = []
    for cls, n in counts.items():
        meta = CLASS_META.get(cls, (cls, "#9e9e9e", False))
        data.append({"name": "%s(%d)" % (meta[0], n), "value": n,
                     "itemStyle": {"color": meta[1]}})
    return {
        "backgroundColor": "transparent",
        "tooltip": {"trigger": "item"},
        "legend": {"bottom": 0, "textStyle": {"color": "#94a3b8", "fontSize": 10}},
        "series": [{
            "type": "pie", "radius": ["40%", "70%"], "center": ["50%", "45%"],
            "label": {"show": False}, "data": data,
        }],
    }


def _rate_options(points):
    return {
        "backgroundColor": "transparent",
        "grid": {"left": 40, "right": 10, "top": 15, "bottom": 25},
        "xAxis": {"type": "value", "name": "秒", "nameTextStyle": {"color": "#94a3b8"},
                  "axisLabel": {"color": "#94a3b8", "fontSize": 9}},
        "yAxis": {"type": "value", "axisLabel": {"color": "#94a3b8", "fontSize": 9}},
        "tooltip": {"trigger": "axis"},
        "series": [{
            "type": "line", "showSymbol": False, "smooth": True,
            "data": points, "lineStyle": {"color": "#38bdf8"},
            "areaStyle": {"color": "rgba(56,189,248,0.15)"},
        }],
    }


def _fmt_event(e: dict) -> str:
    import time
    try:
        t = time.strftime("%H:%M:%S", time.localtime(e.get("ts", 0)))
    except (TypeError, ValueError):
        t = ""
    kind = e.get("kind", "?")
    detail = ""
    if kind == "inject":
        detail = "pdu=%s gate=%s" % (e.get("pdu", "")[:32], e.get("gate_at"))
    elif kind == "rx_att":
        detail = "pdu=%s ev=%s" % (e.get("pdu", "")[:32], e.get("event"))
    elif kind == "terminate":
        detail = "reason=0x%02X" % e.get("reason", 0) if e.get("reason") is not None else ""
    elif kind == "state":
        detail = "%s -> %s" % (e.get("old"), e.get("new"))
    elif kind == "fw_debug":
        detail = str(e.get("msg", ""))[:60]
    elif kind == "connected":
        detail = "aa=%s" % e.get("aa")
    elif kind == "data_size":
        detail = "ll_max=%s att_mtu=%s" % (e.get("ll_max"), e.get("att_mtu"))
    else:
        detail = str({k: v for k, v in e.items()
                      if k not in ("ts", "kind")})[:60]
    return "%s %-10s %s" % (t, kind, detail)
