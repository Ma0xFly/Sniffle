#!/usr/bin/env python3
# att-fuzz/gui/theme.py
"""页面骨架:头部(状态 chip)+ 左侧导航。每个页面开头调用 layout()。"""

from nicegui import ui

from .state import (CLASS_META, CONNECTING, IDLE, PAUSED, RUNNING, STOPPING,
                    STATUS_TEXT, state)

STATUS_COLOR = {IDLE: "grey", CONNECTING: "amber", RUNNING: "green",
                PAUSED: "orange", STOPPING: "red"}


def layout(title: str):
    ui.colors(primary="#0ea5e9")
    ui.dark_mode(True)

    with ui.header().classes("items-center justify-between bg-slate-800"):
        with ui.row().classes("items-center gap-3"):
            ui.icon("bluetooth_searching", color="sky-400").classes("text-2xl")
            ui.label("Sniffle ATT Fuzzer").classes("text-lg font-semibold")
            ui.separator().props("vertical")
            ui.label(title).classes("text-sm opacity-70")
        chip = ui.badge("—", color="grey").classes("text-sm")
        mode_label = ui.label("").classes("text-xs opacity-60")

        def poll_header():
            s = state.status
            txt = STATUS_TEXT.get(s, s)
            if s == RUNNING and state.mode:
                txt = "运行中·%s" % state.mode
            chip.set_text(txt)
            chip._props["color"] = STATUS_COLOR.get(s, "grey")
            chip.update()
            with state.lock:
                err = state.error_short
                mode = state.mode
            mode_label.set_text(("⚠ " + err[:60]) if err else
                                (MODE_NAME.get(mode, "") if mode else ""))

    ui.timer(0.6, poll_header)

    with ui.left_drawer(bordered=True).classes("bg-slate-900 max-w-[220px]"):
        ui.label("导航").classes("text-xs uppercase opacity-50 px-2")
        for path, icon, name in [
                ("/", "tune", "控制台"),
                ("/dashboard", "monitor_heart", "仪表盘"),
                ("/results", "table_view", "结果与重放"),
                ("/history", "history", "历史会话"),
        ]:
            with ui.link(name, path).classes(
                    "flex items-center gap-2 px-3 py-2 rounded hover:bg-slate-800 "
                    "no-underline text-slate-200 w-full"):
                ui.icon(icon).classes("text-slate-400")
                ui.label(name)
        ui.separator()
        if state.demo:
            ui.badge("离线演示模式", color="purple").classes("text-xs")
            ui.label("FakeHw 模拟,无真实硬件").classes("text-[10px] opacity-50 px-2")
        ui.label("串口按任务占用:空闲时 CLI 可用").classes(
                "text-[10px] opacity-40 px-2 mt-auto")


MODE_NAME = {"probe": "广播探测", "discover": "GATT 发现", "fuzz": "Fuzz",
             "replay": "重放", "impersonate": "加密冒充", "server": "反向角色"}
