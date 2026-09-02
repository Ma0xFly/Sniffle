#!/usr/bin/env python3
# att-fuzz/gui/pages/control.py
"""控制台页:硬件连接、目标档案、策略参数、运行控制、GATT 树。"""

import json

from nicegui import ui

from ..controller import controller, list_serial_ports
from ..state import IDLE, PAUSED, RUNNING, state
from ..theme import layout
from ..util import TARGETS_DIR, STRATEGIES_DIR, gatt_tree_nodes

DEMO_TARGET = {"name": "demo-headphone (FakeHw)", "mac": "AA:BB:CC:DD:EE:FF",
               "mac_random": True, "conn_interval": 12, "latency": 0,
               "connect_timeout": 10}

NEW_TEMPLATE = {"name": "new-target", "mac": "", "search_string": "",
                "mac_random": 1, "conn_interval": 12, "latency": 0,
                "connect_timeout": 10, "pairing": "none",
                "bt_keys": "", "keys_mac": "", "phone_mac": "",
                "_字段说明": {
                    "name": "档案名,也是保存的文件名(如 new-target.json)",
                    "mac": "目标蓝牙地址 AA:BB:CC:DD:EE:FF;与 search_string 至少填一个",
                    "search_string": "广播名片段(如 'vivo');目标地址会轮换(耳机常见)时优先用它",
                    "mac_random": "地址类型:1=随机(RPA/静态),0=public;"
                                  "不确定就先跑 --probe 实测校对",
                    "conn_interval": "连接间隔,单位 1.25ms;越小 fuzz 越快(建议 12~24)",
                    "latency": "外设延迟;0=每个连接事件必响应,崩溃判定最稳",
                    "connect_timeout": "连接超时秒数",
                    "pairing": "配对要求;阶段一只支持 none(免配对目标)",
                    "bt_keys": "(可选)密钥文件相对路径(如 bt_keys/vivo.conf);"
                               "放 targets/bt_keys/ 下;加密冒充用",
                    "keys_mac": "(可选)bt_config 里目标设备 MAC(书写序);"
                                "99% 与 mac 相同,留空自动用 mac",
                    "phone_mac": "(可选)手机 public MAC(书写序);加密冒充冒充此地址",
                }}


def page():
    layout("控制台")

    # ---------- 硬件 ----------
    with ui.card().classes("w-full"):
        ui.label("硬件与连接").classes("text-sm font-semibold opacity-80")
        with ui.row().classes("items-center gap-4 w-full flex-nowrap"):
            ser = ui.select(list_serial_ports(), value="", label="串口(留空=自动探测 XDS110)") \
                .classes("w-80").props("dense outlined")
            ui.button(icon="refresh", on_click=lambda: ser.set_options(
                list_serial_ports())).props("flat round dense") \
                .tooltip("刷新串口列表")
            fw = ui.label("固件: —").classes("text-xs opacity-70")

        def poll_fw():
            v = state.conn.get("fw_version")
            fw.set_text("固件: %s" % (v or "—"))
            fw.style("color: #fbbf24" if v and "1.12" not in str(v) and
                     "演示" not in str(v) and "未知" not in str(v) else "")
        ui.timer(1.0, poll_fw)

    # ---------- 目标档案 ----------
    with ui.card().classes("w-full"):
        ui.label("目标档案 (targets/*.json)").classes("text-sm font-semibold opacity-80")
        names = _target_names()
        sel = ui.select(names + (["__demo__"] if _demo() else []),
                        value=names[0] if names else None,
                        label="选择档案", with_input=True).classes("w-72")
        editor = ui.textarea(label="档案 JSON(可编辑)", value="{\n}").classes("w-full") \
            .props("outlined dense rows=8")
        msg = ui.label("").classes("text-xs")

        def load_target(name=None):
            name = name or sel.value
            if not name:
                return
            if name == "__demo__":
                editor.value = json.dumps(DEMO_TARGET, ensure_ascii=False, indent=2)
                return
            p = TARGETS_DIR / ("%s.json" % name if not name.endswith(".json") else name)
            if p.exists():
                editor.value = p.read_text(encoding="utf-8")

        def save_target():
            try:
                data = json.loads(editor.value or "{}")
            except json.JSONDecodeError as e:
                msg.set_text("JSON 解析失败: %s" % e).style("color:#f87171")
                return
            if not data.get("mac") and not data.get("search_string"):
                msg.set_text("mac / search_string 至少填一个").style("color:#f87171")
                return
            name = data.get("name") or "target"
            TARGETS_DIR.mkdir(parents=True, exist_ok=True)
            p = TARGETS_DIR / ("%s.json" % name)
            p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            sel.set_options(_target_names() + (["__demo__"] if _demo() else []))
            sel.set_value(name)
            msg.set_text("已保存: %s" % p).style("color:#4ade80")

        def new_target():
            """生成新档案模板填入编辑器(名字避开现有档案),保存后才落盘。"""
            existing = set(_target_names())
            name, i = NEW_TEMPLATE["name"], 1
            while name in existing:
                i += 1
                name = "%s-%d" % (NEW_TEMPLATE["name"], i)
            editor.value = json.dumps(dict(NEW_TEMPLATE, name=name),
                                      ensure_ascii=False, indent=2)
            msg.set_text("新档案模板: %s -- 填 mac 或 search_string 后点\"保存档案\""
                         % name).style("color:#fbbf24")

        def delete_target():
            name = sel.value
            if not name or name == "__demo__":
                msg.set_text("没有可删除的档案").style("color:#f87171")
                return
            p = TARGETS_DIR / ("%s.json" % name if not name.endswith(".json") else name)
            if not p.exists():
                msg.set_text("档案文件不存在: %s" % p).style("color:#f87171")
                return
            with ui.dialog() as confirm, ui.card():
                ui.label("确认删除档案 %s?" % p.name).classes("text-sm")
                ui.label("删除后不可恢复,文件: %s" % p).classes("text-xs opacity-60")
                with ui.row().classes("justify-end w-full"):
                    ui.button("取消", on_click=confirm.close).props("flat")
                    def _do_delete():
                        confirm.close()
                        p.unlink()
                        msg.set_text("已删除: %s" % p).style("color:#4ade80")
                        names = _target_names()
                        sel.set_options(names + (["__demo__"] if _demo() else []))
                        sel.set_value(names[0] if names else None)
                        if names:
                            load_target(names[0])
                        else:
                            editor.value = "{\n}"
                    ui.button("删除", on_click=_do_delete).props("color=negative")
            confirm.open()

        sel.on_value_change(lambda e: load_target(e.value))
        with ui.row():
            ui.button("新建", on_click=new_target).props("flat dense")
            ui.button("载入", on_click=lambda: load_target()).props("flat dense")
            ui.button("删除", on_click=delete_target).props("flat dense color=negative")
            ui.button("保存档案", on_click=save_target).props("dense color=primary")
        ui.separator().classes("my-1")
        ui.label("从手机扫描（需 root + USB 连接）").classes("text-xs opacity-60")
        with ui.row().classes("items-center gap-2 w-full"):
            scan_adb = ui.input("adb-serial", placeholder="手机序列号(可选)") \
                .classes("w-56").props("dense outlined")
            b_scan = ui.button("扫描手机", icon="phone_android",
                               on_click=lambda: _scan_btconfig()) \
                .props("dense color=primary")
        scan_sel = ui.select(
            [], value=None,
            label="扫描结果(选中后自动填档案)",
            with_input=True).classes("w-full").props("dense outlined")

        def _scan_btconfig():
            ok, why = controller.run_scan_btconfig(
                adb_serial=scan_adb.value or None)
            if not ok:
                ui.notify(why, type="warning")

        def _on_scan_select(e):
            sr = state.bt_scan_results
            if not sr or not e.value:
                return
            mac = str(e.value)
            dev = next((d for d in sr.devices if d.mac == mac), None)
            if dev is None:
                return
            tgt = {
                "name": dev.name or "unknown",
                "mac": dev.mac.upper(),
                "mac_random": dev.addr_type,
                "phone_mac": sr.phone_mac.upper(),
                "ltk": dev.ltk_hex,
                "conn_interval": 12,
                "latency": 0,
                "connect_timeout": 10,
                "pairing": "none",
            }
            editor.value = json.dumps(tgt, ensure_ascii=False, indent=2)
            ui.notify("已填充档案: %s" % dev.name, type="positive")

        scan_sel.on_value_change(_on_scan_select)

        def poll_scan():
            sr = state.bt_scan_results
            if sr and len(scan_sel.options or []) != len(sr.devices):
                opts = [{"label": "%s — %s" % (d.mac, d.name),
                         "value": d.mac} for d in sr.devices]
                scan_sel.set_options(opts)

        ui.timer(1.0, poll_scan)

    # ---------- 策略与参数 ----------
    strat_card = ui.card().classes("w-full")
    with strat_card:
        ui.label("策略与参数").classes("text-sm font-semibold opacity-80")
        strats = [str(p.relative_to(STRATEGIES_DIR)) for p in
                  sorted(STRATEGIES_DIR.rglob("*.yaml"))] if STRATEGIES_DIR.exists() else []
        if strats:
            with ui.element('div').classes('flex flex-wrap gap-2 w-full'):
                checks = {s: ui.checkbox(s, value=True).classes("text-xs")
                          for s in strats}
        else:
            checks = {}
            ui.label("strategies/ 下没有 yaml").classes("text-xs opacity-50")
        with ui.row().classes("items-center gap-4 flex-wrap"):
            seed = ui.number("seed", value=1, min=0, precision=0).classes("w-28")
            maxc = ui.number("max-cases(0=全量)", value=0, min=0, precision=0).classes("w-40")
            rounds_n = ui.number("rounds", value=0, min=0, precision=0).classes("w-28")
            round_budget = ui.number("round-budget", value=100, min=1, precision=0).classes("w-32")

    # ---------- 加密冒充参数(条件显示) ----------
    imp_card = ui.card().classes("w-full")
    with imp_card:
        ui.label("加密冒充参数").classes("text-sm font-semibold opacity-80")
        with ui.column().classes("gap-2 w-full"):
            imp_duration = ui.number("imp-duration(秒,0=无限)", value=0, min=0,
                                     precision=0).classes("w-40")
            ui.label("bt_keys/keys_mac/phone_mac/wall_ledger/ltk 全从档案 JSON 读取,"
                     "用上方扫描手机按钮自动填充").classes("text-[10px] opacity-40")
    imp_card.set_visibility(False)

    # 初始载入档案
    load_target(sel.value)

    # ---------- 反向角色参数(条件显示) ----------
    srv_card = ui.card().classes("w-full")
    with srv_card:
        ui.label("反向角色参数").classes("text-sm font-semibold opacity-80")
        with ui.column().classes("gap-2 w-full"):
            srv_name = ui.input("server-name", value="Sniffle Server") \
                .classes("w-full").props("dense outlined")
            with ui.row().classes("gap-4 flex-wrap"):
                srv_duration = ui.number("server-duration(秒,0=无限)", value=0,
                                         min=0, precision=0).classes("w-40")
                srv_adb = ui.input("adb-serial(可选)", placeholder="ZD9L8H454HDY7DEU") \
                    .classes("w-56").props("dense outlined")
    srv_card.set_visibility(False)

    # ---------- 运行控制 ----------
    with ui.card().classes("w-full"):
        ui.label("运行控制").classes("text-sm font-semibold opacity-80")
        mode_sel = ui.toggle(
            {"central": "直连 Fuzz", "impersonate": "加密冒充",
             "server": "反向角色"},
            value="central").classes("text-xs")

        def _on_mode_change(e):
            m = e.value or "central"
            imp_card.set_visibility(m == "impersonate")
            srv_card.set_visibility(m == "server")
            # 策略+参数卡在 server 模式隐藏(server 无语料)
            strat_card.set_visibility(m != "server")
            # 按钮标签
            b_run.set_text({"central": "开始 Fuzz",
                            "impersonate": "开始冒充",
                            "server": "开始广播"}[m])

        mode_sel.on_value_change(_on_mode_change)

        with ui.row().classes("items-center gap-2"):
            b_probe = ui.button("探测广播", icon="radar", on_click=lambda: _probe())
            b_disc = ui.button("仅发现 GATT", icon="travel_explore", on_click=lambda: _discover())
            b_run = ui.button("开始 Fuzz", icon="play_arrow", on_click=lambda: _start()) \
                .props("color=primary")
            b_pause = ui.button("暂停", icon="pause", on_click=controller.pause) \
                .props("flat")
            b_resume = ui.button("继续", icon="play_circle", on_click=controller.resume) \
                .props("flat")
            b_stop = ui.button("停止", icon="stop", on_click=controller.stop) \
                .props("flat color=negative")
        progress = ui.linear_progress(value=0).classes("w-full")
        stat_line = ui.label("").classes("text-xs opacity-80")
        current_line = ui.label("").classes("text-xs opacity-60")

        def _cur_target():
            try:
                data = json.loads(editor.value or "{}")
            except json.JSONDecodeError:
                return None, "目标档案 JSON 无效"
            if not data.get("mac") and not data.get("search_string"):
                return None, "目标档案需要 mac 或 search_string"
            return data, None

        def _strategy_paths():
            return [str(STRATEGIES_DIR / s) for s, c in checks.items() if c.value]

        def _probe():
            tgt, err = _cur_target()
            if err:
                ui.notify(err, type="negative")
                return
            ok, why = controller.run_probe(tgt, serport=ser.value or None, demo=_demo())
            if not ok:
                ui.notify(why, type="warning")

        def _discover():
            tgt, err = _cur_target()
            if err:
                ui.notify(err, type="negative")
                return
            ok, why = controller.run_discover(tgt, serport=ser.value or None, demo=_demo())
            if not ok:
                ui.notify(why, type="warning")

        def _fuzz():
            tgt, err = _cur_target()
            if err:
                ui.notify(err, type="negative")
                return
            paths = _strategy_paths()
            if not paths:
                ui.notify("至少选一个策略 yaml", type="warning")
                return
            ok, why = controller.run_fuzz(tgt, paths, seed=int(seed.value or 1),
                                          max_cases=int(maxc.value or 0),
                                          serport=ser.value or None, demo=_demo())
            if not ok:
                ui.notify(why, type="warning")

        def _impersonate():
            tgt, err = _cur_target()
            if err:
                ui.notify(err, type="negative")
                return
            bt_keys = tgt.get("bt_keys")
            keys_mac = tgt.get("keys_mac") or tgt.get("mac")
            phone_mac = tgt.get("phone_mac")
            if not bt_keys:
                ui.notify("档案缺少 bt_keys:请在 targets/bt_keys/ 放密钥文件"
                          "并在 JSON 填 bt_keys 字段", type="warning")
                return
            if not phone_mac:
                ui.notify("档案缺少 phone_mac(手机 public MAC)", type="warning")
                return
            paths = _strategy_paths() or None
            ok, why = controller.run_impersonation(
                tgt, bt_keys_path=bt_keys,
                keys_mac=keys_mac or None,
                phone_mac=phone_mac,
                strategy_paths=paths, seed=int(seed.value or 1),
                max_cases=int(maxc.value or 0),
                rounds=int(rounds_n.value or 0),
                round_budget=int(round_budget.value or 100),
                wall_ledger=tgt.get("wall_ledger"),
                duration=float(imp_duration.value or 0),
                serport=ser.value or None, demo=_demo())
            if not ok:
                ui.notify(why, type="warning")

        def _server():
            tgt, _ = _cur_target()
            ok, why = controller.run_server(
                tgt or {}, name=srv_name.value or "Sniffle Server",
                duration=float(srv_duration.value or 0),
                interval_ms=200,
                adb_serial=srv_adb.value or None,
                serport=ser.value or None, demo=_demo())
            if not ok:
                ui.notify(why, type="warning")

        def _start():
            m = mode_sel.value or "central"
            if m == "central":
                _fuzz()
            elif m == "impersonate":
                _impersonate()
            elif m == "server":
                _server()

        def poll_run():
            p = state.progress()
            total, done = p["total"], p["done"]
            progress.set_value(done / total if total else
                               (0.99 if state.status in (RUNNING, PAUSED) else 0))
            rate = done / (p["elapsed"] / 60) if p["elapsed"] > 1 else 0
            stat_line.set_text("%d/%d 用例 · %.1f 用例/分 · 告警 %d · 已用 %.0f 分" %
                               (done, total, rate, p["alerts"], p["elapsed"] / 60))
            current_line.set_text("当前: %s" % (p["current"] or "—"))
            busy = controller.busy()
            live = state.status in (RUNNING, PAUSED)
            b_probe.disable() if busy else b_probe.enable()
            b_disc.disable() if busy else b_disc.enable()
            b_run.disable() if busy else b_run.enable()
            b_pause.disable() if not live or state.status != RUNNING else b_pause.enable()
            b_resume.disable() if state.status != PAUSED else b_resume.enable()
            b_stop.disable() if not busy else b_stop.enable()
        ui.timer(0.4, poll_run)

        # probe 结果
        probe_box = ui.column().classes("w-full")

        def poll_probe():
            r = state.probe_result
            if r is not None and not probe_box.children:
                if r.get("found"):
                    with probe_box, ui.row().classes("items-center gap-2"):
                        ui.badge("目标可见", color="green")
                        ui.label("addr=%s  类型=%s  RSSI=%d dBm" %
                                 (r["addr"], r["addr_type"], r["rssi"])).classes("text-xs")
                else:
                    with probe_box, ui.row().classes("items-center gap-2"):
                        ui.badge("未发现", color="red")
                        ui.label("15s 内未见广播:检查耳机配对模式 / MAC").classes("text-xs")
        ui.timer(1.0, poll_probe)

    # ---------- GATT 树 ----------
    with ui.card().classes("w-full"):
        ui.label("GATT 地图(发现后更新)").classes("text-sm font-semibold opacity-80")
        tree_holder = ui.column().classes("w-full")

        def poll_gatt():
            g = state.gatt
            if g and not tree_holder.children:
                nodes = gatt_tree_nodes(g)
                if nodes:
                    tree_holder.clear()
                    with tree_holder:
                        ui.tree(nodes, label_key="label",
                                on_select=None).classes("w-full text-xs").props(
                                "default-expand-all dense")
                else:
                    tree_holder.clear()
                    with tree_holder:
                        ui.label("GATT 地图为空").classes("text-xs opacity-50")
        ui.timer(1.0, poll_gatt)

    # ---------- 控制器日志 ----------
    with ui.card().classes("w-full"):
        ui.label("运行日志").classes("text-sm font-semibold opacity-80")
        log_area = ui.log(max_lines=200).classes("w-full h-40 text-xs")

        # 每个页面持自己的游标,多标签/多窗口同时打开不会互相抢日志行
        log_cursor = [state.log_seq()]

        def poll_log():
            lines, log_cursor[0] = state.logs_since(log_cursor[0])
            for line in lines:
                log_area.push("%s %s" % (line["ts"], line["line"]))
        ui.timer(0.5, poll_log)

        # 页面打开时若内存日志为空(进程刚重启/新开页面),回放磁盘日志尾部
        from ..state import LOG_FILE, load_log_tail
        if not state.log_lines:
            tail = load_log_tail()
            if tail:
                log_area.push("---- 历史日志回放(%s) ----" % LOG_FILE.name)
                for l in tail:
                    log_area.push(l)


def _demo() -> bool:
    from ..state import DEMO_MODE
    return DEMO_MODE


def _target_names():
    if TARGETS_DIR.exists():
        return sorted(p.stem for p in TARGETS_DIR.glob("*.json"))
    return []
