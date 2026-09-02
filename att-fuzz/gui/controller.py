#!/usr/bin/env python3
# att-fuzz/gui/controller.py
"""
FuzzController -- 把 fuzz 主循环放进工作线程,UI 线程零串口接触。

- 四种模式:probe / discover / fuzz / replay,全部复用 core 的
  SniffleTransport + FuzzSession + corpus(与 CLI 完全同一套逻辑)
- fuzz 循环在每用例边界检查 pause/stop 标志(run_case 本身最多阻塞
  一个 response_timeout ≈ 2s,暂停/停止粒度 = 单用例)
- demo 模式:用 tests/test_dryrun.py 的 FakeHw 替换串口硬件
"""

import importlib.util
import logging
import re
import threading
import time
import traceback
from datetime import datetime
from pathlib import Path

from core.corpus import expand, load_yaml_files
from core.monitor import ObservableLedger
from core.session import FuzzSession
from core.transport import SniffleTransport, TransportError

from .bus import bus
from .state import (CONNECTING, IDLE, PAUSED, RUNNING, STOPPING, state)

log = logging.getLogger("att-fuzz.gui")

REPO = Path(__file__).resolve().parents[2]
ATT_FUZZ = REPO / "att-fuzz"

MODE_TEXT = {"probe": "广播探测", "discover": "GATT 发现",
             "fuzz": "Fuzz 运行", "replay": "PDU 重放",
             "impersonate": "加密冒充", "server": "反向角色",
             "scan_btconfig": "扫描手机"}


def list_serial_ports():
    """跨平台列出可用串口,返回 {设备: 带标签的显示名}。
    空键 "" = 自动探测(SniffleHW 会找 XDS110 数据口)。"""
    try:
        from serial.tools.list_ports import comports
        devices = sorted(p.device for p in comports())
    except Exception:
        import glob
        devices = sorted(glob.glob("/dev/ttyACM*") + glob.glob("/dev/ttyUSB*"))
    # 过滤主板自带的 legacy 串口(噪声)
    import re
    devices = [p for p in devices if not re.match(r"/dev/ttyS\d+$", p)]

    xds = None
    try:
        from sniffle.sniffle_hw import find_xds110_serport
        xds = find_xds110_serport()
    except Exception:
        pass

    opts = {"": "自动探测%s" % (" (%s,推荐)" % xds if xds else " (推荐)")}
    for p in devices:
        if p == xds:
            opts[p] = "%s (XDS110 数据口,推荐)" % p
        elif xds and p.startswith("/dev/ttyACM"):
            opts[p] = "%s (XDS110 辅助/JTAG 口,勿选)" % p
        else:
            opts[p] = p
    return opts


class FuzzController:
    def __init__(self):
        self._thread = None
        self._transport = None
        self._hw_lock = None
        self._snapshot_stop = threading.Event()

    # ---------- 对 UI 的接口 ----------

    def busy(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self, mode, fn):
        if self.busy():
            return False, "已有任务在运行(%s)" % MODE_TEXT.get(state.mode, state.mode)
        state.reset(mode)
        bus.reset()
        self._snapshot_stop.clear()
        self._thread = threading.Thread(
                target=self._worker, args=(mode, fn),
                name="att-fuzz-gui-%s" % mode, daemon=True)
        self._thread.start()
        return True, None

    def pause(self):
        state.pause_requested.set()
        state.set_status(PAUSED if state.status == RUNNING else state.status)

    def resume(self):
        if state.status == PAUSED:
            state.pause_requested.clear()
            state.set_status(RUNNING)

    def stop(self):
        if self.busy():
            state.stop_requested.set()
            state.set_status(STOPPING)
            state.pause_requested.clear()
            state.log_line("用户请求停止(当前用例结束后生效)")

    # ---------- 工作线程框架 ----------

    def _worker(self, mode, fn):
        try:
            fn()
            if not state.error_short and state.status != IDLE:
                state.set_status(IDLE)
                state.log_line("%s 完成" % MODE_TEXT.get(mode, mode))
        except Exception as e:
            log.exception("worker %s failed", mode)
            state.set_error("%s 失败: %s" % (MODE_TEXT.get(mode, mode), e),
                            detail="".join(traceback.format_exception(e)))
        finally:
            self._teardown()

    def _teardown(self):
        """每次任务结束必调:断链、关 pcap、关串口、复位事件桥。
        不清理的话旧串口句柄泄漏,下一次运行在同端口上开第二个句柄,
        固件/串口状态会错乱(实测第二次任务必挂)。"""
        t = self._transport
        self._transport = None
        self._snapshot_stop.set()
        if t is not None:
            try:
                if t.link_up:
                    t.disconnect()
                    time.sleep(1.2)
            except Exception:
                pass
            pcap = getattr(t, "pcap", None)
            if pcap is not None:
                try:
                    pcap.output.close()   # PcapBleWriter 无 close(),句柄在 .output
                except Exception:
                    pass
            try:
                t.hw.ser.close()
            except Exception:
                pass
            time.sleep(0.5)   # 等 CDC 枚举稳定,下次 open 干净
        lk, self._hw_lock = self._hw_lock, None
        if lk is not None:
            lk.release()
        with state.lock:
            state.conn["serial"] = "空闲"
        bus.reset()

    # ---------- 传输层构造 ----------

    def _make_transport(self, target, outdir, demo, serport=None) -> SniffleTransport:
        jsonl_path = (outdir / "transport.jsonl") if outdir else None
        if demo:
            hw = _make_fake_hw()()
            transport = SniffleTransport(hw, pcap=_make_pcap(outdir),
                                         jsonl_path=jsonl_path,
                                         conn_interval_units=target.get("conn_interval", 12))
            state.conn["fw_version"] = "演示模式(FakeHw)"
            with state.lock:
                state.conn["serial"] = "演示(无串口)"
        else:
            from core.serial_lock import SerialBusy, acquire as serial_acquire
            owner = "GUI %s" % MODE_TEXT.get(state.mode, state.mode)
            try:
                self._hw_lock = serial_acquire(
                        serport or target.get("serport"), owner)
            except SerialBusy as e:
                raise TransportError(str(e))
            with state.lock:
                state.conn["serial"] = "占用(%s, %s)" % (owner, self._hw_lock.port)
            try:
                transport = SniffleTransport(
                        _make_hw(serport or target.get("serport")),  # noqa: 延迟构造见 _make_hw
                        pcap=_make_pcap(outdir), jsonl_path=jsonl_path,
                        conn_interval_units=target.get("conn_interval", 12))
            except Exception as e:
                raise TransportError(
                        "打开串口失败(%s)。请确认: 板子已插 / udev 规则生效 / "
                        "串口未被 CLI 或其他程序占用 -- %s" % (serport, e))
            ver = None
            try:
                ver = transport.hw.probe_fw_version()
            except Exception:
                pass
            if ver is not None:
                state.conn["fw_version"] = str(ver)
                m = re.search(r"(\d+)\.(\d+)\.(\d+)", str(ver))
                if m and (int(m.group(1)), int(m.group(2))) < (1, 12):
                    state.log_line("警告: 固件 < 1.12.0,时序用例与掉链 reason 判定不可用")
            else:
                state.conn["fw_version"] = "未知(固件 <1.11?)"
        bus.attach_transport(transport)
        self._transport = transport
        return transport

    def _start_snapshot(self, transport):
        """定期把连接健康快照进 state(独立线程,运行期间)。"""
        def loop():
            while not self._snapshot_stop.is_set() and self._transport is transport:
                try:
                    snap = state.conn_snapshot()
                    snap.update({
                        "link_up": transport.link_up,
                        "cur_event": transport.cur_event,
                        "att_mtu": transport.att_mtu,
                        "ll_max": transport.ll_max,
                        "tx_queue_full": transport.tx_queue_full,
                        "encrypted": getattr(transport, "_enc_enabled", False),
                    })
                    with state.lock:
                        state.conn.update(snap)
                except Exception:
                    pass
                self._snapshot_stop.wait(0.5)
        threading.Thread(target=loop, name="att-fuzz-gui-snap", daemon=True).start()

    # ---------- 模式实现 ----------

    def run_probe(self, target, serport=None, demo=False):
        def fn():
            state.set_status(CONNECTING)
            state.log_line("探测目标广播: %s" % (target.get("mac") or target.get("search_string")))
            transport = self._make_transport(target, None, demo, serport)
            self._start_snapshot(transport)
            if not target.get("mac"):
                raise TransportError("广播探测需要目标档案填 mac(search_string 探测请直接跑发现)")
            wire, _ = transport._parse_mac(target["mac"])
            r = transport.probe(wire, timeout=15)
            with state.lock:
                state.probe_result = r
            if r.get("found"):
                state.log_line("找到目标! addr=%s addr_type=%s rssi=%d" %
                               (r["addr"], r["addr_type"], r["rssi"]))
                if r["addr_type"] != ("random" if target.get("mac_random", True) else "public"):
                    state.log_line("警告: 地址类型与目标档案不一致,请修改 mac_random!")
            else:
                state.log_line("15s 内未发现目标广播。检查: 耳机开盖/配对模式、MAC 是否正确")
        return self.start("probe", fn)

    def run_discover(self, target, outdir=None, serport=None, demo=False):
        def fn():
            od = Path(outdir) if outdir else _new_outdir()
            od.mkdir(parents=True, exist_ok=True)
            state.outdir = str(od)
            state.set_status(CONNECTING)
            state.log_line("连接 + GATT 发现 -> %s" % od)
            transport = self._make_transport(target, od, demo, serport)
            self._start_snapshot(transport)
            session = FuzzSession(transport, target, gatt_map_path=od / "gatt_map.json")
            gatt = session.start()
            _push_gatt(gatt)
            state.log_line("发现完成: 服务 %d,特征 %d,gap %d (ll_max=%d att_mtu=%d)" %
                           (len(gatt.services), len(gatt.characteristics),
                            len(gatt.gaps), transport.ll_max, transport.att_mtu))
            if transport.link_up:
                try:
                    transport.disconnect()
                    time.sleep(1.5)
                except Exception:
                    pass
        return self.start("discover", fn)

    def run_fuzz(self, target, strategy_paths, seed=1, max_cases=0,
                 outdir=None, serport=None, demo=False):
        def fn():
            od = Path(outdir) if outdir else _new_outdir()
            od.mkdir(parents=True, exist_ok=True)
            state.outdir = str(od)
            state.set_status(CONNECTING)
            state.log_line("Fuzz 启动 -> %s (seed=%d max_cases=%d)" %
                           (od, seed, max_cases or 0))
            transport = self._make_transport(target, od, demo, serport)
            self._start_snapshot(transport)
            ledger = ObservableLedger(od / "ledger.jsonl")
            ledger.add_listener(bus.on_case)
            session = FuzzSession(transport, target,
                                  gatt_map_path=od / "gatt_map.json", ledger=ledger)

            gatt = session.start()
            _push_gatt(gatt)
            state.log_line("已连接: ll_max=%d att_mtu=%d,重连计数 %d" %
                           (transport.ll_max, transport.att_mtu, session.reconnects))

            raw_cases = load_yaml_files([Path(p) for p in strategy_paths])
            cases = expand(raw_cases, gatt, transport.att_mtu, seed)
            if max_cases:
                cases = cases[:max_cases]
            state.begin_run(total=len(cases))
            state.log_line("语料: %d 模板 -> %d 用例" % (len(raw_cases), len(cases)))

            done = 0
            for case in cases:
                while state.pause_requested.is_set() and not state.stop_requested.is_set():
                    time.sleep(0.15)
                if state.stop_requested.is_set():
                    state.log_line("已停止: 完成 %d/%d" % (done, len(cases)))
                    break
                expect = case.meta.get("op") != "write_cmd"
                r = session.run_case(case.id, case.layer,
                                     lambda c=case: c.pdu,
                                     replay_ctx={"pdu": case.pdu.hex(),
                                                 "expect_response": expect},
                                     expect_response=expect)
                done += 1
                state.inc_done(case.id)
                if transport.tx_queue_full:
                    transport.tx_queue_full = False
            if transport.link_up:
                try:
                    transport.disconnect()
                except Exception:
                    pass
        return self.start("fuzz", fn)

    def run_replay(self, pdu_hex, target, times=1, outdir=None,
                   serport=None, demo=False):
        def fn():
            od = Path(outdir) if outdir else _new_outdir()
            od.mkdir(parents=True, exist_ok=True)
            state.outdir = str(od)
            state.set_status(CONNECTING)
            pdu = bytes.fromhex(pdu_hex)
            state.log_line("重放 %d 字节 PDU ×%d: %s" % (len(pdu), times, pdu.hex()))
            transport = self._make_transport(target, od, demo, serport)
            self._start_snapshot(transport)
            ledger = ObservableLedger(od / "ledger.jsonl")
            ledger.add_listener(bus.on_case)
            session = FuzzSession(transport, target,
                                  gatt_map_path=od / "gatt_map.json", ledger=ledger)
            session.start()
            state.begin_run(total=times)
            for i in range(times):
                if state.stop_requested.is_set():
                    break
                while state.pause_requested.is_set() and not state.stop_requested.is_set():
                    time.sleep(0.15)
                session.run_case("replay", "replay", lambda p=pdu: p,
                                 replay_ctx={"pdu": pdu.hex(), "expect_response": True})
                state.inc_done("replay")
                if i < times - 1 and not state.stop_requested.is_set():
                    time.sleep(0.3)
            if transport.link_up:
                try:
                    transport.disconnect()
                except Exception:
                    pass
        return self.start("replay", fn)

    def replay_from_ledger(self, case_id, ledger_path, target, times=1,
                           serport=None, demo=False):
        rec = find_case(ledger_path, case_id)
        if rec is None:
            return False, "台账 %s 中找不到用例 %s" % (ledger_path, case_id)
        pdu_hex = (rec.get("replay") or {}).get("pdu")
        if not pdu_hex:
            return False, "该用例缺 replay.pdu,无法重放"
        return self.run_replay(pdu_hex, target, times=times, serport=serport, demo=demo)

    def run_impersonation(self, target, bt_keys_path=None, keys_mac=None,
                          phone_mac=None, strategy_paths=None, seed=1,
                          max_cases=0, rounds=0, round_budget=100,
                          wall_ledger=None, duration=0.0,
                          outdir=None, serport=None, demo=False):
        """加密冒充模式:角色自管 serial_guard + transport。
        on_transport 回调桥接事件总线 + 快照;ObservableLedger 桥接 case 台账。"""
        def fn():
            od = Path(outdir) if outdir else _new_outdir()
            od.mkdir(parents=True, exist_ok=True)
            state.outdir = str(od)
            state.set_status(CONNECTING)
            state.log_line("加密冒充启动 -> %s" % od)
            from roles import impersonation_fuzz
            from core.monitor import ObservableLedger
            obs_ledger = ObservableLedger(od / "fuzz_ledger.jsonl")

            def on_transport(transport):
                bus.attach_transport(transport)
                self._transport = transport
                self._start_snapshot(transport)
                # transport 就绪 = 握手即将开始,切到 RUNNING(冒充角色
                # 内部自管循环,不会调 begin_run,所以这里手动切)
                state.begin_run(total=0)

            # 包装 ledger listener:每条 case 同时推进进度计数
            def _on_case_with_progress(result, case, replayable):
                bus.on_case(result, case, replayable)
                state.inc_done(case_id=result.case_id)

            obs_ledger.add_listener(_on_case_with_progress)

            impersonation_fuzz.run(
                target, od, serport=serport,
                bt_keys_path=bt_keys_path, keys_mac=keys_mac,
                phone_mac=phone_mac, duration=duration,
                max_cases=max_cases,
                strategy_paths=strategy_paths, seed=seed,
                rounds=rounds, round_budget=round_budget,
                wall_ledger=wall_ledger,
                on_transport=on_transport, ledger=obs_ledger,
                stop_check=lambda: state.stop_requested.is_set(),
                pause_check=lambda: state.pause_requested.is_set())
        return self.start("impersonate", fn)

    def run_server(self, target, name="Sniffle Server", duration=0.0,
                   interval_ms=200, adb_serial=None, outdir=None,
                   serport=None, demo=False):
        """反向角色模式:角色自管 serial_guard + transport。"""
        def fn():
            od = Path(outdir) if outdir else _new_outdir()
            od.mkdir(parents=True, exist_ok=True)
            state.outdir = str(od)
            state.set_status(CONNECTING)
            state.log_line("反向角色启动 -> %s" % od)
            from roles import server_fuzz
            from core.monitor import ObservableLedger
            obs_ledger = ObservableLedger(od / "server_ledger.jsonl")

            def on_transport(transport):
                bus.attach_transport(transport)
                self._transport = transport
                self._start_snapshot(transport)
                state.begin_run(total=0)

            def _on_case_with_progress(result, case, replayable):
                bus.on_case(result, case, replayable)
                state.inc_done(case_id=result.case_id)

            obs_ledger.add_listener(_on_case_with_progress)

            server_fuzz.run(
                target, od, serport=serport, duration=duration,
                name=name, interval_ms=interval_ms,
                adb_serial=adb_serial,
                on_transport=on_transport, ledger=obs_ledger)
        return self.start("server", fn)

    def run_scan_btconfig(self, adb_serial=None):
        """扫描手机 bt_config.conf,列出所有 bond 设备(无板子,无 transport)。"""
        def fn():
            state.set_status(CONNECTING)
            state.log_line("扫描手机 bt_config.conf ...")
            from core.bt_config_scanner import scan
            result = scan(adb_serial=adb_serial)
            with state.lock:
                state.bt_scan_results = result
            state.log_line("扫描完成: 手机 %s, %d 个 bond 设备" %
                           (result.phone_mac, len(result.devices)))
        return self.start("scan_btconfig", fn)


# ---------- 模块级工具 ----------

def _make_hw(serport):
    from sniffle.sniffle_hw import SniffleHW
    return SniffleHW(serport=serport)


def _make_pcap(outdir):
    """outdir 给定时配 pcap 双录(对齐 CLI 角色层);probe(outdir=None)无 pcap。"""
    if not outdir:
        return None
    from sniffle.pcap import PcapBleWriter
    return PcapBleWriter(str(Path(outdir) / "capture.pcap"))


def _make_fake_hw():
    """延迟加载 tests/test_dryrun.py 的 FakeHw(离线演示)。"""
    path = ATT_FUZZ / "tests" / "test_dryrun.py"
    spec = importlib.util.spec_from_file_location("att_fuzz_dryrun", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.FakeHw


def _new_outdir():
    return ATT_FUZZ / "logs" / ("run-" + datetime.now().strftime("%Y%m%d-%H%M%S"))


def _push_gatt(gatt):
    """GattMap -> UI 可用的树快照。"""
    base = gatt.baseline
    chars_by_service = []
    services = [{"start": s.start_handle, "end": s.end_handle, "uuid": s.uuid}
                for s in gatt.services]
    chars = [{
        "decl": c.decl_handle, "value": c.value_handle, "props": c.props,
        "uuid": c.uuid, "cccd": c.cccd_handle,
        "baseline": base.get("0x%04X" % c.value_handle),
    } for c in gatt.characteristics]
    with state.lock:
        state.gatt = {"services": services, "characteristics": chars,
                      "gaps": list(gatt.gaps)}


def find_case(ledger_path, case_id):
    """从台账文件里找一条用例记录。"""
    p = Path(ledger_path)
    if not p.exists():
        return None
    with p.open("r", encoding="utf-8") as fh:
        for line in fh:
            try:
                rec = __import__("json").loads(line)
            except Exception:
                continue
            if rec.get("case_id") == case_id:
                return rec
    return None


controller = FuzzController()
