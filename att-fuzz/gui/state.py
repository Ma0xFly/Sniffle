#!/usr/bin/env python3
# att-fuzz/gui/state.py
"""
RunState -- GUI 全局运行状态(单例)。

线程模型:fuzzer 工作线程通过 bus 折叠事件写入这里(UI 线程只读轮询),
所有可变访问走 self.lock。UI 页面用 ui.timer 轮询本对象刷新,
避免任何跨线程 NiceGUI 更新问题。
"""

import os
import threading
from collections import deque
from pathlib import Path

# 离线演示模式(gui_demo.py 设置环境变量后启动)
DEMO_MODE = os.environ.get("ATT_FUZZ_DEMO") == "1"

# 控制台运行日志的持久化文件(跨 GUI 重启保留,便于回放)
LOG_FILE = Path(__file__).resolve().parents[1] / "logs" / "gui.log"


def _append_log_file(line: str):
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        if LOG_FILE.exists() and LOG_FILE.stat().st_size > 2_000_000:
            keep = LOG_FILE.read_text(encoding="utf-8").splitlines()[-1000:]
            LOG_FILE.write_text("\n".join(keep) + "\n", encoding="utf-8")
        with LOG_FILE.open("a", encoding="utf-8") as fh:
            fh.write("%s %s\n" % (_now_str(), line))
    except OSError:
        pass


def load_log_tail(n=150) -> list:
    """读持久化日志的尾部(页面打开时回放,解决重启后日志消失)。"""
    try:
        return LOG_FILE.read_text(encoding="utf-8").splitlines()[-n:]
    except OSError:
        return []


def set_demo_mode(on: bool):
    global DEMO_MODE
    DEMO_MODE = on

# 控制器状态机
IDLE = "idle"
CONNECTING = "connecting"
RUNNING = "running"
PAUSED = "paused"
STOPPING = "stopping"

STATUS_TEXT = {
    IDLE: "空闲", CONNECTING: "连接中", RUNNING: "运行中",
    PAUSED: "已暂停", STOPPING: "停止中",
}

# 分类 -> (中文名, 颜色, 是否告警类)
CLASS_META = {
    "OK_RESPONSE": ("正常响应", "#26a69a", False),
    "ERROR_RESPONSE": ("ATT 错误响应", "#42a5f5", False),
    "TIMEOUT": ("响应超时", "#ffa726", True),
    "DISCONNECT_TERM": ("掉链(TERMINATE)", "#ef5350", True),
    "DISCONNECT_SUP": ("掉链(静默)", "#ef5350", True),
    "TX_QUEUE_FULL": ("传输层错误", "#9e9e9e", False),
    "HEALTH_DEGRADED": ("健康状态异常", "#ff7043", True),
}


class RunState:
    def __init__(self):
        self.lock = threading.RLock()

        # ---- 控制器状态 ----
        self.status = IDLE
        self.mode = None            # probe / discover / fuzz / replay
        self.error = None           # 最近一次失败的完整错误信息
        self.error_short = None     # 一句话提示(给 header chip)
        self.outdir = None          # 当前 run 输出目录
        self.demo = False           # 离线演示模式(FakeHw)

        # ---- 连接健康(控制器线程定期快照) ----
        self.conn = {
            "link_up": False, "cur_event": 0, "att_mtu": 23, "ll_max": 27,
            "tx_queue_full": False, "reconnects": 0, "fw_version": None,
            "serial": "空闲",
        }

        # ---- fuzz 进度 ----
        self.total_cases = 0
        self.done_cases = 0
        self.alerts_total = 0
        self.current_case = None
        self.started_at = None
        self.elapsed_s = 0.0
        self.class_counts = {}       # classification name -> count
        self.rate_hist = deque(maxlen=180)   # (elapsed_s, done_cases) 每 2s 采样

        # ---- 明细流 ----
        self.events = deque(maxlen=500)      # transport 事件 rec dict
        self.results = deque(maxlen=5000)    # 每用例行(dict,给结果页)
        self.alerts = deque(maxlen=200)      # 告警用例行
        self.log_lines = deque(maxlen=400)   # 控制器日志
        self._log_seq = 0
        self._log_read = 0                   # UI 已读游标

        # ---- 结构化结果 ----
        self.gatt = None             # discover/fuzz 后的 GattMap 快照(dict)
        self.probe_result = None     # probe() 返回 dict
        self.replay_result = None    # 最近一次 replay 的用例行

        # 控制标志(控制器线程读)
        self.pause_requested = threading.Event()
        self.stop_requested = threading.Event()

    # ---------- 生命周期 ----------

    def reset(self, mode, demo=False):
        with self.lock:
            self.mode = mode
            self.demo = demo or DEMO_MODE
            self.error = None
            self.error_short = None
            self.total_cases = 0
            self.done_cases = 0
            self.alerts_total = 0
            self.current_case = None
            self.started_at = None
            self.elapsed_s = 0.0
            self.class_counts = {}
            self.rate_hist.clear()
            self.events.clear()
            self.results.clear()
            self.alerts.clear()
            self.log_lines.clear()
            self._log_read = self._log_seq   # 旧 run 的日志不再推给新页面
            self.gatt = None
            self.probe_result = None
            self.replay_result = None
            self.pause_requested.clear()
            self.stop_requested.clear()
            self.conn = {"link_up": False, "cur_event": 0, "att_mtu": 23,
                         "ll_max": 27, "tx_queue_full": False, "reconnects": 0,
                         "fw_version": None, "serial": "空闲"}

    def set_status(self, status):
        with self.lock:
            self.status = status

    def set_error(self, short, detail=None):
        with self.lock:
            self.error_short = short
            self.error = detail or short
            self.status = IDLE
            self.log_line("ERROR: %s" % short)

    def log_line(self, line):
        with self.lock:
            self._log_seq += 1
            self.log_lines.append({"ts": _now_str(), "line": line,
                                   "seq": self._log_seq})
            _append_log_file(line)

    def take_logs(self):
        """(已废弃用法)UI 拉取未读日志行。游标在 state 单例上,
        多个浏览器页面同时轮询会互相抢行 -- 新代码请用 logs_since。"""
        with self.lock:
            lines = [l for l in self.log_lines if l["seq"] > self._log_read]
            if lines:
                self._log_read = lines[-1]["seq"]
            return lines

    def log_seq(self) -> int:
        """当前日志序号(每个页面用它初始化自己的游标)。"""
        with self.lock:
            return self._log_seq

    def logs_since(self, seq: int):
        """按调用方给的游标读增量日志,不改全局状态。
        返回 (行列表, 新游标)。每个浏览器页面持自己的游标,
        多页面/多标签同时打开不再互相抢日志行。"""
        with self.lock:
            lines = [l for l in self.log_lines if l["seq"] > seq]
            return lines, self._log_seq

    # ---------- bus 折叠写入 ----------

    def push_event(self, rec: dict):
        with self.lock:
            self.events.append(rec)
            kind = rec.get("kind")
            conn = self.conn
            if kind == "connected":
                conn["link_up"] = True
            elif kind in ("state", "terminate", "expected_disconnect"):
                if kind == "terminate":
                    conn["link_up"] = False
            elif kind == "data_size":
                conn["ll_max"] = rec.get("ll_max", conn["ll_max"])
                conn["att_mtu"] = rec.get("att_mtu", conn["att_mtu"])
            elif kind == "dle_rsp":
                conn["ll_max"] = rec.get("ll_max", conn["ll_max"])
            elif kind == "fw_debug" and "TX queue full" in str(rec.get("msg", "")):
                conn["tx_queue_full"] = True

    def push_case(self, row: dict, is_replay=False):
        """row = ledger 行(dict)。bus 在 ledger 回调线程调用。"""
        with self.lock:
            self.results.append(row)
            if is_replay:
                self.replay_result = row
            cls = row.get("classification", "?")
            self.class_counts[cls] = self.class_counts.get(cls, 0) + 1
            meta = CLASS_META.get(cls)
            if meta and meta[2]:
                self.alerts_total += 1
                self.alerts.append(row)

    def inc_done(self, case_id=None):
        with self.lock:
            self.done_cases += 1
            self.current_case = case_id
            if self.started_at is not None:
                import time
                self.elapsed_s = time.time() - self.started_at
                self.rate_hist.append((round(self.elapsed_s, 1), self.done_cases))

    def begin_run(self, total=0):
        import time
        with self.lock:
            self.started_at = time.time()
            self.total_cases = total
            self.status = RUNNING

    def conn_snapshot(self):
        with self.lock:
            return dict(self.conn)

    def progress(self):
        with self.lock:
            return {
                "total": self.total_cases, "done": self.done_cases,
                "alerts": self.alerts_total, "elapsed": self.elapsed_s,
                "current": self.current_case,
                "status": self.status, "mode": self.mode,
                "counts": dict(self.class_counts),
                "rate": list(self.rate_hist),
            }


def _now_str():
    import time
    return time.strftime("%H:%M:%S")


state = RunState()
