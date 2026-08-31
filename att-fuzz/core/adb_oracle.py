#!/usr/bin/env python3
# att-fuzz/core/adb_oracle.py
"""
Android logcat 崩溃 oracle(tier 2,设计.md §七)。

两段式设计:
- CrashDetector:纯逻辑,可离线单测。逐行喂 logcat,内置蓝牙崩溃/重启特征
  正则,命中即产生 CrashEvent(含窗口上下文 + 归因 context)。
- AdbOracle:薄包装。子进程 `adb -s <serial> logcat -v threadtime` 后台逐行喂
  给 CrashDetector,命中时窗口落盘(outdir/crashes/)并保留事件供 fuzz 循环
  poll 归因(时间对齐到当前正在测试的响应策略/请求)。adb 缺失或手机未连
  -> fail-open,不影响 fuzz 主循环。

自检/离线:
  python3 -m core.adb_oracle --selfcheck          # 特征正则自检(每条必中样例,良性无误报)
  python3 -m core.adb_oracle --replay-file f.txt  # 回放已知 logcat 文件,输出命中事件
"""

import logging
import os
import re
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger("att-fuzz.adb_oracle")

DEFAULT_ADB = os.path.expanduser("~/Android/Sdk/platform-tools/adb")

# (名称, 正则) 蓝牙崩溃/重启特征。命中任一即视为 oracle 事件。
# 日志正文大小写不固定,统一 IGNORECASE;Zygote 的行是 "Process com.android..."
# (无冒号),也兼容 "Process: com.android..."。
CRASH_PATTERNS = [
    ("native_crash", re.compile(r"Fatal signal \d+", re.I)),
    ("tombstone", re.compile(r"/data/tombstones/|tombstone_\d+|tombstone", re.I)),
    ("java_crash", re.compile(r"Fatal exception", re.I)),
    ("bt_process_died", re.compile(r"Process\s*:?\s+com\.android\.bluetooth", re.I)),
    ("bt_crash_trace", re.compile(r"com\.android\.bluetooth.*(?:crash|died)|bt_stack", re.I)),
    ("system_server_restart", re.compile(
        r"WATCHDOG KILLING SYSTEM PROCESS|System process.*(?:died|restart)", re.I)),
    ("bt_service_restart", re.compile(
        r"(?:Restarting|restart).*Bluetooth|Bluetooth.*(?:is restarting|restarted)", re.I)),
    ("bt_anr", re.compile(r"ANR in com\.android\.bluetooth", re.I)),
]

# 反例:正常蓝牙流量不该命中的样例行(自检用)
BENIGN_SAMPLES = [
    "03-03 10:00:00.000  1234  5678 I BluetoothAdapter: startLeScan()",
    "03-03 10:00:01.000  1234  5678 D BluetoothGatt: onConnectionUpdated 20ms",
    "03-03 10:00:02.000  1234  5678 I bt_btif: bta_dm_rm_cback",
    "03-03 10:00:03.000  1234  5678 V BluetoothSocket: connect",
]


@dataclass
class CrashEvent:
    name: str                 # 命中的特征名(CRASH_PATTERNS 里的 key)
    line: str                 # 命中的行
    context: str | None       # 归因:命中瞬间正在测试的响应策略/请求描述
    ts: float = field(default_factory=time.time)
    window: list = field(default_factory=list)   # 命中行前后上下文


class CrashDetector:
    """逐行喂 logcat,命中特征即返回 CrashEvent。纯逻辑,无 IO/进程。"""

    def __init__(self, patterns=None, window: int = 10):
        self.patterns = patterns or CRASH_PATTERNS
        self.window = window
        self.lines = deque(maxlen=window * 2 + 1)
        self.context: str | None = None

    def feed(self, line: str) -> CrashEvent | None:
        line = line.rstrip("\n")
        if not line:
            return None
        self.lines.append(line)
        for name, rx in self.patterns:
            if rx.search(line):
                return CrashEvent(name=name, line=line, context=self.context,
                                  window=list(self.lines))
        return None

    def replay(self, lines) -> list:
        """批量喂,返回全部命中事件(顺序)。"""
        events = []
        for ln in lines:
            ev = self.feed(ln)
            if ev:
                events.append(ev)
        return events

    def selfcheck(self) -> tuple:
        """每条特征必须在样例行命中,且良性样例全部不误报。
        返回 (ok, 报告行列表)。"""
        samples = {
            "native_crash": "03-03 10:00:00.000  1234  1234 F DEBUG   : Fatal signal 11 (SIGSEGV), code 1 (SEGV_MAPERR)",
            "tombstone": "03-03 10:00:00.000  1234  1234 E DEBUG   : Tombstone written to /data/tombstones/tombstone_00",
            "java_crash": "03-03 10:00:00.000  1234  1234 E AndroidRuntime: FATAL EXCEPTION: main",
            "bt_process_died": "03-03 10:00:00.000  1234  5678 E Zygote  : Process com.android.bluetooth died",
            "bt_crash_trace": "03-03 10:00:00.000  1234  5678 F bt_stack: CRASH: unexpected state",
            "system_server_restart": "03-03 10:00:00.000  1234  5678 E watchdog: WATCHDOG KILLING SYSTEM PROCESS: Blocked in handler",
            "bt_service_restart": "03-03 10:00:00.000  1234  5678 I SystemServer: Restarting Bluetooth Service",
            "bt_anr": "03-03 10:00:00.000  1234  5678 E ActivityManager: ANR in com.android.bluetooth",
        }
        out = []
        ok = True
        for name, rx in self.patterns:
            sample = samples.get(name)
            if sample is None:
                out.append("  ? %s: 无样例" % name)
                ok = False
            elif rx.search(sample):
                out.append("  ok %s" % name)
            else:
                out.append("  FAIL %s 未命中样例: %s" % (name, sample))
                ok = False
        for b in BENIGN_SAMPLES:
            for name, rx in self.patterns:
                if rx.search(b):
                    out.append("  FAIL 良性行被 %s 误命中: %s" % (name, b))
                    ok = False
        if ok:
            out.insert(0, "selfcheck OK: %d 特征全命中,良性样例无误报"
                       % len(self.patterns))
        return ok, out


class AdbOracle:
    """薄包装:adb logcat 子进程 -> CrashDetector。可用性失败时 fail-open。"""

    def __init__(self, serial: str = "ZD9L8H454HDY7DEU", adb_path: str | None = None,
                 outdir=None):
        self.serial = serial
        self.adb_path = adb_path or DEFAULT_ADB
        self.outdir = Path(outdir) if outdir else None
        self.detector = CrashDetector()
        self._proc: subprocess.Popen | None = None
        self._thread: threading.Thread | None = None
        self._events = deque(maxlen=64)
        self._lock = threading.Lock()
        self.saved = 0

    def start(self) -> bool:
        """启动 logcat 监听。adb 缺失/手机未连 -> 返回 False(fail-open)。"""
        if not os.path.exists(self.adb_path):
            log.warning("adb not found (%s), logcat oracle disabled", self.adb_path)
            return False
        try:
            r = subprocess.run([self.adb_path, "-s", self.serial, "get-state"],
                               capture_output=True, timeout=5)
            if r.returncode != 0 or b"device" not in r.stdout:
                log.warning("Android %s not reachable (get-state=%r), oracle disabled",
                            self.serial,
                            r.stdout.decode(errors="replace").strip())
                return False
        except Exception as e:
            log.warning("adb device check failed: %s, oracle disabled", e)
            return False
        try:
            self._proc = subprocess.Popen(
                [self.adb_path, "-s", self.serial, "logcat", "-v", "threadtime"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                bufsize=1)
        except Exception as e:
            log.warning("logcat spawn failed: %s, oracle disabled", e)
            return False
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        log.info("logcat oracle started on %s", self.serial)
        return True

    def _run(self):
        for line in self._proc.stdout:
            ev = self.detector.feed(line)
            if ev is None:
                continue
            self._save(ev)
            with self._lock:
                self._events.append(ev)

    def set_context(self, ctx: str | None):
        """设置归因上下文:当前正在测试的响应策略/请求。崩溃事件携带命中瞬间的 context。"""
        self.detector.context = ctx

    def poll(self) -> list:
        """排空已检测到的崩溃事件(供 fuzz 循环落台账归因)。"""
        with self._lock:
            out = list(self._events)
            self._events.clear()
        return out

    def _save(self, ev: CrashEvent):
        if not self.outdir:
            return
        cr = self.outdir / "crashes"
        cr.mkdir(parents=True, exist_ok=True)
        path = cr / ("%s-%s.txt" % (time.strftime("%Y%m%d-%H%M%S"), ev.name))
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("context: %s\npattern: %s\nmatched: %s\n--- window ---\n" %
                     (ev.context, ev.name, ev.line))
            fh.write("\n".join(ev.window) + "\n")
        self.saved += 1

    def stop(self):
        if self._proc:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=3)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
        self._proc = None
        self._thread = None


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="adb logcat oracle 自检/回放")
    ap.add_argument("--selfcheck", action="store_true", help="特征正则自检")
    ap.add_argument("--replay-file", default=None,
                    help="回放已知 logcat 文件,输出命中事件")
    args = ap.parse_args()
    det = CrashDetector()
    if args.selfcheck:
        ok, lines = det.selfcheck()
        print("\n".join(lines))
        return 0 if ok else 1
    if args.replay_file:
        events = det.replay(Path(args.replay_file).read_text(
                encoding="utf-8", errors="replace").splitlines())
        for ev in events:
            print("%s context=%r line=%s" % (ev.name, ev.context, ev.line))
        print("total %d events" % len(events))
        return 0
    ap.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
