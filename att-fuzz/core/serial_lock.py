#!/usr/bin/env python3
# att-fuzz/core/serial_lock.py
"""
串口互斥锁:防止两个进程同时打开 Sniffle dongle 的串口。

设计原则:锁只覆盖"真正需要硬件的任务窗口",不覆盖进程存活期 --
GUI 空闲时不持锁(CLI 可正常用),点了探测/发现/Fuzz/Replay 才拿锁,
任务结束(_teardown / run finally)释放。

实现:锁文件 <tmpdir>/sniffle-hw-<port>.lock,JSON 记录持有者 pid+名字;
被占时立即抛 SerialBusy(带占用方描述),不死等。持锁进程异常退出后
留下的是陈旧锁,下次 acquire 靠 pid 存活检测自动回收。

serport=None(自动探测)时先按 find_xds110_serport() 解析出具体设备再锁;
解析失败退化为锁名 autodetect(仍能挡住两个全进程的自动探测互撞)。
"""

import contextlib
import json
import os
import re
import sys
import tempfile
import time


class SerialBusy(RuntimeError):
    """串口被其他存活进程占用。message 面向用户,可直接展示。"""


def _pid_alive(pid: int) -> bool:
    if pid == os.getpid():
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True          # 存在但属别的用户/组
    except OSError:
        return False
    return True


def _lock_path(port: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", port)
    return os.path.join(tempfile.gettempdir(), "sniffle-hw-%s.lock" % safe)


def resolve_port(serport=None) -> str:
    """把"自动探测"解析成具体设备名(锁文件要按设备区分)。"""
    if serport:
        return serport
    try:
        from sniffle.sniffle_hw import find_xds110_serport
    except ImportError:
        # 调用方没配好 sys.path 时自愈:serial_lock 位于 <repo>/att-fuzz/core/
        repo = os.path.dirname(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))))
        sys.path.insert(0, os.path.join(repo, "python_cli"))
        try:
            from sniffle.sniffle_hw import find_xds110_serport
        except ImportError:
            return "autodetect"
    try:
        p = find_xds110_serport()
    except Exception:
        return "autodetect"
    return p or "autodetect"


def acquire(serport=None, owner="unknown"):
    """拿到 SerialLock 句柄;被占时抛 SerialBusy。owner 是给人看的描述。"""
    port = resolve_port(serport)
    path = _lock_path(port)
    me = {"pid": os.getpid(), "owner": owner, "ts": time.time()}

    try:
        with open(path, "r", encoding="utf-8") as fh:
            cur = json.load(fh)
        if _pid_alive(int(cur["pid"])):
            raise SerialBusy(
                "串口 %s 正被 %s(PID %d)占用,请先停止对方任务"
                "或等其结束(锁文件: %s)" % (port, cur.get("owner", "?"),
                                            int(cur["pid"]), path))
    except FileNotFoundError:
        pass
    except (ValueError, KeyError):
        pass                      # 内容损坏按陈旧锁处理,直接覆盖

    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path))
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(me, fh)
    os.replace(tmp, path)
    return _Lock(path, port)


class _Lock:
    def __init__(self, path, port):
        self.path = path
        self.port = port

    def release(self):
        """释放自己持有的锁;锁已被他人接管(陈旧回收)时不误删。"""
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                cur = json.load(fh)
            if int(cur.get("pid", -1)) == os.getpid():
                os.unlink(self.path)
        except (OSError, ValueError):
            pass
        self.path = None


@contextlib.contextmanager
def guard(serport=None, owner="unknown"):
    """with 用法:任务全程持锁,退出(含异常)自动释放。"""
    lock = acquire(serport, owner)
    try:
        yield lock
    finally:
        lock.release()
