#!/usr/bin/env python3
# att-fuzz/gui/bus.py
"""
事件桥:把 core 的两类回调(Ledger.record / transport._log_event)
折叠进 RunState。回调在 fuzzer 工作线程内同步触发,这里只做
轻量转换,绝不阻塞、绝不碰 UI。
"""

from .state import state


class Bus:
    def __init__(self):
        self.transport_attached = False

    # transport.add_event_listener 回调
    def on_transport_event(self, rec: dict):
        state.push_event(rec)

    # ObservableLedger.add_listener 回调
    def on_case(self, result, case, replayable):
        from dataclasses import asdict
        row = asdict(result)
        row["classification"] = result.classification.name
        if replayable:
            row["replay"] = replayable
        row["ts_str"] = _fmt_ts(row.get("ts"))
        state.push_case(row, is_replay=(result.case_id == "replay"))

    def attach_transport(self, transport):
        if not self.transport_attached:
            transport.add_event_listener(self.on_transport_event)
            self.transport_attached = True

    def reset(self):
        self.transport_attached = False


def _fmt_ts(ts):
    import time
    try:
        return time.strftime("%H:%M:%S", time.localtime(ts)) if ts else ""
    except (TypeError, ValueError):
        return ""


bus = Bus()
