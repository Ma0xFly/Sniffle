#!/usr/bin/env python3
"""离线集成自测:导入 + 语料展开 + 确定性(不需要板子)。"""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python_cli"))
sys.path.insert(0, str(REPO / "att-fuzz"))

# 1) 全模块导入
from core import att, transport, gatt_map, monitor, session, corpus  # noqa
from roles import central_fuzz  # noqa
print("imports OK")

# 2) 合成 GATT 地图 + 语料展开
from core.gatt_map import GattMap, Service, Characteristic
from core.corpus import expand, load_yaml_files

m = GattMap()
m.services = [Service(0x0001, 0x0009, "1800"), Service(0x000A, 0xFFFF, "180D")]
m.characteristics = [
    Characteristic(2, 3, 0x0A, "2a00", None),       # readable (Device Name)
    Characteristic(4, 5, 0x1A, "2a01", None),        # readable
    Characteristic(6, 7, 0x0E, "2a19", None),        # write-no-rsp
    Characteristic(8, 9, 0x1C, "2a2b", 0x000A),      # notify+indicate + CCCD
]
m.baseline = {"0x0003": {"kind": "value", "value": "414243"},
              "0x0005": {"kind": "error", "code": 2}}

raw = load_yaml_files([REPO / "att-fuzz" / "strategies"])
cases = expand(raw, m, mtu=247, seed=42)
print("raw %d -> concrete %d cases" % (len(raw), len(cases)))

by_layer = {}
for c in cases:
    by_layer.setdefault(c.layer, []).append(c)
print({k: len(v) for k, v in by_layer.items()})

# opcode 层:原始 opcode 直通
op_cases = by_layer["opcode"]
assert any(c.pdu[0] == 0x00 for c in op_cases)
assert any(c.pdu[0] == 0xFF and len(c.pdu) == 1 for c in op_cases)

# handle 层:特殊值 + each 展开
h_cases = by_layer["handle"]
assert any(c.pdu == bytes([0x0A, 0x00, 0x00]) for c in h_cases)   # read 0x0000
assert any(c.pdu == bytes([0x0A, 0xFF, 0xFF]) for c in h_cases)   # read 0xFFFF
real_m1 = [c for c in h_cases if c.id.startswith("h-read-real-m1")]
assert len(real_m1) >= 2, real_m1

# value 层:4 个特征全部含 write 属性(0x0A/0x1A/0x0E/0x1C),每模板展开 4 份
v_cases = by_layer["value"]
counts = {}
for c in v_cases:
    counts[c.id.split("@")[0]] = counts.get(c.id.split("@")[0], 0) + 1
for rid, n in counts.items():
    assert n == 4, (rid, n)
c = [x for x in v_cases if x.id.startswith("v-len-mtu-3-incr@0007")][0]
assert c.pdu[0] == 0x12 and c.pdu[1] == 7 and len(c.pdu) == 3 + 244, (c.pdu[:5].hex(), len(c.pdu))
assert c.pdu[3] == 0 and c.pdu[4] == 1  # incremental

# offset 层:baseline_len=3(handle 3 的 ABC)
o_cases = by_layer["offset"]
bl = [x for x in o_cases if x.id.startswith("o-blob-len@0003")]
assert bl and bl[0].pdu == bytes([0x0C, 0x03, 0x00, 0x03, 0x00])
pw = [x for x in o_cases if x.id.startswith("o-prepare-len-bigval@0007")]
assert pw and pw[0].pdu[0] == 0x16 and pw[0].pdu[1] == 7
assert len(pw[0].pdu) == 5 + (247 - 9)

# 确定性:同 seed 同结果,不同 seed 的 random 用例不同
cases2 = expand(raw, m, mtu=247, seed=42)
assert [c.pdu for c in cases] == [c.pdu for c in cases2]
cases3 = expand(raw, m, mtu=247, seed=43)
rnd1 = [c.pdu for c in cases if "random" in c.id][0]
rnd3 = [c.pdu for c in cases3 if "random" in c.id][0]
assert rnd1 != rnd3
print("corpus 展开自测全部通过")

# 3) 串口锁:acquire/busy/release/陈旧回收(不碰真实设备,用假端口名)
import json as _json
import os
import subprocess

from core import serial_lock

FAKE = "/tmp/att-fuzz-lock-test"
lk = serial_lock.acquire(FAKE, "test-A")
assert lk.port == FAKE
try:
    serial_lock.acquire(FAKE, "test-B")     # 同进程二次拿 = 占用
    raise AssertionError("re-acquire should raise SerialBusy")
except serial_lock.SerialBusy:
    pass
lk.release()
lk2 = serial_lock.acquire(FAKE, "test-B")   # 释放后可再拿
lk2.release()

# 陈旧锁(持锁进程已死)自动回收
proc = subprocess.Popen(["true"]); proc.wait()
path = serial_lock._lock_path(FAKE)
with open(path, "w") as fh:
    _json.dump({"pid": proc.pid, "owner": "ghost", "ts": 0}, fh)
lk3 = serial_lock.acquire(FAKE, "test-C")
assert serial_lock._pid_alive(os.getpid())
assert not serial_lock._pid_alive(proc.pid)
lk3.release()
assert not os.path.exists(path)             # release 清掉自己的锁
print("serial_lock 自测全部通过")

# 4) 序列用例展开 + 台账扩展字段(向后兼容)
import json as _j
import tempfile

from core.att import exchange_mtu_req
from core.corpus import CaseStep
from core.monitor import CaseResult, Classification, Ledger

seq_raw = [
    {"id": "sm-seq-2x", "layer": "state-machine",
     "steps": [{"op": "exchange_mtu_req", "mtu": 517},
               {"op": "exchange_mtu_req", "mtu": 517, "observe": 0.5}]},
    {"id": "sm-seq-dup", "layer": "state-machine",
     "steps": [{"op": "exchange_mtu_req", "mtu": 517},
               {"op": "exchange_mtu_req", "mtu": 517}]},   # 全步相同 -> 判重
    {"id": "sm-seq-wcmd", "layer": "state-machine", "no_mtu_negotiate": True,
     "filter": "writable",
     "steps": [{"op": "write_cmd", "handle": "${each.value}",
                "value": {"len": 4, "pattern": "incremental"}},
               {"op": "read_req", "handle": "${each.value}"}]},
    {"id": "sm-seq-repeat", "layer": "prepare-execute",
     "steps": [{"op": "prepare_write_req", "handle": "${wvalue}", "offset": 0,
                "value": {"len": 4, "pattern": "incremental"}, "repeat": 5}]},
]
seq_cases = expand(seq_raw, m, mtu=247, seed=9)
by_id = {}
for c in seq_cases:
    by_id.setdefault(c.id.split("@")[0], []).append(c)

# 2x 与 dup 全步 PDU 组合相同 -> 只留首条
assert len(by_id["sm-seq-2x"]) == 1 and "sm-seq-dup" not in by_id, sorted(by_id)
s2 = by_id["sm-seq-2x"][0]
assert s2.steps is not None and len(s2.steps) == 2
assert s2.steps[0].pdu == exchange_mtu_req(517), s2.steps[0].pdu.hex()
assert s2.steps[1].observe == 0.5 and s2.steps[1].expect_response
assert s2.meta["seq"] and not s2.meta["no_mtu_negotiate"]

# write_cmd 步默认无响应;fixture 4 特征全部可写 -> each 展开 4 条
wcmd = by_id["sm-seq-wcmd"]
assert len(wcmd) == 4, [c.id for c in wcmd]
assert wcmd[0].meta["no_mtu_negotiate"] and wcmd[0].meta["seq"]
assert wcmd[0].steps[0].expect_response is False      # write_cmd 推断
assert wcmd[0].steps[0].pdu[0] == 0x52
assert len(wcmd[0].steps[0].pdu) == 3 + 4
assert wcmd[0].steps[1].expect_response is True and wcmd[0].steps[1].pdu[0] == 0x0A

# repeat: N 拍平为 N 个同构步;wvalue = 首个可写特征(fixture: 0x0003)
rep = by_id["sm-seq-repeat"][0]
assert len(rep.steps) == 5 and all(s.pdu == rep.steps[0].pdu for s in rep.steps)
assert rep.steps[0].pdu[0] == 0x16 and rep.steps[0].pdu[1] == 0x03
assert rep.meta["ops"] == ["prepare_write_req"] * 5
# 单 PDU 用例的统一视图
single = expand([{"id": "x-read", "layer": "handle", "op": "read_req",
                  "handle": "${each.value}", "filter": "readable"}],
                m, mtu=247, seed=1)[0]
assert single.steps is None and len(single.all_steps()) == 1
assert single.all_steps()[0].pdu == single.pdu

# 台账:extra 只影响传入的记录,单 PDU 记录 schema 不变
tmp_led = Path(tempfile.mkdtemp()) / "ledger-extra.jsonl"
led = Ledger(tmp_led)
led.record(CaseResult(case_id="single", layer="handle",
                      classification=Classification.OK_RESPONSE))
led.record(CaseResult(case_id="seq", layer="state-machine",
                      classification=Classification.TIMEOUT),
           replayable={"kind": "sequence", "steps": [{"pdu": "aa"}]},
           extra={"case_kind": "sequence", "alert_step": 1,
                  "steps": [{"step": 0, "classification": "OK_RESPONSE"}]})
rows = [_j.loads(l) for l in tmp_led.read_text().splitlines()]
assert "case_kind" not in rows[0] and "steps" not in rows[0]
assert rows[1]["case_kind"] == "sequence" and rows[1]["alert_step"] == 1
assert rows[1]["replay"]["kind"] == "sequence"
print("序列用例展开 + 台账扩展自测全部通过")
