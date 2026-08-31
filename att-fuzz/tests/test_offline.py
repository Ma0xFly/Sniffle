#!/usr/bin/env python3
"""离线集成自测:导入 + 语料展开 + 确定性(不需要板子)。"""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python_cli"))
sys.path.insert(0, str(REPO / "att-fuzz"))

# 1) 全模块导入
from core import (att, transport, gatt_map, monitor, session, corpus,  # noqa
                  att_server, adb_oracle)
from roles import central_fuzz, server_fuzz  # noqa
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

# 5) 变异引擎:确定性 + 签名库持久化 + 算子性质
from core.mutator import Mutator, SeedCase, SignatureDb

_mtmp = Path(tempfile.mkdtemp())
_db = SignatureDb(_mtmp / "signatures.json")
_seed = SeedCase(case_id="seed-read", layer="handle",
                 steps=[CaseStep(pdu=bytes([0x0A, 0x03, 0x00]),
                                 expect_response=True, op="read_req")],
                 signature="TIMEOUT", opcode=0x0A, handle=3)

# 确定性:同 seed 同地图 -> 变异序列逐字节一致
_m1 = Mutator(_db, seed=11, mtu=247)
_m2 = Mutator(_db, seed=11, mtu=247)
_c1 = _m1.mutate(_seed, round_no=1)
_c2 = _m2.mutate(_seed, round_no=1)
assert _c1.id == _c2.id and _c1.layer == _c2.layer
assert [s.pdu for s in _c1.steps] == [s.pdu for s in _c2.steps]
assert [s.gate_at for s in _c1.steps] == [s.gate_at for s in _c2.steps]

# 算子不碰 opcode 字节(参数区翻转/边界/长度/时序追加均不改 opcode)
for _c in (_c1, _c2):
    for s in _c.steps:
        if s.pdu:
            assert s.pdu[0] == 0x0A, s.pdu.hex()   # 种子 read_req opcode 保持

# 签名库持久化(跨 run 累积)
_db.add("TIMEOUT")
_db.alert_opcode[0x1F] = 4
_db.save()
_db2 = SignatureDb(_mtmp / "signatures.json")
assert "TIMEOUT" in _db2.signatures and _db2.alert_opcode.get(0x1F) == 4
assert _db2.is_new("HEALTH_DEGRADED|rsp=0x01")     # 未见 -> 新签名
assert _db2.repeat_penalty("TIMEOUT") > 0          # 重复签名降权
assert _db2.energy_bonus(0x1F, 3, "opcode") > _db2.energy_bonus(0x0A, 3, "opcode")

# 同事件多发算子:多跑总能出现两条 PDU 同 gate_at 的变异
_m3 = Mutator(_db, seed=99, mtu=247)
_multi = [_m3.mutate(_seed, round_no=i).steps for i in range(2, 62)]
_same = [st for st in _multi if len(st) >= 2 and st[0].gate_at is not None
         and st[0].gate_at == st[1].gate_at]
assert _same, "同事件多发算子未触发"

# 种子构造:PDU 必须来自 replay 的请求(而非台账 steps 的响应)
_seedrec = {
    "case_id": "seq-x", "layer": "cccd", "signature": "TIMEOUT",
    "opcode": 0x12, "handle": 0x37,
    "replay": {"kind": "sequence",
               "steps": [{"pdu": "1237000100", "expect_response": True, "observe": 0},
                         {"pdu": "1237000000", "expect_response": True, "observe": 0,
                          "gate_at": 2}]},
    "steps": [{"step": 0, "response_pdu": "13"}, {"step": 1, "response_pdu": "13"}],
}
_seed_from = SeedCase.from_ledger(_seedrec)
assert [s.pdu.hex() for s in _seed_from.steps] == ["1237000100", "1237000000"]
assert _seed_from.steps[1].gate_at == 2
assert _seed_from.steps[0].pdu[0] == 0x12    # 请求 opcode,而非响应 0x13
print("变异引擎自测全部通过")

# 6) ATT server 应答引擎:伪 GATT 数据库 + 正常模式请求->响应字节
from core.att_server import build_db, ServerResponder

_db = build_db(device_name="TestDev")
_r = ServerResponder(_db, server_mtu=247)

# 数据库结构:4 服务、句柄连续、Battery 带 CCCD、私有 0xFF01 可写
assert _db.services == [(1, 5, 0x1800), (6, 9, 0x180F), (10, 14, 0x180A),
                        (15, 17, 0xFFF0)], _db.services
assert _db.attrs[3].kind == "char_value" and _db.attrs[3].value == b"TestDev"
assert _db.attrs[9].kind == "cccd" and _db.attrs[9].uuid == 0x2902
assert _db.char_value[8].props & 0x12            # Battery: read|notify
assert _db.char_value[17].props & 0x0C           # 私有特征: write|write-no-rsp

# Exchange MTU:客户端 MTU=64 -> 回我方 247,att_mtu 取 min
rsp = _r.handle_request(bytes([0x02, 0x40, 0x00]))
assert rsp == bytes([0x03, 0xF7, 0x00]) and _r.att_mtu == 64

# Read By Group Type 0x2800:全服务一次回齐
rsp = _r.handle_request(bytes([0x10, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x28]))
assert rsp[0] == 0x11 and rsp[1] == 6
svcs = [(rsp[2+i*6] | rsp[3+i*6] << 8, rsp[4+i*6] | rsp[5+i*6] << 8,
         rsp[6+i*6] | rsp[7+i*6] << 8) for i in range((len(rsp) - 2) // 6)]
assert svcs == _db.services, svcs

# Read By Type 0x2803:特征声明(props+value_handle+uuid,uniform len=7)
rsp = _r.handle_request(bytes([0x08, 0x01, 0x00, 0xFF, 0xFF, 0x03, 0x28]))
assert rsp[0] == 0x09 and rsp[1] == 7
decls = {}
for i in range(2, len(rsp), 7):
    h = rsp[i] | rsp[i+1] << 8
    decls[h] = (rsp[i+2], rsp[i+3] | rsp[i+4] << 8, rsp[i+5] | rsp[i+6] << 8)
assert decls[2] == (0x02, 3, 0x2A00) and decls[7] == (0x12, 8, 0x2A19)
assert decls[16] == (0x0C, 17, 0xFF01)

# Read By Type 0x2A00 -> Device Name("TestDev"=7 字节,item len=2+7=9)
rsp = _r.handle_request(bytes([0x08, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x2A]))
assert rsp[0] == 0x09 and rsp[1] == 9 and rsp[2:] == bytes([3, 0]) + b"TestDev"

# Read 有效/无效/不可读(Error Response: 0x01 | req_op | handle(2) | code)
rsp = _r.handle_request(bytes([0x0A, 0x03, 0x00]))
assert rsp == bytes([0x0B]) + b"TestDev"
rsp = _r.handle_request(bytes([0x0A, 0xFF, 0xFF]))
assert rsp[0] == 0x01 and rsp[4] == 0x01          # INVALID_HANDLE
rsp = _r.handle_request(bytes([0x0A, 0x11, 0x00]))   # 只写特征 -> 读拒绝
assert rsp[0] == 0x01 and rsp[4] == 0x02

# Read Blob offset 越界 -> INVALID_OFFSET
rsp = _r.handle_request(bytes([0x0C, 0x03, 0x00, 0x63, 0x00]))
assert rsp[0] == 0x01 and rsp[4] == 0x07

# Read By Type 0xFF01(不可读) -> READ_NOT_PERMITTED(handle 指向 0x11)
rsp = _r.handle_request(bytes([0x08, 0x01, 0x00, 0xFF, 0xFF, 0x01, 0xFF]))
assert rsp[0] == 0x01 and rsp[4] == 0x02 and (rsp[2] | rsp[3] << 8) == 0x11

# Find Info:按当前 att_mtu=64 截断((64-2)/4=15 条)
rsp = _r.handle_request(bytes([0x04, 0x01, 0x00, 0xFF, 0xFF]))
assert rsp[0] == 0x05 and rsp[1] == 1
pairs = [(rsp[2+i*4] | rsp[3+i*4] << 8, rsp[4+i*4] | rsp[5+i*4] << 8)
         for i in range((len(rsp) - 2) // 4)]
assert pairs[0] == (1, 0x2800) and len(pairs) == 15 and pairs[-1][0] == 15

# Write 到可写特征 -> 0x13 + 值更新;写只读 -> WRITE_NOT_PERMITTED
rsp = _r.handle_request(bytes([0x12, 0x11, 0x00, 0xAB, 0xCD]))
assert rsp == bytes([0x13]) and _db.attrs[17].value == b"\xAB\xCD"
rsp = _r.handle_request(bytes([0x12, 0x03, 0x00, 0x00]))
assert rsp[0] == 0x01 and rsp[4] == 0x03

# Write Cmd 无响应但生效
rsp = _r.handle_request(bytes([0x52, 0x11, 0x00, 0xEF]))
assert rsp is None and _db.attrs[17].value == b"\xEF"

# Prepare + Execute:提交与取消
rsp = _r.handle_request(bytes([0x16, 0x11, 0x00, 0x00, 0x00, 0x01, 0x02]))
assert rsp == bytes([0x17, 0x11, 0x00, 0x00, 0x00, 0x01, 0x02])
rsp = _r.handle_request(bytes([0x18, 0x01]))     # write now
assert rsp == bytes([0x19]) and _db.attrs[17].value == b"\x01\x02"
_r.handle_request(bytes([0x16, 0x11, 0x00, 0x00, 0x00, 0xAA]))
rsp = _r.handle_request(bytes([0x18, 0x00]))     # cancel
assert rsp == bytes([0x19]) and _db.attrs[17].value == b"\x01\x02"
rsp = _r.handle_request(bytes([0x18, 0xFF]))     # 非法 flags
assert rsp[0] == 0x01 and rsp[4] == 0x04

# 未知 opcode -> Request Not Supported;畸形参数 -> INVALID_PDU
rsp = _r.handle_request(bytes([0x99]))
assert rsp[0] == 0x01 and rsp[4] == 0x06
rsp = _r.handle_request(bytes([0x0A]))           # read 缺 handle
assert rsp[0] == 0x01 and rsp[4] == 0x04
print("ATT server 应答引擎自测全部通过")

# 7) adb logcat oracle:CrashDetector 特征命中/良性无误报 + 归因 context
_ok, _lines = adb_oracle.CrashDetector().selfcheck()
assert _ok, "\n".join(_lines)
assert adb_oracle.CrashDetector().replay(adb_oracle.BENIGN_SAMPLES) == []
_log = [
    "03-03 10:00:00.000  1234  5678 I BluetoothAdapter: startLeScan()",
    "03-03 10:00:01.000  1234  5678 F DEBUG   : Fatal signal 11 (SIGSEGV)",
    "03-03 10:00:02.000  1234  5678 E Zygote  : Process com.android.bluetooth died",
    "03-03 10:00:03.000  1234  5678 D BluetoothGatt: onConnectionUpdated 20ms",
]
_det = adb_oracle.CrashDetector()
_det.context = "op=0x10"
_evs = _det.replay(_log)
assert len(_evs) == 2, [e.name for e in _evs]
assert _evs[0].name == "native_crash" and _evs[0].context == "op=0x10"
assert _evs[1].name == "bt_process_died"
assert all(len(e.window) >= 1 for e in _evs)
print("adb logcat oracle 自测全部通过")
