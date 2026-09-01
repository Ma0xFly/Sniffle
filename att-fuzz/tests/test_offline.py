#!/usr/bin/env python3
"""离线集成自测:导入 + 语料展开 + 确定性(不需要板子)。"""
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python_cli"))
sys.path.insert(0, str(REPO / "att-fuzz"))

# 1) 全模块导入
from core import (att, transport, gatt_map, monitor, session, corpus,  # noqa
                  att_server, adb_oracle, bt_crypto, smp)
from roles import central_fuzz, server_fuzz, pairing_sniff, impersonation_fuzz  # noqa
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

# 9) 阶段四 4.1 密码学原语 + SMP 解析:规范向量(crackle 01_crack 实采 + BT spec CCM 样本)
from core import bt_crypto as _bc
from core.smp import SmpExchange as _SmpX, _rev as _smprev, AUTHREQ_SC
_h = lambda s: bytes.fromhex(s)

# ---- bt_crypto: BT spec CCM 样本(crackle test.c sample data)----
_sk = _h("99ad1b5226a37e3e058e3b8e27c2c666")
_iv = _h("24abdcbabebaafde")
_nonce = b"\x00" * 5 + _iv
assert _bc.ccm_decrypt(_sk, _nonce, _h("03"), _h("a3"), _h("4c13a415")) == _h("06")
_ct, _mic = _bc.ccm_encrypt(_sk, _nonce, _h("03"), _h("06"))
assert _ct == _h("a3") and _mic == _h("4c13a415")
# 错误 MIC -> None
assert _bc.ccm_decrypt(_sk, _nonce, _h("03"), _h("a3"), _h("00000000")) is None

# ---- bt_crypto: crackle 01_crack 全链(legacy Just Works,大端序)----
_TK = _h("00000000000000000000000000000000")
_srand = _h("d85a8e2663e8ff8130540640e20baa7d")
_mrand = _h("fca57d0fa4aed3aaf40146fdeb92b6ab")
_preq = _h("01001005000301"); _pres = _h("01001005000002")
_ia = _h("083e8ee10b3e"); _ra = _h("78c5e56edde8"); _iat = 0; _rat = 0
# c1: Mconfirm/Sconfirm
assert _bc.c1(_TK, _mrand, _preq, _pres, _iat, _rat, _ia, _ra) == \
        _h("5d2c8d41c85b683de12080d73e98bbfe")
assert _bc.c1(_TK, _srand, _preq, _pres, _iat, _rat, _ia, _ra) == \
        _h("29cbf88db0a87170a105b587cb8bef78")
# s1: STK
_STK = _bc.s1(_TK, _srand, _mrand)
assert _STK == _h("59d4b35ece0df548c10efe17e9da1f4c")
# session key
_skdm = _h("9f6b013d7eb25f87"); _skds = _h("68f5add3ca185186")
_ivwire = _h("ea6ec7cc6199de66")
_sessk = _bc.session_key(_STK, _skdm, _skds)
assert _sessk == _h("51b22eae6102e4b60b4a84227bfe1d60")
# CCM 解密 LTK 分发帧(slave dir, counter=1)
_nonce2 = _bc.ccm_nonce(1, _bc.DIR_S2M, _ivwire)
_dec = _bc.ccm_decrypt(_sessk, _nonce2, _h("02"),
                       _h("00f4ba44918d57fa21d63803593b179fc7efa6f3cb"),
                       _h("844dcdb2"))
assert _dec == _h("11000600069cd42e6a891d8be6bba504f153c0627f")
assert _dec[5:21] == _h("9cd42e6a891d8be6bba504f153c0627f")   # LTK(wire)
# LLCipherState 端到端:3 个加密包逐包解密
_st = _bc.LLCipherState(_sessk, _ivwire)
_pkts = [
    (0x03, _h("71"), _h("b5acd1d8"), _bc.DIR_M2S, 0),
    (0x02, _h("00f4ba44918d57fa21d63803593b179fc7efa6f3cb"), _h("844dcdb2"), _bc.DIR_S2M, 1),
    (0x03, _h("36e3"), _h("9a83eec6"), _bc.DIR_M2S, 1),
]
_decs = [_st.decrypt_packet(h, e, m, d, sn) for h, e, m, d, sn in _pkts]
assert _decs[0] == _h("06")
assert _decs[1] == _h("11000600069cd42e6a891d8be6bba504f153c0627f")
assert _decs[2] == _h("0213")
print("bt_crypto 规范向量自测全部通过")

# ---- smp: 01_crack 端到端(空口序喂入 SmpExchange)----
_ex = _SmpX()
_ex.set_addresses(bytes(reversed(_ia)), bytes(reversed(_ra)), _iat, _rat)
# 空口序 = 逆序大端字段
_ex.feed(bytes(reversed(_preq)))                          # Pairing Request
_ex.feed(bytes(reversed(_pres)))                         # Pairing Response
_ex.feed(b"\x03" + bytes(reversed(_h("5d2c8d41c85b683de12080d73e98bbfe"))))  # Mconfirm
_ex.feed(b"\x03" + bytes(reversed(_h("29cbf88db0a87170a105b587cb8bef78"))))  # Sconfirm
_ex.feed(b"\x04" + bytes(reversed(_mrand)))              # Mrand
_ex.feed(b"\x04" + bytes(reversed(_srand)))              # Srand
assert _ex.is_secure_connections is False
assert _ex.legacy_method == "JustWorks"
assert _ex.verify_confirms() is True
assert _ex.derive_stk() == _h("59d4b35ece0df548c10efe17e9da1f4c")
# 喂 Encryption Information 收割 LTK
_ex.feed(b"\x06" + bytes(reversed(_h("7f62c053f104a5bbe68b1d896a2ed49c"))))
assert _ex.ltk_be == _h("7f62c053f104a5bbe68b1d896a2ed49c")

# ---- smp: SC 判定(双证据)----
# preq 带 SC 位 -> is_secure_connections=True
_preq_sc = b"\x01\x03\x00" + bytes([AUTHREQ_SC | 0x04]) + b"\x10\x07\x07"
_exsc = _SmpX(); _exsc.set_addresses(b"\x11"*6, b"\x22"*6, 1, 1)
_exsc.feed(_preq_sc); _exsc.feed(b"\x02\x03\x00\x0c\x10\x07\x07")
assert _exsc.is_secure_connections is True
# 或出现 Public Key PDU(0x0C) -> SC
_expk = _SmpX(); _expk.feed(b"\x0c" + b"\x00"*64)
assert _expk.is_secure_connections is True
# Just Works verify_confirms:篡改 mrand 一字节 -> False(TK 非 0/JustWorks 不成立)
_exbad = _SmpX(); _exbad.set_addresses(bytes(reversed(_ia)), bytes(reversed(_ra)), 0, 0)
_exbad.feed(bytes(reversed(_preq))); _exbad.feed(bytes(reversed(_pres)))
_exbad.feed(b"\x03" + bytes(reversed(_h("5d2c8d41c85b683de12080d73e98bbfe"))))
_exbad.feed(b"\x03" + bytes(reversed(_h("29cbf88db0a87170a105b587cb8bef78"))))
_mrand_bad = bytearray(bytes(reversed(_mrand))); _mrand_bad[0] ^= 0xFF
_exbad.feed(b"\x04" + bytes(_mrand_bad)); _exbad.feed(b"\x04" + bytes(reversed(_srand)))
assert _exbad.verify_confirms() is False
print("smp 解析与配对方式判定自测全部通过")

# ---- pairing_sniff: MAC 解析(书写序 -> 线序)----
assert pairing_sniff._parse_mac("64:44:7B:EE:41:F4") == bytes.fromhex("f441ee7b4464")
assert pairing_sniff._parse_mac("AA:BB:CC:DD:EE:11") == bytes.fromhex("11eeddccbbaa")
print("pairing_sniff MAC 解析自测通过")

# 10) 阶段四 4.1 密钥产品化:bt_keys 解析 + pcap 离线解密引擎
import json as _json
import tempfile as _tempfile

from core import bt_keys as _btk
from core import pcap_decrypt as _pcd

# ---- bt_keys: bt_config.conf fixture(Redmi K50 实测 bond 值做 fixture)----
# PENC = ltk(16)+rand(8)+ediv(2)+sec(1)+ks(1);PID = irk(16)+addr_type(1)+addr(6 线序);
# LENC = ltk(16)+div(2)+ks(1)+sec(1)。节名用线序冒号 hex(实测 dump 序)。
_PENC = "a89469ab06f390362c32a49ac1d392c1" + "00" * 8 + "0000" + "01" + "10"
_PID = "a808f85631989a023ac4d9845f6fd7f3" + "00" + "f441ee7b4464"
_LENC = "11223344556677889900aabbccddeeff" + "0000" + "10" + "01"
_BTCONF = """
[Adapter]
Address = 00c30a026c24
Mode = 2

[RemoteName]
00c30a026c24 = Redmi K50

[f4:41:ee:7b:44:64]
TimeCreated = 1758987654
Name = vivo TWS 3e
LE_KEY_PENC = %s
LE_KEY_PID = %s
LE_KEY_LENC = %s
LE_KEY_LID = 00000000
""" % (_PENC, _PID, _LENC)
_tmp = _tempfile.mkdtemp()
_conf = Path(_tmp) / "bt_config.conf"
_conf.write_text(_BTCONF, encoding="utf-8")

_bonds = _btk.parse_bt_config(_conf, target_mac="64:44:7B:EE:41:F4")
assert len(_bonds) == 1, "目标节(线序节名 x 书写序目标)应双序匹配"
_b = _bonds[0]
assert _b.ltk == _h("a89469ab06f390362c32a49ac1d392c1")
assert _b.rand == b"\x00" * 8 and _b.ediv == b"\x00\x00"
assert _b.key_size == 16 and _b.sec_level == 1
assert _b.irk == _h("a808f85631989a023ac4d9845f6fd7f3")
assert _b.peer_addr == _h("f441ee7b4464") and _b.peer_addr_type == 0
assert _b.name == "vivo TWS 3e"
assert _b.lenc_ltk == _h("11223344556677889900aabbccddeeff")
assert _b.misc.get("lenc_ks") == 16 and _b.misc.get("lenc_sec") == 1
assert _b.ltk_candidates() == [(_b.ltk, "penc"), (_b.lenc_ltk, "lenc")]
# 不给目标:解析全部含 LE 密钥的节(Adapter/RemoteName 无 LE 密钥被丢弃)
assert len(_btk.parse_bt_config(_conf)) == 1
# 显示序节名也应命中
_BTCONF2 = _BTCONF.replace("[f4:41:ee:7b:44:64]", "[64:44:7b:ee:41:f4]")
_conf2 = Path(_tmp) / "bt_config2.conf"
_conf2.write_text(_BTCONF2, encoding="utf-8")
assert len(_btk.parse_bt_config(_conf2, target_mac="64:44:7B:EE:41:F4")) == 1
# 目标不在文件里 -> 空 + 不崩
assert _btk.parse_bt_config(_conf, target_mac="AA:BB:CC:DD:EE:FF") == []

# ---- bt_keys: 提取 JSON 形态(vivo_bond_keys.json)+ 自动分派 ----
_KEYSJSON = {
    "target": "vivo TWS 3e (64:44:7B:EE:41:F4)",
    "ltk_hex": "a89469ab06f390362c32a49ac1d392c1",
    "rand_hex": "0000000000000000", "ediv_hex": "0000",
    "irk_remote_hex": "a808f85631989a023ac4d9845f6fd7f3",
    "key_size": 16,
}
_kj = Path(_tmp) / "bond_keys.json"
_kj.write_text(_json.dumps(_KEYSJSON), encoding="utf-8")
_jbonds = _btk.load_keys(_kj)
assert len(_jbonds) == 1 and _jbonds[0].ltk == _h("a89469ab06f390362c32a49ac1d392c1")
assert _jbonds[0].irk == _h("a808f85631989a023ac4d9845f6fd7f3")
assert _btk.load_keys(_conf)[0].ltk == _h("a89469ab06f390362c32a49ac1d392c1")  # 分派到 bt_config
assert _btk.all_ltk_candidates(_jbonds) == [(_h("a89469ab06f390362c32a49ac1d392c1"),
                                             "vivo TWS 3e (64:44:7B:EE:41:F4)|penc")]
print("bt_keys 解析自测全部通过")

# ---- pcap_decrypt: 合成加密 pcap 端到端(01_crack 验证过的密码学材料)----
from sniffle.pcap import PcapBleWriter as _Pbw
_rev8 = lambda x: bytes(x)[::-1]

def _synth_pcap(path, skip_empty=False, key=None):
    """合成一条 legacy 配对连接:明文 SMP + ENC 握手(SKD 空口小端序写入)
    + 加密段(control 也加密,含空包)。key 缺省=STK(01_crack 材料),会话密钥
    按引擎同款推导。"""
    stk = key or _h("59d4b35ece0df548c10efe17e9da1f4c")
    skdm = _h("9f6b013d7eb25f87"); _skds = _h("68f5add3ca185186")
    _iv = _h("ea6ec7cc6199de66")
    _sk = _bc.session_key(stk, skdm, _skds)

    def _enc(cnt, dire, hdr, pt):
        ct, mic = _bc.ccm_encrypt(_sk, _bc.ccm_nonce(cnt, dire, _iv),
                                  bytes([hdr & 0xE3]), pt)
        return bytes([hdr, len(ct) + 4]) + ct + mic

    _w = _Pbw(str(path))
    _ts = [1000]
    def _wr(pdu_type, body):
        _w.write_packet(_ts[0], 0x11223344, 5, -60, body, phy=0, pdu_type=pdu_type)
        _ts[0] += 100
    # 明文段:ENC_REQ(m2s,SKD 空口序=小端,写入前反转)/ENC_RSP/START_ENC_REQ/SMP
    _wr(2, bytes([0x03, 23, 3]) + b"\x00" * 8 + b"\x00\x00" + _rev8(skdm) + _iv[:4])
    _wr(3, bytes([0x03, 13, 4]) + _rev8(_skds) + _iv[4:])
    _wr(3, bytes([0x03, 1, 5]))
    _smp = _h("01001005000301")
    _l2 = len(_smp).to_bytes(2, "little") + b"\x06\x00" + _smp
    _wr(3, bytes([0x02, len(_l2)]) + _l2)
    # 加密段:START_ENC_RSP(c0)/空包(c1,可跳过模拟丢包)/SMP LTK(c1 s2m)/ATT(c2)/TERMINATE(c3)
    _wr(2, _enc(0, _bc.DIR_M2S, 0x03, b"\x06"))
    if not skip_empty:
        _wr(2, _enc(1, _bc.DIR_M2S, 0x01, b""))
    _sdu = b"\x06" + _h("9cd42e6a891d8be6bba504f153c0627f")
    _l2s = len(_sdu).to_bytes(2, "little") + b"\x06\x00" + _sdu
    _wr(3, _enc(1, _bc.DIR_S2M, 0x02, _l2s))
    _att = _h("021700")
    _l2a = len(_att).to_bytes(2, "little") + b"\x04\x00" + _att
    _wr(2, _enc(2, _bc.DIR_M2S, 0x02, _l2a))
    _wr(2, _enc(3, _bc.DIR_M2S, 0x03, _h("0213")))
    _w.close()
    return stk   # 候选 key(=加密用 key)

_pc1 = Path(_tmp) / "cap.pcap"
_stk = _synth_pcap(_pc1)
# 候选给反转序(模拟"存储序与空口相反"):引擎应以 reversed 裁定并解出全部 SDU
_rpts = _pcd.decrypt_pcap(_pc1, [(_stk[::-1], "fixture")])
assert len(_rpts) == 1
_r = _rpts[0]
assert _r.key_match["byte_order"] == "reversed" and _r.key_match["label"] == "fixture"
assert _r.key_match["session_key"] == _h("51b22eae6102e4b60b4a84227bfe1d60").hex()
assert _r.mic_ok == 5 and _r.mic_fail == 0
assert _r.enc["iv"] == "ea6ec7cc6199de66"      # IVm||IVs 空口序原样
_ops = [f.record() for f in _r.sdus]
assert [o["op"] for o in _ops] == ["SMP_OP_0x01", "SMP_OP_0x06", "EXCHANGE_MTU_REQ"]
assert _ops[0]["phase"] == "plaintext" and _ops[0]["dir"] == "s2m"
assert _ops[1]["phase"] == "decrypted" and _ops[1]["pdu"].startswith("069cd42e6a")
assert _ops[2]["phase"] == "decrypted" and _ops[2]["dir"] == "m2s"
assert _r.terminate == {"reason": 0x13, "encrypted": True}
# 丢包窗口回扫:跳过空包(计数器跳 1)仍应解出全部 SDU
_pc2 = Path(_tmp) / "cap_gap.pcap"
_stk2 = _synth_pcap(_pc2, skip_empty=True)
_r2 = _pcd.decrypt_pcap(_pc2, [(_stk2, "fixture")])[0]
assert _r2.key_match["byte_order"] == "as-stored"
assert [f.record()["op"] for f in _r2.sdus] == ["SMP_OP_0x01", "SMP_OP_0x06", "EXCHANGE_MTU_REQ"]
# 错误 key -> 无匹配(MIC 全挂),报告不崩
_r3 = _pcd.decrypt_pcap(_pc1, [(b"\x00" * 16, "wrong")])[0]
assert _r3.key_match is None and _r3.mic_ok == 0
# write_outputs 落档
_top = _pcd.write_outputs(_rpts, Path(_tmp) / "out", str(_pc1))
assert _top["sdus"] == 3 and _top["connections"] == 1
assert (Path(_tmp) / "out" / "decrypt_report.json").is_file()
assert len((Path(_tmp) / "out" / "decrypted_sdu.jsonl").read_text().splitlines()) == 3
print("pcap_decrypt 端到端自测全部通过")

# ---- --decrypt CLI 子进程(用户真实入口,含参数接线) ----
import subprocess as _sp
_proc = _sp.run([sys.executable, str(REPO / "att-fuzz" / "runner.py"),
                 "--decrypt", str(_pc1), "--ltk", _stk[::-1].hex(),
                 "--outdir", str(Path(_tmp) / "cli_out")],
                capture_output=True, text=True, cwd=str(REPO))
assert _proc.returncode == 0, _proc.stdout + _proc.stderr
assert "KEY MATCH: cli-ltk (reversed" in _proc.stdout
assert "EXCHANGE_MTU_REQ x1" in _proc.stdout
_proc2 = _sp.run([sys.executable, str(REPO / "att-fuzz" / "runner.py"),
                  "--decrypt", str(_pc1), "--ltk", "00" * 16,
                  "--outdir", str(Path(_tmp) / "cli_out2")],
                 capture_output=True, text=True, cwd=str(REPO))
assert _proc2.returncode == 2 and "无候选 key 匹配" in _proc2.stdout
# --bt-keys bt_config + --keys-mac(密钥文件主路径):用 fixture LTK 加密的 pcap
_pc3f = Path(_tmp) / "cap_bond.pcap"
_synth_pcap(_pc3f, key=_h("a89469ab06f390362c32a49ac1d392c1"))
_proc3 = _sp.run([sys.executable, str(REPO / "att-fuzz" / "runner.py"),
                  "--decrypt", str(_pc3f), "--bt-keys", str(_conf),
                  "--keys-mac", "64:44:7B:EE:41:F4",
                  "--outdir", str(Path(_tmp) / "cli_out3")],
                 capture_output=True, text=True, cwd=str(REPO))
assert _proc3.returncode == 0, _proc3.stdout + _proc3.stderr
assert "bond:" in _proc3.stdout and "KEY MATCH: f4:41:ee:7b:44:64|penc" in _proc3.stdout
print("--decrypt CLI 自测通过")

# 11) 阶段五:加密冒充 -- bt_crypto.encrypt_packet + 传输层加密 + LL control 代答加密 + 握手
import os as _os
from collections import deque as _deque
from struct import pack as _pack

from sniffle.decoder_state import SniffleDecoderState as _SDS
from sniffle.packet_decoder import DPacketMessage as _DPM
from core.transport import SniffleTransport as _ST

# ---- 测试向量(01_crack 材料,session_key=51b22eae...)----
_SK = _h("51b22eae6102e4b60b4a84227bfe1d60")   # 会话密钥(big-endian)
_IV = _h("ea6ec7cc6199de66")                    # IVm||IVs(空口序)
# enable_encryption 入参(wire/dump 序 = big-endian 反转):
_LTK_WIRE = _h("59d4b35ece0df548c10efe17e9da1f4c")[::-1]   # = STK 反转
_SKDM_WIRE = _h("9f6b013d7eb25f87")[::-1]                   # SKDm 反转
_SKDS_WIRE = _h("68f5add3ca185186")[::-1]                   # SKDs 反转
_IVM_WIRE = _IV[:4]                                         # ea6ec7cc
_IVS_WIRE = _IV[4:]                                         # 6199de66


# ---- bt_crypto.encrypt_packet: round-trip + 计数器推进 ----
_st = _bc.LLCipherState(_SK, _IV, search_window=32)
_pt1 = b"\x06"                          # START_ENC_RSP (1 byte)
_ct1, _mic1 = _st.encrypt_packet(0x03, _pt1, _bc.DIR_M2S)
# 用独立 cipher 回解(同 key/iv,counter 从 0 开始;SN 在 BLE 中交替 0,1,0,1)
_st2 = _bc.LLCipherState(_SK, _IV, search_window=32)
# 首包 SN=0,last_sn=None -> is_retx=False,start=0 -> counter 0 匹配
_dec1 = _st2.decrypt_packet(0x03, _ct1, _mic1, _bc.DIR_M2S, 0)
assert _dec1 == _pt1, "encrypt->decrypt round-trip 失败"
assert _st2.counter[_bc.DIR_M2S] == 1   # 成功解密后计数器推进到 1

# 两个 encrypt 产生不同密文(计数器推进)
_pt2 = b"\x02\x13"                      # 2 bytes
_ct2, _mic2 = _st.encrypt_packet(0x03, _pt2, _bc.DIR_M2S)
assert _ct1 != _ct2 or _mic1 != _mic2, "两次 encrypt 应产生不同密文"
# 第二包 SN=1(与首包 0 不同)-> is_retx=False,start=counter=1 -> counter 1 匹配
_dec2 = _st2.decrypt_packet(0x03, _ct2, _mic2, _bc.DIR_M2S, 1)
assert _dec2 == _pt2, "encrypt counter 1 -> decrypt 失败"
assert _st2.counter[_bc.DIR_M2S] == 2
print("bt_crypto.encrypt_packet round-trip + 计数器推进自测通过")


# ---- 最小 FakeHw(记录 cmd_transmit,不自动响应)----
class _EncFakeHw:
    """记录 cmd_transmit;recv_and_decode 从队列返回(供 _pump 拉取)。
    其他 cmd_* 均 no-op。不自动响应 ATT(测试手动喂 RX)。"""
    def __init__(self):
        self.decoder_state = _SDS()
        self._q = _deque()
        self.sent = []
        r, w = _os.pipe()
        _os.set_blocking(r, False)
        _os.set_blocking(w, False)
        self.ser = type("FS", (), {"fd": r})()
        self._pw = w

    def _emit(self, msg):
        self._q.append(msg)
        try:
            _os.write(self._pw, b"x")
        except BlockingIOError:
            pass

    def recv_and_decode(self, desync=False):
        if not self._q:
            return None
        msg = self._q.popleft()
        if not self._q:
            try:
                _os.read(self.ser.fd, 64)
            except BlockingIOError:
                pass
        return msg

    def cmd_transmit(self, llid, pdu, event=0):
        self.sent.append((llid, bytes(pdu)))

    def cmd_transmit_at(self, llid, pdu, event):
        self.sent.append((llid, bytes(pdu)))

    def __getattr__(self, name):
        if name.startswith("cmd_"):
            return lambda *a, **k: None
        raise AttributeError(name)


def _make_enc_transport():
    """构造一个已启用加密的 transport(用 01_crack 测试向量)。"""
    hw = _EncFakeHw()
    t = _ST(hw, jsonl_path=None, conn_interval_units=12)
    t._link_up = True
    t.aa = 0x11223344
    t.enable_encryption(_LTK_WIRE, _SKDM_WIRE, _SKDS_WIRE, _IVM_WIRE, _IVS_WIRE)
    assert t._enc_enabled and t._enc_cipher is not None
    return t, hw


# ---- 传输层:inject 加密 TX ----
_t1, _hw1 = _make_enc_transport()
_att_pdu = bytes([0x0A, 0x03, 0x00])   # Read Request handle 3
_t1.inject(_att_pdu)
assert len(_hw1.sent) >= 1, "FakeHw 应收到 cmd_transmit"
_llid1, _tx1 = _hw1.sent[-1]
# 明文 SDU = L2CAP 头(4) + ATT(3) = 7 字节;加密后 = 7 ct + 4 mic = 11
assert _llid1 == 2, "首分片 LLID 应为 2"
assert len(_tx1) == 11, "加密后长度应为 11(7 ct + 4 mic), got %d" % len(_tx1)
_plain_sdu = _pack("<HH", len(_att_pdu), 4) + _att_pdu
assert _tx1[:7] != _plain_sdu, "TX 不应是明文"
# 用独立 cipher 回解验证
_c1 = _bc.LLCipherState(_SK, _IV, search_window=32)
_d1 = _c1.decrypt_packet(0x02, _tx1[:7], _tx1[7:], _bc.DIR_M2S, 0)
assert _d1 == _plain_sdu, "inject 加密 TX 回解失败"
print("传输层 inject 加密 TX 自测通过")

# ---- 传输层:加密 RX 解密 ----
_t2, _hw2 = _make_enc_transport()
_rsp_pdu = bytes([0x0B]) + b"hello"   # Read Response, 6 bytes
_rsp_sdu = _pack("<HH", len(_rsp_pdu), 4) + _rsp_pdu  # 10 bytes
_c2 = _bc.LLCipherState(_SK, _IV, search_window=32)
_ct_rx, _mic_rx = _c2.encrypt_packet(0x02, _rsp_sdu, _bc.DIR_S2M)
_body = bytes([0x02, len(_ct_rx) + 4]) + _ct_rx + _mic_rx
_dpkt = _DPM.from_body(_body, is_data=True, peripheral_send=True)
_result = _t2._process_message(_dpkt)
assert _result is not None, "加密 RX 应解出 AttPacket"
assert _result.pdu == _rsp_pdu, "解密后 ATT PDU 不匹配: %s" % _result.pdu.hex()
print("传输层加密 RX 解密自测通过")

# ---- 传输层:LL control 代答加密(FEATURE_REQ -> FEATURE_RSP)----
_t3, _hw3 = _make_enc_transport()
# 构造加密的 LL_FEATURE_REQ(明文 = bytes([0x08]), 1 byte)
_c3 = _bc.LLCipherState(_SK, _IV, search_window=32)
_ct_f, _mic_f = _c3.encrypt_packet(0x03, bytes([0x08]), _bc.DIR_S2M)
_body_f = bytes([0x03, len(_ct_f) + 4]) + _ct_f + _mic_f
_dpkt_f = _DPM.from_body(_body_f, is_data=True, peripheral_send=True)
_t3._process_message(_dpkt_f)
# transport 应已发 FEATURE_RSP(加密)
assert len(_hw3.sent) >= 1, "transport 应代答 FEATURE_RSP"
_llid_f, _tx_f = _hw3.sent[-1]
assert _llid_f == 3, "FEATURE_RSP 应走 llid=3"
# 明文 FEATURE_RSP = bytes([0x09]) + pack("<Q", 0x20) = 9 bytes
# 加密后 = 9 ct + 4 mic = 13 bytes
assert len(_tx_f) == 13, "加密 FEATURE_RSP 应 13 字节, got %d" % len(_tx_f)
_plain_frsp = bytes([0x09]) + _pack("<Q", 0x20)
assert _tx_f[:9] != _plain_frsp, "代答应加密,不是明文"
# 回解验证
_c3b = _bc.LLCipherState(_SK, _IV, search_window=32)
_d_f = _c3b.decrypt_packet(0x03, _tx_f[:9], _tx_f[9:], _bc.DIR_M2S, 0)
assert _d_f == _plain_frsp, "加密 FEATURE_RSP 回解失败"
print("传输层 LL control 代答加密自测通过")

# ---- 传输层:MIC 失败丢弃 ----
_t4, _hw4 = _make_enc_transport()
_bad_body = bytes([0x02, 6]) + b"\x00" * 2 + b"\xDE\xAD\xBE\xEF"  # 2 ct + 4 mic(假)
_dpkt_bad = _DPM.from_body(_bad_body, is_data=True, peripheral_send=True)
_result_bad = _t4._process_message(_dpkt_bad)
assert _result_bad is None, "MIC 失败应返回 None(不喂垃圾给重组)"
print("传输层 MIC 失败丢弃自测通过")

# ---- 传输层:未加密路径回归(inject 原样透传)----
_t5, _hw5 = _make_enc_transport()
_t5._enc_enabled = False   # 关掉加密,模拟普通 central
_t5.inject(_att_pdu)
_llid5, _tx5 = _hw5.sent[-1]
assert _tx5 == _plain_sdu, "未加密路径应原样透传(回归)"
print("传输层未加密路径回归自测通过")

# ---- 冒充握手:FakeHw 模拟耳机,drive_enc_handshake 端到端 ----
class _ImpFakeHw:
    """模拟耳机侧:收到 ENC_REQ 后回 ENC_RSP + START_ENC_REQ(明文);
    收到加密的 START_ENC_RSP 后回加密的 START_ENC_RSP(S2M c0)。
    记录所有 cmd_transmit 供断言。"""
    def __init__(self, ltk_wire):
        self.decoder_state = _SDS()
        self._q = _deque()
        self.sent = []
        self._ltk_wire = ltk_wire
        self._cipher = None
        self._enc_started = False
        r, w = _os.pipe()
        _os.set_blocking(r, False)
        _os.set_blocking(w, False)
        self.ser = type("FS", (), {"fd": r})()
        self._pw = w

    def _emit(self, msg):
        self._q.append(msg)
        try:
            _os.write(self._pw, b"x")
        except BlockingIOError:
            pass

    def _emit_ll_ctrl(self, payload, encrypted=False):
        """发一个 llid=3 的 DataMessage。encrypted=True 时用 S2M 方向加密。"""
        if encrypted and self._cipher is not None:
            ct, mic = self._cipher.encrypt_packet(0x03, payload,
                                                  _bc.DIR_S2M)
            body = bytes([0x03, len(ct) + 4]) + ct + mic
        else:
            body = bytes([0x03, len(payload)]) + payload
        self._emit(_DPM.from_body(body, is_data=True, peripheral_send=True))

    def recv_and_decode(self, desync=False):
        if not self._q:
            return None
        msg = self._q.popleft()
        if not self._q:
            try:
                _os.read(self.ser.fd, 64)
            except BlockingIOError:
                pass
        return msg

    def cmd_transmit(self, llid, pdu, event=0):
        self.sent.append((llid, bytes(pdu)))
        if llid == 3 and len(pdu) >= 23 and pdu[0] == 0x03:
            # LL_ENC_REQ(明文):解析 SKDm/IVm,建 cipher,回 ENC_RSP + START_ENC_REQ
            skdm = pdu[11:19]
            ivm = pdu[19:23]
            ltk_be = self._ltk_wire[::-1]
            skds = _h("68f5add3ca185186")[::-1]   # 固定 SKDs(wire 序)
            ivs = _h("6199de66")                    # 固定 IVs(wire 序)
            sessk = _bc.session_key(ltk_be, skdm[::-1], skds[::-1])
            iv = ivm + ivs
            self._cipher = _bc.LLCipherState(sessk, iv, search_window=2048)
            # ENC_RSP = opcode(1) + SKDs(8) + IVs(4)
            enc_rsp = bytes([0x04]) + skds + ivs
            self._emit_ll_ctrl(enc_rsp, encrypted=False)
            # START_ENC_REQ(明文)
            self._emit_ll_ctrl(bytes([0x05]), encrypted=False)
            self._enc_started = True
        elif llid == 3 and self._enc_started:
            # 收到加密的 START_ENC_RSP(role 发的,c0 M2S)
            # 回加密的 START_ENC_RSP(S2M c0)
            self._emit_ll_ctrl(bytes([0x06]), encrypted=True)
            self._enc_started = False

    def cmd_transmit_at(self, llid, pdu, event):
        self.cmd_transmit(llid, pdu, event)

    def __getattr__(self, name):
        if name.startswith("cmd_"):
            return lambda *a, **k: None
        raise AttributeError(name)


_imp_hw = _ImpFakeHw(_LTK_WIRE)
_imp_t = _ST(_imp_hw, jsonl_path=None, conn_interval_units=12)
_imp_t._link_up = True
_imp_t.aa = 0x11223344

_events = []
def _rec(**f):
    _events.append(f)

# 驱动握手
impersonation_fuzz._drive_enc_handshake(_imp_t, _LTK_WIRE, _rec)

# 断言:加密已启用
assert _imp_t._enc_enabled, "握手后应 _enc_enabled=True"
assert _imp_t._enc_cipher is not None, "握手后应有 cipher"

# 断言:FakeHw 收到了 ENC_REQ(明文,23 字节)和 START_ENC_RSP(加密,5 字节)
_enc_reqs = [(l, p) for l, p in _imp_hw.sent if l == 3 and len(p) >= 23 and p[0] == 0x03]
assert len(_enc_reqs) == 1, "应发 1 个 ENC_REQ, got %d" % len(_enc_reqs)
_start_enc_rsps = [(l, p) for l, p in _imp_hw.sent if l == 3 and len(p) == 5]
assert len(_start_enc_rsps) == 1, "应发 1 个加密 START_ENC_RSP(5 字节), got %d" % len(_start_enc_rsps)
_, _ser_tx = _start_enc_rsps[0]
assert _ser_tx != bytes([0x06]), "START_ENC_RSP 应加密(不是明文 0x06)"
# 回解验证(用 FakeHw 的 cipher -- M2S c0)
_d_start = _imp_hw._cipher.decrypt_packet(0x03, _ser_tx[:1],
                                           _ser_tx[1:], _bc.DIR_M2S, 0)
assert _d_start == bytes([0x06]), "加密 START_ENC_RSP 回解应为 0x06"

# 断言:握手事件记录正确
_kinds = [e.get("kind") for e in _events if isinstance(e, dict)]
assert "enc_req_sent" in _kinds
assert "enc_rsp_recv" in _kinds
assert "start_enc_rsp_sent" in _kinds
assert "start_enc_rsp_recv" in _kinds
print("冒充握手端到端自测通过")

# ---- 冒充握手:超时失败(从机不回 ENC_RSP)----
class _SilentHw(_EncFakeHw):
    """不响应任何 control PDU。"""
    pass

_silent_t = _ST(_SilentHw(), jsonl_path=None, conn_interval_units=12)
_silent_t._link_up = True
_silent_t.aa = 0x11223344
try:
    impersonation_fuzz._drive_enc_handshake(_silent_t, _LTK_WIRE, lambda **k: None)
    raise AssertionError("从机不回 ENC_RSP 应抛 ImpersonationError")
except impersonation_fuzz.ImpersonationError as _e:
    assert "ENC_RSP" in str(_e), "错误消息应提到 ENC_RSP"
print("冒充握手超时失败自测通过")

# ---- --impersonate CLI 参数接线(子进程 --help 确认参数存在)----
import subprocess as _sp2
_proc = _sp2.run([sys.executable, str(REPO / "att-fuzz" / "runner.py"), "--help"],
                capture_output=True, text=True, cwd=str(REPO))
assert "--impersonate" in _proc.stdout, "runner --help 应含 --impersonate"
assert "--imp-duration" in _proc.stdout, "runner --help 应含 --imp-duration"
assert "--phone-mac" in _proc.stdout, "runner --help 应含 --phone-mac"
print("--impersonate CLI 参数接线自测通过")
