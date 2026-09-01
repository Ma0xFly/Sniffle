#!/usr/bin/env python3
# att-fuzz/core/pcap_decrypt.py
"""
加密 BLE pcap 离线解密:pcap + LTK 候选 -> LL 解密 -> L2CAP 重组 -> ATT/SMP 明文流。
全程离线,不碰硬件/串口。

流程:
1. PcapBleReader 读包(pcap.py 方向位已修:pdu_type 从 flags>>7 取)。
2. 按时间序分连接:CONNECT_IND(aa_conn)开新连接,数据信道包按 aa 挂当前连接;
   无 CONNECT_IND 时按 aa 隐式开连接(中途开抓也能解,但计数器起点若不在 0
   靠 LLCipherState 回扫窗口兜底)。
3. 每连接两阶段:
   - 明文阶段(cipher 未就绪):LL control(ENC_REQ/RSP 的 SKD/IV 空口序) +
     明文 L2CAP 数据(配对会话的 SMP 就在这里)。
   - 加密阶段(ENC_REQ+RSP 齐全,会话密钥 = e(LTK, SKDs_be || SKDm_be),
     IV = IVm||IVs 空口序):逐包 CCM 解密。注意 START_ENC_REQ(0x05)之后
     LL control 也走密文(START_ENC_RSP/TERMINATE 均是,01_crack 向量实测),
     与 pairing_sniff 的"control 恒明文"简化不同——解密后 control 照常解析。
4. LTK 候选逐个(原序+反转序都试)跑全连接,以 MIC 通过数裁定获胜 key。
5. 输出:ConnReport(每连接:connect 元数据/enc 握手/key 裁定/帧计数/终止原因)
   + SDU 流(ATT/SMP,CID 标注,明文/密文阶段都收)。

LTK 字节序定案(以新鲜抓包 MIC 验证为准,验证后在此落档):
  [已验证 2026-09-01] vivo TWS 3e + Redmi K50 实测(OTA MIC 验证 45 包/75 条 ATT
  明文 SDU):bt_config.conf LE_KEY_PENC 的 LTK dump 序是 HCI 空口小端序,需要
  **整体反转**才是 e() 可用的大端序 -- 引擎裁定 "reversed" 字节序。
  交叉验证:同日手机 HCI snoop 的 LE_Start_Encryption 命令 LTK 字段与 bt_config
  dump 序逐字节一致,rand/ediv=0 亦与空口 LL_ENC_REQ 相符 -- 两个独立通道同一定论。
  即:bt_keys.py 返回的 ltk 原样喂本引擎即可(引擎自动双序尝试),但手工调用
  bt_crypto.session_key 时必须先 bytes[::-1]。
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from struct import unpack

from sniffle.pcap import PcapBleReader, rf_to_ble_chan
from sniffle.packet_decoder import (ConnectIndMessage, DataMessage,
                                    DPacketMessage, PacketMessage)
from sniffle.sniffle_hw import PhyMode

from core import bt_crypto
from core.att import AttOpcode
from core.transport import _L2capReassembly

log = logging.getLogger("att-fuzz.pcap_decrypt")


class _PcapBleReaderAA(PcapBleReader):
    """PcapBleReader 补丁:回放时把 pcap phdr 的参考 AA 注入 decoder_state。
    上游 from_fields 忽略 phdr AA,包分类(广播 vs 数据)依赖 dstate.cur_aa,
    而它只被 pcap 内的 CONNECT_IND 解码更新——缺 CONNECT_IND 的 pcap 会把
    数据信道包全判成广播。注入后与上游行为一致(广播包 phdr AA 即广播 AA,
    数据包 phdr AA 即连接 AA,update_state 的 CONNECT_IND 路径不受影响)。"""

    def read_packet(self):
        hdr = self.input.read(16)
        if len(hdr) < 16:
            raise EOFError
        ts_sec, ts_usec, size1, size2 = unpack("<IIII", hdr)
        assert size1 == size2
        payload = self.input.read(size1)
        rf_chan, rssi, _, _, aa, flags, _ = unpack("<BbbBIHI", payload[:14])
        assert (flags & 0x0413) == 0x0413
        crc_err = False if (flags & 0x0800) else True
        phy = PhyMode(flags >> 14)
        pdu_type = (flags & 0x0380) >> 7
        assert pdu_type < 4
        body_idx = 14
        if phy == PhyMode.PHY_CODED:
            coding = payload[body_idx]
            body_idx += 1
            assert coding <= 1
            if coding == 1:
                phy = PhyMode.PHY_CODED_S2
        body = payload[body_idx:-3]
        crc_rev = payload[-3] + (payload[-2] << 8) + (payload[-1] << 16)
        assert len(body) == body[1] + 2
        ts32 = (ts_sec * 1000000 + ts_usec) & 0x3FFFFFFF
        chan = rf_to_ble_chan(rf_chan)
        peripheral_send = True if pdu_type == 3 else False
        self.decoder_state.cur_aa = aa          # 与上游唯一差异
        pkt = PacketMessage.from_fields(ts32, len(body), 0, rssi, chan, phy,
                                        body, crc_rev, crc_err,
                                        self.decoder_state, peripheral_send)
        try:
            return DPacketMessage.decode(pkt, self.decoder_state)
        except BaseException:
            return pkt

ATT_CID = 0x0004
SMP_CID = 0x0006

LL_ENC_REQ = 0x03
LL_ENC_RSP = 0x04
LL_START_ENC_REQ = 0x05
LL_TERMINATE_IND = 0x02

# 计数器回扫窗口:单板抓加密连接丢包重(空包心跳 ~40/s,信道跳变时成段丢),32 不够
# 跨大缺口;离线解密不敏感延迟,放大到 2048(错配 MIC 假阳性 ~2048*2^-32/包,可忽略)。
# 实测 vivo 重连会话:32 窗口 23 包 MIC 通过,2048 窗口 43+ 包。
SEARCH_WINDOW = 2048

LL_CONTROL_NAMES = {0x00: "CONNECTION_UPDATE", 0x01: "CHANNEL_MAP",
                    0x02: "TERMINATE", 0x03: "ENC_REQ", 0x04: "ENC_RSP",
                    0x05: "START_ENC_REQ", 0x06: "START_ENC_RSP",
                    0x07: "UNKNOWN_RSP", 0x08: "FEATURE_REQ",
                    0x09: "FEATURE_RSP", 0x0A: "PAUSE_ENC_REQ",
                    0x0B: "PAUSE_ENC_RSP", 0x0C: "VERSION_IND",
                    0x0D: "REJECT_IND", 0x14: "LENGTH_REQ",
                    0x15: "LENGTH_RSP"}


def _be(b: bytes) -> bytes:
    return bytes(b)[::-1]


@dataclass
class SduFrame:
    """一条完整 L2CAP SDU(明文阶段或解密后)。"""
    ts: float
    direction: str            # "m2s" | "s2m"
    cid: int
    sdu: bytes
    phase: str                # "plaintext" | "decrypted"
    conn_index: int = 0

    def op_name(self) -> str | None:
        if not self.sdu:
            return None
        if self.cid == ATT_CID:
            try:
                return AttOpcode(self.sdu[0]).name
            except ValueError:
                return "ATT_OP_0x%02X" % self.sdu[0]
        if self.cid == SMP_CID:
            return "SMP_OP_0x%02X" % self.sdu[0]
        return None

    def record(self) -> dict:
        return {"conn": self.conn_index, "ts": round(self.ts, 6),
                "dir": self.direction, "cid": "0x%04X" % self.cid,
                "op": self.op_name(), "phase": self.phase,
                "len": len(self.sdu), "pdu": self.sdu.hex()}


@dataclass
class ConnReport:
    index: int
    aa: int
    pkt_count: int = 0
    connect: dict | None = None      # CONNECT_IND 元数据(若有)
    enc: dict | None = None          # {rand, ediv, skdm, skds, iv}(空口序 hex)
    key_match: dict | None = None    # {label, byte_order, session_key}
    sdus: list = field(default_factory=list)     # SduFrame
    mic_ok: int = 0
    mic_fail: int = 0                # 加密段 MIC 失败(丢包超窗/错序)
    terminate: dict | None = None    # {reason, encrypted}

    def summary(self) -> dict:
        ops = {}
        for f in self.sdus:
            n = f.op_name() or "cid_0x%04X" % f.cid
            ops[n] = ops.get(n, 0) + 1
        return {
            "conn": self.index, "aa": "0x%08X" % self.aa,
            "packets": self.pkt_count,
            "connect": self.connect, "enc": self.enc,
            "key_match": self.key_match,
            "mic_ok": self.mic_ok, "mic_fail": self.mic_fail,
            "sdu_count": len(self.sdus), "ops": ops,
            "terminate": self.terminate,
        }


class _ConnTrack:
    """一条连接的解密走查状态。walk_keys=True 时只统计 MIC 通过数(裁定 key)。"""

    def __init__(self, sessk: bytes | None, iv: bytes):
        self.sessk = sessk
        self.iv = iv
        self.cipher = None if sessk is None else \
            bt_crypto.LLCipherState(sessk, iv, search_window=SEARCH_WINDOW)
        self.rx = {bt_crypto.DIR_M2S: _L2capReassembly(),
                   bt_crypto.DIR_S2M: _L2capReassembly()}
        self.mic_ok = 0
        self.mic_fail = 0
        self.sdus: list = []
        self.terminate = None
        self.first_ok = False         # 首个 MIC 通过(其后失败才计 gap)
        self.enc_info: dict = {}


def _frame_ll(pkt) -> tuple:
    """DataMessage -> (header_byte, payload, direction, sn, llid)。"""
    body = pkt.body
    hdr = body[0]
    data_len = pkt.data_length
    payload = body[2:2 + data_len]
    direction = bt_crypto.DIR_M2S if pkt.data_dir == 0 else bt_crypto.DIR_S2M
    return hdr, payload, direction, (hdr >> 3) & 1, hdr & 0x03


def _feed_sdu(track: _ConnTrack, ts, direction, llid, frag, phase, conn_index):
    sdu, cid, _trunc = track.rx[direction].feed(llid, frag)
    if sdu is not None:
        track.sdus.append(SduFrame(ts=ts, direction=direction, cid=cid,
                                   sdu=sdu, phase=phase, conn_index=conn_index))


def _on_ll_control_plaintext(track: _ConnTrack, payload: bytes, enc_info: dict):
    """明文阶段(或 MIC 失败回退)的 LL control 解析:收 ENC 握手 + 终止。"""
    if not payload:
        return
    opc = payload[0]
    if opc == LL_ENC_REQ and len(payload) >= 23:
        # opcode + Rand(8) + EDIV(2) + SKDm(8) + IVm(4),全部空口序
        enc_info["rand"] = payload[1:9]
        enc_info["ediv"] = payload[9:11]
        enc_info["skdm"] = payload[11:19]
        enc_info["ivm"] = payload[19:23]
    elif opc == LL_ENC_RSP and len(payload) >= 13:
        enc_info["skds"] = payload[1:9]
        enc_info["ivs"] = payload[9:13]
    elif opc == LL_TERMINATE_IND and len(payload) >= 2 and track.terminate is None:
        track.terminate = {"reason": payload[1], "encrypted": False}


def _on_ll_control_decrypted(track: _ConnTrack, pt: bytes):
    """加密段解密出的 LL control(START_ENC_RSP/TERMINATE 等)。"""
    if not pt:
        return
    opc = pt[0]
    if opc == LL_TERMINATE_IND and len(pt) >= 2 and track.terminate is None:
        track.terminate = {"reason": pt[1], "encrypted": True}


def _walk_connection(pkts: list, sessk: bytes | None, iv: bytes,
                     conn_index: int, collect: bool) -> _ConnTrack:
    """走查一条连接的全部数据信道包。collect=False(裁定模式)只计 MIC 通过数;
    enc_info 由内部维护,走查后读 track.enc_info(ENC 握手字段)。"""
    track = _ConnTrack(sessk, iv)
    enc_info = track.enc_info
    for pkt in pkts:
        hdr, payload, direction, sn, llid = _frame_ll(pkt)
        if track.cipher is None:
            # 明文阶段:control 收握手,数据进重组(配对会话的 SMP)
            if llid == 0x03:
                _on_ll_control_plaintext(track, payload, enc_info)
            else:
                if collect:
                    _feed_sdu(track, pkt.ts_epoch, direction, llid, payload,
                              "plaintext", conn_index)
            continue
        # 加密阶段:所有包(含 control)都带 MIC,逐包解密
        pt = None
        if len(payload) >= 4:
            pt = track.cipher.decrypt_packet(hdr, payload[:-4], payload[-4:],
                                            direction, sn)
        if pt is not None:
            track.mic_ok += 1
            track.first_ok = True
            if collect:
                if llid == 0x03:
                    _on_ll_control_decrypted(track, pt)
                else:
                    _feed_sdu(track, pkt.ts_epoch, direction, llid, pt,
                              "decrypted", conn_index)
        else:
            # MIC 失败:握手段明文 control 回退(ENC_RSP~START_ENC_REQ 窗口内的
            # 重传),或加密前尾巴上的明文数据;首过之后的失败=丢包超窗
            if llid == 0x03:
                _on_ll_control_plaintext(track, payload, enc_info)
            elif not track.first_ok and collect:
                _feed_sdu(track, pkt.ts_epoch, direction, llid, payload,
                          "plaintext", conn_index)
            else:
                track.mic_fail += 1
    return track


def _build_session(key: bytes, enc_info: dict) -> bytes | None:
    """会话密钥 = e(LTK, SKDs_be || SKDm_be);SKD 不齐返回 None。"""
    if not (enc_info.get("skdm") and enc_info.get("skds")):
        return None
    return bt_crypto.session_key(key, _be(enc_info["skdm"]),
                                  _be(enc_info["skds"]))


def _conn_iv(enc_info: dict) -> bytes:
    ivm = enc_info.get("ivm") or b"\x00" * 4
    ivs = enc_info.get("ivs") or b"\x00" * 4
    return (ivm + ivs)[:8]


def decrypt_pcap(pcap_path: str | Path, key_candidates: list) -> list:
    """主入口。key_candidates: [(key_bytes, label)]。返回 [ConnReport]。
    字节序裁定:每个候选 key 与其反转各跑一遍,按 MIC 通过数取最优。"""
    packets = [p for p in _PcapBleReaderAA(str(pcap_path))]
    conns = _split_connections(packets)
    reports = []
    for idx, (aa, connect, pkts) in enumerate(conns):
        reports.append(_decrypt_one(idx, aa, connect, pkts, key_candidates))
    return reports


def _split_connections(packets: list) -> list:
    """时间序分连接:CONNECT_IND 开新连接(同 aa 复用也切);数据包按 aa 挂
    当前连接,无 CONNECT_IND 的 aa 隐式开。返回 [(aa, connect_meta, pkts)]。"""
    conns: list = []              # [ {aa, connect, pkts} ]
    by_aa: dict = {}
    for pkt in packets:
        if isinstance(pkt, ConnectIndMessage):
            aa = pkt.aa_conn
            entry = {"aa": aa,
                     "connect": {"init": bytes(pkt.InitA).hex(),
                                 "adv": bytes(pkt.AdvA).hex(),
                                 "iat": 1 if pkt.TxAdd else 0,
                                 "rat": 1 if pkt.RxAdd else 0,
                                 "interval": pkt.Interval},
                     "pkts": []}
            conns.append(entry)
            by_aa[aa] = entry
        elif isinstance(pkt, DataMessage):
            entry = by_aa.get(pkt.aa)
            if entry is None:
                entry = {"aa": pkt.aa, "connect": None, "pkts": []}
                conns.append(entry)
                by_aa[pkt.aa] = entry
            entry["pkts"].append(pkt)
    return [(e["aa"], e["connect"], e["pkts"]) for e in conns]


def _decrypt_one(idx: int, aa: int, connect: dict | None, pkts: list,
                 key_candidates: list) -> ConnReport:
    rpt = ConnReport(index=idx, aa=aa, pkt_count=len(pkts), connect=connect)
    if not pkts:
        return rpt
    # 先用空 key 走一遍明文阶段收 ENC 握手(SKD/IV)
    probe = _walk_connection(pkts, None, b"\x00" * 8, idx, collect=False)
    enc_info = probe.enc_info
    if enc_info.get("skdm") and enc_info.get("skds"):
        rpt.enc = {"rand": enc_info.get("rand", b"").hex(),
                   "ediv": enc_info.get("ediv", b"").hex(),
                   "skdm": enc_info["skdm"].hex(),
                   "skds": enc_info["skds"].hex(),
                   "iv": _conn_iv(enc_info).hex()}
    else:
        # 无加密握手:整条连接明文,直接收 SDU
        track = _walk_connection(pkts, None, b"\x00" * 8, idx, collect=True)
        rpt.sdus = track.sdus
        rpt.terminate = track.terminate
        _log_conn(rpt, "no encryption handshake (plaintext link)")
        return rpt

    iv = _conn_iv(enc_info)
    best = None
    for key, label in key_candidates:
        for order, k in (("as-stored", key), ("reversed", key[::-1])):
            sessk = _build_session(k, enc_info)
            if sessk is None:
                continue
            track = _walk_connection(pkts, sessk, iv, idx, collect=False)
            score = track.mic_ok
            log.debug("conn#%d candidate %s %s: mic_ok=%d", idx, label,
                      order, score)
            if best is None or score > best[0]:
                best = (score, k, order, label, sessk)
    if best is None or best[0] == 0:
        _log_conn(rpt, "encrypted but no candidate key matched (MIC all fail)")
        return rpt
    score, key, order, label, sessk = best
    rpt.key_match = {"label": label, "byte_order": order,
                     "session_key": sessk.hex(),
                     "mic_ok": score}
    track = _walk_connection(pkts, sessk, iv, idx, collect=True)
    rpt.sdus = track.sdus
    rpt.mic_ok = track.mic_ok
    rpt.mic_fail = track.mic_fail
    rpt.terminate = track.terminate
    _log_conn(rpt, "decrypted with %s (%s)" % (label, order))
    return rpt


def _log_conn(rpt: ConnReport, note: str):
    log.info("conn#%d aa=0x%08X packets=%d %s", rpt.index, rpt.aa,
             rpt.pkt_count, note)


def write_outputs(reports: list, outdir: Path, pcap_path: str) -> dict:
    """落档:decrypt_report.json(每连接摘要)+ decrypted_sdu.jsonl(SDU 流)。
    返回顶层摘要 dict。"""
    outdir.mkdir(parents=True, exist_ok=True)
    sdu_count = 0
    with open(outdir / "decrypted_sdu.jsonl", "w", encoding="utf-8") as fh:
        for rpt in reports:
            for f in rpt.sdus:
                fh.write(json.dumps(f.record(), ensure_ascii=False) + "\n")
                sdu_count += 1
    top = {"pcap": str(pcap_path), "connections": len(reports),
           "sdus": sdu_count,
           "reports": [r.summary() for r in reports]}
    (outdir / "decrypt_report.json").write_text(
            json.dumps(top, ensure_ascii=False, indent=2), encoding="utf-8")
    return top
