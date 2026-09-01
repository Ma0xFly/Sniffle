#!/usr/bin/env python3
# att-fuzz/core/transport.py
"""
SniffleTransport -- att-fuzz 传输层。

- select 事件循环,绝不阻塞死等(照 relay_master.py:238-244 模式)
- ATT 注入: L2CAP 分片(>ll_max 时 LLID=2 首帧/LLID=1 续帧) + cmd_transmit_at 门控
  (gateAt 单调递增, TXQueue_take_at 是队头最长前缀语义) + 发端深度限速
- ATT 接收: L2CAP 重组 + 事件号跟踪(PacketMessage.event -> cur_event)
- LL 控制处理: LL_LENGTH_REQ 自动应答 / LL_LENGTH_RSP 捕获(DLE)、
  TERMINATE reason 捕获(固件补丁 #2 的 TerminateMeasurement + 原始 PDU 双路)
- pcap(PcapBleWriter) + JSONL 双录
"""

import json
import logging
import select
import time
from dataclasses import dataclass, field
from pathlib import Path
from struct import pack, unpack

import serial

from sniffle.constants import BLE_ADV_AA
from sniffle.measurements import TerminateMeasurement
from sniffle.pcap import PcapBleWriter
from sniffle.packet_decoder import (AdvIndMessage, ConnectIndMessage, DataMessage,
                                    DPacketMessage, LlControlMessage, ScanRspMessage)
from sniffle.sniffle_hw import (DebugMessage, MarkerMessage, PacketMessage,
                               SniffleHW, StateMessage)
from sniffle.sniffer_state import SnifferState

from . import bt_crypto
from .att import exchange_mtu_req, parse_exchange_mtu_rsp

log = logging.getLogger("att-fuzz.transport")

ATT_CID = 0x0004
L2CAP_CID_SIGNALING = 0x0005
L2CAP_HDR_LEN = 4

LL_TERMINATE_IND = 0x02
LL_ENC_REQ = 0x03
LL_ENC_RSP = 0x04
LL_START_ENC_REQ = 0x05
LL_START_ENC_RSP = 0x06
LL_UNKNOWN_RSP = 0x07      # 规范:0x07=UNKNOWN_RSP,0x08=FEATURE_REQ(旧值 0x08 误标)
LL_FEATURE_REQ = 0x08
LL_FEATURE_RSP = 0x09
LL_VERSION_IND = 0x0C
LL_CONN_PARAM_REQ = 0x12
LL_CONN_PARAM_RSP = 0x13
LL_LENGTH_REQ = 0x14
LL_LENGTH_RSP = 0x15

# 我们作为 server/peripheral 向手机声明的 LL 特征:DLE(bit5)。无加密(无 SMP,设计边界)。
LL_FEATURES_MASK = 0x20

# 我们代答的 LL 版本信息:TI(0x000D) + BT 5.2。严格栈(实测 MTK)在版本交换
# 未完成时会挂起后续 LL 过程(DLE 等)乃至 host 数据 -> GATT 40s LMP 超时。
LL_VERSION_NR = 11
LL_COMPANY_ID = 0x000D
LL_SUBVERSION_NR = 0x0001

LL_MAX_PAYLOAD_DLE = 251
LL_TIME_DLE = 2120          # 251 字节 @2M 的 us 数,协商值里用它
TX_QUEUE_SOFT_LIMIT = 6     # 固件可用 7,留 1 给控制 PDU


class TransportError(Exception):
    """传输层自身错误(非靶子信号):串口、门控顺序等。
    stuck=True 表示固件可能卡死在 initiator 命令里,需要 cmd_reset。"""

    def __init__(self, msg, stuck: bool = False):
        super().__init__(msg)
        self.stuck = stuck


class LinkDrop(Exception):
    """连接断开。source: 'terminate'(带 reason) / 'supervision'(对端静默超时) / 'state'"""

    def __init__(self, source: str, reason: int | None = None):
        self.source = source
        self.reason = reason
        super().__init__("link dropped: %s%s" % (source,
                " (reason=0x%02X)" % reason if reason is not None else ""))


@dataclass
class AttPacket:
    """一个完整 ATT PDU + 接收元数据"""
    pdu: bytes
    event: int
    ts: float
    rssi: int
    phy: int
    cid: int = ATT_CID


class _L2capReassembly:
    """收方向 L2CAP SDU 重组(固件不做,host 按 LLID 拼)"""

    def __init__(self):
        self.reset()

    def reset(self):
        self.sdu_len = 0
        self.cid = 0
        self.buf = bytearray()

    def feed(self, llid: int, payload: bytes):
        """喂一个 LL data payload。
        返回 (sdu, cid, truncated):sdu 为完整 SDU bytes 或 None;
        truncated=True 表示实际字节多于声明长度(SDU 撒谎/截断)。"""
        if llid == 2:
            if len(payload) < L2CAP_HDR_LEN:
                self.reset()
                return None, 0, False
            self.sdu_len, self.cid = unpack("<HH", payload[:4])
            self.buf = bytearray(payload[4:])
            if self.sdu_len == 0:
                sdu, cid = b"", self.cid
                self.reset()
                return sdu, cid, False
        elif llid == 1:
            if not self.buf:
                # 孤立续帧:重组状态丢了,丢弃
                return None, 0, False
            self.buf += payload
        else:
            return None, 0, False

        if self.sdu_len and len(self.buf) >= self.sdu_len:
            truncated = len(self.buf) > self.sdu_len
            sdu = bytes(self.buf[:self.sdu_len])
            cid = self.cid
            self.reset()
            return sdu, cid, truncated
        return None, 0, False


class SniffleTransport:
    def __init__(self, hw: SniffleHW, pcap: PcapBleWriter | None = None,
                 jsonl_path: Path | None = None, conn_interval_units: int = 12):
        self.hw = hw
        self.pcap = pcap
        self.jsonl = open(jsonl_path, "a") if jsonl_path else None
        self.conn_interval_s = conn_interval_units * 0.00125
        self.response_timeout = 2 * self.conn_interval_s + 2.0

        self.aa = None                 # 当前连接 access address
        self.ll_max = 27               # 协商后的单帧 LL payload 上限
        self.att_mtu = 23              # 协商后的 ATT MTU
        self.cur_event = 0             # 最近 RX 包的连接事件号
        self.tx_queue_full = False     # DebugMessage 里见过 "TX queue full"

        self._link_up = False
        self._link_dropped: LinkDrop | None = None
        self._expected_disconnect = False
        self._rx_l2cap = _L2capReassembly()
        self._rx_backlog = []
        self._tx_pending = 0
        self._tx_watermark_event = 0
        self._tx_last_time = 0.0
        self._last_gate_at = 0
        self._terminate_reason: int | None = None
        self._event_listeners = []     # GUI 等外部订阅者(纯增量,不影响原行为)
        self.role = "central"          # "central" | "peripheral"(server_fuzz 反转角色)
        # ---- 加密层(LL_ENC 握手后启用)----
        # _enc_enabled=True 后:TX 路径(inject/inject_raw/_handle_ll_control 代答)
        # 自动 AES-CCM 加密,RX 路径(_feed_rx_data)自动解密(含 LL control)。
        # 握手驱动(impersonation_fuzz)在握手期间通过 _enc_handshake_q 取回
        # ENC_RSP/START_ENC_REQ/START_ENC_RSP PDU(否则 _handle_ll_control 只记录)。
        self._enc_enabled = False
        self._enc_cipher: bt_crypto.LLCipherState | None = None
        self._enc_handshake_q: list = []   # [(opcode, payload_bytes), ...]
        self._non_att_q: list = []         # [(cid, sdu_bytes), ...] 非 ATT L2CAP(SMP/CID-5 signaling 等)

    def add_event_listener(self, fn):
        """订阅 _log_event 事件流。fn(rec: dict) 在传输层线程内同步调用,
        订阅者必须自己保证线程安全且不可阻塞。"""
        self._event_listeners.append(fn)

    # ---------- 基础事件循环 ----------

    def _select_ready(self, deadline: float) -> bool:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        r, _, _ = select.select([self.hw.ser.fd], [], [], min(remaining, 0.1))
        return bool(r)

    def _log_event(self, kind: str, **fields):
        rec = {"ts": round(time.time(), 6), "kind": kind}
        rec.update(fields)
        line = json.dumps(rec, ensure_ascii=False, default=str)
        if self.jsonl:
            self.jsonl.write(line + "\n")
            self.jsonl.flush()
        if self._event_listeners:
            for fn in self._event_listeners:
                try:
                    fn(rec)
                except Exception as e:
                    log.warning("event listener failed: %s", e)

    def _pcap_rx(self, dpkt):
        if self.pcap:
            try:
                self.pcap.write_packet_message(dpkt)
            except Exception as e:
                log.warning("pcap write failed: %s", e)

    def _pcap_tx(self, ll_pdu: bytes, ts: float):
        """本机发出的 LL PDU 记录。方向按角色:central 是 C->P(pdu_type=2),
        peripheral 是 P->C(=3)。"""
        if self.pcap:
            try:
                pdu_type = 2 if self.role == "central" else 3
                self.pcap.write_packet(int(ts * 1000000), self.aa or 0,
                        0, 0, ll_pdu, 0, pdu_type=pdu_type)
            except Exception as e:
                log.warning("pcap write failed: %s", e)

    # ---------- 连接生命周期 ----------

    def probe(self, mac: bytes, timeout: float = 15.0) -> dict:
        """扫描诊断:按 MAC 过滤找目标广播,报告地址类型/信号/载荷。
        用于排查"连不上"——先确认目标在广播、且地址类型正确。"""
        self.hw.cmd_chan_aa_phy(37, BLE_ADV_AA, 0)
        self.hw.cmd_pause_done(True)
        self.hw.cmd_follow(False)
        self.hw.cmd_rssi(-128)
        self.hw.cmd_mac(mac, False)
        self.hw.cmd_auxadv(False)
        self.hw.cmd_scan()
        self.hw.mark_and_flush()
        deadline = time.monotonic() + timeout
        self._log_event("probe_start", mac=mac.hex())
        while time.monotonic() < deadline:
            if not self._select_ready(deadline):
                continue
            try:
                msg = self.hw.recv_and_decode()
            except Exception as e:
                # 空口残包会让上游解码器抛错(probe 常态),跳过该包继续扫
                log.debug("probe decode error: %s", e)
                continue
            if isinstance(msg, (AdvIndMessage, ScanRspMessage)) and msg.AdvA is not None:
                # MAC 过滤下收到的都是目标
                return {
                    "found": True,
                    "addr": bytes(msg.AdvA).hex(),
                    "addr_type": "random" if msg.TxAdd else "public",
                    "rssi": msg.rssi,
                    "adv_preview": msg.body.hex(),
                }
        return {"found": False, "addr": mac.hex()}

    def _find_target_by_string(self, s: bytes, timeout: float = 30.0):
        """主动扫描按广播串找目标 MAC(参考 initiator.get_mac_from_string)"""
        self.hw.cmd_chan_aa_phy(37, BLE_ADV_AA, 0)
        self.hw.cmd_pause_done(True)
        self.hw.cmd_follow(False)
        self.hw.cmd_rssi(-128)
        self.hw.cmd_mac()
        self.hw.cmd_auxadv(False)
        self.hw.random_addr()
        self.hw.cmd_scan()
        self.hw.mark_and_flush()
        deadline = time.monotonic() + timeout
        self._log_event("scan_start", search=s.decode("latin-1", "replace"))
        while time.monotonic() < deadline:
            if not self._select_ready(deadline):
                continue
            try:
                msg = self.hw.recv_and_decode()
            except Exception as e:
                log.debug("scan decode error: %s", e)
                continue
            if isinstance(msg, (AdvIndMessage, ScanRspMessage)) and msg.AdvA is not None:
                if s in msg.body:
                    mac = bytes(msg.AdvA)
                    self._log_event("target_found", mac=mac.hex())
                    return mac, not msg.TxAdd
        raise TransportError("target not found by advertisement string: %r" % s)

    def connect(self, target, retries: int = 5,
                our_addr: bytes | None = None,
                our_addr_random: bool = False) -> int:
        """发起直连(central),带自愈重试。
        target: dict/TargetProfile,含 mac 或 search_string。
        our_addr/our_addr_random:冒充场景指定本机地址(默认 None=随机地址)。
        已知坑: host 在 INITIATING 期间退出会让固件卡死在 forever initiator
        命令里(radio task 永久阻塞),后续命令全部失效 -> 超时后必须 cmd_reset。
        另外该命令对 extended-advertising/慢广播目标有间歇失败(-1),需重试。"""
        last_err = None
        for attempt in range(1, retries + 1):
            try:
                return self._connect_once(target, our_addr, our_addr_random)
            except (TransportError, serial.SerialException, OSError) as e:
                last_err = e
                log.warning("connect attempt %d/%d failed: %s", attempt, retries, e)
                stuck = getattr(e, "stuck", False) or isinstance(e, (serial.SerialException, OSError))
                if attempt < retries:
                    if stuck:
                        self._reset_firmware()      # 卡死:必须复位
                    else:
                        time.sleep(0.5)             # 干净失败(如 -1):快速重试
        raise last_err

    def _reopen_serial(self):
        """XDS110 UART 复位/重置后常报"假就绪读不到数据",重开串口即可。
        复位后 CDC 需重新枚举,open 可能失败:有限重试,仍失败抛 TransportError
        (否则后续写会裸崩 PortNotOpenError)。"""
        try:
            self.hw.ser.close()
        except Exception:
            pass
        time.sleep(0.5)
        for attempt in range(1, 4):
            try:
                self.hw.ser.open()
                return
            except Exception as e:
                log.warning("serial reopen attempt %d failed: %s", attempt, e)
                time.sleep(1.0)
        raise TransportError("serial reopen failed after firmware reset", stuck=True)

    def _reset_firmware(self):
        """固件若卡死在 initiator 命令里,只能整机复位。"""
        log.warning("resetting firmware to clear stuck radio state")
        try:
            self.hw.cmd_reset()
        except Exception as e:
            log.warning("cmd_reset failed: %s", e)
        time.sleep(2.0)   # 等固件重启完成
        self._reopen_serial()
        self._reset_link_state()

    def _parse_mac(self, mac_str) -> tuple:
        """人类书写序(AA:BB:...) -> 线序字节(LSB first)+ 地址类型推断。
        BLE 广播/CONNECT_IND 里的 AdvA 是小端字节序,固件全线用线序。"""
        mac = bytes.fromhex(str(mac_str).replace(":", "").replace("-", ""))
        wire = mac[::-1]
        # 地址类型看最高字节(线序的最后一字节):bit1=1 或高2位=11 -> random
        msb = wire[-1]
        implied_random = bool(msb & 0x02) or (msb & 0xC0) == 0xC0
        return wire, implied_random

    def _connect_once(self, target, our_addr: bytes | None = None,
                      our_addr_random: bool = False) -> int:
        mac = target.get("mac") if hasattr(target, "get") else target["mac"]
        if mac:
            mac, implied_random = self._parse_mac(mac)
            mac_random = target.get("mac_random", True)
            if implied_random != mac_random:
                log.warning("地址类型疑不匹配: 最高字节 0x%02X 暗示 %s, 目标档案设 %s",
                            msb, "random" if implied_random else "public",
                            "random" if mac_random else "public")
        else:
            mac, mac_random = self._find_target_by_string(
                    target["search_string"].encode("latin-1"))

        interval = target.get("conn_interval", 12)
        latency = target.get("latency", 0)
        self.conn_interval_s = interval * 0.00125
        self.response_timeout = 2 * self.conn_interval_s + 2.0

        # initiator.py:52-97 序列(逐条对齐官方)。
        # auxadv 必须 True:嗅探器的软件 aux 跟踪在 RF core 追 aux 指针时
        # 会 stop 掉 initiator 命令,配合固件 INITIATING 重试循环,这实际是
        # "aux 追踪超时->快速重来"机制,提升抓 legacy ADV_IND 的概率。
        # (实测:auxadv=False 时 RF core 死追 aux 到 RXERR,连接全失败)
        self.hw.cmd_chan_aa_phy(37, BLE_ADV_AA, 0)
        self.hw.cmd_pause_done(True)
        self.hw.cmd_follow(False)
        self.hw.cmd_rssi(-128)
        self.hw.cmd_mac(mac, False)
        self.hw.cmd_auxadv(True)
        self.hw.cmd_interval_preload()
        # 本机地址:冒充场景用指定地址(如手机 public),否则随机
        if our_addr is not None:
            self.hw.cmd_setaddr(our_addr, our_addr_random)
        else:
            self.hw.random_addr()
        self.hw.cmd_tx_power(5)
        self.hw.mark_and_flush()

        self._reset_link_state()
        aa = self.hw.initiate_conn(mac, mac_random, interval, latency)
        deadline = time.monotonic() + target.get("connect_timeout", 10.0)
        while time.monotonic() < deadline:
            if not self._select_ready(deadline):
                continue
            try:
                msg = self.hw.recv_and_decode()
            except Exception as e:
                # 空口残包会让上游解码器抛错(实测截断广播包打死整个连接流程),
                # 跳过该包继续等 CENTRAL
                log.debug("connect decode error: %s", e)
                continue
            if msg is not None:
                if isinstance(msg, StateMessage):
                    log.debug("connect: STATE %s from %s", msg.new_state.name,
                              msg.last_state.name)
                elif isinstance(msg, DebugMessage):
                    log.debug("connect: FW %s", msg.msg)
                else:
                    log.debug("connect: msg %s", type(msg).__name__)
            if isinstance(msg, StateMessage):
                if msg.new_state == SnifferState.CENTRAL:
                    self.hw.decoder_state.cur_aa = aa
                    self.aa = aa
                    self._link_up = True
                    self._log_event("connected", aa="%08X" % aa, mac=mac.hex(),
                                    interval=interval, latency=latency)
                    return aa
                if msg.last_state == SnifferState.INITIATING and \
                        msg.new_state == SnifferState.PAUSED:
                    # 干净失败:initiator 报告失败,固件已自行回 PAUSED,无需复位
                    raise TransportError(
                        "initiator failed cleanly (target not accepting/not advertising "
                        "on ch%d): mac=%s %s" %
                        (37, mac.hex(), "random" if mac_random else "public"))
            # INITIATING 期间的目标广播会流过,忽略即可
        # 超时:固件多半还卡在 forever initiator 命令里 -> 必须复位
        raise TransportError(
            "connection timed out (no CENTRAL state): mac=%s %s interval=%d latency=%d "
            "-- 目标没在广播(配对模式?)或地址类型错(用 --probe 检查)" %
            (mac.hex(), "random" if mac_random else "public", interval, latency),
            stuck=True)

    def _reset_link_state(self):
        self._link_up = False
        self._link_dropped = None
        self._expected_disconnect = False
        self._terminate_reason = None
        self._rx_l2cap.reset()
        self._rx_backlog = []
        self._tx_pending = 0
        self._tx_watermark_event = 0
        self._last_gate_at = 0
        self.cur_event = 0
        self.ll_max = 27
        self.att_mtu = 23
        self.tx_queue_full = False
        # 加密层状态也复位(重连后需重新走 LL_ENC 握手)
        self._enc_enabled = False
        self._enc_cipher = None
        self._enc_handshake_q = []
        self._non_att_q = []

    # ---------- 加密层(LL_ENC 握手后启用)----------

    def enable_encryption(self, ltk_wire: bytes, skdm_wire: bytes,
                          skds_wire: bytes, ivm_wire: bytes, ivs_wire: bytes):
        """LL_ENC 握手材料齐全后启用 host 侧 AES-CCM。ltk_wire = bt_config dump
        序(HCI 小端),内部反转成大端喂 session_key。SKD/IV 保持空口序(同
        pcap_decrypt)。启用后 inject/inject_raw 自动加密 TX,recv 路径自动解密
        RX(含 LL control)。
        字节序定案见 pcap_decrypt 模块尾:bt_config LTK dump 序需整体反转才是
        e() 可用大端序;SKD/IV 各 8/4 字节空口小端序,session_key 取大端
        (skds_be||skdm_be),故反转 SKDm/SKDs 后传入。"""
        ltk_be = bytes(ltk_wire)[::-1]
        sessk = bt_crypto.session_key(ltk_be, bytes(skdm_wire)[::-1],
                                     bytes(skds_wire)[::-1])
        iv = (bytes(ivm_wire) + bytes(ivs_wire))[:8]
        self._enc_cipher = bt_crypto.LLCipherState(sessk, iv, search_window=2048)
        self._enc_enabled = True
        self._enc_handshake_q = []
        self._log_event("enc_enabled", session_key=sessk.hex(), iv=iv.hex())

    def _tx_ll_pdu(self, llid: int, payload: bytes, event: int | None = None,
                   gate_at: int | None = None):
        """发送一个 LL PDU。加密启用时:plaintext -> ct+mic 再交固件;未启用
        则原样透传(非加密路径行为不变)。event/gate_at 同 cmd_transmit(_at)。
        AAD = llid & 0x03(CP=0/RFU=0,固件头字节 & 0xE3 后只剩 LLID 位)。
        pcap 记录本机发出的 LL PDU(加密后 ct+mic,与空口一致)。"""
        if self._enc_enabled and self._enc_cipher is not None:
            ct, mic = self._enc_cipher.encrypt_packet(
                    llid & 0x03, payload, bt_crypto.DIR_M2S)
            tx_pdu = ct + mic
        else:
            tx_pdu = payload
        if gate_at is None:
            self.hw.cmd_transmit(llid, tx_pdu,
                                 (event if event is not None else self.cur_event) & 0xFFFF)
        else:
            if gate_at < self._last_gate_at:
                raise TransportError("gate_at must be monotonic: %d after %d" %
                                     (gate_at, self._last_gate_at))
            self.hw.cmd_transmit_at(llid, tx_pdu, gate_at)
            self._last_gate_at = gate_at
        self._pcap_tx(bytes([llid, len(tx_pdu)]) + tx_pdu, time.time())

    def disconnect(self, reason: int = 0x13):
        """主动断链(我们发 LL_TERMINATE_IND)。断链事件随后会被消费掉,不当作靶子信号。"""
        self._expected_disconnect = True
        self._log_event("disconnect_req", reason=reason)
        self._tx_ll_pdu(3, bytes([LL_TERMINATE_IND, reason]))

    @property
    def link_up(self) -> bool:
        return self._link_up

    def consume_link_drop(self) -> LinkDrop | None:
        drop = self._link_dropped
        self._link_dropped = None
        return drop

    # ---------- peripheral 角色(server_fuzz 反向角色用) ----------

    def _connected_states(self):
        """当前角色下"连接建立"的固件状态集合。"""
        return (SnifferState.CENTRAL,) if self.role == "central" \
            else (SnifferState.PERIPHERAL,)

    def advertise(self, adv_data: bytes, scan_rsp_data: bytes = b"",
                  interval_ms: int = 200, mac: bytes | None = None,
                  is_random: bool = True):
        """进入可连接 peripheral 广播态(ADVERTISING),等手机连入。
        参照 relay_slave.py:63-89 的 advertise 序列;连接结束后固件回 STATIC
        (pause_done(False)),需再次调用本方法重新广播。"""
        self.hw.cmd_chan_aa_phy(37, BLE_ADV_AA, 0)
        self.hw.cmd_pause_done(False)
        self.hw.cmd_follow(True)           # 接受连接
        self.hw.cmd_rssi()                 # 关 RSSI 过滤
        self.hw.cmd_mac()                  # 关 MAC 过滤
        self.hw.cmd_auxadv(False)
        if mac:
            self.hw.cmd_setaddr(mac, is_random)
        else:
            self.hw.random_addr()
        self.hw.cmd_adv_interval(interval_ms)
        self.hw.cmd_tx_power(5)
        self.hw.cmd_interval_preload()
        self.hw.mark_and_flush()
        self._reset_link_state()
        self._log_event("advertise", interval_ms=interval_ms)
        self.hw.cmd_advertise(adv_data, scan_rsp_data)

    def accept_connection(self, timeout: float | None = None) -> dict | None:
        """peripheral 模式:等手机 CONNECT_IND 连入。返回连接参数 dict,超时返回 None。
        固件收到 CONNECT_IND 后 stateTransition(PERIPHERAL)(StateMessage 送达),
        且 CONNECT_IND 本身作为 PacketMessage 转发 -- 从这里取 aa/连接参数,
        设 decoder_state.cur_aa 后开始跟随连接数据。"""
        deadline = time.monotonic() + (timeout if timeout is not None else 30.0)
        while time.monotonic() < deadline:
            if not self._select_ready(deadline):
                continue
            try:
                msg = self.hw.recv_and_decode()
            except Exception as e:
                log.debug("accept decode error: %s", e)
                continue
            if isinstance(msg, PacketMessage):
                try:
                    dpkt = DPacketMessage.decode(msg)
                except Exception as e:
                    log.debug("accept packet decode error: %s", e)
                    continue
                if isinstance(dpkt, ConnectIndMessage):
                    aa = dpkt.aa_conn
                    self.hw.decoder_state.cur_aa = aa
                    self.aa = aa
                    if dpkt.Interval:
                        self.conn_interval_s = dpkt.Interval * 0.00125
                        self.response_timeout = 2 * self.conn_interval_s + 2.0
                    self._link_up = True
                    self._log_event("accepted", aa="%08X" % aa,
                                    interval=dpkt.Interval, latency=dpkt.Latency,
                                    timeout=dpkt.Timeout,
                                    init_addr=bytes(dpkt.InitA).hex(),
                                    init_random=bool(dpkt.TxAdd))
                    return {"aa": aa, "interval": dpkt.Interval,
                            "latency": dpkt.Latency, "timeout": dpkt.Timeout,
                            "init_addr": bytes(dpkt.InitA).hex(),
                            "init_random": bool(dpkt.TxAdd)}
                # 广播期其他包(外界的广告等):忽略
            else:
                # StateMessage/Debug/Marker 等交给标准处理(记录、维护链路状态)
                self._process_message(msg)
        return None

    # ---------- DLE / MTU ----------

    def setup_data_size(self, declare_mtu: int = 517, timeout: float | None = None) -> tuple:
        """DLE(LL_LENGTH_REQ) + ATT Exchange MTU。返回 (ll_max, att_mtu)。"""
        if not self._link_up:
            raise TransportError("not connected")
        if timeout is None:
            timeout = self.response_timeout

        # 1) DLE -- 若对端已先发 LENGTH_REQ 且我们已应答,ll_max 已就位
        if self.ll_max == 27:
            self._tx_ll_pdu(3, bytes([LL_LENGTH_REQ]) +
                    pack("<HHHH", LL_MAX_PAYLOAD_DLE, LL_MAX_PAYLOAD_DLE,
                         LL_TIME_DLE, LL_TIME_DLE))
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline and self.ll_max == 27:
                self._pump(deadline)
            if self.ll_max == 27:
                log.warning("no LL_LENGTH_RSP (DLE unsupported?), ll_max stays 27")
                self._log_event("dle_no_response")

        # 2) ATT Exchange MTU
        self.inject(exchange_mtu_req(declare_mtu))
        rsp = self.recv_att(timeout)
        if rsp is not None and len(rsp.pdu) >= 3 and rsp.pdu[0] == 0x03:
            server_mtu = parse_exchange_mtu_rsp(rsp.pdu[1:])
            self.att_mtu = max(23, min(declare_mtu, server_mtu))
        elif rsp is not None and rsp.pdu[0] == 0x01:
            # Error Response 也算回答,MTU 保持 23
            self._log_event("mtu_exchange_error", pdu=rsp.pdu.hex())
        else:
            log.warning("no Exchange MTU response, att_mtu stays 23")
            self._log_event("mtu_no_response")
        self._log_event("data_size", ll_max=self.ll_max, att_mtu=self.att_mtu)
        return self.ll_max, self.att_mtu

    # ---------- 注入 ----------

    def inject(self, att_pdu: bytes, gate_at: int | None = None):
        """注入一个 ATT PDU。gate_at 给定则用 0x28 门控(须单调递增)。"""
        if not self._link_up:
            raise TransportError("not connected")
        sdu = pack("<HH", len(att_pdu), ATT_CID) + att_pdu
        frags = [sdu[i:i + self.ll_max] for i in range(0, len(sdu), self.ll_max)]
        self._wait_tx_room(len(frags))

        ts = time.time()
        for i, chunk in enumerate(frags):
            llid = 2 if i == 0 else 1
            if gate_at is not None and gate_at < self._last_gate_at:
                raise TransportError(
                        "gate_at must be monotonic: %d after %d" %
                        (gate_at, self._last_gate_at))
            self._tx_ll_pdu(llid, chunk, event=self.cur_event, gate_at=gate_at)
        self._tx_pending += len(frags)
        self._tx_watermark_event = self.cur_event
        self._tx_last_time = time.monotonic()
        self._log_event("inject", pdu=att_pdu.hex(), gate_at=gate_at,
                        frags=len(frags), event=self.cur_event)

    def inject_raw(self, fragments: list, gate_at: int | None = None):
        """原始 LL 帧序列注入(L2CAP 帧欺骗用)。fragments: [(llid, payload_bytes), ...],
        payload 含自构的 L2CAP 头(长度可谎报)。不做头构造/分片,只做 TX 限速与(可选)
        门控;LLID 语义由调用方决定。保持 inject 行为不变。"""
        if not self._link_up:
            raise TransportError("not connected")
        self._wait_tx_room(len(fragments))
        ts = time.time()
        for llid, payload in fragments:
            if gate_at is not None and gate_at < self._last_gate_at:
                raise TransportError(
                        "gate_at must be monotonic: %d after %d" %
                        (gate_at, self._last_gate_at))
            self._tx_ll_pdu(llid, payload, event=self.cur_event, gate_at=gate_at)
        self._tx_pending += len(fragments)
        self._tx_watermark_event = self.cur_event
        self._tx_last_time = time.monotonic()
        self._log_event("inject_raw", frags=len(fragments), gate_at=gate_at,
                        event=self.cur_event)

    def _effective_pending(self) -> int:
        if self.cur_event > self._tx_watermark_event:
            self._tx_pending = 0       # 事件号推进过 => 队列必然已出
        elif time.monotonic() - self._tx_last_time > 2 * self.conn_interval_s:
            self._tx_pending = 0       # 时间兜底:事件早已过去
        return self._tx_pending

    def _wait_tx_room(self, n: int, timeout: float | None = None):
        if timeout is None:
            timeout = 2 * self.conn_interval_s + 0.5
        deadline = time.monotonic() + timeout
        while self._effective_pending() + n > TX_QUEUE_SOFT_LIMIT:
            if time.monotonic() > deadline:
                # 时间上事件早已过去仍视为未决 => 放行并让固件 dprintf 兜底
                log.warning("TX room wait timed out, forcing through")
                self._tx_pending = 0
                break
            got = self._pump(deadline)
            if got is not None:
                self._rx_backlog.append(got)   # 房位等待期收到的包别丢

    # ---------- 接收 ----------

    def recv_att(self, timeout: float | None = None) -> AttPacket | None:
        """等一个完整 ATT PDU;掉链抛 LinkDrop;超时返回 None。"""
        if timeout is None:
            timeout = self.response_timeout
        if self._rx_backlog:
            return self._rx_backlog.pop(0)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            got = self._pump(deadline)
            if got is not None:
                return got
            if self._link_dropped:
                drop = self._link_dropped
                self._link_dropped = None
                self._link_up = False
                raise drop
        return None

    def recv_non_att(self, timeout: float = 0.5):
        """取一条非 ATT L2CAP SDU(SMP CID 6 / LE signaling CID 5 等);超时 None。
        冒充双角色时用来应答 peer 的 L2CAP signaling 请求。"""
        if self._non_att_q:
            return self._non_att_q.pop(0)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self._pump(deadline)
            if self._non_att_q:
                return self._non_att_q.pop(0)
            if self._link_dropped:
                drop = self._link_dropped
                self._link_dropped = None
                self._link_up = False
                raise drop
        return None

    def _pump(self, deadline: float) -> AttPacket | None:
        """排空串口,处理消息;返回首个完整 ATT PDU(如有)。"""
        while time.monotonic() < deadline:
            if not self._select_ready(deadline):
                break
            try:
                msg = self.hw.recv_and_decode()
            except serial.SerialException as e:
                # XDS110 UART 假就绪/脱开:视为链路故障,交给 session 重连恢复
                log.warning("serial error during fuzz loop: %s", e)
                self._mark_link_drop(LinkDrop("serial"))
                break
            except Exception as e:
                log.warning("recv_and_decode failed: %s", e)
                continue
            if msg is None:
                continue
            result = self._process_message(msg)
            if isinstance(result, AttPacket):
                return result
            if self._link_dropped:
                break
        return None

    def _process_message(self, msg) -> AttPacket | None:
        if isinstance(msg, DataMessage):
            self.cur_event = msg.event
            self._pcap_rx(msg)
            return self._feed_rx_data(msg)
        elif isinstance(msg, PacketMessage):
            # 解码失败的包:只记录
            self._log_event("undecodable_packet", body=msg.body.hex()[:64])
            return None
        elif isinstance(msg, StateMessage):
            self._log_event("state", new=msg.new_state.name, old=msg.last_state.name)
            # 连接态判定按角色:central 以 CENTRAL 为连上;peripheral 以 PERIPHERAL 为连上。
            # 其余状态转移(掉链/复位)一律视为 supervision 掉链。
            if self._link_up and msg.new_state not in self._connected_states():
                self._mark_link_drop(LinkDrop("supervision"))
            return None
        elif isinstance(msg, TerminateMeasurement):
            self._terminate_reason = msg.value
            self._log_event("terminate", reason=msg.value)
            if self._link_up:
                self._mark_link_drop(LinkDrop("terminate", msg.value))
            return None
        elif isinstance(msg, DebugMessage):
            if "TX queue full" in msg.msg:
                self.tx_queue_full = True
            self._log_event("fw_debug", msg=msg.msg)
            return None
        elif isinstance(msg, MarkerMessage):
            self._log_event("marker", data=msg.marker_data.hex())
            return None
        return None

    def _mark_link_drop(self, drop: LinkDrop):
        if self._link_dropped is None:
            self._link_up = False
            if self._expected_disconnect:
                self._log_event("expected_disconnect", source=drop.source,
                                reason=drop.reason)
            else:
                self._link_dropped = drop

    def _feed_rx_data(self, dpkt: DataMessage) -> AttPacket | None:
        llid = dpkt.body[0] & 0x3
        payload = dpkt.body[2:2 + dpkt.data_length]
        # 加密段:所有 LL data PDU(含 control)都带 4 字节 MIC,逐包解密。
        # 解密失败(MIC 不通过)记事件并丢弃,不喂给重组/控制处理(防垃圾)。
        if self._enc_enabled and self._enc_cipher is not None and len(payload) >= 4:
            hdr = dpkt.body[0]
            sn = (hdr >> 3) & 1
            ct = payload[:-4]
            mic = payload[-4:]
            pt = self._enc_cipher.decrypt_packet(hdr, ct, mic,
                                                 bt_crypto.DIR_S2M, sn)
            if pt is None:
                self._log_event("enc_mic_fail", llid=llid, sn=sn,
                                len=len(payload))
                return None
            payload = pt
        if llid == 3:
            self._handle_ll_control(payload, dpkt)
            return None
        sdu, cid, truncated = self._rx_l2cap.feed(llid, payload)
        if truncated:
            self._log_event("l2cap_truncated", cid=cid)
        if sdu is None:
            return None
        if cid != ATT_CID:
            self._log_event("non_att_sdu", cid=cid, len=len(sdu))
            self._non_att_q.append((cid, sdu))
            return None
        self._log_event("rx_att", pdu=sdu.hex(), event=dpkt.event)
        return AttPacket(pdu=sdu, event=dpkt.event, ts=dpkt.ts_epoch,
                         rssi=dpkt.rssi, phy=dpkt.phy)

    def _handle_ll_control(self, payload: bytes, dpkt):
        if not payload:
            return
        opcode = payload[0]
        # ---- LL_ENC 握手 PDU:交给 impersonation 角色驱动,不自动代答 ----
        # ENC_REQ(0x03)/ENC_RSP(0x04)/START_ENC_REQ(0x05)/START_ENC_RSP(0x06)
        # 握手期间(未 _enc_enabled)ENC_RSP/START_ENC_REQ 入队列供角色取回;
        # 加密后 START_ENC_RSP 也入队列(已解密后的明文 opcode)。
        if opcode in (LL_ENC_REQ, LL_ENC_RSP, LL_START_ENC_REQ, LL_START_ENC_RSP):
            self._enc_handshake_q.append((opcode, bytes(payload)))
            self._log_event("ll_enc_handshake", opcode=opcode,
                            payload=payload.hex())
            return
        if opcode == LL_FEATURE_REQ:
            # 手机发起特征交换:固件不实现 LL 特征,host 代答 FEATURE_RSP。
            # 声明 DLE 支持(我们确实做 DLE)让 MTK 等严格栈正常走后续 ATT;
            # 不声明加密(无 SMP,设计边界)。加密启用时代答也走密文。
            rsp = bytes([LL_FEATURE_RSP]) + pack("<Q", LL_FEATURES_MASK)
            self._tx_ll_pdu(3, rsp)
            self._log_event("ll_feature_req")
        elif opcode == LL_FEATURE_RSP:
            self._log_event("ll_feature_rsp")
        elif opcode == LL_VERSION_IND:
            # 版本交换:固件不实现,host 代答。LL 控制过程在 central 侧串行,
            # 版本交换挂着 -> DLE/ATT 全不开始(实测 MTK 栈 40s GATT LMP 超时)。
            rsp = bytes([LL_VERSION_IND]) + \
                pack("<BHH", LL_VERSION_NR, LL_COMPANY_ID, LL_SUBVERSION_NR)
            self._tx_ll_pdu(3, rsp)
            self._log_event("ll_version_ind",
                            peer=payload[1:].hex() if len(payload) > 1 else "")
        elif opcode == LL_CONN_PARAM_REQ:
            # central 连接参数请求:回声接受其提议(最小合规应答);
            # 后续 UPDATE_IND 由固件 rconf 机制自行跟随。
            if len(payload) >= 12:
                rsp = bytes([LL_CONN_PARAM_RSP]) + payload[1:12] + b"\x00" * 12
                self._tx_ll_pdu(3, rsp)
            self._log_event("ll_conn_param_req")
        elif opcode == LL_LENGTH_REQ:
            # 对端发起 DLE:回 RSP(我们的收发上限)
            peer_max_rx = unpack("<H", payload[1:3])[0] if len(payload) >= 3 else 27
            rsp = bytes([LL_LENGTH_RSP]) + \
                pack("<HHHH", LL_MAX_PAYLOAD_DLE, LL_MAX_PAYLOAD_DLE,
                     LL_TIME_DLE, LL_TIME_DLE)
            self._tx_ll_pdu(3, rsp)
            self.ll_max = max(27, min(LL_MAX_PAYLOAD_DLE, peer_max_rx))
            self._log_event("dle_req_from_peer", peer_max_rx=peer_max_rx)
        elif opcode == LL_LENGTH_RSP:
            peer_max_rx = unpack("<H", payload[1:3])[0] if len(payload) >= 3 else 27
            self.ll_max = max(27, min(LL_MAX_PAYLOAD_DLE, peer_max_rx))
            self._log_event("dle_rsp", ll_max=self.ll_max)
        elif opcode == LL_UNKNOWN_RSP:
            unknown = payload[1] if len(payload) > 1 else -1
            self._log_event("ll_unknown_rsp", opcode=unknown)
            if unknown == LL_LENGTH_REQ:
                # 对端不支持 DLE,保持 27
                pass
        # TERMINATE 已由 TerminateMeasurement 路径覆盖(补丁 #2),不重复处理

    # ---------- 标记 ----------

    def marker(self, data: bytes):
        self.hw.cmd_marker(data)
