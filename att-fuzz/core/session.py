#!/usr/bin/env python3
# att-fuzz/core/session.py
"""
连接生命周期与用例执行。
- 健康检查(known-good read + 基线对比),前后双查,黑盒归因核心
- run_case: 前 HC -> 注入 -> 等响应 -> 分类 -> 双录 -> 后 HC
- 掉链自动恢复: 重连 -> (GATT 变了才) 重发现 -> 续跑
"""

import hashlib
import logging
import time

from .att import (AttOpcode, parse_error_rsp, read_req)
from .gatt_map import GattMap, discover
from .monitor import (ALERT_CLASSIFICATIONS, CaseResult, Classification,
                      compute_signature)
from .transport import LinkDrop, TransportError

log = logging.getLogger("att-fuzz.session")


class FuzzSession:
    def __init__(self, transport, target, gatt_map_path=None, ledger=None,
                 rediscover_on_mismatch=True, negotiate_mtu=True):
        self.t = transport
        self.target = target
        self.gatt_map_path = gatt_map_path
        self.ledger = ledger
        self.rediscover_on_mismatch = rediscover_on_mismatch
        # False = 连接后不自动 DLE+MTU 协商(⑤层"未协商 MTU 就发读写"用例);
        # 发现/恢复发现照常进行(ATT 默认 MTU 23 足够),仅跳过 setup_data_size。
        self.negotiate = bool(negotiate_mtu)
        self.gatt: GattMap | None = None
        self.reconnects = 0

    # ---------- 启动 ----------

    def start(self, force_discovery=False):
        self._connect()
        if self.negotiate:
            self.t.setup_data_size()
        if not force_discovery and self.gatt_map_path:
            cached = GattMap.load(self.gatt_map_path) if self.gatt_map_path.exists() else None
        else:
            cached = None
        if cached is not None:
            self.gatt = cached
            # 轻校验:服务列表变了就重发现
            fresh = discover(self.t, baseline=False)
            if [(s.start_handle, s.end_handle, s.uuid) for s in fresh.services] != \
               [(s.start_handle, s.end_handle, s.uuid) for s in cached.services]:
                log.info("GATT changed, rediscovering")
                self.gatt = self._discover_and_save()
        else:
            self.gatt = self._discover_and_save()
        return self.gatt

    def _discover_and_save(self) -> GattMap:
        m = discover(self.t)
        if self.gatt_map_path:
            m.save(self.gatt_map_path)
        log.info("GATT: %d services, %d characteristics, %d baseline entries, %d gaps",
                 len(m.services), len(m.characteristics), len(m.baseline), len(m.gaps))
        return m

    def _connect(self):
        self.t.connect(self.target)
        self.reconnects += 1

    def ensure_negotiation(self, want: bool):
        """保证下一条用例在 want 的协商状态下执行。
        状态不符且链路活着:期望性断链并泵掉 terminate 事件
        (否则 _link_up 迟迟不翻 False,后续健康检查会误判超时);
        链路已断:只翻 flag,由下次用例的前置健康检查按新状态恢复。"""
        want = bool(want)
        if self.negotiate == want:
            return
        self.negotiate = want
        if not self.t.link_up:
            return
        log.info("reconnecting %s for next cases",
                 "negotiated" if want else "un-negotiated (MTU=23)")
        self.t.disconnect()
        deadline = time.time() + 3
        while self.t.link_up and time.time() < deadline:
            try:
                self.t.recv_att(timeout=0.3)
            except LinkDrop:
                break

    # ---------- 健康检查 ----------

    def health_check(self, timeout=None) -> str:
        """读 known-good handle 并与基线对比。
        返回 'ok' | 'value_changed' | 'error' | 'timeout' | 'disconnected'。"""
        if not self.t.link_up:
            return "disconnected"
        handle = self.gatt.known_good_handle() if self.gatt else None
        if handle is None:
            return "no_known_good"    # 无锚点,视为未知
        key = "0x%04X" % handle
        base = self.gatt.baseline.get(key, {})
        try:
            self.t.inject(read_req(handle))
            rsp = self.t.recv_att(timeout)
        except LinkDrop:
            return "disconnected"
        except TransportError as e:
            log.warning("health check transport error: %s", e)
            return "error"
        if rsp is None:
            return "timeout"
        if rsp.pdu[0] == int(AttOpcode.ERROR_RSP):
            err = parse_error_rsp(rsp.pdu[1:])
            return "ok" if base.get("kind") == "error" and \
                    base.get("code") == err.error_code else "error"
        if rsp.pdu[0] == int(AttOpcode.READ_RSP):
            if base.get("kind") == "value":
                base_val = base.get("value", "")
                got = rsp.pdu[1:].hex()
                if not self.negotiate:
                    # 未协商链路 MTU=23,长基线值会被截断:前缀一致即算健康
                    return "ok" if base_val[:len(got)] == got else "value_changed"
                return "ok" if base_val == got else "value_changed"
            return "ok"     # 无基线值(如只读权限特性),有响应就算活
        return "error"

    # ---------- 用例执行 ----------

    def run_case(self, case_id, layer, pdu_builder, replay_ctx=None,
                 expect_response=True, timeout=None):
        """执行单个用例。pdu_builder: () -> bytes(注入前才构造,锚点已解析)。
        返回 CaseResult。"""
        pre = self.health_check()
        if pre == "disconnected":
            # 上个用例的迟滞掉链还没恢复:先恢复再打
            pre = self._recover()
            if pre in ("disconnected", "unrecoverable"):
                result = CaseResult(case_id=case_id, layer=layer, health_pre=pre,
                                    classification=Classification.TX_QUEUE_FULL)
                result.notes.append("pre-recover failed")
                if self.ledger:
                    self.ledger.record(result, replayable=replay_ctx)
                return result
        self.t.marker(case_id.encode())

        result = CaseResult(case_id=case_id, layer=layer, health_pre=pre)

        try:
            pdu = pdu_builder()
        except Exception as e:
            result.classification = Classification.TX_QUEUE_FULL  # 构造失败视作无效用例
            result.notes.append("build failed: %r" % e)
            return result

        # 台账字段(value_hash 等)
        self._fill_case_fields(result, pdu)

        dropped = None
        transport_err = None
        try:
            self.t.inject(pdu)
            result.event = self.t.cur_event
            if expect_response:
                rsp = self.t.recv_att(timeout)
            else:
                rsp = None      # Write Cmd 之类:无响应,由后置 HC 判定
        except LinkDrop as drop:
            dropped = drop
            rsp = None
        except TransportError as e:
            transport_err = e
            rsp = None

        # 分类
        if dropped is not None:
            result.classification = (Classification.DISCONNECT_TERM
                    if dropped.source == "terminate" else Classification.DISCONNECT_SUP)
            result.terminate_reason = dropped.reason
            result.notes.append("drop_source=%s" % dropped.source)
        elif transport_err is not None:
            # 传输层错误(门控顺序/未连接等):用例无效,恢复后重跑
            result.classification = Classification.TX_QUEUE_FULL
            result.notes.append("transport_error=%r" % transport_err)
            result.health_post = self._recover()
        elif self.t.tx_queue_full:
            result.classification = Classification.TX_QUEUE_FULL
            self.t.tx_queue_full = False
        elif rsp is not None:
            result.response_pdu = rsp.pdu.hex()
            if rsp.pdu[0] == int(AttOpcode.ERROR_RSP):
                result.classification = Classification.ERROR_RESPONSE
                err = parse_error_rsp(rsp.pdu[1:])
                result.error_code = err.error_code
                result.notes.append("err_handle=0x%04X" % err.handle)
            else:
                result.classification = Classification.OK_RESPONSE
        elif not expect_response:
            result.classification = Classification.OK_RESPONSE
            result.notes.append("no response expected")
        else:
            result.classification = Classification.TIMEOUT

        # 后置 HC(掉链则先恢复)
        if result.classification in (Classification.DISCONNECT_TERM,
                                     Classification.DISCONNECT_SUP):
            result.health_post = self._recover()
        else:
            result.health_post = self.health_check()
            if result.health_post not in ("ok", "no_known_good"):
                # "完成了"但目标已异常 -> 迟滞显现
                result.classification = Classification.HEALTH_DEGRADED
                result.notes.append("post_hc=%s" % result.health_post)
                result.health_post = self._recover()

        if self.ledger:
            result.signature = result.signature or compute_signature(result)
            self.ledger.record(result, replayable=replay_ctx)
        if result.classification in ALERT_CLASSIFICATIONS:
            log.warning("ALERT %s", result.summary())
        return result

    # ---------- 序列用例 ----------

    # 用例级聚合优先级(最差者定分类):掉链 > 传输错误 > 健康异常 > 超时 > 错误响应 > 正常
    _SEQ_PRIORITY = (Classification.DISCONNECT_SUP, Classification.DISCONNECT_TERM,
                     Classification.TX_QUEUE_FULL, Classification.HEALTH_DEGRADED,
                     Classification.TIMEOUT, Classification.ERROR_RESPONSE,
                     Classification.OK_RESPONSE)

    def run_sequence(self, case_id, layer, steps, replay_ctx=None, timeout=None):
        """执行序列用例。steps: [CaseStep](pdu 已按锚点构造)。
        逐步注入/等响应/记录;任一步掉链/传输错误 → 该步定用例分类并恢复;
        全部步执行完 → 后置健康检查。用例级字段(opcode/handle/响应等)
        取决定分类的那一步(alert_step),即最小复现步。"""
        pre = self.health_check()
        if pre == "disconnected":
            pre = self._recover()
            if pre in ("disconnected", "unrecoverable"):
                result = CaseResult(case_id=case_id, layer=layer, health_pre=pre,
                                    classification=Classification.TX_QUEUE_FULL)
                result.notes.append("pre-recover failed")
                if self.ledger:
                    self.ledger.record(result, replayable=replay_ctx)
                return result
        self.t.marker(case_id.encode())

        result = CaseResult(case_id=case_id, layer=layer, health_pre=pre)
        step_rows = []
        alert_step = None
        dropped = None

        for idx, step in enumerate(steps):
            row = {"step": idx, "op": step.op,
                   "expect_response": step.expect_response}
            row.update(self._case_fields(step.pdu))
            notes = []
            cls = None
            rsp = None
            transport_err = None
            try:
                self.t.inject(step.pdu)
                row["event"] = self.t.cur_event
                if step.expect_response:
                    rsp = self.t.recv_att(timeout)
                else:
                    notes.append("no response expected")
            except LinkDrop as drop:
                dropped = drop
            except TransportError as e:
                transport_err = e

            if dropped is not None:
                cls = (Classification.DISCONNECT_TERM
                       if dropped.source == "terminate" else Classification.DISCONNECT_SUP)
                row["terminate_reason"] = dropped.reason
                notes.append("drop_source=%s" % dropped.source)
            elif transport_err is not None:
                cls = Classification.TX_QUEUE_FULL
                notes.append("transport_error=%r" % transport_err)
            elif self.t.tx_queue_full:
                cls = Classification.TX_QUEUE_FULL
                self.t.tx_queue_full = False
            elif rsp is not None:
                row["response_pdu"] = rsp.pdu.hex()
                if rsp.pdu[0] == int(AttOpcode.ERROR_RSP):
                    cls = Classification.ERROR_RESPONSE
                    err = parse_error_rsp(rsp.pdu[1:])
                    row["error_code"] = err.error_code
                    notes.append("err_handle=0x%04X" % err.handle)
                else:
                    cls = Classification.OK_RESPONSE
            elif step.expect_response:
                cls = Classification.TIMEOUT
            else:
                cls = Classification.OK_RESPONSE

            row["classification"] = cls.name
            if notes:
                row["notes"] = notes
            step_rows.append(row)

            if dropped is not None:
                break
            if cls == Classification.TX_QUEUE_FULL:
                break
            if step.observe:
                time.sleep(step.observe)

        # 用例级分类 = 全步最差;alert_step = 首个达到该分类的步
        classes = [Classification[r["classification"]] for r in step_rows]
        final = min(classes, key=self._SEQ_PRIORITY.index) if classes else \
            Classification.TX_QUEUE_FULL
        for i, c in enumerate(classes):
            if c == final:
                alert_step = i
                break
        alert = step_rows[alert_step]

        result.classification = final
        result.opcode = alert.get("opcode")
        result.handle = alert.get("handle")
        result.offset = alert.get("offset")
        result.value_len = alert.get("value_len")
        result.value_hash = alert.get("value_hash")
        result.event = alert.get("event")
        result.error_code = alert.get("error_code")
        result.terminate_reason = alert.get("terminate_reason")
        result.response_pdu = alert.get("response_pdu")
        result.notes.append("sequence=%d steps" % len(steps))
        result.notes.append("alert_step=%d" % alert_step)

        if final in (Classification.DISCONNECT_TERM, Classification.DISCONNECT_SUP):
            result.health_post = self._recover()
        else:
            result.health_post = self.health_check()
            if result.health_post not in ("ok", "no_known_good"):
                result.classification = Classification.HEALTH_DEGRADED
                result.notes.append("post_hc=%s" % result.health_post)
                result.health_post = self._recover()

        if self.ledger:
            result.signature = result.signature or compute_signature(result)
            self.ledger.record(result, replayable=replay_ctx,
                               extra={"case_kind": "sequence",
                                      "alert_step": alert_step,
                                      "steps": step_rows})
        if result.classification in ALERT_CLASSIFICATIONS:
            log.warning("ALERT %s", result.summary())
        return result

    def _case_fields(self, pdu: bytes) -> dict:
        """单条 PDU 的台账字段(opcode/handle/offset/value_len/value_hash)。"""
        out = {"opcode": pdu[0] if pdu else None}
        if len(pdu) >= 3 and pdu[0] in (0x0A, 0x0C, 0x12, 0x16, 0x52):
            out["handle"] = pdu[1] | (pdu[2] << 8)
        if pdu[0] in (0x0C, 0x16) and len(pdu) >= 5:
            out["offset"] = pdu[3] | (pdu[4] << 8)
        if pdu[0] in (0x12, 0x52, 0x16) and out.get("handle") is not None:
            hdr = 5 if pdu[0] == 0x16 else 3
            out["value_len"] = max(0, len(pdu) - hdr)
            out["value_hash"] = hashlib.sha1(pdu[hdr:]).hexdigest()[:12]
        return out

    def _fill_case_fields(self, result: CaseResult, pdu: bytes):
        for k, v in self._case_fields(pdu).items():
            setattr(result, k, v)

    # ---------- 恢复 ----------

    def _recover(self) -> str:
        """掉链后重连(带重试),必要时重发现。返回恢复后健康状态。"""
        for attempt in range(1, 6):
            try:
                time.sleep(min(2 ** attempt, 10) * 0.5)
                self._connect()
                if self.negotiate:
                    self.t.setup_data_size()
                fresh = discover(self.t, baseline=False)
                if fresh.gaps:
                    # 发现不完整(目标恢复期常见):残缺地图会误报 "GATT changed",
                    # 把完好缓存换成残缺版,污染后续健康归因 -- 保留缓存,下轮再核
                    log.info("recovery discovery incomplete (%d gaps), keep cached map",
                             len(fresh.gaps))
                elif self.gatt is not None and \
                        [(s.start_handle, s.end_handle, s.uuid) for s in fresh.services] != \
                        [(s.start_handle, s.end_handle, s.uuid) for s in self.gatt.services]:
                    if self.rediscover_on_mismatch:
                        log.info("GATT changed after crash, rediscovering")
                        self.gatt = self._discover_and_save()
                elif self.gatt is None:
                    self.gatt = self._discover_and_save()
                return self.health_check()
            except (TransportError, LinkDrop) as e:
                log.warning("reconnect attempt %d failed: %s", attempt, e)
        return "unrecoverable"
