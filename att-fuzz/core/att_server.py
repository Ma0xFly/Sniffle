#!/usr/bin/env python3
# att-fuzz/core/att_server.py
"""
ATT server 应答引擎:伪 GATT 数据库 + 正常模式响应生成器(攻击面⑧核心)。

角色反转:Sniffle 作为 peripheral,收到手机 client 的 ATT 请求后按
"假数据库 + 策略"生成响应字节。设计要点:
- 响应生成器与 GATT 数据库解耦:每个请求类型一个生成器函数,响应内容由
  数据库 + 策略参数(policy)决定;下一任务的恶意策略 = 替换生成器行为,
  数据库与应答循环不动。
- 只做字节层编解码(复用 core/att.py 的 opcode/Error 码常量),不碰串口。
- 正常模式:回合法合规响应(完整服务表/特征表/CCCD),手机能正常完成
  服务发现 -- 这是后续恶意响应策略的基线,也是 logcat oracle 归因的对照。

数据库:16 位 UUID 全量,句柄从 1 连续分配;含一个可写私有特征(0xFFF0/0xFF01)
和一个带 CCCD 的通知特征(0x180F/0x2A19),覆盖 read/write/cccd 三类权限面。
"""

from dataclasses import dataclass, field
from struct import pack, unpack

from .att import AttErrorCode

PROP_READ = 0x02
PROP_WRITE_NO_RSP = 0x04
PROP_WRITE = 0x08
PROP_NOTIFY = 0x10
PROP_INDICATE = 0x20

UUID_PRIMARY_SERVICE = 0x2800
UUID_SECONDARY_SERVICE = 0x2801
UUID_CHAR_DECL = 0x2803
UUID_CCCD = 0x2902

MAX_PREPARE_QUEUE = 40       # 正常模式 Prepare 队列上限(超限回 0x09)


def _uuid_bytes(uuid) -> bytes:
    """16 位 UUID 数值 -> 声明/值里的 UUID 字节(小端)。"""
    return pack("<H", uuid)


def _uuid_128(uuid) -> bytes:
    """16 位 -> 128 位标准展开(0000XXXX-0000-1000-8000-00805F9B34FB)。"""
    return pack("<H", uuid) + bytes.fromhex("00001000800000805f9b34fb")


def _opcode_name(op: int) -> str:
    from .att import AttOpcode
    try:
        return AttOpcode(op).name
    except ValueError:
        return "UNKNOWN_0x%02X" % op


# ---------- 数据库 ----------

@dataclass
class CharSpec:
    uuid: int
    props: int
    value: bytes
    cccd: bool = False


@dataclass
class ServiceSpec:
    uuid: int
    chars: list = field(default_factory=list)


@dataclass
class Attr:
    handle: int
    kind: str                # service | char_decl | char_value | cccd
    uuid: int                # 16 位(声明类型/特征 UUID)
    value: bytes = b""       # 语义值:service=服务 UUID 字节,char_decl=声明字节,
                             # char_value/cccd=存储值(可写变更)
    props: int = 0           # 仅 char_value/char_decl:特征属性位
    char_uuid: int = 0       # 仅 char_decl:指向的特征 UUID


@dataclass
class CharInfo:
    decl_handle: int
    value_handle: int
    props: int
    uuid: int
    cccd_handle: int | None = None


class FakeGattDb:
    """伪 GATT 数据库:handle -> Attr + 服务/特征索引。"""

    def __init__(self):
        self.attrs: dict[int, Attr] = {}
        self.services: list = []            # [(start_handle, end_handle, uuid16)]
        self.char_value: dict[int, CharInfo] = {}   # value_handle -> CharInfo

    def attrs_in_range(self, start: int, end: int) -> list:
        return [self.attrs[h] for h in sorted(self.attrs) if start <= h <= end]


def build_db(device_name: str = "Sniffle Server",
             server_mtu: int = 247) -> FakeGattDb:
    """构造默认假 GATT 数据库:
    - 0x1800 Generic Access:0x2A00 Device Name / 0x2A01 Appearance(可读)
    - 0x180F Battery:0x2A19 Battery Level(可读+通知,带 0x2902 CCCD)
    - 0x180A Device Info:0x2A29 / 0x2A24(可读)
    - 0xFFF0 私有:0xFF01(可写) -- 手机服务发现/写操作的真靶子
    句柄从 1 连续分配。"""
    services = [
        ServiceSpec(0x1800, [
            CharSpec(0x2A00, PROP_READ, device_name.encode("utf-8")[:20]),
            CharSpec(0x2A01, PROP_READ, b"\x00\x00"),
        ]),
        ServiceSpec(0x180F, [
            CharSpec(0x2A19, PROP_READ | PROP_NOTIFY, b"\x64", cccd=True),
        ]),
        ServiceSpec(0x180A, [
            CharSpec(0x2A29, PROP_READ, b"Sniffle"),
            CharSpec(0x2A24, PROP_READ, b"Fuzz-1"),
        ]),
        ServiceSpec(0xFFF0, [
            CharSpec(0xFF01, PROP_WRITE | PROP_WRITE_NO_RSP, b"\x00"),
        ]),
    ]
    db = FakeGattDb()
    handle = 1
    for svc in services:
        start = handle
        # 服务声明:属性类型 = 0x2800(主服务),属性值 = 服务 UUID
        db.attrs[handle] = Attr(handle, "service", UUID_PRIMARY_SERVICE,
                                _uuid_bytes(svc.uuid))
        handle += 1
        for ch in svc.chars:
            decl = handle
            value_h = handle + 1
            handle += 2
            decl_bytes = (bytes([ch.props]) + pack("<H", value_h) +
                          _uuid_bytes(ch.uuid))
            db.attrs[decl] = Attr(decl, "char_decl", UUID_CHAR_DECL, decl_bytes,
                                  props=ch.props, char_uuid=ch.uuid)
            db.attrs[value_h] = Attr(value_h, "char_value", ch.uuid, ch.value,
                                     props=ch.props)
            info = CharInfo(decl, value_h, ch.props, ch.uuid, None)
            db.char_value[value_h] = info
            if ch.cccd:
                cccd_h = handle
                handle += 1
                db.attrs[cccd_h] = Attr(cccd_h, "cccd", UUID_CCCD, b"\x00\x00")
                info.cccd_handle = cccd_h
        db.services.append((start, handle - 1, svc.uuid))
    return db


# ---------- 应答引擎 ----------

class ServerResponder:
    """ATT 请求 -> 响应字节。正常模式:全请求类型回合法合规响应。
    policy(dict)预留恶意策略参数;下一任务替换生成器行为即可。"""

    def __init__(self, db: FakeGattDb, server_mtu: int = 247, policy: dict | None = None):
        self.db = db
        self.server_mtu = max(23, server_mtu)
        self.att_mtu = 23              # 当前协商 MTU(随 Exchange MTU 更新)
        self.policy = policy or {}
        self.prepare_queue: list = []  # [(handle, offset, value), ...]

    # ---------- 工具 ----------

    def _err(self, req_op: int, handle: int, code: int) -> bytes:
        return bytes([0x01, req_op & 0xFF]) + pack("<H", handle & 0xFFFF) + bytes([code & 0xFF])

    def _attr_value(self, handle: int):
        """语义值 + 可读性检查。返回 (value|None, err_code|None)。"""
        a = self.db.attrs.get(handle)
        if a is None:
            return None, int(AttErrorCode.INVALID_HANDLE)
        if a.kind == "char_value" and not (a.props & PROP_READ):
            return None, int(AttErrorCode.READ_NOT_PERMITTED)
        return a.value, None

    def _check_writable(self, handle: int):
        a = self.db.attrs.get(handle)
        if a is None:
            return int(AttErrorCode.INVALID_HANDLE)
        if a.kind == "cccd":
            return None
        if a.kind == "char_value" and (a.props & (PROP_WRITE | PROP_WRITE_NO_RSP)):
            return None
        return int(AttErrorCode.WRITE_NOT_PERMITTED)

    # ---------- 请求分派 ----------

    def handle_request(self, pdu: bytes) -> bytes | None:
        """处理一条客户端 ATT 请求,返回响应 PDU bytes;无响应(Write Cmd/
        通知等)返回 None。"""
        if not pdu:
            return None
        op = pdu[0]
        fn = self._handlers.get(op)
        if fn is None:
            # 未支持/未知 opcode:回 Request Not Supported(正常模式;恶意策略改这里)
            return self._err(op, 0, int(AttErrorCode.UNSUPPORTED_REQUEST_TYPE))
        return fn(self, pdu[1:])

    # ---------- 各请求生成器(正常模式) ----------

    def _on_exchange_mtu(self, params):
        if len(params) < 2:
            return self._err(0x02, 0, int(AttErrorCode.INVALID_PDU))
        client_mtu = unpack("<H", params[:2])[0]
        self.att_mtu = max(23, min(self.server_mtu, client_mtu))
        return bytes([0x03]) + pack("<H", self.server_mtu)

    def _on_find_info(self, params):
        if len(params) < 4:
            return self._err(0x04, 0, int(AttErrorCode.INVALID_PDU))
        start, end = unpack("<HH", params[:4])
        attrs = self.db.attrs_in_range(start, end)
        if not attrs:
            return self._err(0x04, 0, int(AttErrorCode.ATTRIBUTE_NOT_FOUND))
        fmt = 1
        item_len = 4
        items = b"".join(pack("<HH", a.handle, a.uuid) for a in attrs)
        space = self.att_mtu - 2
        n = min(len(attrs), max(1, space // item_len))
        return bytes([0x05, fmt]) + items[:n * item_len]

    def _on_find_by_type_value(self, params):
        if len(params) < 7:
            return self._err(0x06, 0, int(AttErrorCode.INVALID_PDU))
        start, end, uuid = unpack("<HHH", params[:6])
        want = params[6:]
        found = [(s, e) for s, e, u in self.db.services
                 if start <= s <= end and u == uuid and _uuid_bytes(u) == want]
        if not found:
            return self._err(0x06, 0, int(AttErrorCode.ATTRIBUTE_NOT_FOUND))
        n = min(len(found), max(1, (self.att_mtu - 1) // 4))
        return bytes([0x07]) + b"".join(pack("<HH", s, e) for s, e in found[:n])

    def _on_read_by_type(self, params):
        if len(params) < 6:
            return self._err(0x08, 0, int(AttErrorCode.INVALID_PDU))
        start, end = unpack("<HH", params[:4])
        rest = params[4:]
        if len(rest) == 2:
            uuid = unpack("<H", rest)[0]
        elif len(rest) == 16:
            uuid = rest
        else:
            return self._err(0x08, 0, int(AttErrorCode.INVALID_PDU))
        matches = [a for a in self.db.attrs_in_range(start, end) if a.uuid == uuid]
        if not matches:
            return self._err(0x08, 0, int(AttErrorCode.ATTRIBUTE_NOT_FOUND))
        # 首个不可读 char_value -> Read Not Permitted(照 spec)
        for a in matches:
            if a.kind == "char_value" and not (a.props & PROP_READ):
                return self._err(0x08, a.handle, int(AttErrorCode.READ_NOT_PERMITTED))
        # 统一条目长度:取首个 value 长度,后续不同长度者不含(客户端会续查)
        length = len(matches[0].value)
        items = [a for a in matches if len(a.value) == length]
        n = min(len(items), max(1, (self.att_mtu - 2) // (2 + length)))
        if n == 0:
            return self._err(0x08, 0, int(AttErrorCode.ATTRIBUTE_NOT_FOUND))
        return bytes([0x09, 2 + length]) + b"".join(
                pack("<H", a.handle) + a.value for a in items[:n])

    def _on_read(self, params):
        if len(params) < 2:
            return self._err(0x0A, 0, int(AttErrorCode.INVALID_PDU))
        handle = unpack("<H", params[:2])[0]
        value, err = self._attr_value(handle)
        if err is not None:
            return self._err(0x0A, handle, err)
        return bytes([0x0B]) + value[:self.att_mtu - 1]

    def _on_read_blob(self, params):
        if len(params) < 4:
            return self._err(0x0C, 0, int(AttErrorCode.INVALID_PDU))
        handle, offset = unpack("<HH", params[:4])
        value, err = self._attr_value(handle)
        if err is not None:
            return self._err(0x0C, handle, err)
        if offset > len(value):
            return self._err(0x0C, handle, int(AttErrorCode.INVALID_OFFSET))
        return bytes([0x0D]) + value[offset:offset + self.att_mtu - 1]

    def _on_read_multiple(self, params):
        if len(params) < 2 or len(params) % 2:
            return self._err(0x0E, 0, int(AttErrorCode.INVALID_PDU))
        out = b""
        for i in range(0, len(params), 2):
            handle = unpack("<H", params[i:i + 2])[0]
            value, err = self._attr_value(handle)
            if err is not None:
                return self._err(0x0E, handle, err)
            out += value
            if len(out) >= self.att_mtu - 1:
                break
        return bytes([0x0F]) + out[:self.att_mtu - 1]

    def _on_read_by_group_type(self, params):
        if len(params) < 6:
            return self._err(0x10, 0, int(AttErrorCode.INVALID_PDU))
        start, end = unpack("<HH", params[:4])
        rest = params[4:]
        uuid = unpack("<H", rest[:2])[0] if len(rest) == 2 else rest
        if uuid not in (UUID_PRIMARY_SERVICE, UUID_SECONDARY_SERVICE):
            return self._err(0x10, 0, int(AttErrorCode.UNSUPPORTED_GROUP_TYPE))
        matches = [svc for svc in self.db.services if start <= svc[0] <= end]
        if not matches:
            return self._err(0x10, 0, int(AttErrorCode.ATTRIBUTE_NOT_FOUND))
        n = min(len(matches), max(1, (self.att_mtu - 2) // 6))
        return bytes([0x11, 6]) + b"".join(pack("<HHH", s, e, u)
                                           for s, e, u in matches[:n])

    def _on_write(self, params):
        if len(params) < 3:
            return self._err(0x12, 0, int(AttErrorCode.INVALID_PDU))
        handle = unpack("<H", params[:2])[0]
        err = self._check_writable(handle)
        if err is not None:
            return self._err(0x12, handle, err)
        self.db.attrs[handle].value = params[2:]
        return bytes([0x13])

    def _on_write_cmd(self, params):
        # Write Cmd 无响应(照 spec,即使错误也不回);校验通过则更新值
        if len(params) >= 3:
            handle = unpack("<H", params[:2])[0]
            if self._check_writable(handle) is None:
                self.db.attrs[handle].value = params[2:]
        return None

    def _on_prepare_write(self, params):
        if len(params) < 5:
            return self._err(0x16, 0, int(AttErrorCode.INVALID_PDU))
        handle, offset = unpack("<HH", params[:4])
        value = params[4:]
        err = self._check_writable(handle)
        if err is not None:
            return self._err(0x16, handle, err)
        if len(self.prepare_queue) >= MAX_PREPARE_QUEUE:
            return self._err(0x16, handle, int(AttErrorCode.PREPARE_QUEUE_FULL))
        self.prepare_queue.append((handle, offset, value))
        return bytes([0x17]) + pack("<HH", handle, offset) + value

    def _on_execute_write(self, params):
        if len(params) < 1:
            return self._err(0x18, 0, int(AttErrorCode.INVALID_PDU))
        flags = params[0]
        if flags == 0x00:                  # cancel:丢弃队列
            self.prepare_queue = []
            return bytes([0x19])
        if flags == 0x01:                  # write now:按序提交
            for handle, _offset, value in self.prepare_queue:
                err = self._check_writable(handle)
                if err is not None:
                    self.prepare_queue = []
                    return self._err(0x18, 0, err)
                self.db.attrs[handle].value = value
            self.prepare_queue = []
            return bytes([0x19])
        return self._err(0x18, 0, int(AttErrorCode.INVALID_PDU))

    def _ignore(self, params):
        return None

    _handlers = {
        0x02: _on_exchange_mtu,
        0x04: _on_find_info,
        0x06: _on_find_by_type_value,
        0x08: _on_read_by_type,
        0x0A: _on_read,
        0x0C: _on_read_blob,
        0x0E: _on_read_multiple,
        0x10: _on_read_by_group_type,
        0x12: _on_write,
        0x16: _on_prepare_write,
        0x18: _on_execute_write,
        0x52: _on_write_cmd,
        0x1B: _ignore,      # Handle Value Notification(客户端不应发,忽略)
        0x1D: _ignore,      # Handle Value Indication(同上)
    }
