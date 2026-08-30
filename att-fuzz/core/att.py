#!/usr/bin/env python3
# att-fuzz/core/att.py
"""
ATT PDU 编解码器。
- 全 opcode 常量表（合法 + 保留）
- 请求构造器（发现/读/写/长写/MTU）
- 响应与 Error Response 解析
只做字节层编解码,不碰串口;连接/MTU 状态由 transport + session 管。
"""

from dataclasses import dataclass
from enum import IntEnum
from struct import pack, unpack


class AttOpcode(IntEnum):
    ERROR_RSP = 0x01
    EXCHANGE_MTU_REQ = 0x02
    EXCHANGE_MTU_RSP = 0x03
    FIND_INFO_REQ = 0x04
    FIND_INFO_RSP = 0x05
    FIND_BY_TYPE_VALUE_REQ = 0x06
    FIND_BY_TYPE_VALUE_RSP = 0x07
    READ_BY_TYPE_REQ = 0x08
    READ_BY_TYPE_RSP = 0x09
    READ_REQ = 0x0A
    READ_RSP = 0x0B
    READ_BLOB_REQ = 0x0C
    READ_BLOB_RSP = 0x0D
    READ_MULTIPLE_REQ = 0x0E
    READ_MULTIPLE_RSP = 0x0F
    READ_BY_GROUP_TYPE_REQ = 0x10
    READ_BY_GROUP_TYPE_RSP = 0x11
    WRITE_REQ = 0x12
    WRITE_RSP = 0x13
    WRITE_CMD = 0x52
    PREPARE_WRITE_REQ = 0x16
    PREPARE_WRITE_RSP = 0x17
    EXECUTE_WRITE_REQ = 0x18
    EXECUTE_WRITE_RSP = 0x19
    HANDLE_VALUE_NTF = 0x1B
    HANDLE_VALUE_IND = 0x1D
    HANDLE_VALUE_CNF = 0x1E
    SIGNED_WRITE_CMD = 0xD2


# 需要(并等待)响应的 opcode;Write Cmd 等不需要
REQUEST_OPCODES = frozenset(op for op in AttOpcode if op not in
    (AttOpcode.WRITE_CMD, AttOpcode.SIGNED_WRITE_CMD,
     AttOpcode.HANDLE_VALUE_NTF, AttOpcode.HANDLE_VALUE_IND))

# 常见保留/非法 opcode 边界集(①层语料锚点)
OPCODE_BOUNDARY_SET = (
    0x00, 0x1F, 0x20, 0x40, 0x53, 0x92, 0xD3, 0xE0, 0xF0, 0xFE, 0xFF)


class AttErrorCode(IntEnum):
    INVALID_HANDLE = 0x01
    READ_NOT_PERMITTED = 0x02
    WRITE_NOT_PERMITTED = 0x03
    INVALID_PDU = 0x04
    INSUFFICIENT_AUTHENTICATION = 0x05
    UNSUPPORTED_REQUEST_TYPE = 0x06
    INVALID_OFFSET = 0x07
    INSUFFICIENT_AUTHORIZATION = 0x08
    PREPARE_QUEUE_FULL = 0x09
    ATTRIBUTE_NOT_FOUND = 0x0A
    ATTRIBUTE_NOT_LONG = 0x0B
    INSUFFICIENT_ENCRYPTION_KEY_SIZE = 0x0C
    INVALID_ATTRIBUTE_VALUE_LENGTH = 0x0D
    UNLIKELY_ERROR = 0x0E
    INSUFFICIENT_ENCRYPTION = 0x0F
    UNSUPPORTED_GROUP_TYPE = 0x10
    INSUFFICIENT_RESOURCES = 0x11
    DB_OUT_OF_SYNC = 0x12
    VALUE_NOT_ALLOWED = 0x13


ERROR_CODE_NAMES = {int(c): c.name for c in AttErrorCode}


@dataclass
class AttPdu:
    opcode: int          # int 而非枚举:未知 opcode 也是合法解码结果(fuzz 需要)
    params: bytes

    def encode(self) -> bytes:
        return bytes([self.opcode & 0xFF]) + self.params

    @classmethod
    def decode(cls, pdu: bytes) -> "AttPdu":
        if not pdu:
            raise ValueError("empty ATT PDU")
        return cls(pdu[0], pdu[1:])

    def __repr__(self):
        try:
            name = AttOpcode(self.opcode).name
        except ValueError:
            name = "UNKNOWN"
        return "AttPdu(0x%02X %s, %d bytes)" % (self.opcode, name, len(self.params))


@dataclass
class AttError:
    request_opcode: int
    handle: int
    error_code: int

    def __repr__(self):
        name = ERROR_CODE_NAMES.get(self.error_code, "?")
        return "AttError(req=0x%02X handle=0x%04X code=0x%02X %s)" % (
            self.request_opcode, self.handle, self.error_code, name)


def parse_error_rsp(params: bytes) -> AttError:
    if len(params) < 4:
        raise ValueError("Error Response too short: %d" % len(params))
    req, handle, code = unpack("<BHB", params[:4])
    return AttError(req, handle, code)


def parse_exchange_mtu_rsp(params: bytes) -> int:
    return unpack("<H", params[:2])[0]


# ---- 请求构造器(全部返回原始 PDU bytes,由 transport.inject 发送) ----

def exchange_mtu_req(mtu: int) -> bytes:
    return bytes([0x02]) + pack("<H", mtu)


def find_info_req(start: int, end: int) -> bytes:
    return bytes([0x04]) + pack("<HH", start, end)


def read_by_type_req(start: int, end: int, uuid: int) -> bytes:
    """uuid 为 16 位(特征声明发现用 0x2803)"""
    return bytes([0x08]) + pack("<HHH", start, end, uuid)


def read_by_type_req_128(start: int, end: int, uuid128: bytes) -> bytes:
    return bytes([0x08]) + pack("<HH", start, end) + uuid128


def read_req(handle: int) -> bytes:
    return bytes([0x0A]) + pack("<H", handle)


def read_blob_req(handle: int, offset: int) -> bytes:
    return bytes([0x0C]) + pack("<HH", handle, offset)


def read_multiple_req(handles) -> bytes:
    return bytes([0x0E]) + b"".join(pack("<H", h) for h in handles)


def read_by_group_type_req(start: int, end: int, uuid: int) -> bytes:
    """服务发现用 0x2800(主)/0x2801(次)"""
    return bytes([0x10]) + pack("<HHH", start, end, uuid)


def write_req(handle: int, value: bytes) -> bytes:
    return bytes([0x12]) + pack("<H", handle) + value


def write_cmd(handle: int, value: bytes) -> bytes:
    return bytes([0x52]) + pack("<H", handle) + value


def prepare_write_req(handle: int, offset: int, value: bytes) -> bytes:
    return bytes([0x16]) + pack("<HH", handle, offset) + value


def execute_write_req(flags: int) -> bytes:
    return bytes([0x18, flags & 0xFF])


def raw_opcode_pdu(opcode: int, payload: bytes = b"") -> bytes:
    """①层语料:任意 opcode + 任意参数"""
    return bytes([opcode & 0xFF]) + payload
