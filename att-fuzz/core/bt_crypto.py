#!/usr/bin/env python3
# att-fuzz/core/bt_crypto.py
"""
BLE 蓝牙密码学原语(攻击面密钥收割用,阶段四 4.1)。

字节序约定(逐行核对 Linux kernel smp.c 与 crackle 实现,二者一致):
- SMP/LL 密钥与随机数(TK/STK/LTK/Mrand/Srand/SKDm/SKDs/Confirm 等)全部
  按**大端(MSB-first)**传入本模块 -- 即蓝牙规范发布测试向量的字节序,
  也是 crackle 内部存储序(copy_reverse 后)。调用方(smp.py)从空口小端
  字节提取时需逐字段反转。
- AES 原语 e() = 原始 AES-128-ECB 单块(不做字节反转 -- 因输入已是大端,
  与 kernel smp_e 的"反转后 AES"等价)。
- AES-CCM(加密流量解密):key 大端;nonce 13 字节 = 计数器小端 5 字节
  (master->slave 在 byte[4] MSB 置方向位) + IV 8 字节**小端/空口序**
  (IVm||IVs 原样);AAD 1 字节 = LL 头 & 0xe3;MIC 4 字节。逐包跟踪计数器,
  含空包(每个方向独立计数;重传复用同计数器,靠 MIC 验证兜底)。

复用 pycryptodome 的 AES-ECB 与 CCM(RFC 3610,与 BLE 控制器/crackle 一致)。
"""

import struct

from Crypto.Cipher import AES


def e(key: bytes, data: bytes) -> bytes:
    """BLE e 函数 = AES-128 单块加密。key/data 均 16 字节大端;输出大端。
    等价于 kernel smp_e(反转->AES->反转) 在大端输入下的退化形式。"""
    return AES.new(bytes(key), AES.MODE_ECB).encrypt(bytes(data))


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def s1(tk: bytes, srand: bytes, mrand: bytes) -> bytes:
    """Legacy STK 推导:STK = s1(TK, Srand, Mrand)。
    取各随机数低 8 字节:srand[8:16] || mrand[8:16](大端序下 [8:16]=LSB 半)。
    对应 crackle: rand = state->srand[8:16] + state->mrand[8:16]。"""
    return e(tk, srand[8:16] + mrand[8:16])


def c1(k: bytes, r: bytes, preq: bytes, pres: bytes,
       iat: int, rat: int, ia: bytes, ra: bytes) -> bytes:
    """Legacy Confirm 值:confirm = e(K, e(K, r ⊕ p1) ⊕ p2)。
    p1 = pres(7) || preq(7) || rat(1) || iat(1);p2 = 0pad(4) || ia(6) || ra(6)。
    preq/pres 为 7 字节 Pairing Request/Response PDU(含 opcode);ia/ra 6 字节
    大端地址;iat/rat 地址类型(0=public,1=random)。对应 crackle calc_confirm。"""
    p1 = bytes(pres)[:7] + bytes(preq)[:7] + bytes([rat & 0xFF, iat & 0xFF])
    p2 = b"\x00" * 4 + bytes(ia)[:6] + bytes(ra)[:6]
    return e(k, _xor(e(k, _xor(r, p1)), p2))


def session_key(stk: bytes, skdm: bytes, skds: bytes) -> bytes:
    """会话密钥 = e(STK, SKD),SKD = SKDs(8) || SKDm(8)。
    对应 crackle calc_session_key: skd = skds + skdm。输出大端(直接喂 CCM)。"""
    return e(stk, bytes(skds)[:8] + bytes(skdm)[:8])


# ---- AES-CCM(BLE LL 加密流量解密)----

DIR_M2S = "m2s"   # master -> slave
DIR_S2M = "s2m"   # slave -> master


def ccm_nonce(counter: int, direction: str, iv: bytes) -> bytes:
    """构造 BLE CCM nonce(13 字节)。
    counter: 该方向包计数器(每个方向独立,空包也推进;从 0 起)。
    direction: 'm2s' 置方向位(0x80 in nonce[4] MSB),'s2m' 不置。
    iv: 8 字节 IVm||IVs(**空口/小端序**,原样入 nonce)。
    对应 crackle decrypt(): nonce = htole64(counter)[:5] | dir-bit || iv。"""
    n = bytearray(struct.pack("<Q", counter & 0xFFFFFFFFFF)[:5])
    if direction == DIR_M2S:
        n[4] |= 0x80
    return bytes(n) + bytes(iv)[:8]


def ccm_decrypt(key: bytes, nonce: bytes, aad: bytes,
                ciphertext: bytes, mic: bytes) -> bytes | None:
    """AES-CCM 解密(M=4,L=2)。MIC 校验失败返回 None。
    key 大端;nonce 13 字节(ccm_nonce 构造);aad 1 字节(LL 头 & 0xe3)。"""
    cipher = AES.new(bytes(key), AES.MODE_CCM, nonce=nonce, mac_len=4)
    cipher.update(bytes(aad))
    try:
        return cipher.decrypt_and_verify(bytes(ciphertext), bytes(mic))
    except ValueError:
        return None


def ccm_encrypt(key: bytes, nonce: bytes, aad: bytes,
                plaintext: bytes) -> tuple:
    """AES-CCM 加密(供测试/反向验证用)。返回 (ciphertext, mic)。"""
    cipher = AES.new(bytes(key), AES.MODE_CCM, nonce=nonce, mac_len=4)
    cipher.update(bytes(aad))
    ct, mic = cipher.encrypt_and_digest(bytes(plaintext))
    return ct, mic


# ---- 计数器跟踪(LL 加密流量逐包)----

class LLCipherState:
    """跟踪一条加密连接的两个方向包计数器,逐包解密。
    重传(SN 位未变)不推进计数器 -- 靠 MIC 验证兜底:先按当前计数器试解,
    失败则在窗口内回扫(crackle 同款策略,容错丢包)。"""

    def __init__(self, session_key: bytes, iv: bytes, search_window: int = 32):
        self.key = session_key
        self.iv = iv
        self.search = search_window
        self.counter = {DIR_M2S: 0, DIR_S2M: 0}
        self.last_sn = {DIR_M2S: None, DIR_S2M: None}

    def decrypt_packet(self, ll_header_byte: bytes, ciphertext: bytes, mic: bytes,
                       direction: str, sn: int) -> bytes | None:
        """解密一个 LL data PDU。ll_header_byte=原始头字节(AAD 取 & 0xe3)。
        sn=该方向本包 SN 位;与上次相同=重传(不推进计数器)。
        返回明文 payload(不含 MIC),MIC 验证失败返回 None。"""
        aad = bytes([ll_header_byte & 0xE3])
        base = self.counter[direction]
        # 重传:SN 不变 -> 先用旧计数器(不推进)试
        is_retx = (self.last_sn[direction] is not None and sn == self.last_sn[direction])
        start = base - 1 if is_retx else base
        for delta in range(0, self.search + 1):
            c = start + delta
            if c < 0:
                continue
            nonce = ccm_nonce(c, direction, self.iv)
            pt = ccm_decrypt(self.key, nonce, aad, ciphertext, mic)
            if pt is not None:
                if not is_retx or delta > 0:
                    self.counter[direction] = c + 1
                self.last_sn[direction] = sn
                return pt
        return None

    def encrypt_packet(self, ll_header_byte, plaintext: bytes,
                       direction: str) -> tuple:
        """加密一个 LL data PDU(TX 用)。ll_header_byte=原始头字节 int(AAD 取
        & 0xE3);返回 (ciphertext, mic)。推进该方向计数器(每新包 +1;重传由
        固件处理,host 不重复加密 -- 固件管 TX SN,host 只按"新包计数"递增)。
        与 decrypt_packet 对称:TX 用 counter[DIR_M2S],RX 用 counter[DIR_S2M]。
        注意:encrypt 不跟踪 last_sn(固件自动管理 TX SN 位,host 侧只关心
        新包计数递增;decrypt 侧才需要 SN 重传回扫)。"""
        hdr = ll_header_byte[0] if isinstance(ll_header_byte,
                                              (bytes, bytearray)) else ll_header_byte
        aad = bytes([hdr & 0xE3])
        c = self.counter[direction]
        nonce = ccm_nonce(c, direction, self.iv)
        ct, mic = ccm_encrypt(self.key, nonce, aad, plaintext)
        self.counter[direction] = c + 1
        return ct, mic
