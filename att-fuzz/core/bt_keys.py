#!/usr/bin/env python3
# att-fuzz/core/bt_keys.py
"""
BLE bond 密钥读取(密钥产品化):Android bt_config.conf 或提取 JSON -> BondKeys。

bt_config.conf(BlueDroid 持久化,root 从 /data/misc/bluedroid/ 拉取)是 INI 形态,
每个远端设备一节;密钥 blob 布局按 AOSP tBTM_LE_PENC/PID/LENC_KEYS 结构体内存
dump(实测核对):
- LE_KEY_PENC = ltk(16) || rand(8) || ediv(2) || sec_level(1) || key_size(1) 共 28B
- LE_KEY_PID  = irk(16) || addr_type(1) || addr(6) 共 23B
- LE_KEY_LENC = ltk(16) || div(2) || key_size(1) || sec(1) 共 20B
- LE_KEY_LID  = ediv(2) || div(2) 共 4B(本地 diversifier,无密钥材料)

节名是远端地址的冒号 hex,实测存在正反两种线序(设备显示序与 dump 序),按目标
MAC 双序匹配;不给 target_mac 时解析全部含 LE 密钥的节。

LTK 字节序:bt_config dump 序(小端)与空口/大端序相反 -- 2026-09-01 vivo TWS 3e +
Redmi K50 实测(MIC 验证 23+ 包):dump 序需整体反转才是 e() 可用大端序。两个方向
都作为候选交给 pcap_decrypt 以 MIC 裁定(见 pcap_decrypt 模块尾"定案"注释)。

JSON 形态(提取归档,如 logs/vivo_bond_keys.json):字段 ltk_hex/rand_hex/
ediv_hex/irk_remote_hex/name,直接映射 BondKeys。
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger("att-fuzz.bt_keys")

KEY_PENC = "LE_KEY_PENC"
KEY_PID = "LE_KEY_PID"
KEY_LENC = "LE_KEY_LENC"
KEY_LID = "LE_KEY_LID"

REPO = Path(__file__).resolve().parents[2]
TARGETS_DIR = REPO / "att-fuzz" / "targets"


def resolve_path(path_str: str) -> Path:
    """把 bt_keys 路径解析为绝对路径。
    绝对路径照旧;相对路径解析到 att-fuzz/targets/ 下
    (如 "bt_keys/vivo.conf" -> att-fuzz/targets/bt_keys/vivo.conf)。
    这样 target JSON 里可以用相对路径引用密钥文件。"""
    p = Path(path_str)
    if p.is_absolute():
        return p
    return (TARGETS_DIR / path_str).resolve()


def _hex(s: str) -> bytes | None:
    s = str(s).strip().replace(":", "").replace("-", "")
    if not s or set(s.lower()) - set("0123456789abcdef"):
        return None
    try:
        return bytes.fromhex(s)
    except ValueError:
        return None


def _mac_variants(mac: str | bytes) -> list[bytes]:
    """书写序 AA:BB:.. 或 6 字节 hex -> [原序, 反转序](双序匹配用)。"""
    raw = _hex(mac) if not isinstance(mac, (bytes, bytearray)) else bytes(mac)
    if raw is None or len(raw) != 6:
        return []
    return [raw, raw[::-1]]


@dataclass
class BondKeys:
    """一个 bond 的密钥材料。字段保持文件原序(dump 序),不做任何反转;
    使用方按需取 display 序(反转)或原序。"""
    source: str = ""                     # 来源文件路径
    section: str = ""                    # bt_config 节名(或 JSON target)
    name: str | None = None              # 设备名
    addr: bytes | None = None            # 节名地址(原序)
    # LE_KEY_PENC(对端 LTK:master 重连加密用)
    ltk: bytes | None = None
    rand: bytes | None = None
    ediv: bytes | None = None
    sec_level: int | None = None
    key_size: int | None = None
    # LE_KEY_PID(对端 IRK/身份)
    irk: bytes | None = None
    peer_addr: bytes | None = None       # PID 尾部地址(原序;注意线序)
    peer_addr_type: int | None = None
    # LE_KEY_LENC(本地 div 密钥)
    lenc_ltk: bytes | None = None
    lenc_div: bytes | None = None
    misc: dict = field(default_factory=dict)

    def ltk_candidates(self) -> list:
        """候选 LTK 列表 [(key_bytes, 来源标签)]。字节序裁定交给 pcap_decrypt。"""
        out = []
        if self.ltk:
            out.append((self.ltk, "penc"))
        if self.lenc_ltk and self.lenc_ltk != self.ltk:
            out.append((self.lenc_ltk, "lenc"))
        return out

    def summary(self) -> dict:
        return {
            "section": self.section, "name": self.name,
            "ltk": self.ltk.hex() if self.ltk else None,
            "rand": self.rand.hex() if self.rand else None,
            "ediv": self.ediv.hex() if self.ediv else None,
            "key_size": self.key_size, "sec_level": self.sec_level,
            "irk": self.irk.hex() if self.irk else None,
            "peer_addr": self.peer_addr.hex() if self.peer_addr else None,
            "lenc_ltk": self.lenc_ltk.hex() if self.lenc_ltk else None,
        }


def parse_bt_config(path: str | Path, target_mac: str | None = None) -> list:
    """解析 bt_config.conf -> [BondKeys]。target_mac 给定时只保留匹配节
    (书写序/线序双序匹配);缺省解析全部含 LE 密钥的节。"""
    want = _mac_variants(target_mac) if target_mac else None
    sections: dict[str, dict] = {}
    cur = None
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            cur = line[1:-1].strip()
            sections[cur] = {}
            continue
        if cur is None or "=" not in line:
            continue
        k, _, v = line.partition("=")
        sections[cur][k.strip().upper()] = v.strip()
    out = []
    for sec, kv in sections.items():
        has_le = any(k in kv for k in (KEY_PENC, KEY_PID, KEY_LENC, KEY_LID))
        if not has_le:
            continue
        sec_mac = _hex(sec)
        if sec_mac is not None and len(sec_mac) == 6:
            if want and sec_mac not in want:
                continue
        elif want:
            # 非地址节名(适配器信息等),目标给定时不保留
            continue
        out.append(_from_bt_config_section(str(path), sec, kv, sec_mac))
    if want and not out:
        log.warning("bt_config 中未找到目标 %s 的密钥节(双序均未匹配)", target_mac)
    return out


def parse_bt_config_all(path: str | Path) -> list:
    """解析 bt_config.conf 返回全部含 LE 密钥的 bond 节（不过滤）。"""
    return parse_bt_config(path, target_mac=None)


def extract_phone_mac(path: str | Path) -> str | None:
    """从 bt_config.conf 的 [Adapter] 节取 Address 字段（手机自身 MAC，书写序小写）。
    bt_config.conf 里 [Adapter] 节含 Address=xx:xx:xx:xx:xx:xx 形式的本机地址。"""
    in_adapter = False
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            in_adapter = line[1:-1].strip().lower() == "adapter"
            continue
        if not in_adapter or "=" not in line:
            continue
        k, _, v = line.partition("=")
        if k.strip().upper() == "ADDRESS":
            return v.strip().lower()
    return None


def _from_bt_config_section(source: str, sec: str, kv: dict,
                            sec_mac: bytes | None) -> BondKeys:
    bk = BondKeys(source=source, section=sec, addr=sec_mac)
    name = kv.get("NAME")
    if name and not name.isdigit():      # TimeCreated 等数字项跳过
        bk.name = name
    penc = _hex(kv[KEY_PENC]) if KEY_PENC in kv else None
    if penc and len(penc) >= 28:
        bk.ltk = penc[:16]
        bk.rand = penc[16:24]
        bk.ediv = penc[24:26]
        bk.sec_level = penc[26]
        bk.key_size = penc[27]
    elif penc:
        bk.misc["penc_len"] = len(penc)
    pid = _hex(kv[KEY_PID]) if KEY_PID in kv else None
    if pid and len(pid) >= 23:
        bk.irk = pid[:16]
        bk.peer_addr_type = pid[16]
        bk.peer_addr = pid[17:23]
    lenc = _hex(kv[KEY_LENC]) if KEY_LENC in kv else None
    if lenc and len(lenc) >= 20:
        bk.lenc_ltk = lenc[:16]
        bk.lenc_div = lenc[16:18]
        bk.misc["lenc_ks"] = lenc[18]
        bk.misc["lenc_sec"] = lenc[19]
    lid = _hex(kv[KEY_LID]) if KEY_LID in kv else None
    if lid and len(lid) >= 4:
        bk.misc["lid_ediv"] = lid[:2].hex()
        bk.misc["lid_div"] = lid[2:4].hex()
    return bk


def load_keys_json(path: str | Path) -> list:
    """提取归档 JSON(vivo_bond_keys.json 形态)-> [BondKeys]。"""
    d = json.loads(Path(path).read_text(encoding="utf-8"))
    bk = BondKeys(source=str(path), section=d.get("target") or "")
    bk.ltk = _hex(d["ltk_hex"]) if d.get("ltk_hex") else None
    bk.rand = _hex(d["rand_hex"]) if d.get("rand_hex") else None
    bk.ediv = _hex(d["ediv_hex"]) if d.get("ediv_hex") else None
    bk.irk = _hex(d["irk_remote_hex"]) if d.get("irk_remote_hex") else None
    bk.name = d.get("target")
    if d.get("key_size"):
        bk.key_size = int(d["key_size"])
    return [bk]


def load_keys(path: str | Path, target_mac: str | None = None) -> list:
    """按内容自动分派:JSON(bt_config 提取归档)或 bt_config.conf。"""
    p = Path(path)
    head = p.read_text(encoding="utf-8", errors="replace").lstrip()[:1]
    if head == "{":
        return load_keys_json(p)
    return parse_bt_config(p, target_mac)


def all_ltk_candidates(bonds: list) -> list:
    """多个 BondKeys 摊平成 [(key_bytes, 'section|tag')] 候选列表。"""
    out = []
    for bk in bonds:
        for key, tag in bk.ltk_candidates():
            out.append((key, "%s|%s" % (bk.section or "?", tag)))
    return out
