#!/usr/bin/env python3
# att-fuzz/core/bt_config_scanner.py
"""
手机 bt_config.conf 扫描器：adb 拉取手机蓝牙 bond 存储，
解析出所有配对设备的密钥信息 + 手机自身 MAC，供自动生成 target JSON。

adb 调用模式：
  1. adb -s <serial> get-state 探活
  2. adb root + adb -s <serial> pull /data/misc/bluedroid/bt_config.conf <tmp>
  3. 上面失败 → adb -s <serial> shell su -c "cat /data/misc/bluedroid/bt_config.conf"
  4. 解析拉到的文本
"""

import logging
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from . import bt_keys

log = logging.getLogger("att-fuzz.bt_config_scanner")

DEFAULT_ADB = os.path.expanduser("~/Android/Sdk/platform-tools/adb")
BT_CONFIG_PATH = "/data/misc/bluedroid/bt_config.conf"


@dataclass
class BondDevice:
    """bt_config.conf 里一个配对设备。"""
    name: str           # 设备名（bt_config Name 字段）
    mac: str            # 书写序 MAC（bt_config 节名，如 64:44:7b:ee:41:f4）
    addr_type: int      # 0=public, 1=random
    ltk_hex: str        # LTK hex（dump 序，16 字节 = 32 字符）
    rand_hex: str       # rand hex（8 字节）
    ediv_hex: str       # ediv hex（2 字节）
    key_size: int
    irk_hex: str | None = None  # IRK（如果有）


@dataclass
class ScanResult:
    """扫描结果。"""
    phone_mac: str          # 手机自身 MAC（书写序）
    phone_name: str         # 手机名（Adapter Name 字段）
    devices: list = field(default_factory=list)  # list[BondDevice]


def scan(adb_serial: str | None = None, adb_path: str | None = None) -> ScanResult:
    """adb 拉取手机 bt_config.conf -> 解析 -> 返回设备列表 + 手机 MAC。
    root 方式：先试 adb root + adb pull，失败回退 adb shell su -c "cat ..."。"""
    adb = adb_path or DEFAULT_ADB
    if not os.path.exists(adb):
        raise RuntimeError("adb 未找到: %s" % adb)

    serial = adb_serial or ""
    serial_args = ["-s", serial] if serial else []

    # 探活
    if serial:
        try:
            r = subprocess.run([adb, "-s", serial, "get-state"],
                               capture_output=True, text=True, timeout=5)
            if r.returncode != 0 or "device" not in r.stdout:
                raise RuntimeError("设备 %s 不在线: %s" % (serial, r.stderr.strip()))
        except subprocess.TimeoutExpired:
            raise RuntimeError("adb get-state 超时")
    else:
        # 无 serial 时用默认设备
        pass

    # 拉取 bt_config.conf
    content = _pull_bt_config(adb, serial_args)

    # 写临时文件解析
    with tempfile.NamedTemporaryFile(mode="w", suffix=".conf", delete=False,
                                     encoding="utf-8") as f:
        f.write(content)
        tmp_path = f.name
    try:
        return _parse_bt_config_file(tmp_path)
    finally:
        os.unlink(tmp_path)


def _pull_bt_config(adb: str, serial_args: list) -> str:
    """拉取 bt_config.conf 内容。先试 root pull，失败回退 su cat。"""
    # 方式 1: adb root + adb pull
    try:
        if serial_args:
            subprocess.run([adb] + serial_args + ["root"],
                           capture_output=True, text=True, timeout=5)
        else:
            subprocess.run([adb, "root"],
                           capture_output=True, text=True, timeout=5)
    except subprocess.TimeoutExpired:
        pass

    with tempfile.NamedTemporaryFile(delete=False, suffix=".conf") as tmp:
        tmp_path = tmp.name
    try:
        pull_cmd = [adb] + serial_args + ["pull", BT_CONFIG_PATH, tmp_path]
        r = subprocess.run(pull_cmd, capture_output=True, text=True, timeout=10)
        if r.returncode == 0 and os.path.exists(tmp_path) and os.path.getsize(tmp_path) > 0:
            content = Path(tmp_path).read_text(encoding="utf-8", errors="replace")
            if content.strip():
                return content
    except subprocess.TimeoutExpired:
        pass
    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

    # 方式 2: adb shell su -c "cat ..."
    log.info("pull 失败,尝试 su -c cat ...")
    cat_cmd = [adb] + serial_args + ["shell", "su", "-c",
                                      '"cat %s"' % BT_CONFIG_PATH]
    try:
        r = subprocess.run(cat_cmd, capture_output=True, text=True, timeout=10)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout
    except subprocess.TimeoutExpired:
        pass

    raise RuntimeError("无法拉取 bt_config.conf（root pull 和 su cat 均失败）")


def _parse_bt_config_file(path: str) -> ScanResult:
    """解析 bt_config.conf 文件 -> ScanResult。"""
    phone_mac = bt_keys.extract_phone_mac(path)
    if not phone_mac:
        phone_mac = "unknown"

    # 手机名
    phone_name = "unknown"
    in_adapter = False
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            in_adapter = line[1:-1].strip().lower() == "adapter"
            continue
        if not in_adapter or "=" not in line:
            continue
        k, _, v = line.partition("=")
        if k.strip().upper() == "NAME":
            phone_name = v.strip()
            break

    # 解析全部 bond
    bonds = bt_keys.parse_bt_config_all(path)
    devices = []
    for b in bonds:
        if not b.ltk:
            continue
        # 从 BondKeys 构造 BondDevice
        mac_str = b.section or ""
        # 节名是冒号 hex（可能线序/书写序）；归一为书写序小写
        if len(mac_str.replace(":", "")) == 12:
            mac_str = mac_str.lower()
        addr_type = 1  # 默认 random
        if b.peer_addr_type is not None:
            addr_type = b.peer_addr_type
        elif b.addr:
            # 从地址最高字节判断：bit 1 = random
            addr_type = 1 if (b.addr[5] & 0xC0) == 0xC0 else 0
        devices.append(BondDevice(
            name=b.name or "unknown",
            mac=mac_str,
            addr_type=addr_type,
            ltk_hex=b.ltk.hex(),
            rand_hex=b.rand.hex() if b.rand else "0000000000000000",
            ediv_hex=b.ediv.hex() if b.ediv else "0000",
            key_size=b.key_size or 16,
            irk_hex=b.irk.hex() if b.irk else None,
        ))

    return ScanResult(
        phone_mac=phone_mac,
        phone_name=phone_name,
        devices=devices,
    )
