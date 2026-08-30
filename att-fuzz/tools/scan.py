#!/usr/bin/env python3
"""扫描工具:枚举附近 BLE 广播设备(CRC 校验开,过滤脏包)。
用法: python3 att-fuzz/tools/scan.py [秒数=15] [--mac AA:BB:CC:DD:EE:FF]
"""
import argparse
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "python_cli"))
sys.path.insert(0, str(REPO / "att-fuzz"))

from sniffle.constants import BLE_ADV_AA
from sniffle.packet_decoder import AdvertMessage, str_mac
from sniffle.sniffle_hw import SniffleHW


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("duration", nargs="?", type=int, default=15)
    ap.add_argument("--mac", default=None, help="只显示该 MAC 的设备")
    ap.add_argument("--serport", default=None, help="串口(默认自动探测 XDS110)")
    args = ap.parse_args()

    from core.serial_lock import SerialBusy, acquire as serial_acquire
    try:
        lock = serial_acquire(args.serport, "CLI 扫描工具")
    except SerialBusy as e:
        raise SystemExit("error: %s" % e)
    try:
        _scan(args)
    finally:
        lock.release()


def _scan(args):
    hw = SniffleHW(timeout=2)
    hw.cmd_chan_aa_phy(37, BLE_ADV_AA, 0)
    hw.cmd_pause_done(True)
    hw.cmd_follow(False)
    hw.cmd_rssi(-128)
    hw.cmd_crc_valid(True)
    if args.mac:
        mac_b = bytes.fromhex(args.mac.replace(":", "").replace("-", ""))
        hw.cmd_mac(mac_b, False)
        print("scanning %ds for %s ..." % (args.duration, args.mac))
    else:
        hw.cmd_mac()
        print("scanning %ds ..." % args.duration)
    hw.cmd_scan()
    hw.mark_and_flush()

    seen = {}
    deadline = time.time() + args.duration
    while time.time() < deadline:
        msg = hw.recv_and_decode()
        if not isinstance(msg, AdvertMessage) or getattr(msg, "AdvA", None) is None:
            continue
        if getattr(msg, "crc_err", True):
            continue
        key = (str_mac(msg.AdvA), "R" if msg.TxAdd else "P")
        seen.setdefault(key, []).append(msg)

    print("CRC 通过,看到 %d 个设备:" % len(seen))
    for (mac, t), pkts in sorted(seen.items()):
        rssi = max(p.rssi for p in pkts)
        body = pkts[0].body.hex()[:48]
        print("  [%s] %s RSSI=%d %s" % (t, mac, rssi, body))


if __name__ == "__main__":
    main()
