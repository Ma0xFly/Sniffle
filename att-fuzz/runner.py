#!/usr/bin/env python3
# att-fuzz/runner.py
"""
att-fuzz CLI(阶段一:central 模式;阶段三:server 反向角色)。

用法:
  python3 att-fuzz/runner.py --target att-fuzz/targets/headphone.json
  python3 att-fuzz/runner.py --target ... --max-cases 50          # 冒烟
  python3 att-fuzz/runner.py --target ... --replay <pdu_hex>      # 重放原始 PDU
  python3 att-fuzz/runner.py --target ... --replay-case <id> --ledger <ledger.jsonl>
  python3 att-fuzz/runner.py --target ... --discover-only         # 只做发现,存 GATT 地图
  python3 att-fuzz/runner.py --target ... --server                # 反向角色打手机(阶段三)
  python3 att-fuzz/runner.py --target ... --probe                 # 扫描诊断
  python3 att-fuzz/runner.py --decrypt <pcap> --bt-keys <file>    # 离线解密(阶段四)
"""

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "python_cli"))
sys.path.insert(0, str(REPO / "att-fuzz"))

from core.monitor import Ledger            # noqa: E402
from core.serial_lock import SerialBusy    # noqa: E402
from roles import central_fuzz             # noqa: E402


def load_target(path: str) -> dict:
    t = json.loads(Path(path).read_text(encoding="utf-8"))
    if not t.get("mac") and not t.get("search_string"):
        raise SystemExit("target profile 需要 mac 或 search_string 之一(填 %s)" % path)
    return t


def main():
    ap = argparse.ArgumentParser(description="Sniffle ATT/GATT fuzzer (stage 1: central)")
    ap.add_argument("--target", default=None, help="targets/*.json 路径"
                    "(--decrypt 离线模式可省)")
    ap.add_argument("--strategy", default=None,
                    help="策略目录/文件(默认 att-fuzz/strategies/)")
    ap.add_argument("--serport", default=None, help="串口(默认自动探测 XDS110)")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--max-cases", type=int, default=0, help="0 = 全量")
    ap.add_argument("--outdir", default=None, help="输出目录(默认 logs/run-<时间戳>)")
    ap.add_argument("--replay", default=None, metavar="PDU_HEX",
                    help="重放指定 ATT PDU(hex)")
    ap.add_argument("--replay-case", default=None, metavar="CASE_ID",
                    help="按 case_id 从台账重放")
    ap.add_argument("--ledger", default=None, help="replay-case 用的台账路径")
    ap.set_defaults(replay_expect=True, replay_steps=None)
    ap.add_argument("--discover-only", action="store_true",
                    help="只连接 + 发现,输出 GATT 地图后退出")
    ap.add_argument("--probe", action="store_true",
                    help="扫描诊断:目标是否在广播 + 地址类型(不连接)")
    ap.add_argument("--rounds", type=int, default=0,
                    help="追加变异轮数(0=纯确定性语料;N>0 在第一轮后进入签名驱动变异)")
    ap.add_argument("--round-budget", type=int, default=100,
                    help="每轮变异预算用例数(默认 100,预算耗尽进下一轮)")
    ap.add_argument("--server", action="store_true",
                    help="反向角色:伪装 GATT server 打手机 client(阶段三,攻击面⑧)")
    ap.add_argument("--server-name", default="Sniffle Server",
                    help="server 广播/服务里的设备名")
    ap.add_argument("--server-duration", type=float, default=0.0,
                    help="server 运行秒数(0=一直跑到 Ctrl-C)")
    ap.add_argument("--adb-serial", default="ZD9L8H454HDY7DEU",
                    help="logcat oracle 的 Android 序列号")
    ap.add_argument("--sniff-pairing", action="store_true",
                    help="被动嗅探配对与密钥收割(阶段四 4.1,单板)")
    ap.add_argument("--sniff-duration", type=float, default=0.0,
                    help="嗅探运行秒数(0=跑到 Ctrl-C)")
    ap.add_argument("--sniff-mac", default=None, metavar="MAC",
                    help="嗅探目标外设 MAC(书写序 AA:BB:..;缺省=猎取模式:无 MAC 过滤+extadv)")
    ap.add_argument("--phone-mac", default=None, metavar="MAC",
                    help="用户手机 MAC(书写序):台账里标记手机发起的 CONNECT_IND(配对连接识别)")
    ap.add_argument("--sniff-hold", action="store_true",
                    help="嗅探跟满整条连接(禁用 60s 无 SMP 的探测超时复位;"
                    "加密重连会话收割用)")
    ap.add_argument("--impersonate", action="store_true",
                    help="加密冒充:用 bond 密钥伪装手机直连耳机,"
                    "绕过 GATT 加密句柄墙(攻击面⑦)")
    ap.add_argument("--imp-duration", type=float, default=0.0,
                    help="冒充运行秒数(0=跑到 Ctrl-C)")
    ap.add_argument("--wall-ledger", default=None, metavar="PATH",
                    help="冒充模式下阶段一台账路径(ledger.jsonl),供 0x05 墙"
                    "handle 加载;缺省=跳过 0x05 墙验证,直接进语料循环")
    ap.add_argument("--decrypt", default=None, metavar="PCAP",
                    help="离线解密模式:加密 BLE pcap + 密钥 -> ATT/SMP 明文流"
                    "(阶段四 4.1,不碰硬件)")
    ap.add_argument("--bt-keys", default=None, metavar="FILE",
                    help="密钥文件:Android bt_config.conf 或提取 JSON"
                    "(logs/vivo_bond_keys.json 形态),与 --decrypt 配合")
    ap.add_argument("--keys-mac", default=None, metavar="MAC",
                    help="bt_config.conf 里目标设备 MAC(书写序;缺省解析全部节)")
    ap.add_argument("--ltk", default=None, metavar="HEX",
                    help="直接给 LTK(16 字节 hex),与 --decrypt 配合,省 --bt-keys")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S")

    outdir = Path(args.outdir) if args.outdir else \
            REPO / "att-fuzz" / "logs" / (
                ("decrypt-" if args.decrypt else "run-")
                + datetime.now().strftime("%Y%m%d-%H%M%S"))

    if args.decrypt:
        sys.exit(_decrypt_cli(args, outdir))

    if not args.target:
        raise SystemExit("error: 需要 --target(targets/*.json)或 --decrypt <pcap> 离线模式")
    target = load_target(args.target)
    strategy = [args.strategy] if args.strategy else [REPO / "att-fuzz" / "strategies"]

    try:
        if args.probe:
            sys.exit(_probe(target, outdir, args.serport))
    except SerialBusy as e:
        raise SystemExit("error: %s" % e)

    if args.replay_case:
        ledger_path = Path(args.ledger) if args.ledger else _latest_ledger()
        rec = Ledger(ledger_path).find(args.replay_case)
        if rec is None:
            raise SystemExit("case %r not found in %s" % (args.replay_case, ledger_path))
        replay = rec.get("replay") or {}
        if replay.get("kind") == "sequence":
            steps = replay.get("steps") or []
            if not steps:
                raise SystemExit("序列台账记录缺 replay.steps,无法重放")
            print("replaying sequence %s: %d steps" % (args.replay_case, len(steps)))
            args.replay_steps = steps
        else:
            pdu_hex = replay.get("pdu")
            if not pdu_hex:
                raise SystemExit("该台账记录缺 replay.pdu,无法重放")
            print("replaying %s: %s" % (args.replay_case, pdu_hex))
            args.replay = pdu_hex
            # 台账记录的 expect_response 必须透传(如 write_cmd 无响应),
            # 否则重放会强制等响应,产生 TIMEOUT 伪影
            args.replay_expect = bool(replay.get("expect_response", True))

    try:
        if args.sniff_pairing:
            from roles import pairing_sniff
            sys.exit(pairing_sniff.run(target, outdir, serport=args.serport,
                                       duration=args.sniff_duration,
                                       mac=args.sniff_mac,
                                       phone_mac=args.phone_mac,
                                       hold=args.sniff_hold))
        if args.server:
            from roles import server_fuzz
            sys.exit(server_fuzz.run(target, outdir, serport=args.serport,
                                     duration=args.server_duration,
                                     name=args.server_name,
                                     adb_serial=args.adb_serial))
        if args.impersonate:
            from roles import impersonation_fuzz
            bt_keys = args.bt_keys or target.get("bt_keys")
            keys_mac = args.keys_mac or target.get("keys_mac")
            phone_mac = args.phone_mac or target.get("phone_mac")
            sys.exit(impersonation_fuzz.run(target, outdir,
                                           serport=args.serport,
                                           bt_keys_path=bt_keys,
                                           keys_mac=keys_mac,
                                           phone_mac=phone_mac,
                                           duration=args.imp_duration,
                                           max_cases=args.max_cases,
                                           adb_serial=args.adb_serial,
                                           strategy_paths=strategy,
                                           seed=args.seed,
                                           rounds=args.rounds,
                                           round_budget=args.round_budget,
                                           wall_ledger=args.wall_ledger))
        if args.discover_only:
            sys.exit(_discover_only(target, outdir, args.serport))

        sys.exit(central_fuzz.run(target, strategy, outdir, serport=args.serport,
                                  seed=args.seed, max_cases=args.max_cases,
                                  replay_pdu=args.replay,
                                  replay_expect=args.replay_expect,
                                  replay_steps=args.replay_steps,
                                  rounds=args.rounds,
                                  round_budget=args.round_budget))
    except SerialBusy as e:
        raise SystemExit("error: %s" % e)


def _decrypt_cli(args, outdir) -> int:
    """离线解密:pcap + 密钥 -> ATT/SMP 明文流。返回码:0=有连接解密成功;
    2=有加密连接但无候选 key 匹配;1=输入错误。"""
    from core import bt_keys, pcap_decrypt
    candidates = []
    if args.ltk:
        try:
            k = bytes.fromhex(args.ltk)
        except ValueError:
            raise SystemExit("error: --ltk 不是合法 hex")
        if len(k) != 16:
            raise SystemExit("error: --ltk 需 16 字节(32 hex 字符)")
        candidates.append((k, "cli-ltk"))
    if args.bt_keys:
        if not Path(args.bt_keys).is_file():
            raise SystemExit("error: 密钥文件不存在: %s" % args.bt_keys)
        bonds = bt_keys.load_keys(args.bt_keys, target_mac=args.keys_mac)
        if not bonds:
            raise SystemExit("error: 密钥文件里没有可用 bond"
                             "(bt_config 目标节未匹配?试试 --keys-mac)")
        for b in bonds:
            print("bond: %s" % json.dumps(b.summary(), ensure_ascii=False))
        candidates.extend(bt_keys.all_ltk_candidates(bonds))
    if not candidates:
        raise SystemExit("error: --decrypt 需要 --bt-keys <file> 或 --ltk <hex>")

    print("decrypt: %s (%d 个 LTK 候 x 双字节序)" % (args.decrypt, len(candidates)))
    reports = pcap_decrypt.decrypt_pcap(args.decrypt, candidates)
    top = pcap_decrypt.write_outputs(reports, outdir, args.decrypt)

    any_ok = False
    for r in reports:
        s = r.summary()
        print("conn#%d aa=%s packets=%d" % (s["conn"], s["aa"], s["packets"]))
        if s["connect"]:
            c = s["connect"]
            print("  CONNECT_IND: %s -> %s (iat=%d rat=%d interval=%d)"
                  % (c["init"], c["adv"], c["iat"], c["rat"], c["interval"]))
        if s["enc"]:
            e = s["enc"]
            print("  LL_ENC: rand=%s ediv=%s" % (e["rand"], e["ediv"]))
            print("    skdm=%s skds=%s iv=%s" % (e["skdm"], e["skds"], e["iv"]))
        if s["key_match"]:
            km = s["key_match"]
            print("  KEY MATCH: %s (%s 字节序) mic_ok=%d session_key=%s"
                  % (km["label"], km["byte_order"], km["mic_ok"],
                     km["session_key"]))
            any_ok = True
            print("  SDU 流 %d 条: %s" % (s["sdu_count"],
                  " ".join("%s x%d" % (k, v) for k, v in sorted(s["ops"].items()))))
        elif s["enc"]:
            print("  加密段无候选 key 匹配(MIC 全挂)")
        elif s["sdu_count"]:
            print("  明文连接: SDU 流 %d 条" % s["sdu_count"])
        if s["terminate"]:
            print("  TERMINATE reason=0x%02X encrypted=%s"
                  % (s["terminate"]["reason"], s["terminate"]["encrypted"]))
    print("报告: %s" % (outdir / "decrypt_report.json"))
    print("SDU 流: %s" % (outdir / "decrypted_sdu.jsonl"))
    return 0 if any_ok else 2


def _latest_ledger() -> Path:
    logs = REPO / "att-fuzz" / "logs"
    cands = sorted((p.parent for p in logs.glob("*/ledger.jsonl")),
                   key=lambda p: p.stat().st_mtime)
    if not cands:
        raise SystemExit("没有历史台账(logs/*/ledger.jsonl,目录改名后只要台账在即可)")
    return cands[-1] / "ledger.jsonl"


def _probe(target, outdir, serport) -> int:
    from core.serial_lock import guard as serial_guard
    from core.transport import SniffleTransport
    from sniffle.sniffle_hw import SniffleHW
    with serial_guard(serport or target.get("serport"), "CLI 广播探测"):
        transport = SniffleTransport(SniffleHW(serport=serport or target.get("serport")),
                                     conn_interval_units=target.get("conn_interval", 12))
        wire, _ = transport._parse_mac(target["mac"])
        print("probe: 扫描目标 %s ..." % target["mac"])
        r = transport.probe(wire)
    if not r["found"]:
        print("probe: 15s 内未发现目标广播。请确认:")
        print("  - 耳机已进入配对/广播模式(开盖或长按配对键,且未被手机占用)")
        print("  - MAC 是否写对(可与手机 nRF Connect 扫描结果核对)")
        return 1
    print("probe: 找到目标!")
    print("  地址类型: %s" % r["addr_type"])
    print("  广播地址: %s" % r["addr"])
    print("  RSSI:     %d dBm" % r["rssi"])
    print("  载荷前 32B: %s" % r["adv_preview"][:64])
    raw_mr = target.get("mac_random", True)
    want_random = bool(raw_mr)
    if raw_mr is True or raw_mr is False:
        mr_show = "true" if raw_mr else "false"
    else:                        # 档案里写的是 0/1 等非布尔值,原样显示
        mr_show = str(raw_mr)
    mr_show += "({})".format("随机地址" if want_random else "public")
    name = target.get("name") or "目标档案"
    if r["addr_type"] == "random" and want_random:
        print("  -> %s mac_random=%s,与广播地址类型(random)一致" % (name, mr_show))
    elif r["addr_type"] != "random" and not want_random:
        print("  -> %s mac_random=%s,与广播地址类型(public)一致" % (name, mr_show))
    else:
        print("  -> 注意:%s mac_random=%s,但广播地址类型是 %s,不一致,请修改档案!"
              % (name, mr_show, r["addr_type"]))
    return 0


def _discover_only(target, outdir, serport) -> int:
    from core.serial_lock import guard as serial_guard
    outdir.mkdir(parents=True, exist_ok=True)
    from core.session import FuzzSession
    with serial_guard(serport or target.get("serport"), "CLI GATT 发现"):
        transport = central_fuzz.make_transport(serport, target, outdir)
        session = FuzzSession(transport, target, gatt_map_path=outdir / "gatt_map.json")
        gatt = session.start()
    print("ll_max=%d att_mtu=%d" % (transport.ll_max, transport.att_mtu))
    print("GATT 地图已保存: %s" % (outdir / "gatt_map.json"))
    print("服务 %d 个,特征 %d 个,gap %d 条" %
          (len(gatt.services), len(gatt.characteristics), len(gatt.gaps)))
    for s in gatt.services:
        print("  service %s [%04X-%04X]" % (s.uuid, s.start_handle, s.end_handle))
    return 0


if __name__ == "__main__":
    main()
