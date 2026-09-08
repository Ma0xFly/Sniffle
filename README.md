# Sniffle ATT/GATT Fuzzer

基于 [nccgroup/Sniffle](https://github.com/nccgroup/Sniffle)（CC2652R1F BLE 嗅探器）的 **Bluetooth Low Energy 攻击面 Fuzzer**。保留原版嗅探器全部能力，新增：

- **ATT/GATT 确定性语料 fuzzing**（8 层攻击面，目标无关，换设备只换档案）
- **签名驱动变异引擎**（跨 run 学习，能量加权，时序门控）
- **信号分类**（HEALTH_DEGRADED / ATT_FREEZE / DISCONNECT 等 8 类）
- **加密冒充**（用手机 bond LTK 冒充 central，绕过 0x05 认证墙，打认证面）
- **反向角色**（伪装 GATT server 攻击手机，带 logcat 崩溃 oracle）
- **被动嗅探配对 + 密钥收割**（SMP 解析、legacy 密钥推导）
- **离线 pcap 解密**（加密 BLE 流量 → ATT/SMP 明文）
- **手机扫描自动填档案**（adb 读 bt_config.conf，一键生成 target JSON）
- **NiceGUI 可视化控制台**（四页面：控制台/仪表盘/结果/历史）

配套文档：《[设计.md](设计.md)》（架构与平台事实）、《[进度.md](进度.md)》（当前状态）、《[使用指南.md](使用指南.md)》（详细使用手册，本文为摘要版）、《[固件开发避坑指南.md](固件开发避坑指南.md)》（编译烧录）。

---

## 硬件与固件

### 支持的硬件

以下任一设备（功能等价，本项目实测为 **CC2652R1F LaunchPad**）：

- TI CC26x2R LaunchPad：<https://www.ti.com/tool/LAUNCHXL-CC26X2R1>
- TI CC2652RB / CC1352R / CC1352P LaunchPad（链接见上游 README）
- TI CC2652R7 / CC1352P7 / CC2651P3 / CC1354P10 LaunchPad
- SONOFF CC2652P USB Dongle Plus / EC Catsniffer V3

### 依赖

- **ARM GNU Toolchain**（arm-none-eabi）：<https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads>
- **TI SimpleLink Low Power F2 SDK 8.30.01.01**：<https://www.ti.com/tool/download/SIMPLELINK-LOWPOWER-F2-SDK/8.30.01.01>
- **TI DSLite Programmer**（或用 UniFlash GUI）
- Python 3.9+：`pip install pyserial pyyaml pycryptodome nicegui`

> 不想搭编译环境？直接烧预编译固件（本项目补丁固件 **1.12.0**，见仓库根 `*.hex`）。注意：预编译固件要配对应版本的 Python 代码。

### 固件编译

```bash
cd fw
make            # 默认 CC26x2R；其他板型指定 PLATFORM=xxx
make clean      # 换 PLATFORM 前必须先 clean
```

SDK 不在默认目录时，改 makefile 里的 `SIMPLELINK_SDK_INSTALL_DIR`。

### 固件烧录（LaunchPad）

```bash
cd fw
make load       # DSLite 烧录（其他板型加 PLATFORM 参数）
```

或用 UniFlash GUI 烧 `sniffle.hex`。烧完 `python3 python_cli/version_check.py` 确认版本为 **1.12.0**（补丁固件含 0x28 门控 / TX 队列满上报 / TERMINATE reason / INITIATING 重试 / RX 8 深队列）。

---

## 快速开始（三步）

### 第 1 步：填目标档案

编辑 `att-fuzz/targets/<name>.json`：

```json
{
  "name": "headphone",
  "mac": "A4:C1:38:xx:xx:xx",
  "search_string": "",
  "mac_random": true,
  "conn_interval": 12,
  "latency": 0,
  "connect_timeout": 10
}
```

`mac` / `search_string` 至少填一个。`mac_random`：1=随机地址（多数耳机），0=public。不确定先跑 `--probe`。

### 第 2 步：冒烟（发现 GATT）

```bash
python3 att-fuzz/runner.py --target att-fuzz/targets/headphone.json --discover-only
```

预期：`ll_max=251 att_mtu=247` + 服务列表。这一步验证串口/固件/连接/发现全链路。

### 第 3 步：首跑（50 例冒烟）

```bash
python3 att-fuzz/runner.py --target att-fuzz/targets/headphone.json --max-cases 50
```

产物在 `att-fuzz/logs/run-<时间戳>/`。分类分布应大量 `ERROR_RESPONSE` + 少量 `OK_RESPONSE`，几乎无 `TIMEOUT`。确认无异常再放开全量或过夜。

---

## 目标档案 targets/*.json

| 字段 | 说明 |
|---|---|
| `name` | 档案名（也是文件名） |
| `mac` | 目标地址（书写序 `AA:BB:CC:DD:EE:FF`） |
| `search_string` | 广播名片段（地址轮换的耳机优先用这个） |
| `mac_random` | 1=随机地址，0=public |
| `conn_interval` | 连接间隔 ×1.25ms（建议 12~24） |
| `latency` | 外设延迟（0=每事件必响应，判定最稳） |
| `connect_timeout` | 连接超时秒数 |
| `phone_mac` | **冒充用**：手机 public MAC（书写序） |
| `ltk` | **冒充用**：bond LTK（32 hex 字符，从 bt_config 提取） |
| `bt_keys` | **冒充用**：密钥文件路径（相对路径解析到 `targets/` 下，如 `bt_keys/vivo.conf`） |
| `wall_ledger` | **冒充用(可选)**：阶段一台账路径，供 0x05 墙 handle 加载 |
| `keys_mac` | **冒充用(可选)**：bt_config 里设备 MAC，99% 与 `mac` 相同，留空自动用 `mac` |

密钥文件放 `att-fuzz/targets/bt_keys/`，从手机 root 提取 `/data/misc/bluedroid/bt_config.conf` 复制过来即可。

---

## Fuzzer CLI 全量参考

```
python3 att-fuzz/runner.py \
  --target att-fuzz/targets/<name>.json \
  [--strategy att-fuzz/strategies]        # 策略目录/文件,默认全目录
  [--seed 1]                              # 确定性种子
  [--max-cases 0]                         # 0=全量
  [--rounds 0] [--round-budget 100]      # 变异轮数/每轮预算
  [--outdir logs/run-xxx] [--serport /dev/ttyACM0]
  [--discover-only] [--probe]
  [--replay <PDU_HEX>] [--replay-case <ID>] [--ledger <path>]
  [--impersonate] [--bt-keys <file>] [--keys-mac <MAC>]
  [--phone-mac <MAC>] [--imp-duration 0] [--wall-ledger <path>]
  [--server] [--server-name "..."] [--server-duration 0] [--adb-serial <serial>]
  [--sniff-pairing] [--sniff-duration 0] [--sniff-mac <MAC>] [--sniff-hold]
  [--decrypt <pcap>] [--ltk <hex>]
  [--scan-btconfig] [--save-target <name>]
  [-v]
```

### 模式 1：直连 Fuzz（默认）

免配对直连 → GATT 发现 → 确定性语料 → 可选变异轮。

```bash
python3 att-fuzz/runner.py --target att-fuzz/targets/headphone.json
python3 att-fuzz/runner.py --target ... --strategy att-fuzz/strategies/offsets.yaml   # 只跑某层
python3 att-fuzz/runner.py --target ... --rounds 3 --round-budget 100                # 变异轮
python3 att-fuzz/runner.py --target ... --replay-case h-read-0000 --ledger logs/run-xxx/ledger.jsonl  # 复现
```

### 模式 2：加密冒充（`--impersonate`）

用手机 bond LTK 冒充手机地址，加密链路绕过 0x05 认证墙，跑认证面语料。

```bash
# 方式 A：LTK 内联在 target JSON（扫描手机自动生成档案默认用这个）
python3 att-fuzz/runner.py --target att-fuzz/targets/vivo_tws.json --impersonate

# 方式 B：命令行指定密钥
python3 att-fuzz/runner.py --target ... --impersonate \
  --bt-keys bt_keys/vivo.conf --keys-mac 64:44:7B:EE:41:F4 --phone-mac 00:C3:0A:02:6C:24
```

产物：`fuzz_ledger.jsonl`（语料台账）+ `impersonation_ledger.jsonl`（握手/连接事件）+ `capture.pcap` + `gatt_enc.json`。

### 模式 2b：扫描手机自动填档案（`--scan-btconfig`）

插手机 USB + root，adb 拉取 bt_config.conf，列出所有 bond 设备，自动生成含 mac/phone_mac/ltk 的 target JSON：

```bash
python3 att-fuzz/runner.py --scan-btconfig --adb-serial <序列号>
python3 att-fuzz/runner.py --scan-btconfig --save-target vivo_tws   # 保存档案
```

GUI 冒充模式也有"扫描手机"按钮（adb-serial 输入 + 结果下拉 → 自动填编辑器）。

### 模式 3：反向角色（`--server`）

板子伪装 GATT server 广播，手机连入后回正常响应，logcat oracle 检测手机侧崩溃：

```bash
python3 att-fuzz/runner.py --target ... --server \
  --server-name "Sniffle Server" --server-duration 300 --adb-serial <序列号>
```

产物：`server_ledger.jsonl` + `crashes/`（oracle 命中落盘）。

### 模式 4：被动嗅探配对（`--sniff-pairing`）

嗅探 SMP 交换 → legacy 密钥推导：

```bash
python3 att-fuzz/runner.py --sniff-pairing --sniff-mac <MAC> --phone-mac <MAC> [--sniff-hold]
```

### 模式 5：离线 pcap 解密（`--decrypt`）

加密 BLE pcap + LTK → ATT/SMP 明文，不碰硬件：

```bash
python3 att-fuzz/runner.py --decrypt capture.pcap --bt-keys bt_keys/vivo.conf --keys-mac <MAC>
python3 att-fuzz/runner.py --decrypt capture.pcap --ltk <32-hex>   # 直接给 LTK
```

LTK 字节序：bt_config dump 序（小端）需整体反转才是密码学大端序，引擎自动双序尝试、MIC 裁定。产物：`decrypt_report.json` + `decrypted_sdu.jsonl`。

---

## 攻击面与语料

| 层 | 文件 | 内容 |
|---|---|---|
| ① opcode | `strategies/opcodes.yaml` | 保留 opcode、合法\|0x40/0x80 翻转、0xE0-0xFF 原始注入 |
| ② handle | `strategies/handles.yaml` | 0x0000/0xFFFF/边界、真实 handle ±1、发现类 start>end |
| ③ value | `strategies/values.yaml` | 长度 0/1/20/MTU±N × 内容模式 |
| ④ offset | `strategies/offsets.yaml` | 0/1/baseline±1、0x7FFF/0x8000/0xFFFF |
| ⑤ MTU 协商 | `strategies/state_machine.yaml` | 未协商/重协商到极小值（稳定损害） |
| ⑥ Prepare 队列 | `strategies/prepare_execute.yaml` | 队列灌满/空队列 Execute/混合 offset/非法 flags |
| ⑦ CCCD | `strategies/cccd.yaml` | 无 2902 特征写 0x0100、值集单发 |
| ⑧ 发现类 | `strategies/discovery.yaml` + `strategies/l2cap.yaml` | Read By Group/Type 越界、L2CAP 帧头欺骗 |

语料锚点：`${each.value}` / `${each.decl}` / `${each.cccd}` / `${mtu-3}` / `${baseline_len+1}` 等，配合 `filter: writable|readable` 按 GATT 地图自动展开。**同 seed 同 GATT 地图 → 语料完全确定**（复现靠它）。

变异引擎（`--rounds N`）：签名库驱动（`logs/signatures.json`），4 类算子（位翻转/字节插入/值替换/时序门控），能量加权（告警层优先）。

---

## 输出产物

| 文件 | 内容 |
|---|---|
| `ledger.jsonl` | 直连 fuzz 每用例一行（case_id/分类/opcode/handle/replay.pdu） |
| `fuzz_ledger.jsonl` | 加密冒充语料台账（格式同 ledger.jsonl） |
| `impersonation_ledger.jsonl` | 冒充事件流（bond_loaded/enc_engaged/conn_start/link_drop） |
| `server_ledger.jsonl` | 反向角色"手机请求→我方响应"对 |
| `capture.pcap` | 全量 LL 无线包（DLT 256，Wireshark 打开） |
| `transport.jsonl` | 传输层原始事件 |
| `gatt_map.json` / `gatt_enc.json` | 发现/加密链路 GATT 地图 |
| `crashes/` | logcat oracle 命中的崩溃窗口 |

**分类含义**：

| 分类 | 含义 | 动作 |
|---|---|---|
| `OK_RESPONSE` | 正常响应 | 无 |
| `ERROR_RESPONSE` | ATT Error Response | 无 |
| `TIMEOUT` | 超时无响应 | 关注 |
| `DISCONNECT_TERM` | 目标发 TERMINATE（**reason=0x08 是"栈崩了"强信号**） | 立即复现 |
| `DISCONNECT_SUP` | 目标静默（supervision timeout） | 复现 |
| `TX_QUEUE_FULL` | 传输层错误，用例无效 | 重跑 |
| `HEALTH_DEGRADED` | 后置健康检查异常 | 重点看 |
| `ATT_FREEZE` | ATT 层冻结（LL 存活，重连恢复） | 立即复现——最高价值信号之一 |

**崩溃分析**：看台账分类分布 → `--replay-case` 复现单条 → pcap 用 marker 定位帧 → 最小化。

---

## 原版 Sniffle 工具

在 `python_cli/` 下，与 fuzzer 共享库但独立运行，串口锁同样约束：

| 工具 | 用途 | 示例 |
|---|---|---|
| `sniff_receiver.py` | 主力嗅探器（广播+连接→pcap） | `python3 python_cli/sniff_receiver.py -c 37 -m <MAC> -o cap.pcap` |
| `scanner.py` | 主动扫描器（发 SCAN_REQ，表格输出） | `python3 python_cli/scanner.py -c 37` |
| `initiator.py` | 连接发起测试 | `python3 python_cli/initiator.py -m <MAC>` |
| `relay_master.py`+`relay_slave.py` | 双板 relay MITM | 见 `python_cli/` 源码头部注释 |
| `advertiser.py` | 广播测试 | `python3 python_cli/advertiser.py` |
| `pcap_decoder.py` | pcap 离线解码（不解密） | `python3 python_cli/pcap_decoder.py cap.pcap` |
| `sniffle_extcap.py` | Wireshark extcap 插件 | 加入 Wireshark extcap 目录 |
| `reset.py` | 固件复位 | `python3 python_cli/reset.py` |
| `version_check.py` | 固件版本检查 | `python3 python_cli/version_check.py` |

---

## GUI 可视化控制台（NiceGUI）

```bash
pip install nicegui
python3 att-fuzz/gui/app.py               # 浏览器 http://localhost:8765
python3 att-fuzz/gui/app.py --native      # 原生窗口(需 pywebview)
python3 att-fuzz/gui_demo.py              # 离线演示(FakeHw,无硬件)
```

**四页面**：

- **控制台**：串口/固件、目标档案编辑（含扫描手机按钮）、模式选择器（直连/加密冒充/反向角色）、策略横排 + seed/max-cases/rounds/round-budget、探测/发现/开始、暂停/继续/停止、GATT 树、日志
- **实时仪表盘**：进度/速率统计卡、分类分布环形图、连接健康（含**加密状态** + **ATT 冻结计数** chip）、告警列表、传输层事件流（kind 过滤）
- **结果与重放**：多台账自动探测、分类/层/关键词过滤、行详情、Replay ×1/×5（仅直连台账）、Markdown 导出
- **历史会话**：run 列表、双会话分类分布对比图、摘要导出

串口按任务懒占用：GUI 空闲不碰串口，CLI 可正常用；任务运行期间由锁文件互斥。

---

## 测试与维护

### 离线测试（不需要板子，改 core 后必跑）

```bash
python3 att-fuzz/tests/test_offline.py   # 编解码/语料展开/加密/冒充握手/多台账
python3 att-fuzz/tests/test_dryrun.py    # FakeHw 走通全流程(含 controller)
```

### 加语料

`strategies/` 加 yaml（见"攻击面与语料"语法）。展开规模 = 模板数 × 命中特征数。

### 换目标设备

复制 `targets/<name>.json` 改参数即可。冒充目标额外填 `phone_mac` + `ltk`（或 `bt_keys`）。语料按运行时 GATT 地图自动展开，**不写死任何设备信息**。

---

## 常见问题

| 现象 | 处理 |
|---|---|
| `Sniffle device not found` | 板子没插/udev 没生效；`--serport` 手动指 |
| 连接失败且日志看不到广播 | **MAC 字节序**：固件用线序（小端），`_parse_mac` 已处理，自写脚本须自己反转 |
| 连接失败 0x1408 | 嘈杂环境 initiator 被干扰；固件 1.12.0 补丁已处理，确认版本 |
| 台账大量 `TIMEOUT` | 目标反应慢，`conn_interval` 调大（如 24） |
| `HEALTH_DEGRADED` 高频 | 健康检查锚点选了动态值特征，改用 Device Name |
| 加密冒充握手失败 | 密钥不匹配/bond 过期，重新提取 bt_config.conf |
| ATT_FREEZE | 无害读预热到 event ~1100 触发（每连接 ATT 死锁），重连恢复 |
| pcap 解密 MIC 全失败 | LTK 字节序/密钥不匹配；引擎自动双序尝试 |
| GUI 冒充缺参数 | target JSON 补 `phone_mac` + `ltk`（或 `bt_keys`） |

---

## 许可

本项目是 nccgroup/Sniffle 的分支扩展，上游版权归 NCC Group（作者 Sultan Qasim Khan），继续以 **GPLv3** 发布。
