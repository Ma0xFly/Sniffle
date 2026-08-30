# AGENTS.md — Sniffle ATT/GATT Fuzzer

仓库级 Agent 规则。项目背景、设计与操作细节见仓库根四份中文文档：《设计.md》（设计与平台事实）、《进度.md》（当前状态与下一步，状态类信息唯一维护处）、《使用指南.md》（操作手册）、《固件开发避坑指南.md》（编译烧录）。

## 项目速览

- nccgroup/Sniffle（CC2652R1F BLE 嗅探器）之上的 ATT/GATT 黑盒 Fuzzer：`att-fuzz/`（Python 工具链）+ `fw/`（补丁固件 1.12.0）+ `python_cli/sniffle/`（host 侧库）。
- 硬件：CC2652R1F LaunchPad，数据串口 `/dev/ttyACM0`；GUI/CLI/多会话靠 serial_lock 跨进程互斥，同一时间只有一个任务能上机。
- 当前目标：vivo TWS 3e（免配对直连，档案 `att-fuzz/targets/vivo_tws.json`）。

## 开发纪律

- 修改 `att-fuzz/core/` 后必跑离线测试（不需板子）：`python3 att-fuzz/tests/test_offline.py`、`python3 att-fuzz/tests/test_dryrun.py`。
- BLE MAC 用线序（小端）：书写序 `64:44:7B:EE:41:F4` → 线序 `f441ee7b4464`。`transport._parse_mac` 已自动处理；自写脚本直调 `cmd_mac`/`initiate_conn` 必须自己反转。
- 固件编译换 PLATFORM 后必须先手动删除生成文件再 make（见《固件开发避坑指南.md》§1）。
- 运行产物（`att-fuzz/logs/`、hex、`__pycache__`、固件构建中间文件）不进 git。

APM_RULES {

## Version Control

- 基线分支：`att-fuzz-fw`。`master` 保持上游（nccgroup/Sniffle）对照，不直接开发。
- 任务从基线分支拉 feature 分支，命名 `<域>/<短描述>`（如 `att-fuzz/gui-pcap`、`fw/terminate-reason`）。
- 提交消息 `<域>: <小写描述>`（如 `att-fuzz: fix gui pcap`、`fw: report terminate reason`），域取 `att-fuzz`、`fw`、`python_cli`、`docs`、`chore`。
- 不向 origin push（origin 是上游仓库）。

## Documentation

- 状态类信息只写《进度.md》（更新约定见文件头）；设计变更先核对《设计.md》§二平台事实再动笔。

}
