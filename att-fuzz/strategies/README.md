# Strategies — 语料模板格式与执行语义

模板为 YAML 列表,由 `core/corpus.py` 的 `expand()` 按目标 GATT 地图展开。
本文档是接口规范:改格式前先改这里,保持"下一个实现者无需追问"的粒度。

## 单 PDU 用例(既有格式)

```yaml
- id: h-read-0000        # 全局唯一;${each.*} 展开后自动加 "@<handle>" 后缀
  layer: handle          # 攻击面分层(handle/offset/opcode/value/state-machine/...)
  op: read_req           # 构造器见 core/corpus.py _build_pdu
  handle: 0              # 字段可为整数或表达式
  filter: readable       # 仅 ${each.*} 模板需要: readable / writable
```

- 表达式:`${var}`、`${var+N}`、`${var-N}`、`${var*N}`;变量见 `_char_vars`/`_global_vars`
  (`value`/`wvalue`/`decl`/`cccd`/`baseline_len`/`mtu`,each 形式为 `each.*`;
  `value`=known-good 锚点,`wvalue`=首个可写特征值句柄——缓冲/灌包类用例锚点)。
- `value: {len, pattern}` 支持 zero/ff/incremental/random/fmtstring/ascii,
  random 由 `seed+case_id` 驱动,确定性可复现。
- 去重:PDU 字节相同的用例只保留首条(对目标等价,白烧连接不值得)。
- `no_mtu_negotiate: true`(可选,任何用例可加):该用例要求**未协商链路**
  (连接后不自动 DLE+MTU,以 LL 27 / ATT MTU 23 态执行)。

## 序列用例(steps)

一个用例 = 有序多步,逐步注入、逐步记录、用例级聚合判定。

```yaml
- id: sm-mtu-reneg-2x
  layer: state-machine
  steps:
    - {op: exchange_mtu_req, mtu: 517}
    - {op: exchange_mtu_req, mtu: 517, observe: 0.5}
```

- 每步字段与单 PDU 模板同构(`op` + 构造参数,或 `payload: "<hex>"` 裸字节步)。
- 步级可选字段:
  - `expect_response`: 默认按 op 推断(write_cmd → false,其余 true);
  - `observe`: 步间观察窗(秒),收到本步响应后等待再走下一步,给迟滞留时间;
  - `repeat: N`: 本步展开为 N 个同构步(flood 类用例靠序列节奏,不绕过发端限速)。
- `${each.*}` 可用在任意步的字段里;case 级 `filter` 决定锚点特征范围。
- 展开与去重:整条序列一起展开;全步 PDU 组合相同的序列才判重。
- `no_mtu_negotiate: true` 同样适用于序列用例(整条序列都在未协商链路上)。
- 纪律:no_mtu_negotiate 用例集中放在 yaml 末尾——协商状态切换 = 断链重连,
  来回切换会产生多余重连。

## 执行语义(session 层)

- 逐步流程:注入 → 等响应(按步 expect_response)→ 分类 → 记录 → observe 窗口。
- 掉链(TERMINATE/supervision)或传输错误在任一步发生:该步定用例分类,停止后续步并恢复。
- 全部步执行完:后置健康检查,异常则用例升级为 HEALTH_DEGRADED。
- 用例级分类 = 各步最差(优先级 DISCONNECT_SUP > DISCONNECT_TERM > TX_QUEUE_FULL >
  HEALTH_DEGRADED > TIMEOUT > ERROR_RESPONSE > OK_RESPONSE);
  `alert_step` = 首个达到该分类的步(0 起)。用例级 opcode/handle/响应等字段
  取 alert_step 的值,即最小复现步。

## 台账 schema(向后兼容)

- 单 PDU 用例记录格式不变。
- 序列用例额外字段:
  - `case_kind: "sequence"`;
  - `alert_step`: 决定用例分类的步(0 起);
  - `steps`: 逐步数组,每步含 `step`(序号)、`op`、`opcode`/`handle`/`offset`/
    `value_len`/`value_hash`(由 PDU 解出)、`event`、`expect_response`、
    `response_pdu`、`error_code`、`terminate_reason`、`classification`、`notes`。
- replay 信息同步扩展:
  - 单 PDU:`replay: {pdu, expect_response}`(expect_response 现已透传,修复了
    write_cmd 类重放强制等响应的 TIMEOUT 伪影);
  - 序列:`replay: {kind: "sequence", steps: [{pdu, expect_response, observe}, ...]}`。
    CLI `--replay-case` 两种格式都支持;GUI 重放目前仅单 PDU 格式。

## 会话协商选项

- `FuzzSession(..., negotiate_mtu=False)`:连接与恢复重连都跳过
  `setup_data_size()`(DLE+Exchange MTU),发现照常(默认 MTU 23 足够)。
- fuzz 主循环按用例 meta 自动调 `ensure_negotiation(want)` 切换协商状态:
  状态不符时期望性断链(泵掉 terminate 事件),下一条用例的前置健康检查按
  新状态重连。默认行为(全程协商)不变。
- 未协商链路上健康检查的基线对比用前缀匹配(响应在 MTU 23 下可能截断)。

## 变异模式(core/mutator.py,runner --rounds)

签名驱动变异:黑盒拿不到 coverage,AFL 式反馈换成响应签名当伪覆盖
(`signature = 分类|响应opcode|error_code|term_reason|hc异常`,台账 signature 列)。

- **`--rounds N`**:N = 第一轮确定性语料之后追加的变异轮数(默认 0)。
  `--round-budget B`(默认 100)= 每轮预算用例数,预算耗尽进下一轮或停止。
- **种子池**:产生新签名的用例 + 全部告警用例(`core.mutator.collect_seeds`),
  从当前 run 台账累积。
- **能量调度**(AFL 式,反馈源换成签名):种子能量 = 历史告警加权
  (告警过的 opcode/handle/layer 高能量)+ 签名新颖度(库中没见过 +3)+
  重复签名降权(永远同一错误码,`repeat_penalty`)。
  `SignatureDb` 跨 run 累积于 `att-fuzz/logs/signatures.json`(git 忽略),
  `scan_runs` 扫所有 run 台账,幂等只增。
- **变异算子**(不做纯随机字节--乱翻 opcode 退化成未知 opcode 轰炸,与①层重复):
  - `_flip_params`:bit/byte 翻转**限参数区**(pdu[1:]),不碰 opcode 字节;
  - `_boundary`:handle/offset 边界邻近变异(±1/±2/×2 及 0x0000/0xFFFF 等边界间跳);
  - `_random_len`:随机长度插值([0, MTU-3],值确定性 incremental);
  - `_timing`:gate_at 随机化(打散到不同连接事件)+ 同事件多发(两条 PDU 同 gate_at,
    复现 SweynTooth 类死锁)。
  每种子随机组合 1-2 个非时序算子 + 概率加时序算子。
- **case_id 命名**:`mut-r<round>-<n>`,同 seed 同地图逐字节一致(可 replay)。
- **时序门控**:`CaseStep.gate_at`(相对注入时刻 cur_event 的偏移,None=不门控;
  同值 = 同事件多发)。`run_sequence` 注入时转绝对 `cur_event + gate_at`,
  台账步骤与 replay 记录相对偏移,`--replay-case` 按门控序列重放。
- **变异轮即长会话**:长会话累积(~900 event)+ 队列压力才触发 ATT 冻结,
  变异轮天然是长会话,ATT_FREEZE 是高价值猎物。

## L2CAP 帧欺骗与 raw 注入

平台事实:固件全链路无 L2CAP 层,分片/重组/MTU 跟踪全在 host 侧
(`transport._L2capReassembly`);单帧 ATT PDU ≤247,`transport.inject` 自动包
4 字节 L2CAP 头并真实计算长度。**收方向**(发向目标)是攻击对象——目标栈按
L2CAP 头声明长度重组 SDU,谎报帧头可让它分配错误缓冲/等待不存在的字节。

- **`transport.inject_raw(fragments, gate_at=None)`**:原始 LL 帧序列注入,
  `fragments = [(llid, payload_bytes), ...]`,payload 含自构 L2CAP 头(长度可谎报)。
  只做 TX 限速与(可选)门控,不代头、不分片;`inject` 行为不变。
- **用例格式**(`strategies/l2cap.yaml`):序列步用 `raw` 字段,
  `{raw: [{llid: 2, payload: "<hex 含 L2CAP 头>"}, {llid: 1, ...}], observe: N}`。
  L2CAP 头 = len(2 小端) + cid(2 小端,ATT=0x0004) + ATT。
- **欺骗形态**:声明长度 > 实际(半截 SDU 等待)、< 实际(多余续条)、只发续条
  (LLID=1 无起始)、只发起始帧无续条、超长声明流式灌包(接近 65535)。
- **oracle**:目标对协议外信号的行为——TIMEOUT/ATT_FREEZE(链路存活无响应)/
  掉链。台账步骤记录 `frames`(llid+payload hex),`--replay-case` 按帧序列重放。


