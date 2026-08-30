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
  (`value`/`decl`/`cccd`/`baseline_len`/`mtu`,each 形式为 `each.*`)。
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
  - `observe`: 步间观察窗(秒),收到本步响应后等待再走下一步,给迟滞留时间。
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
