# 遥测分片恢复（4+2 纠删码）

仅使用 Python 3.11 标准库。纠删码（GF(256)，本原多项式 `0x11d`）全部自行实现，
不依赖任何第三方包，也不调用系统编码库。

- `ecd.py` —— 实现与命令行入口
- `acceptance.py` —— 独立编码的验收脚本（自建比特级 GF 乘法器，不复用 `ecd.py` 的查表编码）

```
python3 ecd.py recover --manifest manifest.json --capture capture.jsonl --output recovery.json
python3 -I acceptance.py
```

`python3 -I` 表示隔离模式，避免工作目录中的同名模块劫持标准库导入。

---

## 1. 输入格式

### 1.1 清单（manifest，JSON 文本）

```json
{
  "version": 1,
  "capture_id": "demo-capture",
  "blocks": [
    {"block_no": 0, "raw_length": 1234, "sha256": "…64 位十六进制…"},
    {"block_no": 1, "raw_length": 5678, "sha256": "…"}
  ]
}
```

约束：`version` 必须是整数 `1`（布尔、字符串、浮点 `1.0` 均拒绝）；`capture_id` 为非空字符串、
不含 NUL 与孤立代理项；`blocks` 为数组，`block_no` 必须等于其在数组中的位置（从 0 连续），
`raw_length` 为 `1..262144` 的整数，`sha256` 为 64 个十六进制字符。
清单中出现重复字段视为格式错误。

### 1.2 捕获（capture，JSONL）

每行一个对象，恰好需要以下五个字段（可额外携带其他字段，本实现不解释它们）：

| 字段 | 类型 | 规则 |
| --- | --- | --- |
| `capture_id` | string | 必须与清单一致，否则拒绝 |
| `block_no` | int | 必须指向清单中存在的块 |
| `shard_index` | int | `0..5` |
| `data_hex` | string | 恰为 `2*w` 个小写十六进制字符 |
| `crc32` | int | 无符号 32 位（`zlib.crc32` 的值） |

其中 `n = raw_length`，`w = ceil(n/4)`，即每片字节数 `w`。行内重复键、非 UTF-8、
空行、非对象、`NaN`/`Infinity` 均被拒绝。`crc32` 的布尔值（`true`/`false`）、负数、
超过 `2^32-1` 的值都非法。

### 1.3 业务流（由各块原字节按块序拼接后得到）

可用 shard 集解码并校验后，得到每个块的原字节 `raw_length` 字节；按 `block_no` 升序连接成
一个字节流，再按 UTF-8 JSONL 解析。字符与行都可以跨块。空流允许；非空流必须以 `LF` 结尾。

每行必须是一个对象，且字段集合**恰为**：

| 字段 | 类型 | 规则 |
| --- | --- | --- |
| `record_id` | string | 1..64 个 ASCII 字母/数字/`_`/`-` |
| `sensor_id` | string | 1..64 个 Unicode 码点，禁止 NUL，禁止孤立代理项 |
| `timestamp_ns` | int | `0 .. 2^63-1`（非负、有符号 64 位范围内） |
| `value_uv` | int 或 null | 有符号 64 位；**真实** `null` 才表示缺失 |

整数一律拒绝布尔（`true`/`false`），同样拒绝浮点（含 `0.0`、`1.0`）。
未知字段、缺失字段、重复字段、重复 `record_id`、空行、非法 UTF-8 均为错误。
JSON 不接受 `NaN`/`Infinity`。

---

## 2. 编码与恢复算法

### 2.1 分片

原块长度 `n`，`w = ceil(n/4)`。尾部补零到 `4w` 字节，顺序切成四个等长片
`D0..D3`。另生成两片校验片：

```
P = D0 ⊕ D1 ⊕ D2 ⊕ D3
Q = D0 ⊕ 2·D1 ⊕ 4·D2 ⊕ 8·D3
```

逐字节在 GF(256)（模 `0x11d`）中运算；`⊕` 即按字节异或。`Q` 的系数 `1,2,4,8` 是
`α^0..α^3`。生成矩阵的 6 行两两任意 4 行都线性无关，因此任意 4 片可恢复。

### 2.2 逐片裁决（按块、按索引独立进行）

对每个（块，索引）：
- 没有任何 CRC 合格内容 → **缺失**；
- 只有一种 CRC 合格内容 → **可用**（重复的相同内容只算一次，不加权）；
- 两种及以上不同 CRC 合格内容 → **冲突**，全部弃用。

坏 CRC 的行**不是**内容，只按 1 基行号记入该块的 `bad_crc_lines`；坏 CRC 不会制造冲突。

### 2.3 恢复条件（全部满足才成功）

1. 每个块**至少 4 个**可用片，否则 `insufficient_shards`；
2. 用可用片解出 `D0..D3` 后，把**全部 6 片**按生成矩阵重新编码；
3. 每个可用片都必须与重编码结果逐字节一致（禁止只挑 4 片自洽的子集），否则
   `redundancy_contradiction`；冲突值从不参与计算；
4. 补零区（`raw_length` 之后的字节）必须全零，否则 `padding_nonzero`；
5. 取 `raw_length` 字节，SHA-256 必须与清单相符，否则 `hash_mismatch`。

只有上述全部通过，才把各块按块序连接并解析业务流。

---

## 3. 输出

```json
{
  "capture_id": "demo-capture",
  "rows": [
    {
      "record_id": "rec-01",
      "sensor_id": "温度-甲",
      "timestamp_ns": 1700000000000000000,
      "value_uv": 1234,
      "line_no": 1,
      "byte_start": 0,
      "byte_end": 105
    }
  ],
  "blocks": [
    {
      "block_no": 0,
      "available": [1, 3, 4, 5],
      "missing": [0, 2],
      "conflicts": [],
      "recovered": [0, 2],
      "bad_crc_lines": []
    }
  ]
}
```

- `rows`：按原序（块序 + 行序）输出业务行，保留输入语义；`line_no` 为从 1 编号的业务行号，
  `byte_start` 为在**拼接流**中的零基字节起点，`byte_end` 为不含 `LF` 的右开终点，满足
  `byte_end - byte_start == 行内容字节长度`。
- `blocks`：按块序；`available` / `missing` / `conflicts` / `recovered` 均为升序 shard 索引；
  `recovered` 是"没有唯一可用值、由重编码补出"的索引（缺失与冲突的并集）；
  `bad_crc_lines` 为该块所有坏 CRC 捕获行的 1 基行号（升序）。
- 输出为 UTF-8、非 ASCII 字符原样保存。

## 4. 原子发布与错误定位

- 先完整计算，**成功后才发布**；目标路径已存在（文件、目录、符号链接）即
  `output_exists`。
- 发布通过同目录临时文件 + `os.link` 完成：写入成功前目标不会出现，中途失败不会留下
  半成品，并发创建的目标也只会让 `link` 返回 `EEXIST` 而不是被覆盖。
- 任何失败都以非零退出码结束，并在 stderr 打印一行 JSON：

```json
{"ok": false, "error": {"code": "hash_mismatch", "message": "...", "block_no": 0}}
```

错误对象按情况携带定位信息：`capture_line_no`（捕获行号，1 基）、`block_no`、
`business_line_no` + `byte_start`（业务流中的行号与绝对字节起点）、`shard_index`。

主要错误码：

| 码 | 含义 |
| --- | --- |
| `manifest_*` | 清单读取/编码/JSON/字段/版本/块号/长度/哈希/capture_id 错误 |
| `capture_io` / `capture_encoding` / `capture_json` / `capture_fields` / `capture_shape` | 捕获语法与结构 |
| `capture_duplicate_field` / `capture_empty_line` | 行内重复键 / 空行 |
| `capture_capture_id` / `capture_source` | 来源字段非字符串 / 与清单不符 |
| `capture_block_no` / `capture_shard_index` / `capture_data_hex` / `capture_crc32` | 值域 |
| `insufficient_shards` | 可用片不足 4 |
| `redundancy_contradiction` | 可用片与重编码不一致 |
| `padding_nonzero` / `hash_mismatch` | 补零区非零 / 哈希不符 |
| `stream_missing_final_lf` | 非空业务流未以 LF 结尾 |
| `business_*` | 业务行的编码/JSON/字段/类型/标识/重复等错误 |
| `output_exists` / `output_io` | 目标存在 / 发布失败 |

## 5. 独立验收（`acceptance.py`）

验收脚本**不复用** `ecd.py` 的编码器来生成期望值：它自带逐位 GF(256) 乘法器
（`gmul`，用移位与 `0x1d` 约减），独立实现编码，再以子进程方式调用 CLI。
覆盖：

- **全部 15 种双擦除**组合 × 4 个块，全部恢复；另有每块不同擦除的交叉组合；
- 少于 4 片、空捕获、全部坏 CRC 等拒绝路径；
- **冲突**：两种/三种不同 CRC 合格内容、重复内容不加权、坏 CRC 不制造冲突；
- **冗余矛盾**：错误数据片、仅 Q 矛盾、P 与 Q 联合才能发现的矛盾、5 片集合矛盾；
- **补零**：非零补零区拒绝、零补零区通过；
- **哈希**不符、清单块号/长度/哈希/版本/布尔字段等非法清单；
- `data_hex`/`crc32`/`block_no`/`shard_index`/`capture_id` 的类型与值域；
- **跨块字符**：把 4 字节 emoji 从中间切断、把 JSON 行切断后恢复；
- **行号与字节偏移**：每行 `byte_start`/`byte_end`，错误在后续块时的绝对字节起点；
- **末尾错误**：缺尾 LF（定位到最后一行及其起点）、末尾空行、末尾坏行；
- 业务行全部类型/标识/重复键/重复 `record_id`/NaN/浮点/孤立代理项规则；
- **发布语义**：目标已存在不动、失败无半成品、无临时文件残留、成功后二次发布被拒；
- 4 个数据片组成的 15 个四片子集与编码结果逐字节一致；
- `encode` 辅助子命令生成的捕获可直接被 `recover` 消费。

当前结果：

```
1006 checks, 121 CLI runs
ALL PASS
```

## 6. 设计取舍

- `capture_id` 的比对只做精确字符串比较；捕获行只要含五个必需字段即可，额外字段被忽略
  （业务行相反：字段集合必须精确相等，这是题干明确要求）。
- 业务行把 `record_id` 唯一性按整个拼接流（即所有块）判定。
- 行号/字节起点都相对拼接后的完整业务流，而不是相对单个块。
- 坏 CRC 只记行号，不额外发出错误；若其导致可用片不足，则由块级错误报告。
- 恢复阶段如有必要，使用最早的 4 个可用索引求解，但校验覆盖全部可用索引，因此
  "挑子集"不可能绕过矛盾检测。
