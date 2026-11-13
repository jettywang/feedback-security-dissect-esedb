# 文本索引取证实验：排序键等价 vs 错误匹配

本目录用**可运行实验**回答一个取证问题：通过文本索引查到的记录，其原始文本
与查询字符串并不逐字节相同，这究竟是排序规则下的**数据库等价**，还是错误匹配。

结论先行：**这是排序规则定义的数据库等价，不是错误匹配。** ESE 文本索引里存的
不是原始字符串，而是归一化后的排序键（sort key）；cursor 的“精确查询”比较的是
排序键的字节，而不是原始文本，也不是 Python 的 `str ==`。

## 运行方式

```sh
# 打印五组对照实验（原始字节 / 编码键 / 命中记录）
.venv/bin/python -m experiments.run_key_equivalence

# 在随库真实 ESE 文件上验证：重建键 == 磁盘节点键、重复键、cursor 定位
.venv/bin/python -m experiments.validate_on_fixtures

# 断言版（CI）
.venv/bin/python -m pytest -q -o addopts= tests/test_experiments_collation.py
```

## 代码追踪：从查询值到命中记录

1. `Cursor.search(**kwargs)` → `Index.make_key(kwargs)`
   （`dissect/esedb/cursor.py:67`、`dissect/esedb/cursor.py:79`）。
2. 文本列进入 `encode_key` → `_encode_text`
   （`dissect/esedb/index.py:140`、`dissect/esedb/index.py:261`），分两条路径：
   - ASCII / Western（代码页 20127 / 1252）：`value.upper().encode()` 后追加 `0x00`，
     即只做大小写折叠，**不**走 LCMapString。
   - Unicode（代码页 1200）：`map_string(value, LCMapFlags, locale)`
     （`dissect/esedb/lcmapstring.py:85`），基于 Wine 排序表 `sorting_table.table`
     生成排序键，结构为 `主权重 0x01 重音权重 0x01 大小写权重 0x01 ... 0x00`。
3. 每个数据段以 `0x7f`（`bPrefixData`）开头；键按 `KeyMost`（旧库默认 255）截断
   （`Index.make_key`，`dissect/esedb/index.py:107`）。
4. `BTree.search(key, exact=True)` 在叶子节点上要求 `key == node.key`
   （`dissect/esedb/btree.py:129`）。`find_node` 注释明确：B 树键比较与 Python
   `bytes` 比较 1:1——先比数据再比长度（`dissect/esedb/btree.py:150`）。
5. 次级索引命中后，`Cursor._node` 再用节点数据（聚簇键）回到主 B 树解析记录
   （`dissect/esedb/cursor.py:41`）。

因此“精确”的含义是 **归一化排序键逐字节相等**。

## 随库真实索引的排序标志

`text.edb`、`index.edb`、`Current.mdb`、`Windows.edb` 中所有文本索引均为
`LCMapFlags = 0x30401`，locale `en-US`：

| 标志 | 含义 | 对等价性的影响 |
| --- | --- | --- |
| `LCMAP_SORTKEY` (0x400) | 生成排序键 | 必须，否则 `map_string` 抛 `NotImplementedError` |
| `NORM_IGNORECASE` (0x1) | 忽略大小写 | `abc` ≡ `ABC` |
| `NORM_IGNOREWIDTH` (0x20000) | 忽略全/半角 | `ABC` ≡ `ＡＢＣ` |
| `NORM_IGNOREKANATYPE` (0x10000) | 忽略平/片假名 | 假名等价（本实现对相关码位抛 `NotImplementedError`） |
| **未设置** `NORM_IGNORENONSPACE` (0x2) | 不忽略重音 | `e` ≢ `é` |

## 五组对照实验结果（`run_key_equivalence.py`）

所有短值同时保留三层信息：原始 UTF-16LE 字节、编码排序键、精确查询命中的记录 id。

| 对照 | 原始字节相同 | Python `str ==` | 数据库排序键相同 | 说明 |
| --- | --- | --- | --- | --- |
| 大小写 `abc`/`ABC` | 否 | 否 | **是** | 大小写权重被 `NORM_IGNORECASE` 屏蔽 |
| 全/半角 `ABC`/`ＡＢＣ` | 否 | 否 | **是** | `NORM_IGNOREWIDTH` 屏蔽宽度位 |
| 重音 `e`/`é` | 否 | 否 | **否** | 重音段保留 `0x02` vs `0x0e`；加 `NORM_IGNORENONSPACE` 后才相等 |
| 组合字符 `é`(U+00E9) / `e`+U+0301 | 否 | 否 | **否** | 组合记号产生独立重音权重序列，本实现不做 Unicode 规范化折叠 |
| 尾随 NUL `abc`/`abc\x00` | 否 | 否 | **是** | U+0000 在排序表中是 UNSORTABLE，被跳过 |

要点：

- **数据库等价集合 ⊃ Python 字符串相等集合 ⊃ 原始字节相等集合**（在默认标志下）。
  用 Python `str ==` 代替数据库比较会**漏报**合法命中（例如忽略大小写/宽度的场景）。
- 重音默认**不**被忽略，所以“忽略重音”不能想当然；它由具体索引的 `LCMapFlags` 决定。
- 组合字符（NFC/NFD）在这套 Wine 派生实现里不会被折叠，与 Windows 原生
  `LCMapStringEx` 的行为可能存在差异——跨实现取证时应以目标库实际排序键为准。
- 实验 4 显示 **KeyMost 截断**：当长文本占满键时，后续索引列（如整数 `Num`）根本
  不进入可比较键，不同 `Num` 的行会得到相同截断键而同时命中；这不是匹配错误，
  而是键长度上限的既定语义。

## 真实夹具验证（`validate_on_fixtures.py`）

- `index.edb` 的四个文本索引：用 `Index.key_from_record` 从记录重建的键，与叶子
  节点磁盘上的 `node.key` **逐字节一致**（0 个不一致），证明实验用的编码器就是
  线上落盘路径。
- `Current.mdb` 的 `Username_RoleGuid_TenantId_index`：5 条 CLIENTS 记录
  （主键 `0x4/0x8/0x11/0x12/0x13`）共享**同一个**次级索引排序键，原始用户名文本
  相同但属于 5 条不同记录（后续列 `Day204` 等不同）。这正是“排序键相等但后续列
  不同”的真实样本。
- `BTree.find_node` 对重复键**不是** `bisect_left` 语义：二分可能落在同键运行区的
  中间（实测落在索引 4，而同键区间是 1–5）。`Cursor.find_all` 通过先回扫到区间
  起点、再向前遍历整个同键运行区来返回全部命中（`dissect/esedb/cursor.py:137`）。
  因此需要“全部等价记录”时应使用 `find_all`，不要假设 `search` 落在首条。

## 后端接口契约建议

不修改任何现有排序规则的前提下，按取证语义区分两类需求，并在接口名/文档中显式标注：

### A. 需要“字节相同”（raw byte identity）

适用于：哈希对账、精确原件比对、需要区分大小写/全半角/重音/规范化形式的场景。

- 数据来源：`Record.get(column, raw=True)`，对文本列取**未解码的原始字节**
  （Unicode 列为 UTF-16LE，Western 为 cp1252）。
- 比较规则：`bytes(raw_a) == bytes(raw_b)`，**不要**先解码成 `str`，也不要经过
  `Index.make_key`。
- 不要使用索引 cursor 的 `search` 来实现该语义——它返回的是排序键等价集合，范围更宽。
- 建议接口：`find_exact_bytes(column: str, raw: bytes) -> list[Record]`，内部用
  `find_all` 取候选后再做原始字节过滤；或全表扫描配合 `Record.get(..., raw=True)`。

### B. 需要“数据库等价”（database collation equivalence）

适用于：复刻 ESE/Windows 搜索行为、按用户输入做大小写/宽度不敏感检索、需要与
原库 `JetSeek` 命中结果一致的场景。

- 数据来源：`Index.make_key({column: value})` 生成排序键，或直接 `Cursor.search` /
  `Index.search`（等价列）与 `Cursor.find_all`（需要全部同键记录或附加非索引列过滤）。
- 比较规则：归一化排序键的**字节相等**，即 cursor 的 `exact=True` 语义；不要用
  Python `str ==` 替代，否则会漏掉大小写/宽度等等价命中。
- 必须读取目标索引自身的 `LCMapFlags` / `LocaleName` / `KeyMost`，不能硬编码假设
  （例如重音是否忽略、键是否被截断）。
- 建议接口：`find_by_index(**columns) -> list[Record]`（文档明确“返回排序键等价的
  全部记录”），并对非索引列的额外条件继续走 `find_all` 的 `other_columns` 过滤。
- 多值列、截断键、重复键场景统一返回列表而非单条；需要单条时由调用方明确取
  `find_all(...)[0]` 并知晓它不保证是聚簇顺序的首条。

### 判定速查

| 后端诉求 | 用什么 | 比较对象 | 典型方法 |
| --- | --- | --- | --- |
| 原件字节相同 | 原始存储字节 | `bytes ==` | `Record.get(raw=True)` 后过滤 |
| 数据库排序等价 | 归一化排序键 | 排序键 `bytes ==` | `Cursor.find_all` / `Index.make_key` |
| 仅 Python 文本相等 | 解码后的 `str` | `str ==` | 两者都不能代表，勿用于取证判定 |

## 范围与未改动项

- 未修改 `lcmapstring.py`、`index.py`、`btree.py`、`cursor.py` 等任何库代码与排序规则。
- 实验全部通过复用生产编码器实现，存储层仅为内存模拟，便于注入受控短值。
- 已知实现边界（非本任务修复范围）：`map_string` 对 EXPANSION、EASTASIA_SPECIAL、
  JAMO_SPECIAL、DIGIT 及未开 `SORT_STRINGSORT` 的 PUNCTUATION 会抛
  `NotImplementedError`；这些码位的对照实验因此无法在本实现内构造。
