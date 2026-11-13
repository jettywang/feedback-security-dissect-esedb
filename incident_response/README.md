# ESE 数据库只读取证分析（无事务日志场景）

本目录基于 `dissect.esedb` 提供一套**只读**的 ESE（Extensible Storage Engine）
数据库应急响应分析方法。适用前提是：事件响应团队只拿到一个 `.edb`/`.dat`
数据库文件，**没有**配套事务日志（`ESE*.log`/`*.jrs`/`ESE*.chk`）。

## 不可逾越的两条红线

1. **绝不修改状态标志伪装修复。** 把数据库头的 `dbstate` 从
   `JET_dbstateDirtyShutdown(2)` 改成 `JET_dbstateCleanShutdown(3)` 只会让文件
   “看起来”干净，既不能回滚未提交事务，也不能补齐缺失的刷盘页，反而销毁了
   原始证据。本工具以 `rb` 打开文件，没有任何写路径，报告中
   `mutations_performed` 恒为空、`replay_attempted` 恒为 `false`。
2. **绝不做没有日志依据的重放。** ESE 的提交语义由预写日志（WAL）保证：
   重做（redo）已提交、撤销（undo）未提交都必须读取日志并对照检查点
   （`lgposConsistent`/`lGenMinRequired` 等）。没有日志时，任何“重放”都是
   凭空捏造事务边界，本工具明确不实现。

## 必须区分的两个概念

| 概念 | 含义 | 无日志时能否成立 |
| --- | --- | --- |
| 结构可解析（structurally parseable） | 字节能被解码成数据库头、页、B-tree 节点、记录 | 能。`dissect.esedb` 直接解析磁盘镜像，不依赖日志 |
| 事务已提交（transaction committed） | 该记录的修改已经过日志提交并处于一致检查点之上 | **不能**。只能给出 `indeterminate-without-logs` |

一条记录能被解码出来，只能证明“这些字节在采集时存在于磁盘页上”，**不能**
证明对应事务已提交。脏关闭后，页里可能同时混有：已提交并刷盘的数据、已提交
但尚未完整刷盘的数据、未提交事务写入后未回滚的痕迹。

## 文件清单

- `ese_forensics.py` —— 只读取证分析器（库 + CLI），输出分级报告（文本/JSON）。
- `build_contradictions.py` —— 仅读取仓库 fixture，在**副本**上构造状态矛盾；
  不触碰原始 fixture，不改写 clean 标志，不合成日志。
- `samples/` —— 由构造器生成的矛盾样本副本与原始对照样本。
- `samples_manifest.json` —— 每个样本被改动的字节偏移、字段与 SHA-256。
- `reports/` —— 每个样本的分级报告（`.txt` 人类可读、`.json` 机器可读）。
- `FORENSIC_REPORT.md` —— 分级报告样例与逐项解读。
- `EVIDENCE_CHECKLIST.md` —— 进一步取证所需证据清单，以及缺日志为何阻断结论。

## 运行方式

```sh
# 1) 用 fixture 的只读副本构造矛盾样本（原始 tests/_data 不被修改）
.venv/bin/python incident_response/build_contradictions.py

# 2) 对任意 ESE 数据库做只读分析
.venv/bin/python incident_response/ese_forensics.py <database.edb>
.venv/bin/python incident_response/ese_forensics.py <database.edb> --json --output report.json
```

测试：

```sh
.venv/bin/python -m pytest tests/test_forensic_triage.py -q -o addopts=
```

## 检查项与可回答的问题

分析器按四个层次组织检查，对应数据库头状态、页号、页时间、B-tree 链接四类信息。

### 1. 数据库头（主头 + 影子头）

- 魔数 `ulMagic == 0x89ABCDEF`、格式版本、页大小。
- 头部页传统 XOR 校验和（可完整复现）。
- `dbstate`：1 刚创建 / 2 脏关闭 / 3 干净关闭 / 4 转换中 / 5 强制分离 /
  6 新日志恢复中。
- `dbtimeDirtied`、`logtimeAttach/Detach/Consistent`、`lgposConsistent`。
- 主头与**影子头**（物理页 2）逐字段比对：`dbstate`、`dbtimeDirtied`、
  `signDb.ulRandom`、`objidLast` 等。
- 日志代范围 `lGenMinRequired/lGenMaxRequired/lGenMaxCommitted/lGenMinConsistent`。

能回答：文件是不是 ESE 库、头部是否自称干净、主副头是否来自同一次刷盘、
是否留下一致检查点指针。不能回答：某个具体事务是否提交。

### 2. 页号与校验和

- 逻辑页号 = 物理页号 − 2（物理页 1/2 为主/影子头）。
- 现代 `XECHECKSUM` 的 **XOR 分量可完整复现**：计算时把 8 字节校验和槽位视为
  `(逻辑页号, 0)`，因此校验和与页号绑定，页被挪位置即失效。小页（≤8K）为整页
  覆盖；本仓库 fixture 已逐页验证该公式。
- 旋转 ECC 分量、以及大页（32K）`PGHDR2.rgChecksum` 的多块校验和属于引擎内部
  算法，本工具**不猜测**：大页统一标注 `engine-validated-only`，绝不因无法复现
  而误报损坏。
- 头部页使用可完整复现的传统 XOR 校验和。

### 3. 页时间（dbtimeDirtied）

- 统计所有非零页的 `PGHDR.dbtimeDirtied` 分布，并与头 `dbtimeDirtied` 对照。
- 出现“页 dbtime 新于头 dbtime”且头声明脏关闭 → `PAGE_TIME_FUTURE`（CRITICAL），
  说明文件由不同时间点的页拼装而成（例如热拷贝、跨卷合并、残缺恢复）。
- 多个不同 dbtime 本身在活动库中正常，但证明各页来自不同刷盘点。

### 4. B-tree 与目录（catalog）

- 从目录根（逻辑页 4）及辅助索引根（7、10）递归遍历分支引用，检测越界子页、环。
- 叶子 `pgnoPrev/pgnoNext` 兄弟链互反性校验；越界链 → `BTREE_LINK_OOB`。
- 覆盖每张表的主树、**二级索引树**与**长值（LongValue）B-tree**，避免把合法
  长值页误判为孤儿。
- 目录引用的表根页不存在 → `CATALOG_DANGLING_ROOT`（CRITICAL）。
- 结构完好但无任何目录/索引/长值树引用的页 → `CATALOG_ORPHAN_PAGE`（MEDIUM），
  这类页仍可作为**残留数据证据**被 carving，但没有目录项为其命名。

## 严重级别

- `CRITICAL`：自相矛盾到目录/页时间层面，数据库作为一致整体不可信。
- `HIGH`：脏关闭、校验和失败、主副头分歧、B-tree 断链等，阻断提交结论。
- `MEDIUM`：缺少一致 LGPOS、孤儿页等，降低完整性但不直接否定所有数据。
- `LOW`/`INFO`：背景事实与验证范围说明（例如大页校验和的验证局限）。

## 证据可用性结论（无日志）

**仍可作为证据：**

- 可解析页/记录中实际存在的字节及其内容（标注为“存在性证据”）。
- 数据库头中的创建时间、附加/分离时间、计算机名、数据库/日志签名随机数。
- 校验和通过的页（小页整页 XOR 可证未被改动/挪动）。
- B-tree 结构本身、目录元数据、表/列/索引定义。
- 孤儿页中可 carving 的残留记录、带删除标记（`TAG_FLAG.Deleted`）的节点。

**不能下的结论：**

- 某条记录的事务**已提交**或**已回滚**。
- 数据库在崩溃瞬间的**一致状态**是什么。
- 哪些页是“已提交但未刷盘”、哪些是“未提交写入”。
- 精确的事务顺序、提交时间线（页 dbtime 是数据库内单调计数器，不是墙钟时间）。
- 仅凭 `dbstate==3` 断言库完好——篡改样本证明干净标志可以与失败校验和并存。
