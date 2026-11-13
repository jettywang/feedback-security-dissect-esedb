# 分级报告样例（基于 fixture 只读副本构造的状态矛盾）

所有样本均由 `build_contradictions.py` 从仓库 fixture `tests/_data/basic.edb.gz`
的**只读副本**构造。原始 fixture 不被修改；每个样本的字节级改动与 SHA-256 记录在
`samples_manifest.json`。完整机器可读结果见 `reports/*.json`，人类可读全文见
`reports/*.txt`。本文给出浓缩样例与取证解读。

对照基线（未改动的干净库）：`structural=parseable`、
`transaction=header-asserts-clean-shutdown`、主副头一致、23 个非零页全部通过
XOR 校验和、无孤儿页。

---

## 样例 0：`basic.pristine.edb`（对照，干净关闭）

| 级别 | 代码 | 含义 |
| --- | --- | --- |
| INFO | HDR_CLEAN | 头部 `dbstate=3` 自称干净关闭 |
| INFO | SHADOW_MATCH | 主头与影子头逐字段一致 |
| INFO | PAGE_TIME_SPREAD | 页 dbtime 分布在 70..403，属正常多刷盘点 |

- 结构可解析：是。提交态：`header-asserts-clean-shutdown`（头部声明，且无矛盾证据）。
- 注意：即便如此，这仍是“头部声明 + 无反证”，不是对每条记录单独的提交证明。

---

## 样例 1：`dirty-shutdown.edb`（主头脏关闭，主副头矛盾）

构造：主头 `dbstate 3→2`、`dbtimeDirtied +40`、清零 `lgposConsistent` 与
`logtimeConsistent`；影子头保持干净。**不**改任何数据页。

| 级别 | 代码 | 关键证据 |
| --- | --- | --- |
| HIGH | HDR_DIRTY | `dbstate=JET_dbstateDirtyShutdown(2)` |
| MEDIUM | HDR_NO_CONSISTENT_LGPOS | `lgposConsistent` 为 null |
| HIGH | SHADOW_DIVERGENCE | 主头 dbstate=2/dbtime=443 vs 影子头 3/403 |

- 结构可解析：**是**（23 个非零页全部可解码、校验和全通过、5 张表记录都能读出）。
- 提交态：`indeterminate-without-logs`。
- 可作为证据：页内现存记录字节、表结构、创建/挂载/分离时间、签名随机数。
- 不能下的结论：这些记录是否全部已提交；崩溃瞬间的一致状态。
- 关键提醒：影子头还停在上一个干净刷盘点，主头已前进到更晚 dbtime，二者分歧本身
  就是“文件混合了两个头部刷盘点”的证据，不能挑一个顺眼的头采信。

---

## 样例 2：`mixed-time-page.edb`（页来自不同时间点）

构造：把逻辑页 14 的 `PGHDR.dbtimeDirtied` 改为比头还新（403→428），并重算该页
XOR 分量（旋转 ECC 分量刻意保留为过期），同时主头置脏。

| 级别 | 代码 | 关键证据 |
| --- | --- | --- |
| CRITICAL | PAGE_TIME_FUTURE | 页 14 dbtime=428 > 头 dbtime=403 |
| HIGH | HDR_DIRTY / SHADOW_DIVERGENCE | 脏头与干净影子头并存 |

- 结构可解析：**是**（页 14 本身仍能解码，记录可读出）。
- 提交态：`indeterminate-without-logs`。
- 含义：页的时间线不自洽，常见于热拷贝、跨时间点合并或残缺恢复。该页记录可作为
  “某时点存在过这些字节”的证据，但不能声称它与库中其他页属于同一一致快照。
- 不能下的结论：整库任一一致时点的内容；页 14 与其他页记录之间的引用完整性。

---

## 样例 3：`missing-catalog-target.edb`（目录引用缺失）

构造：把目录中表 `basic` 的根页（逻辑页 31）整页清零，目录行本身保留；主头置脏。

| 级别 | 代码 | 关键证据 |
| --- | --- | --- |
| CRITICAL | CATALOG_DANGLING_ROOT | 目录引用的根页 31 不存在为已分配页 |
| HIGH | HDR_DIRTY / SHADOW_DIVERGENCE | 脏关闭状态 |

- 结构可解析：**降级**。解析器不崩溃，但遍历表 `basic` 得到 0 条记录。
- 提交态：`indeterminate-without-logs`。
- 区分要点：“目录里有这张表的元数据”与“表的数据页可到达”是两件事。元数据行可解析，
  但数据目标缺失，因此**不能**声称该表无记录——只能说当前镜像中不可到达。
- 若页 31 是被释放而非清零，可能以孤儿页形式残留，可尝试 carving；本样例为整页清零，
  无残留可提取。

---

## 样例 4：`broken-btree-link.edb`（B-tree 兄弟链接断裂）

构造：把叶子页 13 的 `pgnoNext` 改写为越界值 999（文件只有 254 个逻辑页），重算
该页 XOR 分量，主头置脏。

| 级别 | 代码 | 关键证据 |
| --- | --- | --- |
| HIGH | BTREE_LINK_OOB | 页 13 `pgnoNext=999` 超出文件范围 |
| HIGH | BTREE_LINK | 页 14 的 `pgnoPrev=13` 与 13 的 next 不互反 |

- 结构可解析：**parseable-with-errors**。单个页都能解码，`basic` 表的 2 条记录经
  分支遍历仍可读出，但**有序叶子链遍历不可靠**（可能漏页或陷入错误路径）。
- 提交态：`indeterminate-without-logs`。
- 可作为证据：通过分支树可达的记录字节。
- 不能下的结论：基于全表顺序扫描的统计（记录总数、范围查询结果、是否有遗漏页）。
- 这正对应 `page.py` 注释提到的脏库风险：仅靠 `next_page` 链式遍历可能无限循环或
  漏页，分支遍历更安全但可能错过损坏页。

---

## 样例 5：`tampered-page.edb`（静默字节篡改，头仍自称干净）

构造：翻转逻辑页 14 数据区 2 个字节，**不**动校验和，**不**动头部标志。

| 级别 | 代码 | 关键证据 |
| --- | --- | --- |
| HIGH | PAGE_CHECKSUM | 页 14 复现的 XOR 校验和与存储值不符 |
| INFO | HDR_CLEAN / SHADOW_MATCH | 头与影子头仍自称干净且彼此一致 |

- 结构可解析：是（多数记录仍可解码，因为只改了 2 字节）。
- 提交态：被门控逻辑强制降为 `indeterminate-without-logs`，即使 `dbstate=3`。
- 这是最重要的反例：**干净关闭标志完全可以与校验和失败并存**。只检查 `dbstate`
  就宣布库完好是错误的；标志位可被任意保留或伪造，而校验和绑定页号与内容、难以
  静默伪造。
- 不能下的结论：该页任何字段的完整性；以该页记录为准的事实认定。

---

## 总体判定矩阵

| 样本 | 结构可解析 | 校验和 | 目录/B-tree | 提交态（无日志） |
| --- | --- | --- | --- | --- |
| pristine | 完整 | 全通过 | 一致 | 头部声明干净（无反证） |
| dirty-shutdown | 完整 | 全通过 | 一致 | 不确定 |
| mixed-time-page | 完整 | 目标页 ECC 过期 | 时间线矛盾 | 不确定 |
| missing-catalog-target | 降级 | — | 悬挂根 | 不确定 |
| broken-btree-link | 降级 | 目标页 ECC 过期 | 断链 | 不确定 |
| tampered-page | 完整 | 1 页失败 | 一致 | 不确定 |

## 报告字段如何支撑审计

- 每个 finding 带 `severity/code/message/detail`，`detail` 给出页号、物理页号、
  字段偏移、期望值与实际值，可逐条复核。
- `mode=read-only`、`mutations_performed=[]`、`replay_attempted=false` 显式记录
  取证过程未做任何修改或重放。
- 大页校验和无法独立复现时输出 `LARGE_PAGE_CHECKSUM_SCOPE`（INFO），明确验证边界，
  不制造虚假的“通过/失败”。
