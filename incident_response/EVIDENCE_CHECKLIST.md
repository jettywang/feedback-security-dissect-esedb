# 进一步取证所需证据清单，以及缺少日志为何阻断结论

## 为什么没有事务日志就无法判定提交状态

ESE 采用预写日志（Write-Ahead Logging, WAL）+ ARIES 风格恢复。一次修改的生命周期是：

1. 事务产生日志记录，先写日志文件并刷新（日志先于数据落盘）。
2. 提交点写入日志（commit record），之后该事务才算已提交。
3. 数据页随后被惰性刷盘；崩溃时可能只有部分页落盘。
4. 重新挂载时，引擎依据检查点（`ESE*.chk`）和日志做 **redo**（重放已提交但
   未刷盘的改动）与 **undo**（回滚尚活跃事务的改动）。

只有 `.edb` 而没有日志时，第 1、2 步的信息完全缺失。分析器看到的是第 3 步
留下的、可能不完整的页镜像。因此：

- 无法区分页里的一条记录来自“已提交事务”还是“未提交且未回滚事务”。
- 无法知道哪些已提交改动还停留在日志里、从未刷到该数据文件。
- 无法把数据库恢复到任何单一一致时点。

`DBFILEHDR` 里的下列字段本来就是指向日志的“坐标”，在缺日志时只能读出数值、
无法兑现其含义：

- `lgposConsistent`：一致检查点在日志中的位置（脏关闭时通常为 null）。
- `lgposAttach` / `lgposDetach`：最近挂载/分离对应的日志位置。
- `lGenMinRequired` / `lGenMaxRequired`：把库带到一致状态所需的最小/最大日志代。
- `lGenMaxCommitted`：接收活动日志记录的最后日志代（源码注释明确：不重放到这一代
  会丢掉 ACID 中的 D，即持久性）。
- `lGenMinConsistent` / `lGenPreRedoMin*`：干净状态所需日志代下界。
- `signLog.ulRandom`：日志签名，用于校验日志与数据库是否同源匹配。

## 需要补充调取的证据（按优先级）

### 一、事务日志与检查点（最高优先级）

- 完整日志序列：`ESE00000001.log` 起按代连续的全部 `.log`（Exchange/AD 命名可能
  不同，如 `edb*.log`、`ntds*.log`），**不能有断代**。
- 检查点文件 `ESE*.chk`（如 `ESE00000001.chk`、`edb.chk`）。
- 保留日志 `*.jrs`（`RES1.log`/`RES2.log` 之类的应急预留日志）。
- 日志所在目录的卷影副本、`System Volume Information` 内的 VSS 快照。

核对要点：用头里的 `signLog.ulRandom` 与日志头签名比对，确认日志与该库同源；
用 `lGenMinRequired`..`lGenMaxCommitted` 确认日志代覆盖完整，断代即无法完整恢复。

### 二、同源副本与时间点证据

- 同一数据库的其他副本：备份集、VSS 快照、复制副本（DAG 被动副本等）。
- 头里 `bkinfoFullPrev/bkinfoIncPrev/bkinfoFullCur` 等备份信息指向的备份。
- 文件系统元数据：`$MFT`、USN journal、`$LogFile`，用于确定 `.edb` 的创建、
  修改、拷贝时间，辅助判断页时间矛盾是否来自热拷贝或文件合并。

### 三、运行环境与崩溃上下文

- 应用事件日志（Exchange AD 等 ESE 事件源，Event ID 如 482/454/474 等恢复、
  脏关闭事件）。
- 进程内存/休眠文件/崩溃转储：可能残留尚未刷盘的最新页或事务上下文。
- 采集方式说明：是冷拷贝（先停服务/卸载）还是热拷贝（活动状态直接复制）。
  热拷贝极易产生“页来自不同时间点”的 `PAGE_TIME_FUTURE` 现象。

### 四、校验和修复历史（头内自带）

- `ulBadChecksum` / `logtimeBadChecksum`：历史上不可纠正校验和错误次数与时间。
- `ulECCFixSuccess/Fail`：单位 ECC 自愈成功/失败计数。
- `ulRepairCount` / `logtimeRepair`：历史上 `esentutl /p` 等修复次数与时间。
- `logtimeDbscanPrev/Start`、`pgnoDbscanHighest*`：上一次完整性扫描（dbscan）
  的进度与时间。

这些字段即使没有日志也能从头读出，可揭示该库在采集前是否已被修复或扫描过。

## 证据缺口 → 结论限制 对照表

| 缺失的证据 | 因此不能下的结论 | 仍可给出的替代表述 |
| --- | --- | --- |
| 全部事务日志 | 任何记录的提交/回滚状态 | “该记录字节存在于采集时的页中，提交状态不确定” |
| 检查点 `.chk` | 一致检查点位置、恢复起点 | 报告 `lgposConsistent` 是否为 null 及其原始值 |
| 日志序列断代 | 完整 redo/undo、单一一致时点 | 标注恢复所需代范围 `lGenMinRequired..lGenMaxCommitted` |
| 同源日志签名匹配 | 日志是否属于该库 | 给出 `signDb/signLog` 随机数，留待与日志头比对 |
| 采集过程说明 | 时间矛盾是否为热拷贝所致 | 仅陈述 `PAGE_TIME_FUTURE` 事实，不臆断成因 |
| 大页旋转 ECC 算法/引擎 | 大页逐字节完整性 | 标注 `engine-validated-only`，小页 XOR 仍完整验证 |

## 工具侧的诚实性约束

- 分析器对**无法独立复现**的校验和（旋转 ECC、大页多块校验和）只报告“需引擎
  验证”，不输出可能错误的“通过/失败”。
- 报告区分 `structural_parse_state`（可解析/降级/不可解析）与
  `transaction_commit_state`（干净头声明 / 无日志不确定），避免把二者混为一谈。
- 所有结论附带支撑它的字段与偏移，便于复核；矛盾样本附 SHA-256 与字节级改动清单，
  保证实验可复现、证据链可审计。
