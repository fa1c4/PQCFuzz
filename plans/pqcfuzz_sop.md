# PQCFuzz 单目标 SOP 实施计划

> 执行前读取 `designs/architecture.md` 及其中七个 Modules 链接，再读取 `agent/pqc_sop.md`。架构是设计权威；本计划只规定实施顺序，不能改变架构语义。当前仓库有旧版固定套件、oracle JSON、trace/replay/report 代码；它们是可复用实现，不是新目标交付布局。

## 目标与边界

用户给定 specification 文档或已提取的 spec Markdown，以及 target source code 路径。Agent 完成规范主张提取、现役 property 与 pattern 匹配、target-specific oracle 设计、adapter/oracle/配对 mutator 实现和 smoke。交付以 `oracles/<target-name>/` 中的 Agent 生成产物为准；运行由 Runtime 模块负责，产物只写入 `workspace/<target-name>/runs/<run-id>/`。

人核实 spec 是可选操作：`draft` 和 `verified` 均可注册。draft 的运行证据标注 `unverified_spec`。本阶段只保存 counterexample candidate，不自动 replay、最小化、去重、归因或宣布已确认漏洞。119 个目标的逐一接入是后续运营工作；本计划先实现可复用协议并以签名、KEM、密钥交换、杂凑各一个真实目标验收。

## 交付布局

`agent/pqc_sop.md` 是仓库 SOP；`knowledge/property/` 和 `knowledge/oracles/` 提供现役知识。每个目标产生：

`oracles/spec/<target-name>-<algorithm>.md` — 带来源定位、歧义和 front matter 状态的规范提取。
`oracles/<target-name>/manifest.json` — 目标、来源哈希、算法/API/profile、property/pattern/oracle/mutator/adapter 注册。
`oracles/<target-name>/design/<algorithm>/<api>/<oracle-id>.md` — oracle 的前置条件、输入、干预、关系、观测、正反控、边界和判定。
`oracles/<target-name>/implement/` — 可构建的 adapter、oracle、配对 mutator 与必要构建 recipe。
`configs/targets.json` — 每个 target+algorithm 一个配置条目，API 和 build profile 为变体。
`scripts/pqcfuzz_eval_<target-name>.sh` — 单目标薄入口；`scripts/pqcfuzz_all_eval.sh` 按参数和 manifest 选择目标。
`workspace/<target-name>/runs/<run-id>/` — 所有构建、缓存、临时文件、smoke、campaign、trace、反例及报告。

不得为新目标生成 `plugins/<target-id>/`，也不得把旧 `src/oracles/specs/*.json` 当成新目标 oracle 的权威交付。

## 阶段 1：固定静态契约

1. 为 `configs/targets.json`、目标 manifest、spec Markdown front matter、oracle 设计、结构化输入、mutator 记录、run manifest 和 counterexample bundle 定义版本与校验规则。
2. 明确 ID 组合、Git 与非 Git target 命名、源码和 spec 哈希、API/profile 能力、未知项失败规则，以及 candidate-only 状态。
3. 加入校验测试：未知/重复 ID、来源哈希漂移、缺配对 mutator、draft 状态保留、能力不匹配、schema 版本错误。保留旧 oracle JSON 的兼容路径。

验收：静态产物能独立校验；配置错误不会被当作 pass。

## 阶段 2：Agent SOP 与知识匹配

1. 按 `agent/pqc_sop.md` 从原始规范或现有 spec Markdown 开始，保留页码/章节和原始文档哈希；新提取默认 `draft`。
2. 从现役 property、pattern 中选择可适用条目，记录筛选理由、能力需求和不适用/不支持项。新 property 只进入候选区；future pattern 文件仍由人维护。
3. 在 `oracles/<target-name>/design/` 为每个目标 oracle 写完整设计，再生成 adapter/oracle/mutator 和 manifest。源代码只作为输入，必要补丁另行记录。

验收：给定 spec 与 source，Agent 产出可追溯且可校验的真实目标包；不能构建或无可评价关系时给出具体 `blocked`/`needs_input` 诊断。

## 阶段 3：Runtime 动态执行

1. 在 [runtime.md](../designs/runtime.md) 的边界内实现 manifest 发现、准确注册、能力匹配、作业生成、受限构建、preflight、smoke、campaign 调度和统一脚本入口；避免每个目标修改核心硬编码分发。
2. 每个 run 隔离工作目录、临时目录、缓存、预算和并行资源；同一 target 的不同算法/API/profile 和不同 run 不得互相覆盖。
3. Smoke 检查有效基线、有效变异、目标可达、正反控与故障注入；正式 run 只接受对应身份下已通过的 gate。
4. 将结构化 baseline/mutated input、干预、harness、trace、预期/实际观察、退出状态、资源及文件哈希原子写入 run bundle，保留 `replay_status: not_run` 和 `unverified_spec` 标签。
5. 汇总 candidate、inconclusive、not_applicable、unsupported、harness_error；不把旧 replay 验证结果静默混入新目标候选统计。

验收：一个真实目标能经新入口从 preflight 到 smoke、run、候选报告；未知 target/oracle/mutator 非零失败，旧固定套件仍可按兼容路径使用。

## 阶段 4：纵向样板与推广

1. 先用签名和 KEM 各一个真实目标打通全链路，再覆盖密钥交换与杂凑输入模型；四原语都要有至少一个真实示范目标。
2. 对每类至少验证健康样本、定向故障、反控、无效变异、缺能力、未知 ID 和 draft spec 标签。不要用仅检查文件存在的镜像测试替代行为验收。
3. 更新操作文档，说明只需给出 spec/source、如何查看 `oracles/<target-name>/`、如何启动单目标和总入口、如何定位 run 证据。
4. 逐步接入 `E:\PQCFuzz\China\Targets.md` 的 119 项候选提案；台账区分未开始、输入就绪、阻塞、smoke 通过和已运行，不把支持数当成完成测试数。

## 最终验收

- 干净检出、仅给定 spec 与 source 时，Agent 可以生成一个真实目标的规范提取、oracle 设计、adapter/oracle/mutator、manifest、配置和 smoke 证据；人工可选核实 spec。
- 单目标与统一脚本按注册目标运行，所有动态产物进入对应 workspace run 目录，且反例候选包含足以供人工重放的输入、trace、harness、变异和身份信息。
- 未知项、能力不足、不可构建或不适用有明确分类，不计为 pass 或漏洞。
- 当前新目标不依赖自动 replay/triage；旧目标关键测试和 oracle spec 生成检查仍通过。


## 2026-10-08 实施检查点

七个模块设计已展开，退役的八份设计文档已删除。新目标包的 schema 1 协议、配置/清单校验、运行快照、smoke 控制组、候选报告和统一脚本动态选择已实现，且以本地流式哈希 demo 验收。该 demo 仅验证基础设施，不等于阶段 4 要求的真实 PQC 四原语样板，也不代表 119 个目标已接入。

当前主机缺少 pytest、C/C++ 编译器和容器运行时；真实目标源码和规格尚未置入 `third_party/`。因此原生 C++ 兼容测试、签名/KEM/密钥交换真实目标样板，以及对敌意第三方源码的强沙箱执行尚未验收。新 runtime 在 Windows 上对有限 CPU/内存预算和敏感输入策略失败闭合；待具备对应运行环境后继续阶段 4 和这些执行约束。