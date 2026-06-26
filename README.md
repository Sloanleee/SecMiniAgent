# SecMiniAgent

> 面向工业互联网安全运维的本地威胁分析 Agent：输入代码仓库、工业资产、告警日志、IOC、漏洞信息或风电场景 CSV 告警 → Agent 自动规划工具调用 → 执行安全扫描、OT 规则分析、RAG 知识检索 → 输出带证据的 Markdown 安全报告。

![Python](https://img.shields.io/badge/Python-3.11%2B-blue)
![Agent](https://img.shields.io/badge/Agent-Function%20Calling-green)
![RAG](https://img.shields.io/badge/RAG-Local%20Knowledge-orange)
![Security](https://img.shields.io/badge/Security-OT%2FICS-red)

---

## 项目简介

SecMiniAgent 是一个基于 Python 实现的本地安全分析 Agent CLI 原型。项目保留通用 Coding Agent 的基础能力，包括 Agent Loop、Function Calling、工具注册、文件读写、代码搜索、Git 检查、Shell 安全执行、会话状态保存和 Skills 加载；在此基础上，进一步面向工业互联网安全运维场景增加了资产解析、告警分析、IOC 匹配、OT 风险规则、RAG 知识检索和威胁报告生成能力。

项目重点不是做一个泛用聊天助手，而是验证一个更具体的安全工程问题：

```text
本地 Agent 能否在不依赖云端安全平台的情况下，
结合工具调用、规则分析和本地 RAG 知识库，
完成工业互联网安全告警的初步研判和报告生成？
```

当前项目已经支持：

- 默认无真实 LLM 的 fake provider，可离线复现完整工具调用链路。
- 接入 OpenAI-compatible、火山 Ark、讯飞 MaaS 等真实模型 provider。
- 本地代码安全扫描、Secret 检测、依赖文件识别和 Markdown 安全报告。
- 工业资产、IDS 告警、防火墙日志、IOC、漏洞信息解析与关联分析。
- OT/ICS 场景下的可疑访问、横向移动、暴力破解、工业协议访问检测。
- 本地 RAG 知识库检索，支持风电场景告警增强分析。
- Skills 驱动的安全任务提示，如告警研判、IOC Hunting、工业资产风险审查等。

---

## 核心工作流

```text
用户输入安全分析任务
         │
         ▼
python -m secminiagent "<task>"
         │
         ▼
配置解析：provider / model / cwd / .env / session
         │
         ▼
SkillLoader 根据任务加载安全分析 Skill
         │
         ▼
AgentLoop 调用 LLM 或 fake provider
         │
         ├── 模型输出普通回答
         └── 模型请求 Function Calling 工具
                    │
                    ▼
          ToolRegistry 执行本地工具
                    │
                    ├── 代码安全扫描
                    ├── 文件 / Git / Shell 工具
                    ├── 工业威胁分析工具
                    ├── RAG 知识检索工具
                    └── 计划管理工具
                    │
                    ▼
          工具结果回填给 AgentLoop
                    │
                    ▼
          多轮执行直到生成最终报告
```

---

## 系统架构

```text
┌─────────────────────────────────────────────────────────────┐
│                        CLI 入口层                            │
│  __main__.py / cli.py                                       │
│  参数解析 / .env 加载 / Provider 选择 / Skill 选择             │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                       Agent 执行层                           │
│  AgentLoop: model -> tool call -> observation -> final       │
│  Planner: create_plan / update_plan                         │
│  Events: streaming 输出 model/tool 状态                       │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                       工具能力层                             │
│  File / Search / Git / Shell / Patch                         │
│  Security Scanner / Threat Tools / RAG Tools                 │
│  ToolRegistry + JSON Schema                                  │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                     工业安全分析层                           │
│  Asset / Alert / IOC / Vulnerability parsers                 │
│  OT Rules / Risk Scoring / Correlation / Reports             │
│  Brute Force / Lateral Movement / Suspicious OT Access       │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                       本地 RAG 层                            │
│  Markdown Knowledge -> Chunk -> Local Embedding              │
│  VectorStore / Retriever / Evaluation                        │
│  RAG Threat Report with Knowledge Evidence                   │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│                       模型适配层                             │
│  fake / OpenAI-compatible / Volcengine Ark / XFYun MaaS      │
│  统一 LLMClient 协议，屏蔽供应商差异                          │
└─────────────────────────────────────────────────────────────┘
```

---

## 技术亮点

### 1. ReAct 风格 Agent Loop

SecMiniAgent 使用简化 ReAct 执行流程：

```text
User Task -> Model Thought / Tool Call -> Tool Result -> Model Continue -> Final Report
```

模型不直接访问本地文件和命令，而是通过工具层执行受控操作。这样可以把 LLM 推理能力和本地安全工具能力解耦。

核心文件：

```text
secminiagent/agent/loop.py
secminiagent/tools/registry.py
secminiagent/tools/base.py
```

### 2. Function Calling 工具框架

每个工具都包含：

```text
name
description
input_schema
read_only
execute()
```

工具通过 JSON Schema 暴露给模型，模型选择工具和参数，Agent 执行后将结果回填给模型。

当前主要工具类型：

```text
文件工具      list_dir / read_file / write_file
代码搜索      search_code
Git 工具      git_status / git_diff / git_log
Shell 工具    run_shell
Patch 工具    apply_patch
安全扫描      scan_secrets / scan_insecure_patterns / generate_security_report
工业分析      parse_assets / parse_alerts / correlate_alerts / generate_threat_report
RAG 工具      ingest_knowledge / search_knowledge / generate_rag_threat_report
```

### 3. 工业互联网威胁分析

项目内置了工业安全运维常见数据对象：

```text
资产清单        assets.csv
IDS 告警        ids_alerts.json
防火墙日志      firewall.log
IOC 情报        ioc.txt
漏洞上下文      vulns.json
```

支持的分析能力包括：

- 工业资产分区、关键性、协议暴露分析。
- 告警源 IP、目的 IP、端口、协议、动作、级别解析。
- IOC 与告警流量匹配。
- PLC、HMI、SCADA、工程站、跳板机等关键资产风险评分。
- 可疑 OT 访问、横向移动、暴力破解行为检测。
- 资产、告警、IOC、漏洞信息综合关联。

### 4. 本地 RAG 威胁分析

SecMiniAgent 增加了本地 RAG 能力，用于把“告警数据”和“安全知识”结合起来。

RAG 数据流：

```text
knowledge/*.md
     │
     ▼
Markdown 文档加载与 Chunk
     │
     ▼
本地 deterministic embedding / lexical retrieval
     │
     ▼
根据告警字段构造 Query
     │
     ▼
检索 Modbus / OPC UA / 风电场景 / 响应剧本等知识
     │
     ▼
生成带 Knowledge Evidence 的威胁报告
```

当前知识库包括：

```text
knowledge/protocols/modbus.md
knowledge/protocols/opcua.md
knowledge/protocols/s7comm.md
knowledge/playbooks/brute_force_response.md
knowledge/playbooks/lateral_movement_response.md
knowledge/playbooks/suspicious_ot_access.md
knowledge/rules/ot_rules.md
knowledge/wind_power/wind_farm_security_context.md
knowledge/wind_power/remote_maintenance_risks.md
```

RAG 工具：

```text
ingest_knowledge
search_knowledge
explain_alert_with_rag
generate_rag_threat_report
```

### 5. 真实模型 Provider 适配

当前支持：

| Provider | 说明 |
| --- | --- |
| `fake` | 离线测试 provider，不调用远程 API |
| `openai` | OpenAI-compatible Chat Completions API |
| `volcengine` | 火山 Ark API |
| `xfyun` | 讯飞 MaaS API |

业务层只依赖统一的 LLMClient 协议。新增模型供应商时，只需要增加 provider client，并在 CLI 中注册。

### 6. 安全边界与权限控制

SecMiniAgent 是防御性、本地优先项目：

- 文件访问限制在当前 workspace 内。
- 高风险 Shell 命令会被阻断或要求确认。
- `rm`、`sudo`、`pip install`、`git reset --hard` 等高风险操作不会静默执行。
- `.env`、运行会话、生成报告默认不进入 Git。
- 项目用于安全审查、告警研判和防御分析，不用于攻击自动化。

---

## RAG 能力说明

### RAG 与普通工业分析的区别

普通工业分析主要依赖结构化规则：

```text
资产 + 告警 + IOC + 漏洞 -> 规则关联 -> 威胁报告
```

RAG 分析会额外检索本地知识库：

```text
告警 CSV -> 构造检索 Query -> 检索工业安全知识 -> 生成带证据报告
```

因此 RAG 报告中会出现：

```text
Knowledge Evidence
Source: knowledge/protocols/modbus.md
Source: knowledge/wind_power/wind_farm_security_context.md
```

### RAG Demo

默认风电场景告警文件：

```text
examples/wind_power/alerts.csv
```

默认知识库目录：

```text
knowledge/
```

运行：

```powershell
python -m secminiagent --no-env "generate a RAG wind power threat report"
```

如果使用真实模型，例如火山 Ark：

```powershell
python -m secminiagent "generate a RAG wind power threat report"
```

为了提高真实模型工具调用稳定性，`generate_rag_threat_report` 已在 schema 中声明默认路径：

```text
alerts_path = examples/wind_power/alerts.csv
knowledge_path = knowledge
top_k = 8
```

即使真实模型误传：

```json
{"alerts_path": "alerts.csv"}
```

当根目录不存在 `alerts.csv` 时，工具层也会自动 fallback 到：

```text
examples/wind_power/alerts.csv
```

---

## 快速开始

### 环境要求

- Python 3.11+
- Windows PowerShell / macOS / Linux shell
- 可选：OpenAI、火山 Ark 或讯飞 MaaS API Key

### 1. 进入项目

```powershell
cd C:\D\code\ClaudeCode\SecMiniAgent
```

或从 GitHub 克隆后进入项目目录：

```powershell
git clone https://github.com/Sloanleee/SecMiniAgent.git
cd SecMiniAgent
```

### 2. 创建虚拟环境

Windows PowerShell：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

如果 PowerShell 执行策略拦截：

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

### 3. 安装项目

项目当前运行时不依赖第三方包，可以直接运行：

```powershell
python -m secminiagent --help
```

也可以使用 editable install：

```powershell
python -m pip install -e .
```

安装后可使用命令：

```powershell
secminiagent "generate an industrial threat report"
```

### 4. 运行测试

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

当前测试覆盖 Agent Loop、配置、权限策略、安全扫描、工业威胁工具、RAG chunk、RAG retrieval、RAG evaluator 和 RAG tools。

### 5. 运行 Demo

普通代码安全报告：

```powershell
python -m secminiagent --no-env "generate a security report"
```

工业威胁分析报告：

```powershell
python -m secminiagent --no-env "generate an industrial threat report"
```

RAG 风电威胁分析报告：

```powershell
python -m secminiagent --no-env "generate a RAG wind power threat report"
```

---

## RAG Evaluation Benchmark

SecMiniAgent includes a reproducible RAG benchmark for industrial security knowledge retrieval. It compares retrieval quality across:

- Backend: `local`, optional `chroma`
- Top-K: `1`, `3`, `5`, `8`
- Query strategy: `description_only`, `description_port`, `description_port_hint`
- Metrics: `recall@k`, `precision@k`, `mrr`, `hit_rate`

Run the local benchmark:

```powershell
python -m secminiagent --no-env "evaluate rag benchmark"
```

Latest local benchmark result:

| Backend | Query Strategy | Top-K | Recall@K | Precision@K | MRR | Hit Rate |
|---|---|---:|---:|---:|---:|---:|
| local | description_only | 1 | 0.5000 | 0.7500 | 0.7500 | 0.7500 |
| local | description_only | 3 | 0.7500 | 0.3750 | 0.8125 | 0.8750 |
| local | description_only | 5 | 0.9375 | 0.2750 | 0.8438 | 1.0000 |
| local | description_only | 8 | 1.0000 | 0.1875 | 0.8438 | 1.0000 |
| local | description_port | 1 | 0.3125 | 0.5000 | 0.5000 | 0.5000 |
| local | description_port | 3 | 0.7500 | 0.3750 | 0.6667 | 0.8750 |
| local | description_port | 5 | 0.9375 | 0.2750 | 0.6917 | 1.0000 |
| local | description_port | 8 | 0.9375 | 0.1719 | 0.6917 | 1.0000 |
| local | description_port_hint | 1 | 0.5000 | 0.7500 | 0.7500 | 0.7500 |
| local | description_port_hint | 3 | 0.8125 | 0.4167 | 0.8125 | 0.8750 |
| local | description_port_hint | 5 | 1.0000 | 0.3000 | 0.8375 | 1.0000 |
| local | description_port_hint | 8 | 1.0000 | 0.1875 | 0.8375 | 1.0000 |

Interpretation:

- `description_port_hint` generally improves industrial protocol retrieval because it adds OT protocol context such as Modbus TCP/502 or OPC UA TCP/4840.
- Higher `top_k` can improve recall while lowering precision.
- Chroma can be enabled with `python -m pip install -e ".[chroma]"` and selected with `backend=chroma` or `backend=all`.

---

## 配置真实模型

默认 provider 是 `fake`，不需要 API Key。

如果要使用真实模型，复制配置文件：

```powershell
copy .env.example .env
```

### OpenAI-compatible

```env
SECMINI_PROVIDER=openai
OPENAI_API_KEY=sk-your-openai-key
OPENAI_MODEL=gpt-4.1-mini
OPENAI_BASE_URL=https://api.openai.com/v1
```

### 火山 Ark

```env
SECMINI_PROVIDER=volcengine
ARK_API_KEY=your-volcengine-ark-key
ARK_MODEL=your-endpoint-id
ARK_BASE_URL=https://ark.cn-beijing.volces.com/api/v3
```

### 讯飞 MaaS

```env
SECMINI_PROVIDER=xfyun
XFYUN_API_KEY=your-xfyun-maas-key
XFYUN_MODEL=your-model-id
XFYUN_BASE_URL=http://maas-api.cn-huabei-1.xf-yun.com/v1
XFYUN_LORA_ID=0
```

CLI 参数可以覆盖 `.env`：

```powershell
python -m secminiagent --provider volcengine --model your-endpoint-id "generate a RAG wind power threat report"
```

查看当前配置：

```powershell
python -m secminiagent --show-config
```

忽略 `.env`，强制使用 fake provider：

```powershell
python -m secminiagent --no-env "generate a RAG wind power threat report"
```

---

## 常用命令

### Agent 基础能力

```powershell
python -m secminiagent --help
python -m secminiagent --list-skills
python -m secminiagent --show-config
python -m secminiagent "explain current project structure"
```

### 代码安全分析

```powershell
python -m secminiagent "scan this project for hardcoded secrets"
python -m secminiagent "scan insecure code patterns"
python -m secminiagent "generate a security report"
python -m secminiagent "review current git diff for security risks"
```

### 工业互联网威胁分析

```powershell
python -m secminiagent "parse industrial assets"
python -m secminiagent "triage industrial alerts"
python -m secminiagent "hunt IOC matches in alerts"
python -m secminiagent "detect suspicious OT access"
python -m secminiagent "detect lateral movement in industrial alerts"
python -m secminiagent "detect brute force attempts"
python -m secminiagent "generate an industrial threat report"
```

### RAG 威胁分析

```powershell
python -m secminiagent "generate a RAG wind power threat report"
python -m secminiagent "search knowledge for Modbus PLC TCP 502"
python -m secminiagent "explain alert with RAG: source 10.10.5.23 accessed 172.16.20.10 port 502"
```

---

## 项目目录

```text
SecMiniAgent/
  pyproject.toml
  README.md
  .env.example
  examples/
    industrial/
      assets.csv
      ids_alerts.json
      firewall.log
      ioc.txt
      vulns.json
    wind_power/
      alerts.csv
  knowledge/
    protocols/
    playbooks/
    rules/
    wind_power/
  secminiagent/
    __main__.py
    cli.py
    config.py
    agent/
    context/
    llm/
    parsers/
    rag/
    safety/
    security/
    skills/
    storage/
    threat/
    tools/
  tests/
```

核心模块说明：

| 模块 | 作用 |
| --- | --- |
| `secminiagent/cli.py` | 命令行入口、参数解析、provider 选择、工具注册 |
| `secminiagent/agent/loop.py` | Agent 主循环、模型调用、工具调用、结果回填 |
| `secminiagent/llm/` | fake、OpenAI、火山 Ark、讯飞 MaaS provider |
| `secminiagent/tools/` | Function Calling 工具实现 |
| `secminiagent/security/` | 安全扫描规则、OT 规则、报告渲染 |
| `secminiagent/threat/` | 工业安全数据模型、风险评分、事件关联 |
| `secminiagent/parsers/` | 资产、告警、日志、IOC、漏洞解析器 |
| `secminiagent/rag/` | 本地 RAG 文档、chunk、检索、评估 |
| `secminiagent/skills/` | 安全任务 Skill 文档 |
| `secminiagent/storage/` | JSONL 会话记录 |

---

## 测试说明

运行全量测试：

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

只运行 RAG 相关测试：

```powershell
python -m unittest tests.test_rag_chunker tests.test_rag_retriever tests.test_rag_evaluator tests.test_rag_tools -v
```

只运行 RAG 指标测试：

```powershell
python -m unittest tests.test_rag_evaluator -v
```

当前 RAG 指标包括：

| 指标 | 说明 |
| --- | --- |
| `recall_at_k` | Top-K 检索结果中召回了多少应命中文档 |
| `precision_at_k` | Top-K 检索结果中命中文档所占比例 |
| `mrr` | 正确文档排名越靠前，分数越高 |
| `hit_rate` | Top-K 内是否至少命中一个正确文档 |

测试重点：

- 中文 / 英文 CSV 告警表头解析。
- Markdown 知识库加载与 chunk。
- 本地知识检索与 metadata filter。
- RAG 指标计算。
- RAG 工具默认路径和 fallback。
- Agent 工具注册。
- 工业威胁分析工具链。

---

## 内置 Skills

当前内置 Skill：

```text
alert_triage
code_security_review
dependency_audit
incident_response
industrial_threat_analysis
ioc_hunting
ot_asset_risk_review
secret_scan
```

查看 Skill：

```powershell
python -m secminiagent --list-skills
```

强制加载某个 Skill：

```powershell
python -m secminiagent --skill industrial_threat_analysis "generate an industrial threat report"
```

---

## 输出文件

运行时文件位于：

```text
.secminiagent/
  sessions/   会话 JSONL 记录
  reports/    可选生成的 Markdown 报告
  rag/        可选 RAG 运行缓存
```

这些路径建议加入 `.gitignore`，避免提交本地会话、报告和缓存。

---

## 与 MiniClaude 的区别

MiniClaude 更偏向通用本地 Coding Agent：

```text
文件读写 / Shell / Git / Patch / Planning / Tool Call
```

SecMiniAgent 在这些基础能力之上，增加了明确的安全运维和工业互联网场景：

```text
资产清单解析
IDS / 防火墙告警解析
IOC Hunting
OT 规则检测
工业资产风险评分
风电场景 RAG 知识库
威胁分析 Markdown 报告
```

一句话区分：

```text
MiniClaude 是通用 Coding Agent 原型。
SecMiniAgent 是面向工业互联网安全运维的本地威胁分析 Agent 原型。
```

---

## 应用场景

- 本地代码安全审查。
- 提交 GitHub 前扫描 Secret 和危险代码模式。
- 工业资产清单风险审查。
- IDS / 防火墙告警初步研判。
- IOC 与告警日志匹配。
- PLC / HMI / SCADA / 工程站可疑访问检测。
- 风电场站远程维护风险分析。
- 工业安全学习、演示和简历项目展示。

---

## Roadmap

后续可继续增强：

- 支持 Syslog、Suricata、Zeek、Windows Event 等更多日志格式。
- 增加 MITRE ATT&CK for ICS 技术映射。
- 引入更完整的事件状态流转，如 open / investigating / contained / closed。
- 增加 RAG 评估集和检索质量对比报告。
- 接入可选向量库，如 Chroma、FAISS 或 SQLite FTS。
- 增加报告模板：日报、周报、事件响应报告、资产风险报告。
- 增强真实模型 provider 的 streaming tool call 测试。

---

## 免责声明

SecMiniAgent 是本地防御性安全分析原型，适合学习、演示和安全运维辅助分析。项目不提供攻击自动化能力，不应被用于未授权测试、攻击或破坏性操作。
