# SecMiniAgent

> 面向工业互联网安全运维的本地 AI Agent：把代码安全扫描、OT/ICS 告警研判、本地 RAG 和隐私优先的安全记忆系统组合为一条可审计、可测试、可离线运行的分析链路。

![Python](https://img.shields.io/badge/Python-3.11%2B-blue)
![Agent](https://img.shields.io/badge/Agent-Function%20Calling-green)
![Memory](https://img.shields.io/badge/Memory-Encrypted%20SQLite-purple)
![RAG](https://img.shields.io/badge/RAG-Local%20%2B%20Chroma-orange)
![Security](https://img.shields.io/badge/Security-OT%2FICS-red)

## 项目定位

SecMiniAgent 是一个 Python CLI 项目，目标不是实现泛用聊天机器人，而是验证以下工程问题：

```text
本地 Agent 能否在明确的权限和数据边界内，
结合 Function Calling、安全工具、工业安全规则、本地知识库和安全记忆，
完成可复现、带证据、可审计的安全分析？
```

项目目前包含四条相互协作的能力主线：

- Agent：多轮模型调用、工具调用、流式事件、计划管理、Skills 和会话恢复。
- 工业安全：资产、IDS 告警、防火墙日志、IOC、漏洞上下文、OT 风险规则和威胁报告。
- 本地 RAG：Markdown 知识库、确定性 embedding、lexical/Chroma backend、检索评估和带来源报告。
- 安全记忆：加密 SQLite 权威存储、Thread/Run、结构化 Note/摘要、长期记忆、混合检索、TTL/pin 和可恢复删除。

默认使用 `fake` provider，不需要 API Key，可离线演示完整工具调用链。也支持 OpenAI-compatible、火山 Ark 和讯飞 MaaS。

## 最新实现状态

隐私优先记忆系统的 M7.1–M7.8 已完成并通过阶段验收：

- Schema v2、AAD v2、state MAC 和显式可恢复迁移。
- Session → Thread → Run 三层生命周期与 Thread 强隔离。
- Thread-aware 加密 Transcript 和上下文恢复。
- 结构化 Notes、滚动摘要、watermark 和 provenance。
- 显式长期记忆：确认、修订、撤回、Thread → Session → Workspace 提升。
- SQLite 权威回查的混合检索，以及只生成 candidate 的受控自动记忆。
- TTL、pin、Run/Thread 级联删除、认证 deletion job 和 Chroma 补偿恢复。
- 固定合成数据集上的迁移、攻击、离线、资源和质量验收。

当前验收基线：277 个测试通过，1 个互斥环境分支按设计跳过；合成记忆 benchmark 的 Recall@3 和 MRR 均为 1.0，非授权召回为 0；100k 合成加密 v1 记录完成 v2 迁移且无丢行。

## 架构概览

```text
用户任务 / 工业数据 / 代码仓库
               │
               ▼
       CLI + 配置 + Skills
               │
               ▼
   AgentLoop + Function Calling
       │          │          │
       ▼          ▼          ▼
安全扫描工具   OT 分析工具   RAG 工具
       │          │          │
       └──────────┴──────────┘
               │
               ▼
  Thread-aware ContextAssembler
               │
               ▼
加密 SQLite 权威记忆 ──► 可选 Chroma 派生索引
  Session / Thread / Run       仅 Workspace、非 Secret
  Transcript / Note / Summary 所有命中回查 SQLite
```

核心安全原则：

1. SQLite 是正文、权限、状态和 provenance 的唯一权威。
2. Chroma 只返回 Workspace 候选 ID，不能决定可见性。
3. 先按 workspace/session/thread、状态、过期和分类过滤，再认证解密。
4. 自动记忆只能生成可追溯 candidate，不能自行成为确认事实。
5. 召回正文始终作为不可信 `<memory_data>`，不能提升为系统指令。
6. 删除先撤销 SQLite 权威访问，再幂等清理 Chroma。

## 主要能力

### Agent 与工具框架

- ReAct 风格多轮循环：model → tool call → observation → final。
- JSON Schema Function Calling 和统一 `ToolRegistry`。
- 文件、代码搜索、Git、Shell、Patch、计划管理等基础工具。
- ask/deny 权限策略；`--yes` 只能自动批准 ask，不能绕过 deny。
- 流式事件输出、交互模式、Session/Thread 恢复和 Skills 选择。

### 工业互联网安全分析

- 解析资产清单、IDS 告警、防火墙日志、IOC 和漏洞上下文。
- 识别可疑 OT 访问、暴力破解、横向移动和关键资产风险。
- 关联 PLC、HMI、SCADA、工程站、跳板机及 Modbus、OPC UA、S7 等工业协议。
- 生成带风险等级、证据和处置建议的 Markdown 报告。

示例数据位于 `examples/industrial/` 和 `examples/wind_power/`。

### 本地 RAG

- 加载和切分 `knowledge/` 下的本地 Markdown 知识。
- 支持 deterministic local backend 和可选 Chroma backend。
- 提供知识检索、单告警解释、RAG 威胁报告和 Recall/MRR 等评估。
- 报告保留 Knowledge Evidence 和来源路径。

### 隐私优先的安全记忆

- AES-256-GCM 加密正文；Windows 第一版使用 DPAPI 保护工作区密钥。
- 作用域：Thread、Session、Workspace；Run 只用于生命周期和排序，不是权限域。
- classification：Public、Internal、Confidential、Secret。
- 认证字段：AAD、state MAC、relation MAC、keyed provenance digest。
- 状态机：candidate、active、superseded、retracted、expired、deleted 等。
- 显式 promotion 创建新 ID、新密文和新 AAD，不原地扩大权限。
- Secret 永不进入 Chroma；Confidential 只允许本地 Provider 上下文。
- deletion preview 与 snapshot-bound token，支持中断恢复和安全 receipt。

## 快速开始

### 环境要求

- Python 3.11+
- 推荐 Windows PowerShell；安全记忆的当前密钥保护实现以 Windows DPAPI 为第一目标
- 可选：OpenAI、火山 Ark 或讯飞 MaaS API Key
- 可选：Chroma

### 安装

```powershell
git clone https://github.com/Sloanleee/SecMiniAgent.git
cd SecMiniAgent

python -m venv .venv
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1

python -m pip install -e .
```

如需 Chroma：

```powershell
python -m pip install -e ".[chroma]"
```

验证：

```powershell
python -m secminiagent --version
python -m secminiagent --help
python -m secminiagent memory --help
```

### 离线运行

```powershell
python -m secminiagent --no-env "generate a security report"
python -m secminiagent --no-env "generate an industrial threat report"
python -m secminiagent --no-env "generate a RAG wind power threat report"
```

省略任务会进入交互模式：

```powershell
python -m secminiagent --no-env
```

输入 `/exit` 或 `/quit` 退出。

## Provider 配置

复制配置模板：

```powershell
Copy-Item .env.example .env
```

默认：

```env
SECMINI_PROVIDER=fake
```

OpenAI-compatible：

```env
SECMINI_PROVIDER=openai
OPENAI_API_KEY=sk-your-key
OPENAI_MODEL=gpt-4.1-mini
OPENAI_BASE_URL=https://api.openai.com/v1
```

火山 Ark：

```env
SECMINI_PROVIDER=volcengine
ARK_API_KEY=your-key
ARK_MODEL=your-endpoint-id
ARK_BASE_URL=https://ark.cn-beijing.volces.com/api/v3
```

讯飞 MaaS：

```env
SECMINI_PROVIDER=xfyun
XFYUN_API_KEY=your-key
XFYUN_MODEL=your-model-id
XFYUN_BASE_URL=http://maas-api.cn-huabei-1.xf-yun.com/v1
XFYUN_LORA_ID=0
```

查看最终配置：

```powershell
python -m secminiagent --show-config
```

CLI 的 `--provider`、`--model`、`--env-file` 可覆盖默认选择；`--no-env` 禁止自动读取 `.env`。

## 常用 Agent 指令

```powershell
# 配置与 Skills
python -m secminiagent --show-config
python -m secminiagent --list-skills

# 代码安全
python -m secminiagent "scan this project for hardcoded secrets"
python -m secminiagent "review current git diff for security risks"
python -m secminiagent "generate a security report"

# 工业安全
python -m secminiagent "parse industrial assets"
python -m secminiagent "triage industrial alerts"
python -m secminiagent "detect suspicious OT access"
python -m secminiagent "detect lateral movement in industrial alerts"
python -m secminiagent "generate an industrial threat report"

# RAG
python -m secminiagent "search knowledge for Modbus PLC TCP 502"
python -m secminiagent "generate a RAG wind power threat report"
python -m secminiagent "evaluate rag benchmark"
```

常用控制参数：

```powershell
python -m secminiagent --cwd C:\path\to\workspace --max-turns 12 --no-stream "review this repository"
python -m secminiagent --skill industrial_threat_analysis "generate an industrial threat report"
python -m secminiagent --resume <session-id> --thread <thread-id> "continue the analysis"
```

## 安全记忆最小工作流

高级 Thread/Note 命令只打开已经显式激活的 Schema v2，不会静默创建或迁移数据库。

### 1. 创建初始 Session

```powershell
python -m secminiagent --no-env "initialize a local security review session"
```

记录输出中的 `session` ID。

### 2. 显式迁移到 Schema v2

```powershell
python -m secminiagent memory --cwd . migration-status
python -m secminiagent memory --cwd . migrate-schema --to 2 --dry-run
python -m secminiagent memory --cwd . migrate-schema --to 2 --yes
```

### 3. 创建 Thread

```powershell
python -m secminiagent memory --cwd . thread create --session <session-id> --title "OT review" --goal "triage wind farm alerts"
```

记录输出中的 `thread_id`，随后运行：

```powershell
python -m secminiagent --resume <session-id> --thread <thread-id> "continue the OT review"
```

### 4. 添加和检索长期 Note

正文通过 stdin 输入，避免进入 shell history：

```powershell
"PLC-17 maintenance requires an offline backup" |
  python -m secminiagent memory --cwd . note add --session <session-id> --thread <thread-id> --kind fact

"PLC backup" |
  python -m secminiagent memory --cwd . search --session <session-id> --thread <thread-id> --explain
```

默认 `show/search` 只输出安全元数据；正文需要明确指定 `--show-content`。

### 5. 提升作用域

```powershell
python -m secminiagent memory --cwd . note promote-preview <note-id> --session <session-id> --thread <thread-id> --to session
python -m secminiagent memory --cwd . note promote <note-id> --session <session-id> --thread <thread-id> --to session --confirmation-token <token>
```

Session Note 如需进入 Workspace，再对新的 Session Note 执行一次 preview/promote。

### 6. 安全删除

```powershell
python -m secminiagent memory --cwd . clear-run <run-id> --session <session-id> --thread <thread-id> --preview
python -m secminiagent memory --cwd . clear-run <run-id> --session <session-id> --thread <thread-id> --yes --confirmation-token <token>
python -m secminiagent memory --cwd . deletion status <job-id> --session <session-id> --thread <thread-id>
python -m secminiagent memory --cwd . deletion resume <job-id> --session <session-id> --thread <thread-id>
```

## Benchmark 与测试

全量测试：

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_*.py"
.\.venv\Scripts\python.exe -m compileall -q secminiagent benchmarks\memory
git diff --check
```

可重复的安全记忆 benchmark：

```powershell
New-Item -ItemType Directory -Force .tmp-memory-benchmark | Out-Null
.\.venv\Scripts\python.exe benchmarks\memory\run_retrieval.py --output-dir .tmp-memory-benchmark
.\.venv\Scripts\python.exe benchmarks\memory\run_summary.py --output-dir .tmp-memory-benchmark
.\.venv\Scripts\python.exe benchmarks\memory\run_auto_memory.py --output-dir .tmp-memory-benchmark
.\.venv\Scripts\python.exe benchmarks\memory\run_migration.py --output-dir .tmp-memory-benchmark
```

Benchmark 只读取版本化合成 fixture，拒绝把输出写到任何 `.secminiagent` 目录。详细阈值见 [benchmarks/memory/README.md](benchmarks/memory/README.md)。

## 项目目录

```text
SecMiniAgent/
├─ secminiagent/
│  ├─ agent/           Agent Loop、事件和计划工具
│  ├─ llm/             fake/OpenAI/Ark/XFYun provider
│  ├─ memory/          加密存储、Thread/Run、Note、检索、删除
│  ├─ rag/             本地知识检索与评估
│  ├─ safety/          权限边界
│  ├─ security/        安全扫描和报告
│  ├─ storage/         v1/v2 Transcript 运行时适配
│  ├─ threat/          OT/ICS 风险分析
│  └─ tools/           Function Calling 工具
├─ knowledge/          工业安全知识库
├─ examples/           工业与风电合成示例
├─ benchmarks/memory/  安全记忆验收基准
└─ tests/              单元、集成、安全和恢复测试
```

## 已知边界

- 这是研究与工程原型，不是经过认证的工业生产安全平台。
- 当前本地密钥保护以 Windows DPAPI 为第一实现目标。
- 不对已完全控制当前 OS 用户或 Agent 进程内存的攻击者提供隔离。
- SQLite tombstone 不等于 SSD 或备份介质上的物理安全擦除。
- Chroma 是可选派生索引；缺失或损坏时退化到 SQLite，不影响权威状态。
- 真实模型输出具有不确定性，安全硬边界必须由本地代码和测试保证。

## 免责声明

本项目仅用于防御性安全研究、课程实践、原型验证和授权环境中的安全分析。使用者应自行确认数据权限、模型 Provider 的隐私条款及适用法律法规。
