# SecMiniAgent RAG Benchmark 与 Chroma 向量数据库设计

## 1. 背景

SecMiniAgent 当前已经实现本地 RAG 能力，可以读取 `knowledge/` 下的 Markdown 工业安全知识，解析风电场景告警 CSV，并通过本地 deterministic 检索生成带 `Knowledge Evidence` 的威胁分析报告。

当前 RAG 版本的优点是轻量、无第三方依赖、可离线复现；不足是仍偏 demo 原型，缺少更完整的 RAG 工程能力：

- 缺少向量数据库后端。
- 缺少不同检索后端的统一抽象。
- 缺少可运行的 RAG Benchmark 工具。
- 当前指标已有 `recall@k`、`mrr`、`hit_rate`，但缺少 `precision@k` 和批量实验汇总。
- README 中还没有可复现的 RAG 实验结果表格。

本阶段目标是将 RAG 能力从“能运行”推进到“可评估、可对比、可展示”。

## 2. 总体目标

新增 `RAG Evaluation Benchmark` 能力，支持：

1. 保留现有 local deterministic retriever 作为 baseline。
2. 新增可选 Chroma 向量数据库后端。
3. 构建 RAG 评估集。
4. 支持 `recall@k`、`precision@k`、`mrr`、`hit_rate` 指标。
5. 对比不同 `top_k`：
   - `top_k=1`
   - `top_k=3`
   - `top_k=5`
   - `top_k=8`
6. 对比不同 query 构造策略：
   - `description_only`
   - `description_port`
   - `description_port_hint`
7. 输出 Markdown 对比表格，用于 README 和简历展示。

最终希望在 README 中沉淀一段可复现实验结论，例如：

```text
在工业告警 RAG 评估集上，引入端口信息和 OT protocol hint 的 query 策略，相比仅使用告警描述，提高了 recall@k 和 MRR。
```

## 3. 非目标

本阶段不做以下内容：

- 不接入真实 embedding API。
- 不引入 Milvus、Qdrant、Weaviate 等服务化向量数据库。
- 不做复杂 Web UI。
- 不替换现有 local retriever。
- 不要求 Chroma 成为默认依赖。
- 不把 Chroma 缓存、运行报告、临时索引提交到 Git。

Chroma 作为可选后端存在；未安装 Chroma 时，SecMiniAgent 的默认功能仍应正常运行。

## 4. 技术方案

### 4.1 RAG 后端抽象

新增统一后端抽象：

```text
secminiagent/rag/backends.py
```

建议接口：

```python
class RagBackend:
    def ingest_path(self, path: Path) -> int:
        ...

    def search(
        self,
        query: str,
        top_k: int = 5,
        filters: dict[str, str] | None = None,
    ) -> list[SearchResult]:
        ...
```

实现两个后端：

```text
LocalRagBackend
ChromaRagBackend
```

其中：

- `LocalRagBackend` 复用当前 `KnowledgeRetriever`。
- `ChromaRagBackend` 使用 Chroma collection 存储 chunk、embedding 和 metadata。

### 4.2 Chroma 后端

Chroma 作为可选依赖：

```toml
[project.optional-dependencies]
chroma = ["chromadb>=0.5.0"]
```

安装方式：

```powershell
python -m pip install -e ".[chroma]"
```

默认持久化路径：

```text
.secminiagent/rag/chroma/
```

该路径应被 `.gitignore` 忽略。

当用户指定 `backend="chroma"` 但未安装 `chromadb` 时，应返回清晰错误：

```text
Chroma backend requires chromadb. Install with: python -m pip install -e ".[chroma]"
```

### 4.3 Embedding 策略

第一阶段使用当前 deterministic embedding，保证：

- 无 API Key。
- 无远程调用费用。
- 测试稳定。
- 本地可复现。

后续可扩展真实 embedding provider：

- OpenAI embedding
- 火山 embedding
- 本地 sentence-transformers

本阶段只预留接口，不实现真实 embedding provider。

### 4.4 Query Strategy

新增 query 构造模块：

```text
secminiagent/rag/query.py
```

支持三种策略：

#### description_only

只使用告警描述：

```text
Office host accessed PLC Modbus service.
```

#### description_port

使用告警描述和目的端口：

```text
Office host accessed PLC Modbus service. traffic to port 502
```

#### description_port_hint

使用告警描述、目的端口和 OT protocol hint：

```text
Office host accessed PLC Modbus service. traffic to port 502 Modbus PLC industrial control protocol suspicious OT access
```

OT port hint 可复用当前 `rag_tools.py` 中已有的端口知识：

```python
OT_PORT_HINTS = {
    502: "Modbus PLC industrial control protocol suspicious OT access",
    102: "S7comm Siemens PLC industrial control protocol access",
    4840: "OPC UA industrial data exchange OT access",
}
```

为了避免重复，建议将该常量移动到 `secminiagent/rag/query.py` 或公共模块中，再由工具层复用。

### 4.5 RAG 评估集

扩展：

```text
tests/fixtures/rag_eval.json
```

建议结构：

```json
[
  {
    "id": "modbus_plc_access",
    "description": "Office host accessed PLC Modbus service.",
    "destination_port": 502,
    "protocol": "tcp",
    "severity": "high",
    "expected_doc_ids": [
      "knowledge/protocols/modbus.md",
      "knowledge/rules/ot_rules.md"
    ]
  }
]
```

评估样本应覆盖：

- Modbus 502
- OPC UA 4840
- S7comm 102
- RDP brute force
- office-to-OT
- remote maintenance
- lateral movement
- wind farm SCADA

最小样本数建议为 8 条，后续可扩展到 12 条以上。

### 4.6 RAG 指标

增强：

```text
secminiagent/rag/evaluator.py
```

已有指标：

```text
recall_at_k
mrr
hit_rate
```

新增：

```text
precision_at_k
```

指标定义：

```text
recall@k = top_k 中命中的相关文档数 / 应该命中的相关文档总数
precision@k = top_k 中命中的相关文档数 / top_k 返回文档数
mrr = 第一个正确结果排名的倒数
hit_rate = top_k 中至少命中一个正确文档则为 1，否则为 0
```

当某条样本没有 expected docs 时：

- `recall@k` 返回 `0.0`
- `precision@k` 返回 `0.0`
- `mrr` 返回 `0.0`
- `hit_rate` 返回 `0.0`

### 4.7 Benchmark 工具

新增工具文件：

```text
secminiagent/tools/rag_eval_tools.py
```

新增工具：

```text
evaluate_rag
```

输入 schema：

```json
{
  "eval_path": "tests/fixtures/rag_eval.json",
  "knowledge_path": "knowledge",
  "backend": "local",
  "top_k_values": [1, 3, 5, 8],
  "query_strategies": [
    "description_only",
    "description_port",
    "description_port_hint"
  ],
  "write_file": false,
  "output_path": ".secminiagent/reports/rag-evaluation.md"
}
```

`backend` 支持：

```text
local
chroma
all
```

当 `backend="all"` 时，同时运行 local 和 chroma，并输出同一张对比表。

### 4.8 输出格式

输出 Markdown：

```markdown
# RAG Evaluation Report

| Backend | Query Strategy | Top-K | Recall@K | Precision@K | MRR | Hit Rate |
|---|---|---:|---:|---:|---:|---:|
| local | description_only | 1 | 0.42 | 0.42 | 0.42 | 0.42 |
| local | description_port | 3 | 0.72 | 0.39 | 0.63 | 0.75 |
| local | description_port_hint | 3 | 0.83 | 0.44 | 0.74 | 0.83 |
| chroma | description_port_hint | 3 | 0.88 | 0.48 | 0.80 | 0.92 |
```

表格中的数值必须由工具实际运行产生，README 中不得手写未验证的假数据。

报告还应包含：

- evaluation dataset path
- knowledge path
- sample count
- backend list
- top_k list
- query strategy list
- generated time

### 4.9 CLI 集成

在 `secminiagent/cli.py` 中注册：

```python
EvaluateRagTool()
```

支持自然语言触发，例如：

```powershell
python -m secminiagent --no-env "evaluate rag benchmark"
```

fake provider 可增加路由：

```text
evaluate rag
rag benchmark
rag evaluation
```

默认参数：

```text
eval_path=tests/fixtures/rag_eval.json
knowledge_path=knowledge
backend=local
top_k_values=[1, 3, 5, 8]
query_strategies=[description_only, description_port, description_port_hint]
```

### 4.10 README 展示

README 新增：

```text
RAG Evaluation Benchmark
```

内容包括：

- 实验目标
- 后端说明：local vs chroma
- 指标定义
- Query 策略说明
- 运行命令
- 实际结果表格
- 结论

示例命令：

```powershell
python -m secminiagent --no-env "evaluate rag benchmark"
```

如需 Chroma：

```powershell
python -m pip install -e ".[chroma]"
python -m secminiagent --no-env "evaluate rag benchmark with chroma"
```

## 5. 文件变更范围

预计新增：

```text
secminiagent/rag/backends.py
secminiagent/rag/query.py
secminiagent/rag/benchmark.py
secminiagent/tools/rag_eval_tools.py
tests/test_rag_query.py
tests/test_rag_benchmark.py
tests/test_rag_eval_tools.py
```

预计修改：

```text
pyproject.toml
.gitignore
README.md
secminiagent/cli.py
secminiagent/llm/fake.py
secminiagent/rag/evaluator.py
tests/fixtures/rag_eval.json
```

可选修改：

```text
secminiagent/tools/rag_tools.py
```

用于复用 query strategy 或移动 `OT_PORT_HINTS`。

## 6. 测试计划

### 6.1 单元测试

新增或扩展：

```text
tests/test_rag_evaluator.py
tests/test_rag_query.py
tests/test_rag_benchmark.py
tests/test_rag_eval_tools.py
```

覆盖：

- `precision_at_k`
- `recall_at_k`
- `mrr`
- `hit_rate`
- 三种 query strategy
- local backend benchmark
- Chroma 未安装时的友好错误
- `backend=all` 参数解析
- Markdown 表格输出

### 6.2 回归测试

运行：

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

### 6.3 手动验证

local benchmark：

```powershell
python -m secminiagent --no-env "evaluate rag benchmark"
```

Chroma benchmark：

```powershell
python -m pip install -e ".[chroma]"
python -m secminiagent --no-env "evaluate rag benchmark with chroma"
```

RAG 报告原有能力仍应可用：

```powershell
python -m secminiagent --no-env "generate a RAG wind power threat report"
```

## 7. 验收标准

本阶段完成后，应满足：

1. 全量测试通过。
2. 无 Chroma 依赖时，默认 local backend 仍可运行。
3. 指定 Chroma backend 且未安装依赖时，有清晰错误信息。
4. 安装 Chroma 后，可以运行 Chroma benchmark。
5. `evaluate_rag` 能输出 Markdown 对比表格。
6. 指标包含 `recall@k`、`precision@k`、`mrr`、`hit_rate`。
7. 对比维度包含 `top_k=1/3/5/8`。
8. 对比维度包含三种 query strategy。
9. README 展示真实运行得到的实验结果。
10. 原有 RAG threat report、industrial threat report、安全扫描能力不回归。

## 8. 简历表达

完成后可写入简历：

```text
实现 Local 与 Chroma 双检索后端，构建工业安全 RAG Benchmark 评估集，支持 recall@k、precision@k、MRR、hit_rate 等检索指标，对 top_k 和 query 构造策略进行量化对比，并输出 Markdown 实验报告用于评估工业告警知识召回质量。
```

更偏工程表达：

```text
基于统一 Retriever Backend 抽象实现可插拔 RAG 检索架构，支持本地 deterministic retriever 与 Chroma 向量数据库切换；构建评估工具对不同 top_k 和领域增强 query 策略进行实验对比，验证 OT protocol hint 对检索质量的提升效果。
```

## 9. 风险与处理

### Chroma 依赖安装失败

处理：

- Chroma 设置为 optional dependency。
- 默认测试不强制依赖 Chroma。
- Chroma 相关测试在依赖缺失时只验证友好错误。

### 真实 Chroma 指标不一定优于 local

处理：

- README 中如实展示结果。
- 强调本阶段重点是可插拔后端和可量化评估，而不是保证某个后端一定更高。

### Benchmark 样本太少导致结论不稳定

处理：

- 第一版至少 8 条样本。
- README 中标明是 demo evaluation set。
- 后续可扩展更多风电和 OT/ICS 场景样本。

### `rag_tools.py` 文件继续变大

处理：

- 新增 `rag_eval_tools.py` 单独承载评估工具。
- 新增 `rag/benchmark.py` 承载评估流程。
- 新增 `rag/query.py` 承载 query strategy。

## 10. 推荐实施顺序

1. 增强 evaluator：加入 `precision_at_k`。
2. 新增 query strategy 模块。
3. 扩展 `rag_eval.json`。
4. 新增 local backend benchmark。
5. 新增 `evaluate_rag` 工具。
6. 注册 CLI 和 fake provider 路由。
7. 新增 Chroma optional dependency 与 Chroma backend。
8. 增加 Chroma 缺依赖友好错误测试。
9. 运行 benchmark 生成真实结果。
10. 更新 README 的 RAG Benchmark 章节。
