# Memory benchmark

本目录只使用 `datasets/synthetic-memory-v1.json` 中的合成数据，不读取工作区或用户的 `.secminiagent`。固定随机种子为 `20260731`；每份报告记录数据集 SHA-256 digest、Python/SQLite 版本、阈值和结果。

从项目根目录执行，并把结果写入显式临时目录：

```powershell
New-Item -ItemType Directory -Force .tmp-memory-benchmark | Out-Null
.\.venv\Scripts\python.exe benchmarks\memory\run_retrieval.py --output-dir .tmp-memory-benchmark
.\.venv\Scripts\python.exe benchmarks\memory\run_summary.py --output-dir .tmp-memory-benchmark
.\.venv\Scripts\python.exe benchmarks\memory\run_auto_memory.py --output-dir .tmp-memory-benchmark
.\.venv\Scripts\python.exe benchmarks\memory\run_migration.py --output-dir .tmp-memory-benchmark
```

`run_migration.py` 默认测量 1k/10k/100k 合成 v1 记录的 v2 shadow/activate 吞吐、Python 峰值分配与数据库放大；CI 快速检查可显式使用 `--scales 1000`，发布验收不得省略默认完整 scales。

冻结发布门：Recall@3 ≥ 0.90、MRR ≥ 0.80；跨 scope/status 的 forbidden recall 为 0；摘要事实保持、provenance 完整和 classification 单调继承均为 1.0；自动记忆分类准确率为 1.0 且 automatic confirmed 为 0。耗时仅记录趋势，不使用不稳定的窄绝对时钟断言。

输出目录不得位于任何 `.secminiagent` 路径内。JSON/Markdown 报告只含合成统计、环境信息和 digest，不含 fixture 正文。
