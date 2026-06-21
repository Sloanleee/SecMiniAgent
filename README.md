# SecMiniAgent

SecMiniAgent is a local defensive security review Agent CLI. It reads a local repository, calls structured tools, scans for common risks, and produces concise remediation guidance.

Current version: `0.2.0`.

## Quick Start

Show CLI help:

```bash
python -m secminiagent --help
```

Run with the built-in fake provider, which does not call any remote API:

```bash
python -m secminiagent "scan this project for hardcoded secrets"
```

Generate a local security report:

```bash
python -m secminiagent "generate a security report"
```

List built-in skills:

```bash
python -m secminiagent --list-skills
```

Show resolved configuration:

```bash
python -m secminiagent --show-config
```

## Configuration

Copy `.env.example` to `.env` and fill in one provider:

```bash
copy .env.example .env
```

The default provider is `fake`, so the project can run and test without API keys.

OpenAI-compatible example:

```env
SECMINI_PROVIDER=openai
OPENAI_API_KEY=sk-your-openai-key
OPENAI_MODEL=gpt-4.1-mini
OPENAI_BASE_URL=https://api.openai.com/v1
```

Volcengine Ark example:

```env
SECMINI_PROVIDER=volcengine
ARK_API_KEY=your-volcengine-ark-key
ARK_MODEL=doubao-seed-1-6-251015
ARK_BASE_URL=https://ark.cn-beijing.volces.com/api/v3
```

XFYun MaaS example:

```env
SECMINI_PROVIDER=xfyun
XFYUN_API_KEY=your-xfyun-maas-key
XFYUN_MODEL=your-xfyun-model-id
XFYUN_BASE_URL=http://maas-api.cn-huabei-1.xf-yun.com/v1
XFYUN_LORA_ID=0
```

CLI flags override `.env`:

```bash
python -m secminiagent --provider xfyun --model your-model-id "scan this project"
```

## Implemented Capabilities

- Python + AsyncIO CLI.
- AgentLoop with tool calling and tool-result feedback.
- Fake provider for offline development and tests.
- OpenAI-compatible provider base client.
- Volcengine Ark provider.
- XFYun MaaS provider.
- Streaming/progress events for model turns and tool execution.
- JSON Schema based ToolRegistry.
- File tools: `list_dir`, `read_file`, `write_file`.
- Search tool: `search_code`.
- Git tools: `git_status`, `git_diff`, `git_log`.
- Shell tool with safety policy.
- Patch editing tool: `apply_patch`.
- Security tools: `scan_secrets`, `scan_insecure_patterns`, `scan_dependency_files`, `generate_security_report`.
- Built-in skills: `code_security_review`, `secret_scan`, `dependency_audit`.
- Session transcripts under `.secminiagent/sessions/`.
- Optional Markdown reports under `.secminiagent/reports/`.

## Security Scans

Secret scanning detects examples such as:

- private keys
- OpenAI-style keys
- AWS access key IDs
- suspicious `api_key`, `secret`, `token`, or `password` assignments

Insecure pattern scanning detects examples such as:

- Python `eval` / `exec`
- `subprocess(..., shell=True)`
- unsafe `pickle.load` / `pickle.loads`
- weak `md5` / `sha1`
- plaintext HTTP URLs
- possible SQL string concatenation
- path traversal hints

## Safety Boundary

SecMiniAgent is defensive and local-first:

- file access is constrained to the workspace
- dangerous shell commands are denied or require confirmation
- broad destructive commands such as `git reset --hard` and recursive delete are blocked
- generated reports and sessions are ignored by git

## Architecture

- `secminiagent/cli.py`: command-line entry point.
- `secminiagent/config.py`: `.env` loading and runtime configuration.
- `secminiagent/agent/loop.py`: ReAct-style AgentLoop.
- `secminiagent/llm/`: LLM provider adapters.
- `secminiagent/tools/`: local tools and tool registry.
- `secminiagent/security/`: security rules, scanner, findings, and report rendering.
- `secminiagent/safety/`: command safety policy.
- `secminiagent/context/`: context compaction.
- `secminiagent/storage/`: session transcripts.
- `secminiagent/skills/`: built-in and local skills.

## Tests

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```
