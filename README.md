# SecMiniAgent

SecMiniAgent is a local security operations Agent CLI for defensive code review and industrial internet threat analysis.

Current version: `0.3.0`

## Overview

SecMiniAgent is a Python-based local Agent prototype. It keeps the basic Agent abilities of planning, tool calling, local file access, code search, Git inspection, shell execution with safety checks, session storage, and skill loading. On top of that, it adds a security-oriented workflow for industrial internet and OT/ICS operations:

- parse industrial asset inventories
- parse IDS alerts and firewall logs
- parse local IOC and vulnerability files
- correlate assets, alerts, IOCs, and vulnerabilities
- detect suspicious OT access, lateral movement signals, and brute-force attempts
- score industrial asset risk
- generate Markdown security and threat analysis reports

The project is local-first and defensive. It is suitable as a Mini Agent prototype, a security engineering learning project, or a resume project for "local threat analysis Agent" scenarios.

## Quick Start

Run commands from the project root:

```bash
cd SecMiniAgent
```

Show help:

```bash
python -m secminiagent --help
```

Run the built-in fake provider. This mode does not call any remote API:

```bash
python -m secminiagent "scan this project for hardcoded secrets"
```

Generate a code security report:

```bash
python -m secminiagent "generate a security report"
```

Generate an industrial threat analysis report from the bundled demo data:

```bash
python -m secminiagent "generate an industrial threat report"
```

Try several industrial security workflows:

```bash
python -m secminiagent "parse industrial assets"
python -m secminiagent "triage industrial alerts"
python -m secminiagent "hunt IOC matches in alerts"
python -m secminiagent "detect suspicious OT access"
python -m secminiagent "detect lateral movement in industrial alerts"
python -m secminiagent "detect brute force attempts"
```

List available skills:

```bash
python -m secminiagent --list-skills
```

Show resolved runtime configuration:

```bash
python -m secminiagent --show-config
```

## Installation

SecMiniAgent currently uses Python standard-library modules for runtime behavior.

Requirements:

- Python `>=3.11`
- No mandatory third-party Python packages
- Optional API keys for real LLM providers

Optional editable install:

```bash
pip install -e .
```

After editable install, the console command can also be used:

```bash
secminiagent "generate an industrial threat report"
```

## Configuration

The default provider is `fake`, so the project can run without API keys.

To use a real model provider, copy `.env.example` to `.env`:

```bash
copy .env.example .env
```

OpenAI-compatible provider:

```env
SECMINI_PROVIDER=openai
OPENAI_API_KEY=sk-your-openai-key
OPENAI_MODEL=gpt-4.1-mini
OPENAI_BASE_URL=https://api.openai.com/v1
```

Volcengine Ark provider:

```env
SECMINI_PROVIDER=volcengine
ARK_API_KEY=your-volcengine-ark-key
ARK_MODEL=doubao-seed-1-6-251015
ARK_BASE_URL=https://ark.cn-beijing.volces.com/api/v3
```

XFYun MaaS provider:

```env
SECMINI_PROVIDER=xfyun
XFYUN_API_KEY=your-xfyun-maas-key
XFYUN_MODEL=your-xfyun-model-id
XFYUN_BASE_URL=http://maas-api.cn-huabei-1.xf-yun.com/v1
XFYUN_LORA_ID=0
```

CLI arguments override `.env` values:

```bash
python -m secminiagent --provider xfyun --model your-model-id "generate an industrial threat report"
```

Useful runtime flags:

```bash
python -m secminiagent --cwd C:\path\to\workspace "scan this project"
python -m secminiagent --max-turns 12 "analyze alerts"
python -m secminiagent --no-stream "generate a security report"
python -m secminiagent --yes "run safe local checks"
```

## Features

### Agent Framework

- AsyncIO-based CLI entry point
- ReAct-style Agent loop
- Function Calling style tool registration
- JSON Schema tool definitions
- tool call execution and tool-result feedback
- streaming model output and progress events
- session transcripts under `.secminiagent/sessions/`
- context compaction for long conversations and large tool outputs
- built-in and workspace-local skills

### LLM Providers

- `fake`: offline provider for local development and tests
- `openai`: OpenAI-compatible HTTP Chat Completions API
- `volcengine`: Volcengine Ark compatible provider
- `xfyun`: XFYun MaaS compatible provider

### Local Engineering Tools

- `list_dir`: list workspace files
- `read_file`: read local text files with line numbers
- `write_file`: create or overwrite workspace files
- `search_code`: search local code
- `git_status`: inspect Git status
- `git_diff`: inspect Git diff
- `git_log`: inspect Git history
- `run_shell`: run shell commands with safety policy
- `apply_patch`: apply patch-style file edits
- `create_plan` / `update_plan`: maintain task plans

### Code Security Tools

- `scan_secrets`: detect hardcoded secrets and credential-like assignments
- `scan_insecure_patterns`: detect risky code patterns
- `scan_dependency_files`: locate dependency manifests for audit review
- `generate_security_report`: generate a Markdown code security report

Supported code scan examples include:

- private keys
- OpenAI-style keys
- AWS access key IDs
- suspicious `api_key`, `secret`, `token`, or `password` assignments
- Python `eval` / `exec`
- `subprocess(..., shell=True)`
- unsafe `pickle.load` / `pickle.loads`
- weak `md5` / `sha1`
- plaintext HTTP URLs
- possible SQL string concatenation
- path traversal hints

### Industrial Threat Analysis Tools

- `parse_assets`: parse industrial asset inventory CSV files
- `parse_alerts`: parse IDS alert JSON files or firewall logs
- `extract_iocs`: parse local IOC text files
- `match_iocs`: match IOC values against alert source and destination IPs
- `analyze_asset_risk`: score assets by criticality, zone, alert severity, and OT exposure
- `correlate_alerts`: correlate assets, alerts, IOCs, and vulnerabilities into suspected incidents
- `detect_bruteforce`: detect repeated login-like alerts
- `detect_lateral_movement`: detect one source reaching many destination assets
- `detect_suspicious_ot_access`: detect office-to-OT, cross-zone, IOC, and industrial protocol access
- `generate_threat_report`: generate a Markdown industrial threat analysis report

### RAG-Enhanced Threat Analysis

SecMiniAgent includes a local RAG demo for industrial security alert analysis. It can ingest local Markdown knowledge under `knowledge/`, parse CSV alert exports, retrieve relevant protocol/playbook/wind-power context, and generate a RAG-enhanced Markdown threat report.

Example:

```bash
python -m secminiagent "generate a RAG wind power threat report"
```

RAG tools:

- `ingest_knowledge`
- `search_knowledge`
- `explain_alert_with_rag`
- `generate_rag_threat_report`

OT/ICS correlation rules currently cover:

- access to industrial protocol ports on critical OT assets
- office or IT source accessing critical OT assets
- cross-zone access to OT assets
- IOC matches in alert traffic
- one source probing multiple OT assets
- high-risk vulnerable asset with recent alerts

## Demo Data

The `examples/industrial/` directory contains local demo data:

```text
examples/industrial/
  assets.csv        Industrial asset inventory
  ids_alerts.json   IDS alerts
  firewall.log      Firewall flow logs
  ioc.txt           Local IOC values
  vulns.json        Vulnerability context
```

The fake provider routes common prompts to this demo data, which makes the industrial threat analysis workflow runnable without a real LLM API.

## Application Scenarios

SecMiniAgent is designed for local defensive security workflows such as:

- local code security review before committing or publishing a project
- hardcoded secret and insecure pattern scanning
- Git diff security review
- industrial asset inventory review
- IDS and firewall alert triage
- IOC hunting against local alert files
- OT/ICS suspicious access detection
- asset risk ranking for PLC, HMI, engineering stations, jump hosts, and production-zone assets
- incident response summary generation
- Markdown report generation for security review or learning demonstrations

## Project Architecture

```text
SecMiniAgent/
  pyproject.toml
  README.md
  .env.example
  examples/
    industrial/
  secminiagent/
    __main__.py
    cli.py
    config.py
    agent/
      loop.py
      planner.py
      events.py
    context/
      compressor.py
      manager.py
    llm/
      base.py
      fake.py
      openai_client.py
      volcengine_client.py
      xfyun_client.py
    tools/
      base.py
      registry.py
      file_tools.py
      search_tool.py
      git_tools.py
      shell_tool.py
      patch_tool.py
      security_tools.py
      threat_tools.py
    security/
      scanner.py
      rules.py
      ot_rules.py
      report.py
      threat_report.py
    threat/
      assets.py
      alerts.py
      indicators.py
      incidents.py
      risk_score.py
      analyzer.py
      attack_chain.py
    parsers/
      asset_csv_parser.py
      alert_json_parser.py
      firewall_parser.py
      ioc_parser.py
      vuln_parser.py
    safety/
      command_policy.py
      permissions.py
    skills/
      loader.py
      builtin/
    storage/
      transcript.py
  tests/
```

Core module responsibilities:

- `secminiagent/cli.py`: command-line argument parsing, provider selection, tool registry setup
- `secminiagent/agent/loop.py`: Agent loop, model calls, tool calls, tool result feedback
- `secminiagent/llm/`: model provider adapters
- `secminiagent/tools/`: Function Calling tools
- `secminiagent/security/`: code security scanner, OT rules, and report renderers
- `secminiagent/threat/`: industrial threat domain models and correlation logic
- `secminiagent/parsers/`: local parsers for assets, alerts, IOCs, firewall logs, and vulnerabilities
- `secminiagent/safety/`: shell command risk policy and approval handling
- `secminiagent/skills/`: built-in task guidance for security workflows
- `secminiagent/storage/`: JSONL session transcripts

## Built-in Skills

The current built-in skills are:

- `code_security_review`
- `secret_scan`
- `dependency_audit`
- `industrial_threat_analysis`
- `alert_triage`
- `ioc_hunting`
- `ot_asset_risk_review`
- `incident_response`

Skills are Markdown files under `secminiagent/skills/builtin/`. They are selected automatically by prompt keywords or can be loaded explicitly:

```bash
python -m secminiagent --skill industrial_threat_analysis "generate an industrial threat report"
```

## Output Files

Runtime output is stored under `.secminiagent/`:

```text
.secminiagent/
  sessions/   JSONL conversation transcripts
  reports/    Optional generated Markdown reports
```

These paths are ignored by Git.

## Safety Boundary

SecMiniAgent is defensive and local-first:

- file access is constrained to the selected workspace
- high-risk shell commands are denied or require approval
- broad destructive operations such as `git reset --hard` and recursive delete are blocked
- `.env`, sessions, and generated reports are ignored by Git
- the project is intended for security review, triage, and defensive analysis, not exploit automation

## Tests

Run the full test suite:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

Current tests cover:

- config and `.env` loading
- Agent loop tool execution
- tool registry behavior
- shell safety policy
- patch application
- secret and insecure pattern scanning
- security report generation
- industrial parsers
- OT rules
- industrial threat tools

## Difference From MiniClaude

MiniClaude focuses on local coding tasks: reading files, editing code, running shell commands, planning, and interacting with Git.

SecMiniAgent keeps those local Agent foundations but changes the project goal and adds domain-specific security operations capabilities:

- industrial asset and alert data models
- asset, alert, IOC, firewall, and vulnerability parsers
- OT/ICS correlation rules
- industrial asset risk scoring
- suspicious OT access and lateral movement detection
- defensive security report and industrial threat report generation
- security-specific built-in skills

In short, MiniClaude is a coding Agent prototype. SecMiniAgent is a local defensive security and industrial threat analysis Agent prototype.

## Roadmap

Planned improvements:

- support more real-world log formats such as Syslog, Suricata, Zeek, and Windows Event logs
- add MITRE ATT&CK for ICS technique mapping
- add richer incident severity and status workflow
- improve report templates for daily reports, weekly reports, and incident response reports
- support directory-level batch ingestion for industrial security data
- add more tests for real provider request formatting and streaming tool calls
