# Condor

**Agentic AI security scanner — OWASP ASI Top 10**

[![CI](https://github.com/CobaltoSec/condor/actions/workflows/ci.yml/badge.svg)](https://github.com/CobaltoSec/condor/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/cobaltosec-condor)](https://pypi.org/project/cobaltosec-condor/)
[![Python 3.11+](https://img.shields.io/pypi/pyversions/cobaltosec-condor)](https://pypi.org/project/cobaltosec-condor/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Condor scans agentic AI platforms for security vulnerabilities mapped to the [OWASP Top 10 for Agentic Applications](https://owasp.org/www-project-top-10-for-agentic-applications/). It understands the semantics of each platform — enumerating chatflows, tools, vectorstores, and agent surfaces — then runs 10 specialized modules in parallel.

Against a Flowise 1.8.2 instance, Condor finds **9 findings in 3.6 seconds** — 3 CRITICAL, 5 HIGH, 1 MEDIUM — all confirmed true positives mapping to published GHSAs.

> Part of the CobaltoSec toolkit alongside [Corvus](https://github.com/CobaltoSec/corvus) (MCP security) and [Llamascope](https://github.com/CobaltoSec/llamascope-mcp) (AI infra discovery).

## Install

```bash
pip install cobaltosec-condor
```

## Quick start

```bash
# Scan a Flowise instance
condor scan --url http://localhost:3000 --platform flowise

# JSON output for piping
condor scan --url http://localhost:3000 --platform flowise --format json --stdout | jq '.findings[].severity'

# SARIF output for GitHub Code Scanning
condor scan --url http://localhost:3000 --platform flowise --format sarif

# Authenticated scan
condor scan --url https://letta.internal --platform letta --api-key $LETTA_KEY

# Batch scan from a targets file
condor scan --targets targets.txt --platform generic --concurrency 10 --format json

# Run specific modules only
condor scan --url http://localhost:3000 --platform flowise -m privilege-abuse -m code-execution
```

## Modules — 10 / 10 OWASP ASI

| Module | ASI | What it tests |
|--------|-----|---------------|
| `goal-hijack` | ASI01 | Prompt injection, jailbreaks, indirect injection via tool output |
| `tool-misuse` | ASI02 | Path traversal, SSRF, SSTI, credential exposure |
| `privilege-abuse` | ASI03 | Unauthenticated endpoints, IDOR, header bypass (CVE-2026-30820) |
| `supply-chain` | ASI04 | CVE detection via OSV.dev, poisoned tool descriptions |
| `code-execution` | ASI05 | eval/exec sinks, unauthenticated RCE endpoints |
| `memory-poisoning` | ASI06 | Vectorstore access without auth, adversarial injection |
| `inter-agent` | ASI07 | Inter-agent channels, origin forgery |
| `cascading-failures` | ASI08 | Rate limit bypass, task queue exposure |
| `trust-exploitation` | ASI09 | System prompt exposure, AI identity disclosure |
| `rogue-agents` | ASI10 | Unauthenticated agent/tool creation, webhook registration |

## Supported platforms — 16

| Platform | `--platform` | Notes |
|----------|-------------|-------|
| Flowise | `flowise` | chatflows, tools, vectorstores, apikey endpoint |
| Langflow | `langflow` | flows, custom component execution |
| Dify | `dify` | apps, datasets, system prompt modification |
| AutoGen Studio | `autogen` | tools/execute RCE surface |
| n8n | `n8n` | workflows, credential endpoints |
| LlamaIndex | `llamaindex` | FastAPI agent server |
| CrewAI | `crewai` | FastAPI serve |
| LangGraph | `langgraph` | threads, store, runs |
| Ollama | `ollama` | model server, write endpoints |
| OpenAI-compatible | `openai-compat` | vLLM, LocalAI, LM Studio |
| Open WebUI | `openwebui` | Python function/tool creation (persistent RCE surface) |
| Hayhooks | `hayhooks` | pipeline endpoints, OpenAPI spec |
| Letta | `letta` | per-agent memory IDOR, `/v1/tools/run` RCE (GHSA-p67m-xf4h-2r78) |
| Qdrant | `qdrant` | collections, snapshot SSRF |
| Chroma | `chroma` | collections v1/v2, unauthenticated writes |
| Generic HTTP | `generic` | OpenAPI/Swagger auto-parsing, GraphQL introspection |

## Output formats

```bash
--format table    # Rich terminal table (default)
--format json     # Structured JSON
--format sarif    # SARIF 2.1.0 — GitHub Code Scanning / SAST tooling
--format html     # Self-contained HTML with dark mode and collapsible findings
--format junit    # JUnit XML — Jenkins, GitLab, CircleCI
--format both     # JSON + SARIF written simultaneously
--stdout          # Emit JSON to stdout for piping (suppresses progress bar)
```

## Advanced usage

```bash
# Suppress known-good findings with a baseline
condor scan --url http://localhost:3000 --platform flowise --save-baseline baseline.json
condor scan --url http://localhost:3000 --platform flowise --baseline baseline.json

# Route through Burp Suite
condor scan --url http://localhost:3000 --platform flowise \
  --proxy http://127.0.0.1:8080 --insecure

# Only report HIGH and above
condor scan --url http://localhost:3000 --platform flowise --min-severity high

# Load defaults from a config file
condor scan --config condor.yaml

# Scaffold a new module
condor scaffold --name my-check --asi 03
```

## GitHub Actions

```yaml
- uses: CobaltoSec/condor/.github/actions/condor-scan@v1
  with:
    url: ${{ env.STAGING_URL }}
    platform: flowise
    format: sarif
    fail-on: critical

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: condor-results/report.sarif
```

## Integrations

```bash
# Slack / Teams notifications
condor scan --url http://localhost:3000 --platform flowise \
  --notify-slack $SLACK_WEBHOOK_URL

# DefectDojo export
condor scan --url http://localhost:3000 --platform flowise \
  --defectdojo-url https://defectdojo.internal \
  --defectdojo-token $DD_TOKEN \
  --defectdojo-product "AI Platform Audit"
```

## Plugin system

Third-party modules and platform adapters are auto-discovered via `importlib.metadata` entry points:

```toml
# pyproject.toml of your plugin package
[project.entry-points."condor.modules"]
my-check = "my_package.modules:MyCheckModule"

[project.entry-points."condor.platforms"]
my-platform = "my_package.platforms:MyPlatform"
```

## Compliance

Every finding includes references to ISO/IEC 42001, NIST AI RMF, and EU AI Act. CWE IDs are included in SARIF output for integration with SAST tooling.

## License

MIT © [CobaltoSec](https://cobalto-sec.tech)
