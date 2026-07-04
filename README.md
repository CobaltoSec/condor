# Condor

**Agentic AI security testing framework — OWASP ASI Top 10**

Condor scans agentic AI platforms (Flowise, Langflow, Dify, AutoGen Studio) for security vulnerabilities mapped to the [OWASP Top 10 for Agentic Applications](https://owasp.org/www-project-top-10-for-agentic-applications/).

> By CobaltoSec — companion to [Corvus](https://github.com/CobaltoSec/corvus) (MCP security) and [Llamascope](https://github.com/CobaltoSec/llamascope-mcp) (AI infra discovery).

## Install

```bash
pip install cobaltosec-condor
```

## Quick start

```bash
# Scan a Flowise instance
condor scan --url http://localhost:3000 --platform flowise

# Scan with specific module
condor scan --url http://localhost:3000 --platform flowise --module privilege-abuse

# List available modules
condor list-modules
```

## Modules

| Module | OWASP | Description |
|--------|-------|-------------|
| `goal-hijack` | ASI01 | Prompt injection / goal override via user input |
| `privilege-abuse` | ASI03 | Unauthenticated access to sensitive endpoints |
| `code-execution` | ASI05 | eval/exec sinks and unauthenticated code execution |

## Supported platforms

| Platform | Status |
|----------|--------|
| Flowise | ✅ |
| Generic HTTP | ✅ |
| Langflow | 🔲 coming |
| Dify | 🔲 coming |
| AutoGen Studio | 🔲 coming |

## Stack

Python 3.11+ · httpx · pydantic v2 · typer · rich
