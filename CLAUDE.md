# CLAUDE.md — Condor

Agentic AI security scanner — OWASP ASI Top 10. Análogo a Corvus pero para plataformas agentic (Flowise, Langflow, Dify, AutoGen).

## Stack

- Python 3.11+, `hatchling`, `httpx`, `pydantic v2`, `typer`, `rich`
- CLI entry point: `condor` → `condor/cli.py`
- Tests: `pytest` + `pytest-asyncio` (asyncio_mode=auto) + `pytest-mock`
- Venv: `.venv/` — usar `.venv\Scripts\python.exe` / `.venv\Scripts\condor.exe`

## Estructura

```
condor/
  core/models.py        — Finding, Severity, OWASPCategory, AgentSurface, ScanResult
  platforms/base.py     — BasePlatform (httpx async context manager)
  platforms/flowise.py  — Flowise REST API v1
  platforms/generic.py  — Generic HTTP probe
  platforms/langflow.py — Langflow REST API v1
  platforms/dify.py     — Dify console API
  modules/base.py       — BaseModule (abstracto, run() → list[Finding])
  modules/asi01_goal_hijack.py   — ASI01: prompt injection
  modules/asi02_tool_misuse.py   — ASI02: path traversal, SSRF, cred exposure
  modules/asi03_privilege.py     — ASI03: unauth endpoint access
  modules/asi04_supply_chain.py  — ASI04: CVE via OSV.dev, poisoned descriptions
  modules/asi05_code_exec.py     — ASI05: eval/exec sinks, RCE endpoints
  modules/asi06_memory_poisoning.py — ASI06: vectorstore access sin auth, doc injection
  modules/asi07_inter_agent.py   — ASI07: inter-agent channels, agentflow enumeration
  modules/asi08_cascading.py     — ASI08: rate limits ausentes, task queue expuesta
  modules/asi09_trust.py         — ASI09: system prompt exposure, human impersonation
  modules/asi10_rogue.py         — ASI10: agent/tool creation sin auth, webhooks
  sarif.py              — to_sarif() → SARIF 2.1.0 (usado por cli.py --sarif)
  cli.py                — registro de _ALL_MODULES y _PLATFORMS; --sarif; --targets
```

## Agregar un módulo nuevo

1. Crear `condor/modules/asiNN_nombre.py` heredando `BaseModule`
2. Registrar en `condor/cli.py` → `_ALL_MODULES`
3. Tests en `tests/test_asiNN.py`

## Agregar un platform adapter nuevo

1. Crear `condor/platforms/nombre.py` heredando `BasePlatform`
2. Implementar `health_check()` y `enumerate() → AgentSurface`
3. Registrar en `condor/cli.py` → `_PLATFORMS`
4. Tests en `tests/test_platform_nombre.py`

## Módulos implementados (10/10)

| Módulo | ASI | Estado |
|--------|-----|--------|
| goal-hijack | ASI01 | ✅ |
| tool-misuse | ASI02 | ✅ |
| privilege-abuse | ASI03 | ✅ |
| supply-chain | ASI04 | ✅ |
| code-execution | ASI05 | ✅ |
| memory-poisoning | ASI06 | ✅ |
| inter-agent | ASI07 | ✅ |
| cascading-failures | ASI08 | ✅ |
| trust-exploitation | ASI09 | ✅ |
| rogue-agents | ASI10 | ✅ |

## Notas de implementación

- `_is_api_response(r)` helper en todos los módulos (ASI03–ASI10): filtra respuestas HTML (SPA catch-all de Flowise 3.x/Next.js) para evitar falsos positivos. Flowise 3.x+ devuelve `200 text/html` para rutas desconocidas. En tests, el mock `resp_404` debe tener `headers={"content-type": "text/html"}` para que el helper lo filtre correctamente.
- `BasePlatform` expone `get`, `post`, `put`, `delete` — todos asientan que `self._client` esté abierto.
- SARIF output: `condor/sarif.py` → `to_sarif(ScanResult, version) → dict`. `--sarif` escribe `report.sarif` junto a `report.json`.
- Batch scan: `--targets <file>` — formato `URL [platform]` por línea, `#` para comentarios. Platform default: `generic`.
- Flowise 2.x+ y 3.x fuerzan workspace auth por defecto (SQLite). Para E2E con findings: usar `flowiseai/flowise:1.8.x` o instancia sin credenciales de versión <2.x.

## Plataformas soportadas (5)

`flowise` · `generic` · `langflow` · `dify` · `autogen`
