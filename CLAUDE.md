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
  platforms/flowise.py    — Flowise REST API v1
  platforms/generic.py    — Generic HTTP probe
  platforms/langflow.py   — Langflow REST API v1
  platforms/dify.py       — Dify console API
  platforms/n8n.py        — n8n workflow automation
  platforms/llamaindex.py — LlamaIndex agents server (FastAPI)
  platforms/crewai.py     — CrewAI serve (FastAPI)
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
  sarif.py              — to_sarif() → SARIF 2.1.0 (usado por cli.py --format sarif|both)
  cli.py                — registro de _ALL_MODULES y _PLATFORMS; --format; --exclude-module; --concurrency; --api-key; --targets
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
- Auth: `BasePlatform.__init__` acepta `api_key`, `username`, `password`. Plataformas construyen headers estáticos en `__init__`; Langflow y Dify hacen pre-auth POST en `_authenticate()` (hook llamado en `__aenter__`).
- CLI auth flags: `--api-key` / `--username` / `--password` — threaded a `_scan()` y a la construcción del platform.
- Output format: `--format json|sarif|both|table` (reemplaza `--sarif`). `both` escribe `report.json` + `report.sarif`.
- Batch scan concurrente: `--targets <file>` con `--concurrency N` (default 5). `asyncio.gather` + `asyncio.Semaphore`. `_scan()` acepta `verbose=False` para suprimir output inline en batch.
- Progress bar: `rich.Progress` en loop de módulos y en batch scan (outer progress).
- `--exclude-module` / `-x` (repeatable): skip módulos específicos con warning si nombre desconocido.
- Flowise 2.x+ y 3.x fuerzan workspace auth por defecto (SQLite). Para E2E con findings: usar `flowiseai/flowise:1.8.x` o instancia sin credenciales de versión <2.x.
- ASI01: detección semántica (compliance phrases) con confidence 60, además de markers exactos (90). Soporta Dify y Langflow endpoints. 8 payloads incluyendo base64, prompt continuation, Unicode, tool-result simulation.
- ASI02: payloads URL-encoded + double-encoded para path traversal; GCP/Azure IMDS + IPv6 para SSRF. Indicadores extendidos.
- ASI05: OS command probe activo (`child_process.execSync('id')` para JS, `subprocess.check_output(['id'])` para Python). Output confirmation para AutoGen y Langflow. Blind timing probe para entornos non-reflective.

## Plataformas soportadas (8)

`flowise` · `generic` · `langflow` · `dify` · `autogen` · `n8n` · `llamaindex` · `crewai`
