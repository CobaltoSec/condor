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
  core/models.py        — Finding, Severity, OWASPCategory, AgentSurface, ScanResult (+ timestamps)
  platforms/base.py     — BasePlatform (httpx async context manager; proxy/verify_ssl support)
  platforms/flowise.py    — Flowise REST API v1
  platforms/generic.py    — Generic HTTP probe + OpenAPI/Swagger auto-parsing + GraphQL introspection
  platforms/langflow.py   — Langflow REST API v1
  platforms/dify.py       — Dify console API
  platforms/n8n.py        — n8n workflow automation
  platforms/llamaindex.py — LlamaIndex agents server (FastAPI)
  platforms/crewai.py     — CrewAI serve (FastAPI)
  platforms/langgraph.py  — LangGraph Platform (threads, store, runs)
  platforms/ollama.py     — Ollama local model server
  platforms/openai_compat.py — OpenAI-compatible (vLLM, LocalAI, LM Studio)
  platforms/openwebui.py  — Open WebUI (Bearer auth, /api/v1/functions Python exec)
  platforms/hayhooks.py   — Haystack/hayhooks (/pipelines, /openapi.json)
  platforms/letta.py      — Letta/MemGPT (Bearer auth, per-agent /memory IDOR surface)
  platforms/qdrant.py     — Qdrant standalone (api-key header nativo, /telemetry version)
  platforms/chroma.py     — Chroma standalone (/api/v1/heartbeat, bare-string version)
  modules/base.py       — BaseModule (abstracto, run() → list[Finding])
  modules/asi01_goal_hijack.py   — ASI01: prompt injection
  modules/asi02_tool_misuse.py   — ASI02: path traversal, SSRF, SSTI, cred exposure
  modules/asi03_privilege.py     — ASI03: unauth endpoint access, IDOR, mass assignment
  modules/asi04_supply_chain.py  — ASI04: CVE via OSV.dev (npm+PyPI), poisoned descriptions
  modules/asi05_code_exec.py     — ASI05: eval/exec sinks, RCE endpoints
  modules/asi06_memory_poisoning.py — ASI06: vectorstore access sin auth, adversarial injection
  modules/asi07_inter_agent.py   — ASI07: inter-agent channels, origin forgery
  modules/asi08_cascading.py     — ASI08: burst probe rate limits, task queue expuesta
  modules/asi09_trust.py         — ASI09: system prompt exposure, AI disclosure, impersonation
  modules/asi10_rogue.py         — ASI10: agent/tool creation sin auth, webhooks, rogue detection
  sarif.py              — to_sarif() → SARIF 2.1.0
  html_report.py        — to_html() → reporte self-contained con dark mode y collapsibles
  junit_report.py       — to_junit() → JUnit XML para Jenkins/GitLab/CircleCI
  baseline.py           — fingerprint SHA-256, load/save/apply baseline (suppression)
  config.py             — carga condor.yaml / .condor.yaml / ~/.condor.yaml
  remediation.py        — enrich_findings(findings, platform) → remediaciones específicas por plataforma
  compliance.py         — get_compliance_refs(owasp_id) → {iso_42001, nist_ai_rmf, eu_ai_act}
  integrations/
    notify.py           — notify_slack(), notify_teams() async webhooks
    defectdojo.py       — export_to_defectdojo() → Product→Engagement→Test→Finding
  cli.py                — _ALL_MODULES, _PLATFORMS, _load_plugins(); todos los flags de scan + scaffold command
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
- Output format: `--format json|sarif|both|table|html|junit`. `both` escribe `report.json` + `report.sarif`.
- Batch scan concurrente: `--targets <file>` con `--concurrency N` (default 5). `asyncio.gather` + `asyncio.Semaphore`. `_scan()` acepta `verbose=False` para suprimir output inline en batch.
- Progress bar: `rich.Progress` en loop de módulos y en batch scan (outer progress).
- `--exclude-module` / `-x` (repeatable): skip módulos específicos con warning si nombre desconocido.
- `--baseline` / `--save-baseline`: suppression file por fingerprint SHA-256[:16] de `(owasp_id|title|endpoint)`.
- `--proxy` / `--insecure`: Burp Suite integration. `BasePlatform(proxy, verify_ssl)`.
- `--min-severity`: filtra findings por debajo del threshold en el output.
- `--config` / `-c`: carga `condor.yaml` con defaults. Prioridad: CLI > env > config > hardcoded.
- `--stdout`: emite JSON a stdout para piping (`| jq`). Suprime progress bar.
- Exit codes: 0=clean, 1=findings ≥ threshold, 2=config error.
- Módulos paralelos: `asyncio.gather` sobre los 10 módulos ASI → ~70% reducción de tiempo de scan.
- Deduplicación: `_dedup_findings()` por `(owasp_id, title, endpoint)` antes de output.
- Remediation Advisor: `enrich_findings(findings, platform)` wired post-dedup — appenda fix específico a cada finding.
- Plugin system: `_load_plugins()` via `importlib.metadata.entry_points(group="condor.modules")` — auto-discovery de módulos y plataformas externas.
- Flowise 2.x+ y 3.x fuerzan workspace auth por defecto (SQLite). Para E2E con findings: usar `flowiseai/flowise:1.8.x` o instancia sin credenciales de versión <2.x.
- ASI01: detección semántica (compliance phrases) con confidence 60, además de markers exactos (90). Soporta Dify y Langflow endpoints. 8 payloads incluyendo base64, prompt continuation, Unicode, tool-result simulation.
- ASI02: payloads URL-encoded + double-encoded para path traversal; GCP/Azure IMDS + IPv6 + Kubernetes para SSRF; SSTI probes. `_check_qdrant_ssrf()` — POST `/collections/{name}/snapshots/recover`; skip list incluye 405 (evita FP en plataformas con SPA/catch-all).
- ASI03: `_check_header_bypass()` — probe CVE-2026-30820 (`x-request-from: internal`, Flowise ≤ 3.0.12). Solo dispara si baseline es 401/403; skip si endpoint ya abierto (no duplica con probe principal). Hayhooks usa `/status` en `_SENSITIVE` (no `/pipelines` — esa ruta no existe); Letta usa `/v1/agents`.
- ASI05: OS command probe activo (`child_process.execSync('id')` para JS, `subprocess.check_output(['id'])` para Python). Output confirmation para AutoGen y Langflow. Blind timing probe: warmup request previo + threshold 0.5s (evita cold-TCP FP de ~200ms en primer request).
- ASI06: `_check_vectorstore_collections()` — GET `/collections` (Qdrant) y `/api/v2/tenants/default_tenant/databases/default_database/collections` (Chroma v2; v1 → 410 Gone). `_check_letta_memory_idor()` — GET `/v1/agents/{id}/memory` con IDs canónicos (CWE-639).
- ASI08: DELETE 404 no se reporta — endpoint puede no existir; solo 200/204 es evidencia de job cancellation sin auth. `_check_rate_limit_burst()` solo dispara en 200/201 — 400/405/422 son FP en plataformas donde el endpoint no existe.
- ASI09: `_check_version_exposure()` detecta `info.version` anidado (formato OpenAPI spec); `/openapi.json` incluido en `_VERSION_DISCLOSURE_ENDPOINTS`. Retorna en el primer finding encontrado.
- ASI10: `_check_vectorstore_creation()` — Qdrant PUT `/collections/condor-probe` (idempotente; CRITICAL si 200/201, HIGH si 400+); Chroma POST v2 (CRITICAL si 200/201; HIGH si 400/409/422). 409 = collection ya existe → endpoint accesible sin auth.
- Open WebUI `:main` eliminó `WEBUI_AUTH=False` API bypass — `get_current_user()` ya no lo respeta. Para E2E usar `v0.5.20`. OWI v0.5.20 sirve HTML para GET `/api/v1/*` (SPA catch-all) — `_is_api_response()` lo filtra; probes efectivos requieren POST. OWI v0.5.20 enforces auth en write paths incluso con `WEBUI_AUTH=False` — POST a `/api/v1/functions/create` → 403, POST a `/api/v1/tools/` → 405.
- `Finding.cwe_id: str | None` — campo opcional, ej. `"CWE-306"`. Usado en SARIF (rule tags) y HTML (badge). NO almacenado en DefectDojo como string — se convierte a `int(cwe_id.split("-")[1])`.
- Qdrant: usa header `api-key` nativo (no `Authorization: Bearer`).
- Chroma: `/api/v1/version` retorna bare string `"0.5.11"` (sin JSON wrapper) — parsear con `r.text.strip().strip('"')`. API v1 deprecada → 410 Gone para `/api/v1/collections`; usar `/api/v2/tenants/default_tenant/databases/default_database/collections`.
- Integrations wiring: `--notify-slack/teams/defectdojo-*` se evalúan post-dedup en `_scan()` con try/except — fallos no bloquean el scan ni el exit code.
- `condor scaffold --name <slug> --asi <nn>`: genera `condor/modules/asiNN_slug.py` + `tests/test_asiNN_slug.py`; valida regex `^[a-z][a-z0-9_-]*$`; sale con exit 1 si el archivo ya existe.

## Plataformas soportadas (16)

`flowise` · `generic` · `langflow` · `dify` · `autogen` · `n8n` · `llamaindex` · `crewai` · `langgraph` · `ollama` · `openai-compat` · `openwebui` · `hayhooks` · `letta` · `qdrant` · `chroma`
