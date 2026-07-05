# Changelog

## [RT-CONDOR-PRE-E2E] — 2026-07-04 — FP REDUCTIONS + TEST COVERAGE + FIRST E2E RUN

- **ASI05 test coverage**: `tests/test_asi05.py` — 12 tests cubriendo todas las rutas del módulo RCE (Flowise cmd/os/timing, AutoGen, Langflow); cobertura era 0%, único módulo sin tests
- **ASI04 FP reduction**: `_GENERIC_NAMES_SKIP_OSV` frozenset en `asi04_supply_chain.py` — nombres genéricos ("search", "calculator", "tool", etc.) skippean el OSV.dev lookup para evitar falsos positivos masivos en E2E
- **ASI02 SSTI FP reduction**: length guard en `asi02_tool_misuse.py` — indicador "49" ignorado si `body > 500 chars`; confidence 85 → 70
- **ASI08 burst size**: `_BURST_SIZE = 10 → 30` para detectar rate limits reales (10 concurrent nunca dispara en instalaciones por defecto)
- **ASI09 impersonation FP**: removido `my name is \w+` regex de `_HUMAN_IMPERSONATION_PATTERNS` — triggereaba CRITICAL en customer service bots ("My name is Alex…")
- **LangGraph surface.endpoints**: corregido para acumular solo endpoints que respondieron (200 o 401/403); antes siempre retornaba lista de 4 fijos sin verificar
- **Remediation coverage**: ASI02 sin entradas en `condor/remediation.py` — agregadas `("ASI02", "flowise")` y `("ASI02", "generic")`
- **HTML report**: remediation `<p>` → `<pre>` para preservar formato de snippets de configuración
- **First E2E run**: `flowise-1.8` container (`:3002`) → 10 findings reales (4 CRITICAL, 3 HIGH, 1 MEDIUM, 2 LOW); scan 5s
- Suite total: **269/269 passing**

## [RT-CONDOR-V08] — 2026-07-04 — INTEGRATIONS + ECOSYSTEM

- **GitHub Actions**: composite action `.github/actions/condor-scan/action.yml` — inputs `url / platform / format / fail-on / api-key / exclude-module`; outputs `sarif-file / report-file / html-file`; workflow de ejemplo con SARIF upload a GitHub Code Scanning; CI matrix Python 3.11/3.12; `Dockerfile` python:3.11-slim
- **Remediation Advisor**: `condor/remediation.py` — 22 entries plataforma × ASI (flowise/langflow/n8n/ollama/langgraph/openai-compat/generic); `enrich_findings(findings, platform)` appenda fix específico al campo `remediation` de cada finding (pydantic `model_copy`); fallback a generic si no hay entry específica; wired en `_scan()` post-dedup
- **Plugin system**: `_load_plugins()` en `cli.py` via `importlib.metadata.entry_points`; grupos `condor.modules` y `condor.platforms`; `pip install condor-module-xyz` → auto-discovery sin tocar el core
- **Config file**: `condor/config.py` — carga `condor.yaml` / `.condor.yaml` / `~/.condor.yaml`; flag `--config`/`-c`; prioridad CLI > env > config > defaults; solo aplica a parámetros `None` para no pisar flags explícitos
- 11 tests nuevos (remediation); suite total: **256/256 passing**

## [RT-CONDOR-V07] — 2026-07-04 — DX + REPORTING

- **HTML report** (`--format html`): `condor/html_report.py` — self-contained, dark mode, severity badges, secciones colapsables de evidencia/remediación, XSS-safe via `html.escape`
- **JUnit XML** (`--format junit`): `condor/junit_report.py` — findings como `<testcase><failure>` agrupados por owasp_id; Jenkins/GitLab/CircleCI nativos
- **Baseline/suppression**: `condor/baseline.py` — fingerprint SHA-256[:16] de `(owasp_id|title|endpoint)`; `--baseline` suprime findings conocidos, `--save-baseline` persiste estado actual; clave para uso en CI/CD sin bloquear riesgos aceptados
- **`ScanResult` timestamps**: `started_at`, `finished_at`, `duration_seconds` en `core/models.py`
- **Proxy + insecure**: `BasePlatform(proxy, verify_ssl)` → `httpx.AsyncClient(proxy=..., verify=False)` — Burp Suite integration
- **Env vars**: `CONDOR_API_KEY` / `CONDOR_USERNAME` / `CONDOR_PASSWORD` como fallback de flags CLI
- **Módulos en paralelo**: `asyncio.gather` sobre los 10 módulos ASI — ~70% reducción de tiempo de scan
- **Deduplicación**: `_dedup_findings()` por clave `(owasp_id, title, endpoint)` antes de escribir report
- **`--stdout`**, **`--min-severity`**, **`--fail-on`**, exit codes 0/1/2 (clean/findings/error)
- 76 tests nuevos (html, junit, baseline, cli); suite total: **245/245 passing**

## [RT-CONDOR-V06] — 2026-07-04 — PLATFORMS

- **3 nuevos platform adapters**: `langgraph` (LangGraph Platform — `/assistants`, `/threads`, `/store/items`, `/runs`; sin auth en Docker self-hosted), `ollama` (`/api/tags`, `/api/ps`, write endpoint probe), `openai-compat` (`/v1/models`, `/v1/assistants`, `/v1/vector_stores`, `/v1/files`; cubre vLLM, LocalAI, LM Studio)
- **Generic OpenAPI auto-parsing**: 7 candidate paths (`/openapi.json`, `/swagger.json`, `/api-docs`, etc.) → extrae endpoints automáticamente; GraphQL introspection probe (`__schema`)
- 42 tests nuevos (3 platforms + generic); suite total: **211/211 passing**

## [RT-CONDOR-V05] — 2026-07-04 — MODULE-DEPTH

- **ASI01**: indirect injection via tool output (`_check_tool_response_injection()`), 4 jailbreak payloads (DAN, developer mode, no-restrictions, CONDOR_INJECTED × 3)
- **ASI02**: SSTI probes (`{{7*7}}`, `${7*7}`), Kubernetes API SSRF (`10.96.0.1`, `kubernetes.default.svc`)
- **ASI03**: IDOR check IDs 1-5 + UUIDs, mass assignment probe (`role: admin`)
- **ASI04**: ecosistema PyPI en OSV.dev, regex de inyección sentence-level (`(ignore|disregard).{0,20}(instruction|above|previous)`)
- **ASI06**: adversarial chunk injection activa — CRITICAL si el endpoint acepta el documento
- **ASI07**: origin forgery test (`X-Forwarded-For: 127.0.0.1`, `X-Internal-Request: true`)
- **ASI08**: burst probe 10 requests concurrentes (reemplaza single-probe de rate limit)
- **ASI09**: active AI disclosure test + 7 impersonation patterns extendidos
- **ASI10**: cleanup robusto (DELETE inmediato post-creación), detección de rogue agents existentes
- 41 tests nuevos; suite total: **169/169 passing**

## [RT-CONDOR-V04] — 2026-07-04 — SCALE + AUTH + DEPTH + PLATFORMS

- **CLI (SCALE)**: `--format json|sarif|both|table` reemplaza `--sarif`; `--exclude-module` (repeatable, warn en nombre desconocido); `--concurrency N` para batch scan (`asyncio.Semaphore` + `gather`); progress bar `rich.Progress` en loop de módulos y en batch; `verbose=False` en batch para suprimir output inline
- **Auth (AUTH)**: `--api-key` / `--username` / `--password` threadeados hasta la construcción del platform; `BasePlatform._authenticate()` hook (llamado en `__aenter__`); Flowise/Generic: header estático Bearer/Basic; Langflow: `x-api-key` + pre-auth POST `/api/v1/login` → JWT; Dify: Bearer + pre-auth POST `/console/api/login` → token; AutoGen/n8n/LlamaIndex/CrewAI: Bearer
- **Depth ASI01**: 8 payloads (+base64, prompt-continuation, Unicode, tool-result-simulation); detección semántica `_COMPLIANCE_PHRASES` (confidence 60) además de markers exactos (90); soporta endpoints Dify y Langflow además de Flowise
- **Depth ASI02**: 10 payloads path traversal (+URL-encoded, double-encoded, absolute paths, `/etc/hosts`, `/proc/self/environ`); 6 payloads SSRF (+GCP metadata, Azure IMDS, IPv6 loopback); indicadores de confirmación extendidos
- **Depth ASI05**: OS command probes activos (`child_process.execSync('id')` JS, `subprocess.check_output(['id'])` Python); output confirmation para AutoGen (`_PATH_INDICATORS`) y Langflow (`condor` en respuesta); blind timing probe (`setTimeout 300ms`, elapsed ≥ 0.25s → confidence 50)
- **3 nuevos platform adapters**: `n8n` (X-N8N-API-KEY, `/api/v1/workflows`, credential enumeration), `llamaindex` (FastAPI `/api/v1/agents`, versión desde OpenAPI spec), `crewai` (`crewai serve`, crews+agents, versión desde `/openapi.json`)
- `tests/test_cli.py` nuevo (14 tests); 3 nuevos `tests/test_platform_*.py` (23 tests); suite total: **128/128 passing**

## [RT-CONDOR-V03] — 2026-07-04 — ASI08 + ASI09 + ASI10 + SARIF output + batch scan

- 3 nuevos módulos — Condor alcanza **10/10 módulos OWASP ASI** (cobertura completa):
  - `cascading-failures` (ASI08): detecta endpoints de inferencia sin rate limiting, colas de tareas expuestas sin auth, y job management accesible sin autenticación
  - `trust-exploitation` (ASI09): detecta system prompts expuestos sin auth, impersonación de humanos en prompts, y modificación de identidad de agente sin auth (PUT)
  - `rogue-agents` (ASI10): detecta creación de agentes sin auth, registro de tools/plugins sin auth, y registro de webhooks/triggers sin auth
- SARIF output: `--sarif` ahora escribe `report.sarif` (SARIF 2.1.0) junto a `report.json`; integrable con GitHub Code Scanning
- Batch scan: `--targets <file>` escanea múltiples targets secuencialmente desde un archivo (`URL [platform]` por línea, `#` para comentarios)
- `BasePlatform.put()` agregado para soportar probing de endpoints PUT/PATCH
- 33 tests nuevos; suite total: **92/92 passing**

## [RT-CONDOR-V02] — 2026-07-04 — ASI06 + ASI07 + AutoGen adapter + false-positive fix

- 2 nuevos módulos: `memory-poisoning` (ASI06) y `inter-agent` (ASI07) — Condor pasa a 7/10 módulos
- ASI06: detecta vectorstores accesibles sin auth (Flowise docstore, Langflow monitor/messages, Dify datasets) y prueba inyección de documentos en RAG pipeline
- ASI07: detecta agentflows expuestos (Flowise), internal-prediction channel (bypass de guardrails), teams/sessions/runs de AutoGen Studio, y workflow trigger sin auth (Dify)
- Nuevo platform adapter `autogen` — enumera teams, tools, sessions; health check multi-endpoint
- **Fix crítico (todos los módulos de probing)**: `_is_api_response()` filtra respuestas `text/html` que generaban falsos positivos CRITICAL/HIGH al escanear plataformas Next.js (Flowise 3.x); guard `isinstance(ct, str)` preserva mocks
- D1 (E2E Flowise) diferido: Flowise 2.x+ auto-inicializa workspace auth en SQLite; requiere `flowiseai/flowise:1.8.2` para instancia sin auth
- 21 tests nuevos; suite total: 59/59 passing

## [RT-CONDOR-V01] — 2026-07-04 — Platform Coverage + ASI04 + ASI02

- 2 nuevos módulos: `tool-misuse` (ASI02) y `supply-chain` (ASI04) — Condor pasa a 5/10 módulos operativos
- ASI02: detecta path traversal y SSRF via parámetros de tool, credenciales expuestas en tool config, source code exposure
- ASI04: CVE check por tool via OSV.dev API, detección de tool descriptions con payloads de inyección
- 2 nuevos platform adapters: `langflow` y `dify` — Condor cubre 4 plataformas (flowise, generic, langflow, dify)
- 16 tests nuevos; suite total: 38/38 passing
- D5 (E2E contra Flowise local) diferido — Flowise no disponible en esta sesión

## [RT-CONDOR-BOOTSTRAP-01] — 2026-07-04 — Research: OWASP ASI Top 10

- Investigación completa del OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10)
- `docs/owasp-asi-top10.md`: referencia de implementación con escenarios de ataque, casos reales,
  pseudocódigo por módulo, y tabla de priorización para Condor
- 3/10 ASIs ya cubiertos en v0.1.0 (ASI01/ASI03/ASI05); orden de implementación documentado

## [0.1.0] — 2026-07-04 — Bootstrap

- Initial project structure
- Core models: `Finding`, `Severity`, `OWASPCategory` (ASI01–10), `AgentSurface`, `ScanResult`
- Platform adapters: `flowise`, `generic`
- 3 modules: `goal-hijack` (ASI01), `privilege-abuse` (ASI03), `code-execution` (ASI05)
- CLI: `condor scan`, `condor list-modules`, `condor version`
- 8 unit tests
