# Changelog

## [RT-CONDOR-V11] — 2026-07-18 — MODULE FIXES + NEW PROBES

- **ASI03 — Langflow default creds + n8n endpoints**: `_check_langflow_auto_login()` — prueba `langflow/langflow` y `admin/admin` en `/api/v1/login` + `/api/v1/auth/login`; 200 + token (len > 20) → CRITICAL CWE-1392; 422 ignorado (validation error ≠ auth check). n8n: `/api/v1/executions` (CRITICAL) + `/rest/owner` (HIGH) agregados a `_SENSITIVE`
- **ASI05 — Hayhooks pipeline execution**: `_check_hayhooks_pipeline_exec()` — enumera pipelines de `surface.flows` o `GET /pipelines`, ejecuta `POST /pipelines/{name}/run` (fallback `POST /{name}/run` versión older); 200/201/202 → CRITICAL, 422 → HIGH; CWE-306
- **ASI06 — Vector injection con dimension detection**: `_check_qdrant_vector_injection(collection)` — `GET /collections/{name}` para leer dim, `POST /points` con vector correcto, cleanup `POST /points/delete {points:[9999999]}` en `finally`; CRITICAL/HIGH. `_check_chroma_vector_injection(collection)` — `POST /add` + cleanup en `finally`. `_check_vectorstore_collections()` retorna tuple con nombres de colecciones Qdrant/Chroma
- **ASI07/ASI09 — Active flow discovery**: `_discover_flow_ids(platform)` helper en ambos módulos — antes del early return por `flow_ids` vacío, prueba activamente `GET /api/v1/chatflows`, `/api/v1/flows`, `/api/v1/agents`; fix en 5 funciones (ASI09: `_check_system_prompt_exposure`, `_check_ai_disclosure`, `_check_system_prompt_modification`; ASI07: `_check_internal_prediction`, `_check_origin_forgery`)
- **ASI08 — Health probe separation**: `_HEALTH_PROBE_ENDPOINTS` al inicio de `_INFERENCE_PROBE_ENDPOINTS` (GET probe); `_BURST_PROBE_ENDPOINTS` excluye health (POST a /health → 405 = FP en burst check)
- **ASI10 — Cleanup post-probe**: flags `_qdrant_probed`/`_chroma_probed` en `finally` → `DELETE /collections/condor-probe` (Qdrant) + equivalente Chroma; best-effort, resultado ignorado, finding ya registrado
- **E2E validado**: 7/7 plataformas OK, 19 findings, 0 errores, 0 regresiones
- +38 tests (377 → **415/415 passing**)

## [RT-CONDOR-CS01] — 2026-07-10 — CASE STUDIES + E2E FLOWISE/LANGFLOW

- **E2E infra ampliada**: docker-compose + run_e2e.py — flowise:1.8.2 (port 3200; 3000/3100 excluidos por rango Hyper-V 2971-3170) y langflow:latest (port 7860, LANGFLOW_AUTO_LOGIN=true)
- **Flowise 1.8.2 — scan real**: 6 findings en 3.0s — 2 CRITICAL (`/api/v1/credentials`, `/api/v1/apikey`), 3 HIGH (`/api/v1/variables`, `/api/v1/chatflows`, ASI06 vectorstore upsert), 1 MEDIUM (`/api/v1/tools`)
- **Langflow 1.10.2 — scan real**: 1 finding — ASI09 LOW (version disclosure via `/openapi.json`); auth enforced en API REST incluso con `LANGFLOW_AUTO_LOGIN=true` (afecta solo la UI)
- **Case studies**: `docs/case-studies/cs01-flowise-1.8.2.md` (findings reales + análisis + remediación) + `docs/case-studies/cs02-langflow-latest.md` (findings + historial CVEs + comparativa de posturas de seguridad)
- **CFP abstract actualizado**: métricas reales (6 findings, 3.0s), coverage multi-plataforma (Langflow/Qdrant/Chroma/Letta mencionados), strings "pendiente PyPI/publicación" removidos
- **GHSA deferred**: Langflow 1.10.2 sin nuevas vulns detectadas; vector potencial (`POST /api/v1/login` + auto-login bypass) documentado en cs02 para investigación separada

## [RT-CONDOR-PYPI] — 2026-07-10 — PUBLIC RELEASE + PYPI PUBLISH

- **Repo público**: `github.com/CobaltoSec/condor` — creado y pusheado con historial completo; CLAUDE.md + SIGUIENTE.md removidos del repo público (.gitignore)
- **PyPI publish**: tag `v1.0.0` → workflow OIDC → `cobaltosec-condor 1.0.0` en PyPI; verificado con `pip install cobaltosec-condor` + `condor --help`
- **GitHub Release**: `v1.0.0` con release notes user-facing (install, quick start, módulos, plataformas)
- **Topics del repo**: `security`, `ai`, `agents`, `owasp`, `agentic-ai`, `red-team`, `flowise`, `langflow`, `pentesting`, `llm`
- **Org README**: Condor agregado a tabla de Frameworks en `CobaltoSec/.github` (debajo de Corvus)

## [RT-CONDOR-LETTA-BYPASS + RT-CONDOR-PYPI] — 2026-07-07 — LETTA RCE PROBE + v1.0.0 PYPI PREP

- **ASI05 — Letta `/v1/tools/run` probe**: `_check_letta_tools_run()` — POST con Python arbitrario sin auth (GHSA-p67m-xf4h-2r78); CRITICAL 98 si `uid=` confirmado, fallback `os.getcwd()` (90/80); 5 tests nuevos (372 → **377/377 passing**)
- **E2E docker-compose**: Letta ahora usa `LETTA_SERVER_PASS` sin `LETTA_SERVER_SECURE=true` — simula deployment "protegido" que en realidad está abierto por el bypass del middleware
- **v1.0.0**: `pyproject.toml` — version bump, classifiers `Production/Stable`, `[project.urls]`
- **README rewrite**: 10 módulos, 16 plataformas, badges CI/PyPI, ejemplos completos, sección de integrations y plugin system
- **`.github/workflows/publish.yml`**: OIDC trusted publisher, trigger en tag `v*` — pendiente operativa (cuenta PyPI, Trusted Publisher config, repo público)
- **`action.yml`**: plataformas actualizadas de 11 → 16

## [RT-CONDOR-V10-DEEPENED] — 2026-07-05 — PLATFORM-SPECIFIC PROBES + FP FIXES

- **ASI02 — Qdrant SSRF probe**: `_check_qdrant_ssrf()` en `asi02_tool_misuse.py` — POST `/collections/{name}/snapshots/recover` con payload IMDS; skip list extendida con 405 para eliminar FP en plataformas que retornan Method Not Allowed (OWI, etc.)
- **ASI03 — Hayhooks `/status` + Letta `/v1/agents`**: agregados a `_SENSITIVE`; `/status` expone pipeline list (MEDIUM), `/v1/agents` expone agent registry (HIGH); path `/pipelines` incorrecto corregido a `/status` (Hayhooks no tiene esa ruta)
- **ASI05 — OWI function creation probe**: `_check_owui_functions()` — POST `/api/v1/functions` con Python exec payload; CRITICAL si 200/201, HIGH si 400/422; cleanup DELETE con ID
- **ASI06 — Vectorstore collection listing**: `_check_vectorstore_collections()` — GET `/collections` (Qdrant) y `/api/v2/tenants/default_tenant/databases/default_database/collections` (Chroma v2); Chroma v1 deprecated → 410 Gone
- **ASI06 — Letta IDOR**: `_check_letta_memory_idor()` — GET `/v1/agents/{id}/memory` con IDs canónicos; CWE-639 (HIGH, conf 88)
- **ASI09 — Version disclosure ampliada**: `/openapi.json` agregado a `_VERSION_DISCLOSURE_ENDPOINTS`; `_check_version_exposure()` ahora detecta `info.version` anidado (formato OpenAPI spec); LOW findings en Hayhooks, Chroma, Letta E2E
- **ASI10 — Vectorstore creation**: `_check_vectorstore_creation()` — Qdrant PUT `/collections/condor-probe` (idempotente → CRITICAL); Chroma POST v2 (200/201 → CRITICAL; 409/400/422 → HIGH); OWI tool registration POST `/api/v1/tools`
- **E2E validado**: 11 findings, 0 FP. `EXPECTED: all N target ASI IDs detected` en 5/5 plataformas (Qdrant: ASI06+ASI10; Chroma: ASI06+ASI09+ASI10; Hayhooks: ASI03+ASI09; Letta: ASI03+ASI04+ASI09; OWI: ASI09)
- **Gaps documentados**: ASI02 SSRF (Qdrant; requiere collection pre-cargada); ASI06 IDOR Letta (probe IDs no matchean instancia fresca); OWI ASI05/ASI10 POST (v0.5.20 enforces auth incluso con WEBUI_AUTH=False)
- 27 tests nuevos (345 → **372/372 passing**)

## [RT-CONDOR-V10-E2E] — 2026-07-05 — E2E VALIDATION + ASI08 FP FIX

- **Docker Compose E2E**: `tests/e2e/docker-compose.yml` — 5 servicios V09 sin auth (Qdrant, Chroma, Hayhooks, Letta, Open WebUI v0.5.20) con healthchecks y `--no-wait` flag
- **Script de validación**: `tests/e2e/run_e2e.py` — espera health, corre `condor scan --stdout`, imprime findings vs expected, emite gap summary para V10-DEEPENED; exit 0/1
- **Findings reales**: Letta ASI04 HIGH confirmado — `/v1/tools` tool registry accesible sin auth en Docker por defecto; 4 plataformas con 0 findings → gaps documentados
- **ASI08 FP fix**: `_check_rate_limit_burst()` disparaba en 400/405/422 (endpoints inexistentes con POST JSON) — cambiado a solo 200/201; elimina FPs en Chroma y OWI
- **Gaps documentados para V10-DEEPENED**: 8 items específicos — Qdrant (ASI06/ASI10/ASI02), Chroma (ASI06/ASI10), Hayhooks (ASI03/ASI09), Letta (ASI03/ASI06), OWI (ASI05 POST, ASI10)
- **Discovery**: OWI `:main` eliminó `WEBUI_AUTH=False` API bypass; E2E usa `v0.5.20`. OWI v0.5.20 sirve SPA HTML para GET `/api/v1/*` — probes de POST necesarios para detectar function creation
- Suite total: **345/345 passing**

## [RT-CONDOR-V09] — 2026-07-05 — PLATFORM COVERAGE ROUND 2 + INTEGRATIONS

- **5 platform adapters nuevos**: `openwebui` (`/api/v1/functions` Python exec, `functions_unauth` flag), `hayhooks` (`/pipelines`, normalización strings→dicts, `/openapi.json`), `letta` (Bearer auth, per-agent `/memory` IDOR surface), `qdrant` (header `api-key` nativo — no Bearer, `/telemetry` para version), `chroma` (version = bare string vía `r.text.strip().strip('"')`, `/api/v1/heartbeat`)
- **CWE IDs por finding**: `Finding.cwe_id: str | None` en `core/models.py`; 18 CWEs distintos mapeados (CWE-20, CWE-22, CWE-74, CWE-77, CWE-78, CWE-94, CWE-200, CWE-284, CWE-285, CWE-290, CWE-306, CWE-312, CWE-346, CWE-639, CWE-770, CWE-915, CWE-918, CWE-1357) en los 10 módulos ASI
- **Compliance mapping**: `condor/compliance.py` — `get_compliance_refs(owasp_id)` → `{iso_42001, nist_ai_rmf, eu_ai_act}`; ISO/IEC 42001:2023, NIST AI RMF, EU AI Act para ASI01–10
- **Integrations package**: `condor/integrations/` — `notify_slack()` + `notify_teams()` (MessageCard, themeColor por severidad), `export_to_defectdojo()` (Product→Engagement→Test→Finding hierarchy, test FK requerido)
- **CLI flags nuevos**: `--notify-slack`, `--notify-teams`, `--defectdojo-url`, `--defectdojo-key`, `--defectdojo-product`; wired en `_scan()` y `_scan_batch()` con try/except para no bloquear el scan
- **`condor scaffold`**: genera boilerplate `condor/modules/asiNN_slug.py` + `tests/test_asiNN_slug.py`; valida slug, detecta colisiones, imprime instrucción de registro
- **SARIF mejorado**: `message.text` con prefijo `[Title]`, `rule.help.text` con remediation, `rule.properties.tags` con `["security", "CWE-XXX"]`
- **HTML mejorado**: `.cwe-badge` (purple, monospace) junto al título; sección compliance con `.compliance-tag` por framework; dark mode aware
- 73 tests nuevos (272 → **345/345 passing**)

## [RT-CONDOR-CFP] — 2026-07-05 — FP REDUCTION + CVE DETECTION + CFP MATERIAL

- **Triage E2E**: verificación manual de 10 findings contra Flowise 1.8.2; 5 FPs identificados y eliminados (ASI02 ×2, ASI05 ×2, ASI08 ×1); 8 TPs confirmados en scan final
- **ASI05 FP fix**: `node-load-method` endpoints no reportan sin OS indicator en body; timing probe con warmup request + threshold 0.5s para evitar cold-connection FP
- **ASI02 FP fix**: `_is_api_response()` + `len(body) > 2` en generic probe — filtra HTML (SPA catch-all) y responses vacías `[]`
- **ASI08 FP fix**: DELETE 404 ya no se reporta como auth bypass — solo 200/204 es evidencia real
- **ASI03 Ollama coverage**: `/api/tags` (MEDIUM) y `/api/ps` (LOW) en `_SENSITIVE` — detecta model inventory sin auth
- **ASI03 CVE-2026-30820**: `_check_header_bypass()` — probe `x-request-from: internal`; CRITICAL si endpoint protegido flipea 401→200; skip si ya abierto; 3 tests
- **Scan Ollama**: 2 TPs reales confirmados contra `ollama:latest` en `:11434`
- **Chatflow E2E**: ASI09 CRITICAL confirmado — system prompt expuesto + modificación sin auth (secret code `ACME-2026-INTERNAL` exfiltrado)
- **CFP material**: `docs/cfp-abstract.md` — abstract español + inglés + bio; targets Ekoparty/DragonJAR
- Suite total: **272/272 passing**

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
