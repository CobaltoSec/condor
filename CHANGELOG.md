# Changelog

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
