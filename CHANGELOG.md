# Changelog

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
