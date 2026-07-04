# Changelog

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
