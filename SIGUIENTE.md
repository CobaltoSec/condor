# SIGUIENTE — Condor

## Bloque activo

### RT-CONDOR-CFP — Curar findings E2E + case study para conferencia

**Objetivo**: verificar manualmente los 10 findings del primer scan real (Flowise 1.8.2), documentarlos como case study y preparar el material para submission (Ekoparty u otra conf).

**Pre-requisito**: Flowise 1.8.2 corriendo en `:3002` (`docker start flowise-1.8`). Ollama en descarga (`:11434`).

**D1 — Triage de los 10 findings del primer scan**
- Verificar manualmente cada finding: ¿es real? ¿hay FP?
- Scan guardado en `condor-sessions/scan-20260704-222126/`
- Findings: 4 CRITICAL (code exec × 2, credentials, apikey), 3 HIGH (vectorstore, variables, chatflows), 1 MEDIUM (tools), 2 LOW (generic endpoints)
- Criterio: tabla con finding / veredicto (TP/FP/Enhancement) / evidencia manual

**D2 — Agregar chatflow de prueba a Flowise 1.8.2**
- POST `/api/v1/chatflows` para crear un flow con systemMessage real
- Repetir scan con flow creado → ASI01 / ASI09 / ASI05 (inference) deberían disparar
- Criterio: scan con ≥ 15 findings, incluye ASI01 y ASI09

**D3 — Scan contra Ollama** (una vez que la imagen termine de bajar)
- `condor scan --url http://localhost:11434 --platform ollama --format both`
- Criterio: ≥ 1 finding real documentado (model listing sin auth, write endpoint)

**D4 — HTML report del scan final**
- `--format html` → abrir en browser, capturar screenshot para CFP
- Criterio: screenshot del reporte con ≥ 3 findings CRITICAL/HIGH con evidencia colapsada

**D5 — Draft de abstract CFP**
- 300 palabras máx, estructura: problema / tool / demo / impacto
- Targets: Ekoparty (Buenos Aires, octubre), DragonJAR (Colombia), o similar
- Criterio: draft listo en `docs/cfp-abstract.md`

Talla estimada: M

---

## Backlog

### RT-CONDOR-V09: INTEGRATIONS ROUND 2

Items diferidos de V08 (media prioridad) + nuevas ideas:

- **DefectDojo integration**: exportar findings via API REST (`/api/v2/findings/`). Convierte Condor de research tool a tool de engagements reales.
- **Slack/Teams webhook**: `--notify-slack <webhook>` al finalizar scan. POST JSON con summary (total findings, CRITICAL count, url). Bajo esfuerzo, alto valor percibido.
- **Compliance mapping**: cada finding incluye referencia a ISO 42001 / NIST AI RMF / EU AI Act. Valor para auditores y CISOs. Implementar como dict lookup en `condor/compliance.py`.
- **Module scaffold CLI**: `condor module scaffold --name asi99-custom` genera boilerplate `condor/modules/asi99_custom.py` + `tests/test_asi99.py`. Reduce barrera de entrada a contribuciones.
- **Finding.cwe_id**: complementar ASI ID con CWE para pentest reports formales.
- **Open WebUI adapter**: `/api/v1/tools`, `/api/v1/functions` = ejecución de Python arbitrario si sin auth.
- **Haystack/hayhooks adapter**: `GET /pipelines`, `POST /pipeline/run/{name}`. Sin auth por default.

Talla estimada: M

---

### RT-CONDOR-PYPI — Publicar en PyPI + GitHub público

- Prerequisito: validación E2E con findings reales (CFP o equivalente)
- Tareas: bump versión → 1.0.0, README público, CI/CD con GitHub Actions (V08), `pip install cobaltosec-condor`

---

## Estado del proyecto

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

**Plataformas:** `flowise` · `generic` · `langflow` · `dify` · `autogen` · `n8n` · `llamaindex` · `crewai` · `langgraph` · `ollama` · `openai-compat`  
**Cobertura:** 10/10 módulos OWASP ASI · 269 tests passing  
**Output:** JSON · SARIF 2.1.0 · HTML · JUnit XML · `--stdout`  
**Auth:** `--api-key` / `--username` / `--password` / env vars · `--proxy` · `--insecure`  
**DX:** `--min-severity` · `--baseline` / `--save-baseline` · `--config` (condor.yaml) · módulos en paralelo · deduplicación  
**Ecosystem:** GitHub Actions action · Dockerfile · Plugin system (entry_points) · Remediation Advisor

---

## Corvus: RT-CORVUS-SCALE (pendiente separado)

Ver `sectors/red-team/corvus/SIGUIENTE.md` para el bloque de mejoras batch de Corvus.
