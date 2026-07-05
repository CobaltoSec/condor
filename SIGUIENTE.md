# SIGUIENTE — Condor

## Bloque activo

— (ninguno abierto)

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

### RT-CONDOR-CFP — Case study con findings reales

Requiere instancia Flowise 1.8.x (o Ollama para demo más simple):
```
docker run -d --name flowise -p 3001:3000 flowiseai/flowise:1.8.2
condor scan --url http://localhost:3001 --platform flowise --format both
```
- Documentar findings reales para submission a Ekoparty u otra conf
- Con **V07** completado (HTML report + timestamps) el entregable es mucho más sólido
- Con **Ollama** adapter (V06) se suma un target sin auth sin necesidad de configurar Flowise

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
**Cobertura:** 10/10 módulos OWASP ASI · 256 tests passing  
**Output:** JSON · SARIF 2.1.0 · HTML · JUnit XML · `--stdout`  
**Auth:** `--api-key` / `--username` / `--password` / env vars · `--proxy` · `--insecure`  
**DX:** `--min-severity` · `--baseline` / `--save-baseline` · `--config` (condor.yaml) · módulos en paralelo · deduplicación  
**Ecosystem:** GitHub Actions action · Dockerfile · Plugin system (entry_points) · Remediation Advisor

---

## Corvus: RT-CORVUS-SCALE (pendiente separado)

Ver `sectors/red-team/corvus/SIGUIENTE.md` para el bloque de mejoras batch de Corvus.
