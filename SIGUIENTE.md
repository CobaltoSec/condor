# SIGUIENTE — Condor

## Bloque activo

### RT-CONDOR-V09: PLATFORM COVERAGE ROUND 2 + INTEGRATIONS

#### Plataformas nuevas (prioridad alta)

Arquitectura: cada platform adapter hereda automáticamente los 10 módulos ASI existentes.
Solo hay que implementar `health_check()`, `enumerate() → AgentSurface`, y auth si aplica.

| Plataforma | Endpoints clave | Finding probable | Prioridad |
|-----------|----------------|-----------------|-----------|
| **Open WebUI** | `/api/v1/tools`, `/api/v1/functions` | CRITICAL RCE — Python execution sin auth | 1 |
| **Haystack/hayhooks** | `GET /pipelines`, `POST /pipeline/run/{name}` | HIGH — pipeline execution sin auth | 2 |
| **Letta (MemGPT)** | REST API completa, agentes con memoria | HIGH — acceso a memoria de agentes, IDOR | 3 |
| **Qdrant standalone** | `GET /collections`, `PUT /collections/{name}/points` | HIGH — RAG poisoning directo sin plataforma | 4 |
| **Chroma standalone** | `GET /api/v1/collections`, `POST /api/v1/collections/{id}/add` | HIGH — idem Qdrant | 4 |

**Open WebUI** es el más urgente: 50k+ stars, `/api/v1/functions` = Python arbitrario sin auth en default. Finding CRITICAL garantizado y demostrable.

#### Integraciones (prioridad media, diferidas de V08)

- **DefectDojo**: exportar findings via API REST (`/api/v2/findings/`). Convierte Condor de research tool a tool de engagements reales.
- **Slack/Teams webhook**: `--notify-slack <webhook>` al finalizar scan.
- **Finding.cwe_id**: CWE por finding (CWE-285, CWE-306, etc.) para reportes formales.
- **Compliance mapping**: ISO 42001 / NIST AI RMF / EU AI Act por finding. Dict lookup en `condor/compliance.py`.
- **Module scaffold CLI**: `condor module scaffold --name asi99-custom`.

Talla estimada: L (plataformas) + M (integraciones)

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
**Cobertura:** 10/10 módulos OWASP ASI · 272 tests passing  
**Output:** JSON · SARIF 2.1.0 · HTML · JUnit XML · `--stdout`  
**Auth:** `--api-key` / `--username` / `--password` / env vars · `--proxy` · `--insecure`  
**DX:** `--min-severity` · `--baseline` / `--save-baseline` · `--config` (condor.yaml) · módulos en paralelo · deduplicación  
**Ecosystem:** GitHub Actions action · Dockerfile · Plugin system (entry_points) · Remediation Advisor

---

## Corvus: RT-CORVUS-SCALE (pendiente separado)

Ver `sectors/red-team/corvus/SIGUIENTE.md` para el bloque de mejoras batch de Corvus.
