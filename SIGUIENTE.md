# SIGUIENTE — Condor

## Bloques siguientes

### RT-CONDOR-PYPI — Publicar en PyPI + GitHub público ⭐ recomendado siguiente

- Prerequisito: ✅ validación E2E con findings reales (Flowise 1.8.2, CFP)
- Tareas: bump versión → 1.0.0, README público con ejemplos, CI/CD con GitHub Actions, `pip install cobaltosec-condor`
- Talla: M

---

### RT-CONDOR-V10-E2E — Validación E2E con plataformas V09

Docker Compose con las 5 plataformas nuevas + script de validación de findings reales.

| Plataforma | Docker image | Finding esperado |
|-----------|--------------|-----------------|
| Open WebUI | `ghcr.io/open-webui/open-webui:main` | CRITICAL — `/api/v1/functions` Python exec sin auth |
| Qdrant | `qdrant/qdrant` | HIGH — colecciones accesibles sin auth |
| Chroma | `chromadb/chroma` | HIGH — collections sin auth |
| Hayhooks | `deepset/hayhooks` | HIGH — pipeline execution sin auth |
| Letta | `lettaai/letta` | HIGH — IDOR en `/v1/agents/{id}/memory` |

- Objetivo: scan real contra cada plataforma, capturar findings, documentar en `tests/e2e/`
- Talla: L

---

### RT-CONDOR-V10-DEEPENED — Módulos ASI profundizados para Qdrant/Chroma

ASI06 y ASI10 con conocimiento específico de vectorstores standalone:
- ASI06: queries de poisoning reales contra Chroma/Qdrant (no solo auth probe)
- ASI10: collection injection — crear colección `__admin__` o similar sin auth
- ASI02: SSRF via Qdrant snapshot restore (`POST /collections/{name}/snapshots/recover`)

- Talla: M

---

### ~~RT-CONDOR-V09: PLATFORM COVERAGE ROUND 2 + INTEGRATIONS~~ ✅ CERRADO

5 plataformas (Open WebUI, Hayhooks, Letta, Qdrant, Chroma) + CWE IDs + compliance mapping (ISO 42001 / NIST AI RMF / EU AI Act) + Slack/Teams/DefectDojo integrations + scaffold CLI. 272 → 345 tests.

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

**Plataformas:** `flowise` · `generic` · `langflow` · `dify` · `autogen` · `n8n` · `llamaindex` · `crewai` · `langgraph` · `ollama` · `openai-compat` · `openwebui` · `hayhooks` · `letta` · `qdrant` · `chroma`  
**Cobertura:** 10/10 módulos OWASP ASI · 345 tests passing  
**Output:** JSON · SARIF 2.1.0 · HTML · JUnit XML · `--stdout`  
**Auth:** `--api-key` / `--username` / `--password` / env vars · `--proxy` · `--insecure`  
**DX:** `--min-severity` · `--baseline` / `--save-baseline` · `--config` (condor.yaml) · módulos en paralelo · deduplicación  
**Ecosystem:** GitHub Actions action · Dockerfile · Plugin system (entry_points) · Remediation Advisor

---

## Corvus: RT-CORVUS-SCALE (pendiente separado)

Ver `sectors/red-team/corvus/SIGUIENTE.md` para el bloque de mejoras batch de Corvus.
