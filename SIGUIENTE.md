# SIGUIENTE — Condor

## Ekoparty 2026 — Submission #2 (deadline CFP: 14 agosto)

**Contexto:** Corvus ya está submitteado como Submission #1. Condor es Submission #2 — complementario (Corvus = MCP layer, Condor = agentic platform layer). Shrike ocupa Semanas 3-4.

**Ángulo del talk:** "El 17% de las plataformas agentic AI deployadas tienen vulns CRITICAL sin auth — auditamos 200+ instancias con Condor" / OWASP ASI Top 10 para el orquestador, no el modelo.

| Fecha | Bloque | Objetivo |
|-------|--------|---------|
| Jul 7–14 | **RT-CONDOR-PYPI** | `pip install cobaltosec-condor`, GitHub público, README con ejemplos, CI |
| Jul 14–21 | **RT-CONDOR-CS01** | Scan instancias reales (Flowise/Langflow/Dify públicas), case studies, ≥1 GHSA |
| Jul 21 | **CFP submitteado** | Abstract a Sessionize (ya existe en `docs/cfp-abstract.md`) |
| Jul 21+ | Buffer | Responder maintainers, polish |

**Paralelo siempre:** Corvus disclosure — publicar GHSAs en lotes (2-3 por semana) antes de octubre.

---

## Bloques siguientes

### RT-CONDOR-PYPI — Publicar en PyPI + GitHub público ⭐ recomendado siguiente

- Prerequisito: ✅ validación E2E con findings reales (Flowise 1.8.2, CFP)
- Tareas: bump versión → 1.0.0, README público con ejemplos, CI/CD con GitHub Actions, `pip install cobaltosec-condor`
- Talla: M

---

### RT-CONDOR-LETTA-BYPASS — ~~Verificar bypass de auth en Letta~~ ✅ INVESTIGADO

- **Resultado**: `LETTA_SERVER_PASS` completamente ignorado — bypass confirmado en v0.5.1 y v0.16.8
- **Root cause**: `CheckPasswordMiddleware` solo activa con `LETTA_SERVER_SECURE=true` (opt-in); `LETTA_SERVER_PASS` no hace nada
- **Ya cubierto**: GHSA-p67m-xf4h-2r78 (CRITICAL, RCE via `/v1/tools/run`) y GHSA-99r8-mqp7-c7wq (HIGH, `/v1/admin/users`) — ambos submiteados por Shrike en junio 2026
- **Pendiente para siguiente bloque**:
  1. E2E docker-compose: cambiar `LETTA_SERVER_PASS` → `LETTA_SERVER_SECURE=true` para testear el bypass correctamente
  2. ASI05 probe nuevo: `POST /v1/tools/run` en Letta — RCE directo (Python exec sin auth); actualmente solo tenemos probe de OWI
- Talla: S

---

### ~~RT-CONDOR-V10-E2E — Validación E2E con plataformas V09~~ ✅ CERRADO

Docker Compose + script `tests/e2e/run_e2e.py`. 5/5 plataformas escaneadas.

| Plataforma | Docker image | Finding real | Gap documentado |
|-----------|--------------|-------------|----------------|
| Qdrant | `qdrant/qdrant:latest` | 0 (sin probes específicos) | ASI06/ASI10/ASI02 — V10-DEEPENED |
| Chroma | `chromadb/chroma:latest` | 0 (sin probes específicos) | ASI06/ASI10 — V10-DEEPENED |
| Hayhooks | `deepset/hayhooks:main` | 0 (sin probes específicos) | ASI03/ASI09 — V10-DEEPENED |
| Letta | `lettaai/letta:latest` | **ASI04 HIGH** — tool registry sin auth ✅ | ASI03/ASI06 — V10-DEEPENED |
| Open WebUI | `ghcr.io/open-webui/open-webui:v0.5.20` | 0 (SPA catch-all) | ASI05/ASI10 POST probe — V10-DEEPENED |

Notas:
- OWI `:main` eliminó `WEBUI_AUTH=False` API bypass — usar `v0.5.20` para E2E
- OWI v0.5.20 devuelve HTML para GET `/api/v1/*` (SPA); probes de POST necesarios
- ASI08 FP corregido: burst check ahora solo trigerea en 200/201 (no en 400/405/422)

---

### ~~RT-CONDOR-V10-DEEPENED — Módulos ASI profundizados para V09 platforms~~ ✅ CERRADO

27 tests nuevos (345 → 372). 9 probes implementados en 6 módulos. E2E: 11 findings, 0 FP.

| Gap original | Estado | Finding E2E |
|---|---|---|
| ASI06: Qdrant `/collections` | ✅ cerrado | HIGH |
| ASI10: Qdrant collection creation | ✅ cerrado | CRITICAL |
| ASI02: Qdrant SSRF snapshots | ✅ probe implementado | Gap: requiere collection pre-cargada |
| ASI06: Chroma collections (v1→v2) | ✅ cerrado | HIGH |
| ASI10: Chroma collection creation | ✅ cerrado | HIGH (409) |
| ASI03: Hayhooks `/status` | ✅ cerrado | MEDIUM |
| ASI09: `/openapi.json` + nested version | ✅ cerrado | LOW (×3 plataformas) |
| ASI03: Letta `/v1/agents` | ✅ cerrado | HIGH |
| ASI06: Letta IDOR `/v1/agents/{id}/memory` | ✅ probe implementado | Gap: IDs no matchean instancia fresca |
| ASI05: OWI POST `/api/v1/functions` | ⏸ código listo | Gap: OWI v0.5.20 enforces auth en write paths incluso con `WEBUI_AUTH=False` |
| ASI10: OWI POST `/api/v1/tools` | ⏸ código listo | Gap: mismo que ASI05 |

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
**Cobertura:** 10/10 módulos OWASP ASI · 372 tests passing  
**Output:** JSON · SARIF 2.1.0 · HTML · JUnit XML · `--stdout`  
**Auth:** `--api-key` / `--username` / `--password` / env vars · `--proxy` · `--insecure`  
**DX:** `--min-severity` · `--baseline` / `--save-baseline` · `--config` (condor.yaml) · módulos en paralelo · deduplicación  
**Ecosystem:** GitHub Actions action · Dockerfile · Plugin system (entry_points) · Remediation Advisor

---

## Corvus: RT-CORVUS-SCALE (pendiente separado)

Ver `sectors/red-team/corvus/SIGUIENTE.md` para el bloque de mejoras batch de Corvus.
