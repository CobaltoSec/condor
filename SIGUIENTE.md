# SIGUIENTE — Condor

## Bloque activo

### RT-CONDOR-V01 — Platform Coverage + ASI04 + ASI02

**Objetivo:** Ampliar cobertura de plataformas (Langflow, Dify) e implementar los
siguientes 2 módulos ASI priorizados. Dejar Condor con 5/10 módulos operativos.

**Talla:** M (3–4 sesiones)

**Deliverables:**

| ID | Descripción | Criterio de completitud |
|----|-------------|------------------------|
| D1 | Langflow platform adapter | `condor scan --platform langflow` enumera flows y tools |
| D2 | Dify platform adapter | `condor scan --platform dify` enumera apps y datasets |
| D3 | Módulo ASI04 `supply-chain` | Detecta plugins con CVEs via OSV.dev; verifica tool descriptions |
| D4 | Módulo ASI02 `tool-misuse` | Enumera tools, prueba path traversal y SSRF por tool |
| D5 | E2E scan contra Flowise local | `condor scan` arroja ≥1 finding real en instancia de laboratorio |

**Dependencias:**
- Flowise corriendo en lab (LXC 200 / Docker local) para D5
- OSV.dev API sin auth — sin costo

**Notas:**
- D3 reutiliza lógica de `sectors/red-team/corvus/corvus/modules/static/osv_supply_chain.py`
- D4: el punto de entrada es la enumeración de tools via `flowise.enumerate()` ya implementada
- AutoGen Studio adapter es V02 (requiere más research de su API)

---

## Backlog

- **RT-CONDOR-V02** — ASI06 (Memory Poisoning) + ASI07 (Inter-Agent) + AutoGen adapter
- **RT-CONDOR-V03** — ASI08/ASI09/ASI10 + SARIF output + batch scan
- **RT-CONDOR-CFP** — Case study con findings reales + CFP (post-Ekoparty o siguiente conf)
- **RT-CONDOR-PYPI** — Publicar `cobaltosec-condor` en PyPI + repo público GitHub

---

## Corvus: RT-CORVUS-SCALE (pendiente separado)

Ver `sectors/red-team/corvus/SIGUIENTE.md` para el bloque de mejoras batch de Corvus.
