# SIGUIENTE — Condor

## Bloque activo

### RT-CONDOR-V02 — ASI06 + ASI07 + E2E Flowise + AutoGen adapter

**Objetivo:** Implementar los 2 módulos de mayor impacto diferencial (Memory Poisoning e Inter-Agent),
cerrar el E2E diferido contra Flowise, y agregar el adapter de AutoGen Studio.

**Talla:** M (3–4 sesiones)

**Deliverables:**

| ID | Descripción | Criterio de completitud |
|----|-------------|------------------------|
| D1 | E2E scan contra Flowise local | `condor scan` arroja ≥1 finding real en instancia de laboratorio |
| D2 | Módulo ASI06 `memory-poisoning` | Detecta vectorstores accesibles sin auth + prueba inyección en documentos |
| D3 | Módulo ASI07 `inter-agent` | Detecta endpoints de comunicación inter-agente expuestos; prueba escalación via sub-agents |
| D4 | AutoGen Studio adapter | `condor scan --platform autogen` enumera teams y tools |

**Dependencias:**
- D1: Flowise corriendo localmente (Docker: `docker run -p 3000:3000 flowiseai/flowise`)
- D2: Research del API de vectorstore en Flowise/Langflow (Chroma, Pinecone, Weaviate endpoints)
- D3: Research de AutoGen Studio API (endpoints de team execution e inter-agent messaging)
- D4: AutoGen Studio corriendo para pruebas manuales

**Notas:**
- D1 es carry-over de RT-CONDOR-V01; levantar Flowise con `docker run` antes de la sesión
- ASI06 es alto valor para el case study — las vectorstores sin auth son finding frecuente
- ASI07 requiere instancia con multi-agent flow configurado; documentar en docs/ si no hay acceso

---

## Backlog

- **RT-CONDOR-V03** — ASI08/ASI09/ASI10 + SARIF output + batch scan
- **RT-CONDOR-CFP** — Case study con findings reales + CFP (post-Ekoparty o siguiente conf)
- **RT-CONDOR-PYPI** — Publicar `cobaltosec-condor` en PyPI + repo público GitHub

---

## Corvus: RT-CORVUS-SCALE (pendiente separado)

Ver `sectors/red-team/corvus/SIGUIENTE.md` para el bloque de mejoras batch de Corvus.
