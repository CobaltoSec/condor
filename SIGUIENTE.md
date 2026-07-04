# SIGUIENTE — Condor

## Bloque activo

### RT-CONDOR-V02 — ASI06 + ASI07 + E2E Flowise + AutoGen adapter

**Objetivo:** Implementar los 2 módulos de mayor impacto diferencial (Memory Poisoning e Inter-Agent),
cerrar el E2E diferido contra Flowise, y agregar el adapter de AutoGen Studio.

**Talla:** M (3–4 sesiones)

**Deliverables:**

| ID | Descripción | Criterio de completitud | Estado |
|----|-------------|------------------------|--------|
| D1 | E2E scan contra Flowise local | `condor scan` arroja ≥1 finding real en instancia de laboratorio | ⚠️ parcial |
| D2 | Módulo ASI06 `memory-poisoning` | Detecta vectorstores accesibles sin auth + prueba inyección en documentos | ✅ |
| D3 | Módulo ASI07 `inter-agent` | Detecta endpoints de comunicación inter-agente expuestos; prueba escalación via sub-agents | ✅ |
| D4 | AutoGen Studio adapter | `condor scan --platform autogen` enumera teams y tools | ✅ |

**D1 — Estado:**

El E2E corre correctamente end-to-end (health check, surface enumeration, 7 módulos). Flowise 2.x y 3.x tienen workspace auth activa por defecto (SQLite), resultando en 0 findings (comportamiento correcto en instancia hardened).

Para ≥1 finding real, levantar Flowise 1.x:
```
docker run -d --name flowise -p 3001:3000 flowiseai/flowise:1.8.2
condor scan --url http://localhost:3001 --platform flowise
```

**Fix crítico incluido este bloque:** `_is_api_response(r)` en ASI03/05/06/07 — filtra respuestas `text/html` (SPA catch-all de Flowise 3.x/Next.js) que generaban falsos positivos CRITICAL/HIGH.

---

## Backlog

- **RT-CONDOR-V03** — ASI08/ASI09/ASI10 + SARIF output + batch scan
- **RT-CONDOR-CFP** — Case study con findings reales + CFP (post-Ekoparty o siguiente conf)
- **RT-CONDOR-PYPI** — Publicar `cobaltosec-condor` en PyPI + repo público GitHub

---

## Corvus: RT-CORVUS-SCALE (pendiente separado)

Ver `sectors/red-team/corvus/SIGUIENTE.md` para el bloque de mejoras batch de Corvus.
