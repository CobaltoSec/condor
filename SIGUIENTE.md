# SIGUIENTE — Condor

## Bloque activo

— (ninguno abierto)

---

## Backlog

- **RT-CONDOR-CFP** — Case study con findings reales contra instancia Flowise 1.8.x + CFP (Ekoparty u otra conf)
  - Requiere: `docker run -d --name flowise -p 3001:3000 flowiseai/flowise:1.8.2`
  - Ejecutar `condor scan --url http://localhost:3001 --platform flowise --sarif`
  - Documentar findings reales para submission

- **RT-CONDOR-PYPI** — Publicar `cobaltosec-condor` en PyPI + repo público GitHub
  - Requisito previo: validación E2E con findings reales (RT-CONDOR-CFP o similar)
  - Tareas: bump versión → 1.0.0, README público, CI/CD (GitHub Actions), `pip install cobaltosec-condor`

- **RT-CONDOR-SCALE** — Mejoras de escala y output
  - Concurrency en batch scan (`asyncio.gather` con semáforo)
  - Output `--format json|sarif|both|table`
  - Progress bar para módulos (rich progress)
  - `--exclude-module` para skip de módulos específicos

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

**Plataformas:** `flowise` · `generic` · `langflow` · `dify` · `autogen`  
**Cobertura:** 10/10 módulos OWASP ASI · 92 tests passing  
**Output:** JSON + SARIF 2.1.0 · Batch scan (`--targets`)

---

## Corvus: RT-CORVUS-SCALE (pendiente separado)

Ver `sectors/red-team/corvus/SIGUIENTE.md` para el bloque de mejoras batch de Corvus.
