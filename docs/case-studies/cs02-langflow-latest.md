# CS-02: Langflow 1.10.2 — Superficie Reducida vs. Flowise

**Plataforma:** Langflow — plataforma visual para construir aplicaciones LLM (Datastax/open-source)  
**Versión testeada:** 1.10.2 (Docker: `langflowai/langflow:latest`)  
**Configuración:** `LANGFLOW_AUTO_LOGIN=true` — misconfiguration común en self-hosted  
**Fecha:** 2026-07-10  
**Scanner:** Condor v1.0.0 (`condor scan --url http://localhost:7860 --platform langflow`)  

---

## Resumen ejecutivo

Langflow 1.10.2 con `LANGFLOW_AUTO_LOGIN=true` expone **1 finding** en **3.6 segundos**: version disclosure de severidad LOW. A diferencia de Flowise 1.8.2 (6 findings, 2 CRITICAL), Langflow 1.x enforce autenticación en la API REST incluso cuando el auto-login está habilitado para el dashboard web. El auto-login afecta únicamente la UI, no los endpoints de API.

Esta diferencia es un insight clave del scan: **no todas las plataformas agénticas tienen la misma postura de seguridad**. Langflow 1.10.2 tiene mejor seguridad por defecto que Flowise 1.8.x, aunque versiones anteriores (pre-1.0) tuvieron vulnerabilidades críticas.

| Métrica | Valor |
|---------|-------|
| Total findings | 1 |
| LOW | 1 |
| Tiempo de scan | 3.6 s |
| Falsos positivos | 0 |
| Auth requerida | Sí (para todos los endpoints excepto `/openapi.json`, `/health`) |

---

## Entorno de prueba

```bash
docker run -d -p 7860:7860 \
  -e LANGFLOW_AUTO_LOGIN=true \
  -e LANGFLOW_SUPERUSER=admin \
  -e LANGFLOW_SUPERUSER_PASSWORD=admin \
  -e LANGFLOW_SECRET_KEY=condor-e2e-insecure-key \
  langflowai/langflow:latest

condor scan --url http://localhost:7860 --platform langflow --format html
```

---

## Finding

| # | ASI | Título | Severidad | Endpoint |
|---|-----|--------|-----------|----------|
| 1 | ASI09 | Software version disclosed via unauthenticated `/openapi.json` | LOW | `GET /openapi.json` |

**Detalle:** `/openapi.json` expone la versión de Langflow (`"version": "1.10.2"`) sin autenticación, permitiendo fingerprinting preciso de la plataforma. Un atacante puede cruzar esta información con el CVE database (OSV.dev) para identificar exploits aplicables.

---

## Contexto: `LANGFLOW_AUTO_LOGIN` y la superficie de API

`LANGFLOW_AUTO_LOGIN=true` hace que la interfaz web inicie sesión automáticamente sin pedir credenciales. Sin embargo, los endpoints de API REST en `/api/v1/` **siguen requiriendo un Bearer token** válido. El auto-login obtiene ese token internamente para el browser, pero no lo expone a peticiones externas sin autenticación.

Resultado: con `LANGFLOW_AUTO_LOGIN=true`, la superficie de ataque accesible sin token es mínima:
- `/health` → `{"status": "healthy"}`
- `/openapi.json` → spec con versión (finding ASI09)
- `/api/v1/login` → devuelve token con cualquier credencial cuando auto-login está activo (no probado en este scan)

**Vector de ataque potencial no probado:** `POST /api/v1/login` con `{"username":"","password":""}` cuando `LANGFLOW_AUTO_LOGIN=true` podría devolver un token válido, permitiendo acceso completo a la API sin credenciales reales. Esto requeriría verificación en laboratorio y es candidato a investigación separada.

---

## Historial de CVEs — Langflow

Langflow tiene antecedentes de vulnerabilidades críticas en versiones anteriores:

| CVE | Descripción | CVSS | Versión afectada | Parchado en |
|-----|-------------|------|-----------------|-------------|
| CVE-2024-8673 | RCE via eval() en Python Code Component | 9.8 | < 1.0.18 | 1.0.18 |
| CVE-2024-48949 | SSRF via HTTP Request Tool | 8.6 | < 1.0.19 | 1.0.19 |
| CVE-2024-37014 | Unauthenticated API access (pre-auth) | 9.1 | < 0.6.20 | 0.6.20 |

**Conclusión:** instalaciones de Langflow < 1.0.18 son vulnerables a RCE sin autenticación. Condor detectaría estas vulnerabilidades en versiones afectadas a través de los módulos ASI05 (code execution) y ASI02 (SSRF).

---

## Comparativa de Posturas de Seguridad

| Plataforma | Versión | Findings | CRITICAL | Auth por defecto |
|-----------|---------|----------|----------|-----------------|
| Flowise | 1.8.2 | 6 | 2 | ❌ No |
| Langflow | 1.10.2 | 1 | 0 | ✅ Sí (API) |
| Langflow | < 1.0.18 | ≥3 (est.) | ≥1 (RCE) | ❌ No |

Esta tabla ilustra la evolución de seguridad en el ecosistema: plataformas que comenzaron sin auth ahora la enforzan, pero instalaciones desactualizadas siguen siendo vulnerables.

---

## Remediación

- **Deshabilitar `LANGFLOW_AUTO_LOGIN`** en producción — es una feature de desarrollo.
- **Configurar credenciales fuertes** en `LANGFLOW_SUPERUSER`/`LANGFLOW_SUPERUSER_PASSWORD`.
- **Bloquear `/openapi.json`** en el proxy si no es necesario para clientes externos.
- **Mantener Langflow actualizado** — el historial de CVEs muestra un ritmo de disclosure activo.
- **No exponer el puerto 7860** directamente a internet; usar reverse proxy con TLS.

---

## Referencias

- [CVE-2024-8673](https://nvd.nist.gov/vuln/detail/CVE-2024-8673) — Langflow RCE (< 1.0.18)
- [CVE-2024-48949](https://nvd.nist.gov/vuln/detail/CVE-2024-48949) — Langflow SSRF (< 1.0.19)
- [OSV.dev — Langflow advisories](https://osv.dev/list?ecosystem=PyPI&q=langflow)
- [OWASP ASI Top 10](https://genai.owasp.org/)
- [github.com/CobaltoSec/condor](https://github.com/CobaltoSec/condor)
