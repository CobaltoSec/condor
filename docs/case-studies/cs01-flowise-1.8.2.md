# CS-01: Flowise 1.8.2 — 6 Findings Críticos en 3.0 Segundos

**Plataforma:** Flowise — orquestador visual de chatbots y pipelines LLM  
**Versión testeada:** 1.8.2 (Docker: `flowiseai/flowise:1.8.2`)  
**Configuración:** sin autenticación (FLOWISE_USERNAME/PASSWORD vacíos — default de instalación bare)  
**Fecha:** 2026-07-10  
**Scanner:** Condor v1.0.0 (`condor scan --url http://localhost:3200 --platform flowise`)  

---

## Resumen ejecutivo

Flowise 1.8.2 en instalación por defecto (sin credenciales, sin chatflows configurados) expone **6 vulnerabilidades** detectadas en **3.0 segundos**: 2 CRITICAL, 3 HIGH, 1 MEDIUM. Ninguna requiere autenticación previa ni conocimiento de la instancia. Un atacante con acceso de red puede exfiltrar credenciales de integraciones, API keys, variables de entorno, e inyectar datos maliciosos en el vectorstore sin dejar rastro de usuario.

**Nota:** en instancias con chatflows y LLMs configurados (escenario productivo real), Condor detecta hallazgos adicionales en ASI01 (prompt injection sobre chatflows activos) y ASI02 (path traversal/SSRF a través de herramientas configuradas).

| Métrica | Valor |
|---------|-------|
| Total findings | 6 |
| CRITICAL | 2 |
| HIGH | 3 |
| MEDIUM | 1 |
| Tiempo de scan | 3.0 s |
| Falsos positivos | 0 |
| Auth requerida | Ninguna |

---

## Entorno de prueba

```bash
docker run -d -p 3200:3000 \
  -e FLOWISE_USERNAME="" \
  -e FLOWISE_PASSWORD="" \
  flowiseai/flowise:1.8.2

condor scan --url http://localhost:3200 --platform flowise --format html
```

**Nota:** Flowise 2.x+ fuerza autenticación por defecto. La versión 1.8.x (ampliamente desplegada en self-hosted) no tiene auth out-of-the-box. La actualización a 2.x+ requiere migración de base de datos.

---

## Findings

| # | ASI | Título | Severidad | Endpoint |
|---|-----|--------|-----------|----------|
| 1 | ASI03 | Unauthenticated read access to credentials database | CRITICAL | `GET /api/v1/credentials` |
| 2 | ASI03 | Unauthenticated read access to API keys | CRITICAL | `GET /api/v1/apikey` |
| 3 | ASI03 | Unauthenticated read access to environment variables | HIGH | `GET /api/v1/variables` |
| 4 | ASI03 | Unauthenticated read access to chatflow configurations | HIGH | `GET /api/v1/chatflows` |
| 5 | ASI06 | Vectorstore upsert accessible without auth (RAG poisoning) | HIGH | `POST /api/v1/vector/upsert/condor-probe` |
| 6 | ASI03 | Unauthenticated read access to tool configurations | MEDIUM | `GET /api/v1/tools` |

---

## Análisis por finding

### Findings 1-2 — Credential & API Key Exfiltration (CRITICAL)

`GET /api/v1/credentials` devuelve todas las credenciales configuradas en la instancia (OpenAI API key, Pinecone, otros servicios de terceros) sin requerir autenticación.  
`GET /api/v1/apikey` devuelve la API key interna de Flowise en plaintext.

**Impacto:**
- Las API keys de LLM providers (OpenAI, Anthropic) permiten realizar llamadas a nombre de la víctima, generando cargos y acceso a datos del tenant.
- La Flowise API key permite control total sobre la instancia vía API.
- Sin rate limiting ni alertas, el robo puede pasar desapercibido.

**Demostración:**
```bash
curl http://flowise-instance/api/v1/credentials
# → [{"id":"...","name":"OpenAI","credentialName":"openAIApi","encryptedData":"..."}, ...]

curl http://flowise-instance/api/v1/apikey
# → [{"id":"...","apiKey":"flo_...","apiSecret":"...","keyName":"default"}]
```

### Finding 3 — Environment Variable Exposure (HIGH)

`GET /api/v1/variables` expone todas las variables de entorno definidas en Flowise, incluyendo secretos internos, URIs de base de datos, y claves de integración que los chatflows referencian como `{{variable_name}}`.

### Finding 4 — Chatflow Enumeration (HIGH)

`GET /api/v1/chatflows` enumera todos los chatflows definidos incluyendo:
- Nombres y descripciones (que pueden contener información sensible de la empresa)
- System prompts completos (instrucciones internas, contexto de negocio)
- Configuración de nodos (tools conectadas, modelos usados, parámetros)

### Finding 5 — RAG Poisoning via Unauthenticated Vectorstore Write (HIGH)

`POST /api/v1/vector/upsert/condor-probe` permite insertar documentos arbitrarios en el vectorstore sin autenticación.

**Impacto:** envenenamiento de la base de conocimiento del agente. Todos los usuarios que interactúen con el chatflow recibirán respuestas contaminadas con la información inyectada. El ataque es:
- **Persistente:** los vectores quedan almacenados hasta que alguien los elimine manualmente.
- **Escalable:** un atacante puede inyectar miles de documentos en segundos.
- **Silencioso:** no hay alertas por defecto; los usuarios no notan la degradación inmediatamente.

### Finding 6 — Tool Configuration Exposure (MEDIUM)

`GET /api/v1/tools` expone la lista de herramientas (functions/tools) definidas en la instancia, incluyendo código Python custom y configuraciones de integración.

---

## Remediación

| Finding | Remediación |
|---------|------------|
| Credenciales/API key exposure | Habilitar `FLOWISE_USERNAME` + `FLOWISE_PASSWORD`. Upgrade a 2.x+ (RBAC nativo). |
| Variables exposure | Misma remediación de auth. Usar secrets manager externo en lugar de Flowise variables. |
| Chatflow enumeration | Auth + RBAC por chatflow (disponible en Flowise cloud / 2.x+). |
| RAG poisoning | Auth en todos los endpoints de vector store. Validar fuentes de ingesta. |
| Tool exposure | Auth + principio de mínimo privilegio en configuración de tools. |
| General | No exponer el puerto de Flowise directamente a internet. Usar reverse proxy con TLS y autenticación HTTP básica como capa adicional. |

---

## Referencias

- [CVE-2026-30820](https://nvd.nist.gov/vuln/detail/CVE-2026-30820) — Flowise auth bypass via `x-request-from: internal` header (≤ 3.0.12)
- [OWASP ASI Top 10](https://genai.owasp.org/) — Agentic Security Initiative
- [Condor on PyPI](https://pypi.org/project/cobaltosec-condor/) — `pip install cobaltosec-condor`
- [github.com/CobaltoSec/condor](https://github.com/CobaltoSec/condor)
