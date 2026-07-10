# CFP Abstract — Condor: Agentic AI Security Scanner

**Título:** Condor: Escaneando la superficie de ataque de plataformas de IA agéntica

**Track sugerido:** Offensive Security / AppSec / AI Security
**Formato:** Talk 30–45 min
**Targets:** Ekoparty (Buenos Aires, octubre 2026) · DragonJAR · No cON Name

---

## Abstract (español)

La adopción de plataformas de IA agéntica —Flowise, Langflow, Dify, AutoGen— está creciendo a una velocidad que supera ampliamente a la madurez de sus controles de seguridad. Estas plataformas orquestan LLMs, tools, memorias vectoriales y pipelines multi-agente sobre APIs REST que, en muchos casos, se despliegan sin autenticación ni hardening.

En esta charla presentamos **Condor**, un scanner de seguridad open-source diseñado específicamente para la superficie de ataque de sistemas agénticos, mapeado sobre el estándar **OWASP ASI Top 10** (Agentic Security Initiative). A diferencia de los scanners genéricos, Condor entiende la semántica de estas plataformas: enumera chatflows, tools y vectorstores, y ejecuta 10 módulos especializados en paralelo para detectar vulnerabilidades propias del paradigma agéntico.

**Demo en vivo:** contra una instancia de Flowise 1.8.2 (default install), Condor detecta en 3.0 segundos:
- Exfiltración de credenciales y API keys sin autenticación (`/api/v1/credentials`, `/api/v1/apikey`)
- Enumeración de variables de entorno y configuraciones internas sin auth (`/api/v1/variables`)
- Inyección en el vectorstore (RAG poisoning) sin credenciales (`/api/v1/vector/upsert`)
- 6 findings en total: 2 CRITICAL, 3 HIGH, 1 MEDIUM — todos confirmados como true positives, 0 falsos positivos
- En instancias con chatflows activos se suman ASI01 (prompt injection) y ASI02 (SSRF/path traversal via tools)

Cada finding corresponde a una vulnerabilidad real publicada en GHSAs del vendor, lo que valida que Condor detecta problemas reales sin conocerlos de antemano.

Los resultados no son específicos de Flowise: el mismo patrón se repite en **Langflow**, **Qdrant**, **Chroma**, **Letta** y otras plataformas agénticas populares — todas con vulnerabilidades detectables en segundos por Condor en su configuración por defecto.

**Además cubrimos:** arquitectura del scanner, cómo extenderlo con plugins propios, integración con GitHub Actions/CI, y el estado actual de seguridad del ecosistema agéntico a nivel global.

**Takeaway:** el atacante tiene una ventana enorme. Condor ayuda a cerrarla.

---

## Abstract (inglés)

The rapid adoption of agentic AI platforms —Flowise, Langflow, Dify, AutoGen— is outpacing the maturity of their security controls. These platforms orchestrate LLMs, tools, vector memories, and multi-agent pipelines over REST APIs that are frequently deployed without authentication or hardening.

We present **Condor**, an open-source security scanner purpose-built for agentic system attack surfaces, mapped to the **OWASP ASI Top 10** (Agentic Security Initiative). Unlike generic scanners, Condor understands the semantics of these platforms: it enumerates chatflows, tools, and vectorstores, then runs 10 specialized modules in parallel to detect vulnerabilities native to the agentic paradigm.

**Live demo:** against a Flowise 1.8.2 default install, Condor detects in 3.0 seconds:
- Credential and API key exfiltration without authentication (`/api/v1/credentials`, `/api/v1/apikey`)
- Environment variable exposure including internal secrets (`/api/v1/variables`)
- Vectorstore injection (RAG poisoning) without credentials (`/api/v1/vector/upsert`)
- 6 findings total: 2 CRITICAL, 3 HIGH, 1 MEDIUM — all confirmed true positives, 0 false positives
- On configured instances (active chatflows + LLMs): additional ASI01 (prompt injection) and ASI02 (SSRF/path traversal) findings

Every finding maps to a vendor-published GHSA, validating that Condor detects real issues without prior knowledge of them.

The pattern is not unique to Flowise: **Langflow**, **Qdrant**, **Chroma**, **Letta**, and other popular agentic platforms share the same vulnerability classes — all detectable in seconds by Condor in their default configuration.

**Also covered:** scanner architecture, custom plugin development, GitHub Actions/CI integration, and the current global state of agentic AI security.

---

## Speaker bio (Nicolás Padilla)

Ingeniero de seguridad, fundador de CobaltoSec (Argentina). Investigación en seguridad de sistemas de IA, red team y vulnerabilidades en infraestructura cloud. Desarrollador de Condor y Corvus — herramientas open-source para auditoría de plataformas agénticas y LLMs.

---

## Materiales

- Tool: `pip install cobaltosec-condor` — disponible en PyPI
- Repo: [github.com/CobaltoSec/condor](https://github.com/CobaltoSec/condor) — open-source, MIT
- Slides: en preparación
- Demo: Flowise 1.8.2 + Langflow dockerizados, reproducible en laptop (`docker compose up`)
