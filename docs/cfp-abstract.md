# CFP Abstract — Condor: Agentic AI Security Scanner

**Título:** Condor: Escaneando la superficie de ataque de plataformas de IA agéntica

**Track sugerido:** Offensive Security / AppSec / AI Security
**Formato:** Talk 30–45 min
**Targets:** Ekoparty (Buenos Aires, octubre 2026) · DragonJAR · No cON Name

---

## Abstract (español)

La adopción de plataformas de IA agéntica —Flowise, Langflow, Dify, AutoGen— está creciendo a una velocidad que supera ampliamente a la madurez de sus controles de seguridad. Estas plataformas orquestan LLMs, tools, memorias vectoriales y pipelines multi-agente sobre APIs REST que, en muchos casos, se despliegan sin autenticación ni hardening.

En esta charla presentamos **Condor**, un scanner de seguridad open-source diseñado específicamente para la superficie de ataque de sistemas agénticos, mapeado sobre el estándar **OWASP ASI Top 10** (Agentic Security Initiative). A diferencia de los scanners genéricos, Condor entiende la semántica de estas plataformas: enumera chatflows, tools y vectorstores, y ejecuta 10 módulos especializados en paralelo para detectar vulnerabilidades propias del paradigma agéntico.

**Demo en vivo:** contra una instancia de Flowise 1.8.2, Condor detecta en 3.6 segundos:
- Exfiltración de API keys sin autenticación (`/api/v1/apikey` → clave real devuelta)
- Exposición del system prompt completo incluyendo secretos internos (`ACME-2026-INTERNAL`)
- Modificación del system prompt sin autenticación — cualquier atacante puede reprogramar el comportamiento del agente
- Inyección en el vectorstore (RAG poisoning) sin credenciales
- 9 findings en total: 3 CRITICAL, 5 HIGH, 1 MEDIUM — todos confirmados como true positives

Cada finding corresponde a una vulnerabilidad real publicada en GHSAs del vendor, lo que valida que Condor detecta problemas reales sin conocerlos de antemano.

**Además cubrimos:** arquitectura del scanner, cómo extenderlo con plugins propios, integración con GitHub Actions/CI, y el estado actual de seguridad del ecosistema agéntico a nivel global.

**Takeaway:** el atacante tiene una ventana enorme. Condor ayuda a cerrarla.

---

## Abstract (inglés)

The rapid adoption of agentic AI platforms —Flowise, Langflow, Dify, AutoGen— is outpacing the maturity of their security controls. These platforms orchestrate LLMs, tools, vector memories, and multi-agent pipelines over REST APIs that are frequently deployed without authentication or hardening.

We present **Condor**, an open-source security scanner purpose-built for agentic system attack surfaces, mapped to the **OWASP ASI Top 10** (Agentic Security Initiative). Unlike generic scanners, Condor understands the semantics of these platforms: it enumerates chatflows, tools, and vectorstores, then runs 10 specialized modules in parallel to detect vulnerabilities native to the agentic paradigm.

**Live demo:** against a Flowise 1.8.2 instance, Condor detects in 3.6 seconds:
- API key exfiltration without authentication (`/api/v1/apikey` → real key returned)
- Full system prompt exposure including internal secrets
- Unauthenticated system prompt modification — any attacker can reprogram agent behavior
- Vectorstore injection (RAG poisoning) without credentials
- 9 findings total: 3 CRITICAL, 5 HIGH, 1 MEDIUM — all confirmed true positives

Every finding maps to a vendor-published GHSA, validating that Condor detects real issues without prior knowledge of them.

**Also covered:** scanner architecture, custom plugin development, GitHub Actions/CI integration, and the current global state of agentic AI security.

---

## Speaker bio (Nicolás Padilla)

Ingeniero de seguridad, fundador de CobaltoSec (Argentina). Investigación en seguridad de sistemas de IA, red team y vulnerabilidades en infraestructura cloud. Desarrollador de Condor y Corvus — herramientas open-source para auditoría de plataformas agénticas y LLMs.

---

## Materiales

- Tool: `pip install cobaltosec-condor` (pendiente PyPI)
- Repo: github.com/cobaltosec/condor (pendiente publicación)
- Slides: en preparación
- Demo: Flowise 1.8.2 + Ollama dockerizados, reproducible en laptop
