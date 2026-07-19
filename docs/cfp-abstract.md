# CFP Abstract — Condor: Agentic AI Security Scanner

**Título:** La alfombra de bienvenida de JADEPUFFER: auditando infraestructura de IA agéntica expuesta  
**Título (inglés):** JADEPUFFER's Welcome Mat: Systematically Auditing Exposed Agentic AI Infrastructure

**Track sugerido:** Offensive Security / AppSec / AI Security  
**Formato:** Talk 30–45 min  
**Targets:** Ekoparty 2026 (Buenos Aires, deadline 14 agosto) · DragonJAR · 8.8 Chile

---

## Hook

En julio 2026, el ransomware **JADEPUFFER** entró por CVE-2025-3248 — ejecución de código remoto en Langflow sin autenticación (CVSS 9.8, CISA KEV). Los servidores afectados estaban expuestos en internet, sin parchear, y auditables en menos de 60 segundos con una herramienta open source. Esa herramienta existía antes de que JADEPUFFER llegara. Tenía descargas. La pregunta no es si alguien la usó contra esos servidores — es si el defensor llegó primero.

---

## Abstract (español)

La adopción de plataformas de IA agéntica —Flowise, Langflow, Dify, n8n, LangGraph— está creciendo a una velocidad que supera ampliamente a la madurez de sus controles de seguridad. Estas plataformas orquestan LLMs, tools, memorias vectoriales y pipelines multi-agente sobre APIs REST que, en muchos casos, se despliegan sin autenticación ni hardening.

El resultado es cuantificable: **más de 12,000 instancias Flowise** y **~7,000 instancias Langflow** estaban expuestas en internet cuando sus respectivos CVEs críticos fueron explotados activamente (CVE-2025-59528 CVSS 10.0; CVE-2025-3248 CISA KEV). El ransomware JADEPUFFER cifró 1,342 registros y GreyNoise observó 361 IPs maliciosas escaneando activamente instancias Langflow. Los servidores afectados estaban en su configuración por defecto — sin credenciales, sin hardening, auditables en segundos.

En esta charla presentamos **Condor**, un scanner de seguridad open-source diseñado específicamente para la superficie de ataque de sistemas agénticos, mapeado sobre el estándar **OWASP ASI Top 10** (Agentic Security Initiative). Condor soporta **16 plataformas** con **431 tests** y ejecuta 10 módulos ASI especializados en paralelo — cubriendo desde inyección de prompt hasta RAG poisoning, SSRF via tools, escalamiento de privilegios y rogue agent creation.

**Demo en vivo:** contra una instancia de Flowise 1.8.2 (default install, sin credenciales), Condor detecta en 3.0 segundos:

- Exfiltración de credenciales y API keys sin autenticación (`/api/v1/credentials`, `/api/v1/apikey`)
- Enumeración de variables de entorno incluyendo secretos internos (`/api/v1/variables`)
- Inyección en el vectorstore (RAG poisoning) sin credenciales (`/api/v1/vector/upsert`)
- **6 findings: 2 CRITICAL, 3 HIGH, 1 MEDIUM** — todos true positives, 0 falsos positivos, reproducible con `docker compose up`

En instancias con chatflows activos se suman ASI01 (prompt injection sobre flows en vivo) y ASI02 (SSRF/path traversal vía tools configuradas).

El mismo patrón se repite en **Langflow**, **Dify**, **n8n**, **Qdrant**, **Chroma**, **Letta** y otras plataformas agénticas populares — todas con vulnerabilidades detectables en segundos en su configuración por defecto.

**Vulnerabilidades descubiertas con Condor durante el desarrollo:**

- **GHSA-95xp-fhhm-xfj2** (n8n ≤ 2.30.7, CRITICAL, CWE-306): race window en `POST /rest/owner/setup` permite tomar control del servidor como `global:owner` en instalación fresca — sin credenciales, sin tokens, un solo request.
- **GHSA-p67m-xf4h-2r78** (Letta ≤ 0.16.8, CRITICAL, CWE-306, RCE): ejecución de código Python arbitrario vía `POST /v1/tools/run` sin autenticación. `LETTA_SERVER_PASS` está ignorado por defecto; requiere opt-in explícito con `LETTA_SERVER_SECURE=true` que no está documentado en la guía de instalación.

Ambas vulnerabilidades fueron descubiertas y publicadas por CobaltoSec Security Research. Condor implementa detección automática de los patrones de vulnerabilidad correspondientes en los módulos ASI03 y ASI05.

**¿Por qué no alcanza con Nuclei?** Los templates de Nuclei son excelentes para CVEs conocidos y respuestas HTTP determinísticas. Condor opera en una capa diferente: primero enumera el estado de la instancia —chatflows activos, colecciones vectoriales disponibles, IDs de agentes— y luego construye probes semánticamente válidos en contexto. Para detectar RAG poisoning, Condor lee la dimensión del vector de la colección objetivo, inyecta un vector con las dimensiones exactas y elimina el artefacto antes de reportar. Un template genérico que envíe `[0.0]*4` contra Qdrant recibe un 400 y termina sin finding. La diferencia no es de superficie — es de profundidad semántica.

**También cubrimos:** arquitectura del scanner, extensión mediante el sistema de plugins (`entry_points`), integración con GitHub Actions/CI, output SARIF 2.1.0/JUnit para DefectDojo/Semgrep, y el estado actual de seguridad del ecosistema agéntico.

**Takeaway:** el atacante tiene una ventana enorme. JADEPUFFER la usó. Condor ayuda a cerrarla.

---

## Abstract (inglés)

The rapid adoption of agentic AI platforms —Flowise, Langflow, Dify, n8n, LangGraph— is outpacing the maturity of their security controls. These platforms orchestrate LLMs, tools, vector memories, and multi-agent pipelines over REST APIs that are frequently deployed without authentication or hardening.

The scale is measurable: **over 12,000 Flowise instances** and **~7,000 Langflow instances** were exposed on the internet when their respective critical CVEs were actively exploited (CVE-2025-59528 CVSS 10.0; CVE-2025-3248 CISA KEV). The JADEPUFFER ransomware encrypted 1,342 records and GreyNoise tracked 361 malicious IPs actively scanning Langflow instances. All affected servers were running default configurations — no credentials, no hardening, auditable in seconds.

We present **Condor**, an open-source security scanner purpose-built for agentic system attack surfaces, mapped to the **OWASP ASI Top 10** (Agentic Security Initiative). Condor covers **16 platforms** with **431 tests**, running 10 specialized ASI modules in parallel — from prompt injection and RAG poisoning to SSRF via tools, privilege escalation, and rogue agent creation.

**Live demo:** against a Flowise 1.8.2 default install (no credentials), Condor detects in 3.0 seconds:

- Credential and API key exfiltration without authentication (`/api/v1/credentials`, `/api/v1/apikey`)
- Environment variable exposure including internal secrets (`/api/v1/variables`)
- Vectorstore injection (RAG poisoning) without credentials (`/api/v1/vector/upsert`)
- **6 findings: 2 CRITICAL, 3 HIGH, 1 MEDIUM** — all confirmed true positives, 0 false positives, reproducible with `docker compose up`

On configured instances (active chatflows + LLMs): additional ASI01 (prompt injection on live flows) and ASI02 (SSRF/path traversal via configured tools).

The pattern is not unique to Flowise: **Langflow**, **Dify**, **n8n**, **Qdrant**, **Chroma**, **Letta**, and other popular agentic platforms share the same vulnerability classes — all detectable in seconds by Condor in their default configuration.

**Original vulnerabilities discovered with Condor:**

- **GHSA-95xp-fhhm-xfj2** (n8n ≤ 2.30.7, CRITICAL, CWE-306): race window on `POST /rest/owner/setup` allows claiming `global:owner` control on a fresh installation — no credentials, no tokens, one request.
- **GHSA-p67m-xf4h-2r78** (Letta ≤ 0.16.8, CRITICAL, CWE-306, RCE): arbitrary Python code execution via `POST /v1/tools/run` without authentication. `LETTA_SERVER_PASS` is silently ignored by default; protection requires an undocumented opt-in flag (`LETTA_SERVER_SECURE=true`).

Both vulnerabilities were discovered and published by CobaltoSec Security Research. Condor implements automatic detection for the corresponding vulnerability patterns across ASI03 and ASI05 modules.

**Why Nuclei templates aren't enough:** Nuclei templates excel at known CVEs and deterministic HTTP responses. Condor operates at a different layer: it first enumerates instance state —active chatflows, available vector collections, agent IDs— then constructs semantically valid probes. Detecting RAG poisoning requires knowing the target collection's vector dimension before injecting. Condor reads the collection config, crafts a correctly-dimensioned vector, and cleans up the artifact before reporting. A generic template sending `[0.0]*4` against Qdrant gets a 400 and exits with no finding. The difference is not surface coverage — it's semantic depth.

**Also covered:** scanner architecture, custom plugin development via `entry_points`, GitHub Actions/CI integration, SARIF 2.1.0/JUnit output for DefectDojo, and the current global state of agentic AI security.

**Takeaway:** the attacker's window is wide open. JADEPUFFER used it. Condor helps close it.

---

## Speaker bio (Nicolás Padilla)

Ingeniero de seguridad, fundador de CobaltoSec (Argentina). Investigación en seguridad de sistemas de IA, red team y vulnerabilidades en infraestructura cloud. Desarrollador de Condor y Corvus — herramientas open-source para auditoría de plataformas agénticas y LLMs. Autor de GHSA-95xp-fhhm-xfj2 (n8n — owner takeover sin auth, CWE-306) y GHSA-p67m-xf4h-2r78 (Letta — RCE sin auth, CWE-306).

---

## Materiales

- Tool: `pip install cobaltosec-condor` — disponible en PyPI
- Repo: [github.com/CobaltoSec/condor](https://github.com/CobaltoSec/condor) — open-source, MIT
- Demo: Flowise 1.8.2 + Langflow + n8n dockerizados, reproducible en laptop (`docker compose up`)
- Slides: en preparación
