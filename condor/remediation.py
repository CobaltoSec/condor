"""Platform-specific remediation advisor for OWASP ASI findings."""
from __future__ import annotations

from .core.models import Finding

_REMEDIATIONS: dict[tuple[str, str], dict] = {
    # ASI01 — Goal Hijack
    ("ASI01", "flowise"): {
        "title": "Enable Flowise prompt moderation / guardrails",
        "code": (
            "# In Flowise environment (.env or docker-compose)\n"
            "FLOWISE_SECRETKEY_OVERWRITE=your-secret-key\n"
            "# Enable moderation in chatflow settings:\n"
            "# Chatflow → Settings → Moderation → Enable Input Moderation"
        ),
    },
    ("ASI01", "langflow"): {
        "title": "Use LangChain input validators or constitutional AI",
        "code": (
            "# Wrap your chain with an input validator component:\n"
            "from langchain.callbacks import StdOutCallbackHandler\n"
            "# Add a Guard component before the LLM node in your flow\n"
            "# or use langchain-guardrails / nemoguardrails"
        ),
    },
    ("ASI01", "generic"): {
        "title": "Implement input validation and prompt hardening",
        "code": (
            "# System prompt hardening:\n"
            "# 1. Place instructions in a separate, non-overridable system channel\n"
            "# 2. Validate/sanitize user input before passing to the LLM\n"
            "# 3. Use an LLM-based guardrail layer (e.g. NeMo Guardrails)"
        ),
    },
    # ASI02 — Tool Misuse (path traversal, SSRF, SSTI)
    ("ASI02", "flowise"): {
        "title": "Disable unauthenticated tool execution in Flowise",
        "code": (
            "# Enable Flowise authentication to block unauthenticated tool execution:\n"
            "FLOWISE_USERNAME=admin\n"
            "FLOWISE_PASSWORD=your-strong-password\n"
            "# Restrict /api/v1/node-load-method/* via reverse proxy if needed:\n"
            "# location /api/v1/node-load-method/ { deny all; }"
        ),
    },
    ("ASI02", "generic"): {
        "title": "Sanitize tool parameter inputs and restrict outbound requests",
        "code": (
            "# Path traversal — validate and jail file paths:\n"
            "import os\n"
            "SAFE_ROOT = '/app/data'\n"
            "def safe_path(user_input):\n"
            "    p = os.path.realpath(os.path.join(SAFE_ROOT, user_input))\n"
            "    if not p.startswith(SAFE_ROOT):\n"
            "        raise ValueError('Path traversal denied')\n"
            "    return p\n\n"
            "# SSRF — block RFC-1918 and link-local in egress proxy (nginx):\n"
            "# geo $blocked_ip { default 0; 169.254.0.0/16 1; 10.0.0.0/8 1; 172.16.0.0/12 1; 192.168.0.0/16 1; }\n\n"
            "# SSTI — never eval user input as template code:\n"
            "# Use sandboxed Jinja2: jinja2.sandbox.SandboxedEnvironment()"
        ),
    },
    # ASI03 — Privilege Abuse
    ("ASI03", "flowise"): {
        "title": "Enable Flowise authentication via environment variables",
        "code": (
            "# .env or docker-compose environment:\n"
            "FLOWISE_USERNAME=admin\n"
            "FLOWISE_PASSWORD=your-strong-password\n"
            "# Restart Flowise after setting these variables."
        ),
    },
    ("ASI03", "langflow"): {
        "title": "Enable authentication in Langflow",
        "code": (
            "# langflow.yaml or environment:\n"
            "LANGFLOW_AUTO_LOGIN=false\n"
            "LANGFLOW_SUPERUSER=admin\n"
            "LANGFLOW_SUPERUSER_PASSWORD=your-strong-password\n"
            "LANGFLOW_SECRET_KEY=your-secret-key"
        ),
    },
    ("ASI03", "n8n"): {
        "title": "Enable n8n user management and authentication",
        "code": (
            "# n8n environment variables:\n"
            "N8N_USER_MANAGEMENT_DISABLED=false\n"
            "N8N_BASIC_AUTH_ACTIVE=true\n"
            "N8N_BASIC_AUTH_USER=admin\n"
            "N8N_BASIC_AUTH_PASSWORD=your-strong-password"
        ),
    },
    ("ASI03", "ollama"): {
        "title": "Restrict Ollama to localhost binding",
        "code": (
            "# Bind Ollama to loopback only (environment or systemd):\n"
            "OLLAMA_HOST=127.0.0.1\n"
            "# Or via systemd override:\n"
            "# Environment=\"OLLAMA_HOST=127.0.0.1\"\n"
            "# If external access is required, place behind an auth-enabled reverse proxy."
        ),
    },
    ("ASI03", "langgraph"): {
        "title": "Add authentication middleware to LangGraph server",
        "code": (
            "# Add auth middleware in your LangGraph server entrypoint:\n"
            "from langgraph_sdk import get_client\n"
            "# Use LangGraph Platform API keys:\n"
            "# LANGSMITH_API_KEY=your-key in environment\n"
            "# Or wrap with FastAPI dependency injection for custom auth"
        ),
    },
    ("ASI03", "openai-compat"): {
        "title": "Enable API key authentication on your OpenAI-compatible endpoint",
        "code": (
            "# vLLM: --api-key your-secret-key\n"
            "# LocalAI: set API_KEY=your-secret-key in environment\n"
            "# LM Studio: enable API key in server settings\n"
            "# Place behind a reverse proxy with auth if the server lacks native support."
        ),
    },
    ("ASI03", "generic"): {
        "title": "Enable authentication on your agentic platform",
        "code": (
            "# General steps:\n"
            "# 1. Enable authentication in platform settings/config\n"
            "# 2. Use strong credentials and rotate them regularly\n"
            "# 3. Place the service behind a reverse proxy (nginx/Caddy) if no native auth"
        ),
    },
    # ASI04 — Supply Chain
    ("ASI04", "generic"): {
        "title": "Audit tool descriptions and scan dependencies for CVEs",
        "code": (
            "# Audit tool descriptions for injection patterns:\n"
            "condor scan --url <target> --module supply-chain\n\n"
            "# Dependency scanning:\n"
            "pip audit  # Python\n"
            "npm audit  # Node.js\n"
            "# Use OSV Scanner: https://github.com/google/osv-scanner"
        ),
    },
    # ASI05 — Code Execution
    ("ASI05", "flowise"): {
        "title": "Disable or sandbox Flowise code execution nodes",
        "code": (
            "# Disable dangerous nodes via FLOWISE_DISABLED_NODES env var:\n"
            "FLOWISE_DISABLED_NODES=customFunction,codeExecutor\n"
            "# Or restrict to authenticated users and audit all code node usage."
        ),
    },
    ("ASI05", "n8n"): {
        "title": "Restrict n8n Code node execution",
        "code": (
            "# Disable the Code node in n8n community edition:\n"
            "N8N_DISABLE_PRODUCTION_WEBHOOKS=false  # keep but restrict\n"
            "# For n8n Enterprise: use execution policies to allow-list operations\n"
            "# Consider running n8n in a sandboxed container with no network egress"
        ),
    },
    ("ASI05", "generic"): {
        "title": "Isolate code execution in sandboxed environments",
        "code": (
            "# Options:\n"
            "# 1. Run code execution inside a gVisor/Firecracker sandbox\n"
            "# 2. Use WASM-based execution (e.g. Pyodide for Python)\n"
            "# 3. Enforce resource limits (CPU, memory, network) via cgroups\n"
            "# 4. Require auth for all code execution endpoints"
        ),
    },
    # ASI06 — Memory Poisoning
    ("ASI06", "flowise"): {
        "title": "Restrict Flowise vector store upsert to authenticated requests",
        "code": (
            "# Enable Flowise auth (required for API endpoints):\n"
            "FLOWISE_USERNAME=admin\n"
            "FLOWISE_PASSWORD=your-strong-password\n"
            "# All /api/v1/vector/upsert endpoints require auth once credentials are set."
        ),
    },
    ("ASI06", "langflow"): {
        "title": "Enable authentication on Langflow document store endpoints",
        "code": (
            "LANGFLOW_AUTO_LOGIN=false\n"
            "LANGFLOW_SUPERUSER=admin\n"
            "LANGFLOW_SUPERUSER_PASSWORD=your-strong-password\n"
            "# All document store and vector endpoints then require a valid JWT."
        ),
    },
    ("ASI06", "generic"): {
        "title": "Require authentication for all vector store write operations",
        "code": (
            "# Enforce auth on upsert/ingest endpoints:\n"
            "# 1. Add API key or Bearer token requirement to /upsert, /ingest, /upload\n"
            "# 2. Validate document content before storage (scan for injection patterns)\n"
            "# 3. Implement per-user namespacing in the vector store"
        ),
    },
    # ASI07 — Inter-Agent (generic only, specific platforms via fallback)
    ("ASI07", "generic"): {
        "title": "Validate origin and authenticate inter-agent communication channels",
        "code": (
            "# 1. Require signed JWTs or mutual TLS for agent-to-agent calls\n"
            "# 2. Do not trust X-Forwarded-For or custom internal headers as auth\n"
            "# 3. Use a service mesh (Istio, Linkerd) to enforce mTLS between agents"
        ),
    },
    # ASI08 — Cascading Failures
    ("ASI08", "flowise"): {
        "title": "Configure rate limiting on Flowise inference endpoints",
        "code": (
            "# nginx rate limiting in front of Flowise:\n"
            "limit_req_zone $binary_remote_addr zone=flowise:10m rate=10r/s;\n"
            "location /api/v1/prediction/ {\n"
            "    limit_req zone=flowise burst=20 nodelay;\n"
            "    proxy_pass http://flowise:3000;\n"
            "}"
        ),
    },
    ("ASI08", "generic"): {
        "title": "Implement rate limiting on inference endpoints",
        "code": (
            "# nginx example:\n"
            "limit_req_zone $binary_remote_addr zone=ai_api:10m rate=10r/s;\n"
            "location /api/ {\n"
            "    limit_req zone=ai_api burst=20 nodelay;\n"
            "    proxy_pass http://backend;\n"
            "}\n\n"
            "# Or use an API gateway (Kong, Traefik) with rate limit plugins."
        ),
    },
    # ASI09 — Trust Exploitation
    ("ASI09", "flowise"): {
        "title": "Add AI disclosure to Flowise system prompt",
        "code": (
            "# In your chatflow System Message field, prepend:\n"
            "You are an AI assistant. You must always identify yourself as an AI\n"
            "when asked. Never claim to be human.\n\n"
            "# Then add your actual instructions below."
        ),
    },
    ("ASI09", "generic"): {
        "title": "Always disclose AI nature in the system prompt",
        "code": (
            "# Prepend to every agent system prompt:\n"
            "\"You are an AI assistant. If asked whether you are a human or AI,\n"
            " you must truthfully identify yourself as an AI.\"\n\n"
            "# Optionally add output validation to catch deceptive responses."
        ),
    },
    # ASI10 — Rogue Agents
    ("ASI10", "flowise"): {
        "title": "Restrict chatflow creation to authenticated admins only",
        "code": (
            "# Enable Flowise authentication:\n"
            "FLOWISE_USERNAME=admin\n"
            "FLOWISE_PASSWORD=your-strong-password\n"
            "# POST /api/v1/chatflows requires valid credentials once auth is enabled."
        ),
    },
    ("ASI10", "n8n"): {
        "title": "Disable unauthenticated workflow creation in n8n",
        "code": (
            "N8N_USER_MANAGEMENT_DISABLED=false\n"
            "N8N_BASIC_AUTH_ACTIVE=true\n"
            "N8N_BASIC_AUTH_USER=admin\n"
            "N8N_BASIC_AUTH_PASSWORD=your-strong-password\n"
            "# POST /api/v1/workflows then requires authentication."
        ),
    },
    ("ASI10", "generic"): {
        "title": "Require admin authentication for agent/tool/webhook creation",
        "code": (
            "# 1. Enable platform authentication (see ASI03 remediation)\n"
            "# 2. Restrict creation endpoints to admin role:\n"
            "#    POST /agents, /tools, /webhooks → require admin JWT/API key\n"
            "# 3. Audit existing agents/tools for unexpected system prompt injections"
        ),
    },
}


def get_platform_fix(owasp_id: str, platform: str) -> dict | None:
    specific = _REMEDIATIONS.get((owasp_id, platform))
    if specific is not None:
        return specific
    generic = _REMEDIATIONS.get((owasp_id, "generic"))
    return generic


def enrich_findings(findings: list[Finding], platform: str) -> list[Finding]:
    enriched = []
    for f in findings:
        fix = get_platform_fix(f.owasp_id.value, platform)
        if fix:
            suffix = f"\n\n[{fix['title']}]\n{fix['code']}"
            updated = f.model_copy(update={"remediation": f.remediation + suffix})
            enriched.append(updated)
        else:
            enriched.append(f)
    return enriched
