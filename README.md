# Cyber Range — Threat Modelling Workshop

A three-tier web application range with intentional misconfigurations for STRIDE analysis.

## Quick Start

```bash
git clone <this-repo> cyber-range && cd cyber-range
docker compose up -d
```

Startup takes ~60 seconds for all services to become healthy.

---

## Access Points

| Service | URL / Address | Credentials |
|---|---|---|
| **Target app** (Juice Shop) | http://localhost | — |
| **Grafana** (logs) | http://localhost:3000 | anonymous |
| **Bastion** (SSH) | `ssh analyst@localhost -p 2222` | `analyst123` |
| **Agent service** | `http://10.10.2.30:5000` (from bastion) | none |
| **Internal API** | `http://10.10.2.20` (from bastion) | none |
| **Database** | `mysql -h 10.10.2.40 -u root -ppassword` (from bastion) | `root / password` |
| **LDAP** | `ldapsearch -H ldap://10.10.3.30` (from bastion) | anonymous bind enabled |

---

## Network Map

```
[Internet / Red Team]
        │
        ▼
  ┌─────────────┐   DMZ (10.10.1.0/24)
  │  proxy:80   │   nginx reverse proxy
  └──────┬──────┘
         │
         ▼
  ┌─────────────┐   App Net (10.10.2.0/24)
  │  juiceshop  │   OWASP Juice Shop
  │  api        │   httpbin mock API
  │  agent      │   Agentic service (Flask)
  └──────┬──────┘
         │
         ▼
  ┌─────────────┐   Internal Net (10.10.3.0/24) — isolated
  │  db         │   MySQL 8.0
  │  ldap       │   OpenLDAP (mock AD)
  └─────────────┘

  ┌─────────────┐   Bastion — bridges ALL networks
  │  bastion    │   SSH on :2222
  └─────────────┘

  ┌─────────────┐   Monitoring (10.10.4.0/24)
  │  loki       │   Log aggregation
  │  promtail   │   Log shipping (reads Docker socket)
  │  grafana:3000│  Dashboard
  └─────────────┘
```

---

## Intentional Vulnerabilities (Workshop Threat Surfaces)

Marked `[VULN]` throughout config files. Summary:

### DMZ / Proxy
- nginx version exposed in Server header
- No rate limiting on `/rest/user/login` → brute-force
- Missing security headers (CSP, X-Frame-Options, HSTS)

### Juice Shop (App Tier)
- SQL injection on product search
- XSS on feedback / review forms
- IDOR on basket API
- JWT signed with hardcoded secret (`secret`)
- Admin panel accessible with weak credentials

### Agent Service
- No approval gate before tool execution ← **key focus for agentic threat modelling**
- System prompt injectable via `context` field (prompt injection)
- Tool output returned raw to caller
- No tool call count limit (DoS / loop risk)
- No auth on the service itself

### Database
- Root password `password` passed via environment variable
- Juice Shop connects as root (no least-privilege user)
- General query log enabled — credentials in plaintext logs
- PII and API keys stored in plaintext

### LDAP / Identity
- Anonymous bind enabled → full directory enumerable
- Admin password `admin`

### Bastion
- SSH password auth enabled (should be key-only)
- Direct route to `internal_net` — no additional network hop required

---

## Workshop Flow

### Phase 1 — Reconnaissance (20 min)
Participants review the network diagram above and identify:
- Trust boundaries between tiers
- Entry points from the simulated internet
- Data flows crossing boundaries

### Phase 2 — STRIDE Enumeration (40 min)
Teams apply STRIDE to each component. Suggested assignments:
- **Team A** → proxy + juiceshop (Spoofing, Tampering, Info Disclosure)
- **Team B** → agent service (all STRIDE categories, esp. Elevation of Privilege)
- **Team C** → db + ldap (Info Disclosure, Denial of Service)

### Phase 3 — Attack Path Validation (30 min)
Facilitator demonstrates two live paths:
1. SQLi on Juice Shop → lateral pivot to `rangecorp.employees` table
2. Prompt injection on agent → SSRF to internal API → tool call without approval

Participants observe log artefacts in Grafana in real time.

### Phase 4 — Mitigation Design (30 min)
Teams propose controls. Key discussion: the agent approval workflow.
- What should the approval gate look like?
- How do you prevent prompt injection from bypassing it?
- What does human oversight mean for an agent with write access to production?

---

## Teardown

```bash
docker compose down -v   # removes volumes — wipes all range data
```

---

## Requirements

- Docker 24+ and Docker Compose v2
- ~4 GB RAM recommended
- Ports 80, 2222, 3000 free on host
