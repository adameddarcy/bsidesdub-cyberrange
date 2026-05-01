# Cyber Range Architecture Documentation

This folder contains C4 model diagrams and network sequence diagrams for the Cyber Range Threat Modelling Workshop.

## Viewing the Diagrams

These are PlantUML (`.puml`) files. You can render them using:

1. **VS Code**: Install the "PlantUML" extension
2. **Online**: Paste into [plantuml.com](https://www.plantuml.com/plantuml/uml/)
3. **CLI**: `java -jar plantuml.jar *.puml`
4. **Docker**: `docker run -v $(pwd):/data plantuml/plantuml *.puml`

## C4 Model Diagrams

| File | Level | Description |
|------|-------|-------------|
| `c4-context.puml` | Context | System context showing participants, admin, and the range |
| `c4-container.puml` | Container | All containers across 4 network tiers with vulnerabilities marked |
| `c4-component-agent.puml` | Component | Deep dive into the Agent Service internals |
| `c4-deployment.puml` | Deployment | Infrastructure view showing Docker, networks, and host services |

## Network Diagrams

| File | Description |
|------|-------------|
| `network-topology.puml` | IP address layout and inter-network connections |

## Sequence Diagrams

| File | Flow Documented |
|------|-----------------|
| `sequence-http-flow.puml` | Normal user HTTP request through proxy to Juice Shop |
| `sequence-ssrf-attack.puml` | SSRF exploitation path from Juice Shop to internal services |
| `sequence-agent-exploit.puml` | Agent prompt injection and tool abuse scenarios |
| `sequence-monitoring-flow.puml` | Log collection from containers to Grafana |
| `sequence-bastion-access.puml` | Participant SSH access and network enumeration |

## Network Tiers

```
┌─────────────────────────────────────────────────────────────┐
│                        VPS HOST                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │                  Docker Networks                        │ │
│  │                                                         │ │
│  │  ┌─────────────────┐    ┌─────────────────┐            │ │
│  │  │   DMZ Network   │    │   App Network   │            │ │
│  │  │  10.10.1.0/24   │    │  10.10.2.0/24   │            │ │
│  │  │                 │    │                 │            │ │
│  │  │  • Proxy :80    │    │  • API          │            │ │
│  │  │  • Juice Shop   │◄──►│  • Agent :5000  │            │ │
│  │  │  • Bastion :2222│    │  • MySQL :3306  │            │ │
│  │  └─────────────────┘    └────────┬────────┘            │ │
│  │                                  │                      │ │
│  │  ┌─────────────────┐    ┌───────▼─────────┐            │ │
│  │  │ Monitoring Net  │    │ Internal Network│            │ │
│  │  │  10.10.4.0/24   │    │  10.10.3.0/24   │            │ │
│  │  │                 │    │  [internal:true]│            │ │
│  │  │  • Loki         │    │                 │            │ │
│  │  │  • Promtail     │    │  • MySQL        │            │ │
│  │  │  • Grafana :3000│    │  • LDAP :389    │            │ │
│  │  └─────────────────┘    │  • Agent        │            │ │
│  │                         └─────────────────┘            │ │
│  └────────────────────────────────────────────────────────┘ │
│                                                              │
│  UFW: 22 (admin), 80 (web), 2222 (bastion), 3000 (grafana)  │
└─────────────────────────────────────────────────────────────┘
```

## Vulnerability Summary by Component

### DMZ Tier
- **Proxy**: Server version exposed, no rate limiting
- **Juice Shop**: SQLi, XSS, IDOR, weak JWT (`secret`)
- **Bastion**: Password auth, routes to all tiers

### App Tier  
- **Internal API**: No authentication
- **Agent**: No approval gate, prompt injection, no auth, unlimited tool calls, SSRF
- **MySQL**: Weak root password, query logging

### Internal Tier
- **LDAP**: Anonymous bind, weak admin password
- **MySQL**: Reachable from app tier with trivial credentials

## Generating PNG/SVG

```bash
# Generate all diagrams as PNG
docker run --rm -v $(pwd):/data plantuml/plantuml -tpng "*.puml"

# Generate as SVG
docker run --rm -v $(pwd):/data plantuml/plantuml -tsvg "*.puml"
```
