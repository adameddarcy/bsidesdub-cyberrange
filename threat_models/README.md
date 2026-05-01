# Cyber Range Threat Model

Automated threat model for the cyber range workshop environment using [pytm](https://pypi.org/project/pytm/).

## Prerequisites

- Python 3.x
- Graphviz (`brew install graphviz` or `apt install graphviz`)
- PlantUML JAR (for sequence diagrams)
- Pandoc (for HTML report generation)

## Quick Start

```bash
cd threat_models

pip install -r requirements.txt

./cyber_range_tm.py --list

mkdir -p output
./cyber_range_tm.py --dfd | dot -Tpng -o output/dfd.png
```

## Generate All Outputs

### Using Make

```bash
make all
```

### Using Docker (no local dependencies)

```bash
make docker-all
```

## Available Commands

| Command | Description |
|---------|-------------|
| `--dfd` | Generate Data Flow Diagram (Graphviz DOT format) |
| `--seq` | Generate Sequence Diagram (PlantUML format) |
| `--report TEMPLATE` | Generate report from template |
| `--list` | List all identified threats |
| `--json FILE` | Export threats to JSON |
| `--describe ELEMENT` | Describe element properties |

## Model Components

### Trust Boundaries

| Boundary | Subnet | Description |
|----------|--------|-------------|
| Internet | External | Untrusted external network |
| DMZ | 10.10.1.0/24 | Internet-facing services |
| App Network | 10.10.2.0/24 | Application tier |
| Internal Network | 10.10.3.0/24 | Sensitive data stores |
| Monitoring | 10.10.4.0/24 | Logging and observability |

### Modelled Assets

| Asset | Type | Network | Key Vulnerabilities |
|-------|------|---------|---------------------|
| nginx Proxy | Server | DMZ | Version disclosure, no rate limiting |
| Juice Shop | Server | DMZ/App | SQLi, XSS, IDOR, weak JWT |
| Bastion | Server | All | Password auth, broad network access |
| httpbin API | Server | App | No authentication |
| Agent Service | Server | App/Internal | Prompt injection, no approval gate, SSRF |
| MySQL | Datastore | Internal | Weak password, root access, query logging |
| OpenLDAP | Datastore | Internal | Anonymous bind, weak admin password |
| Grafana | Server | Monitoring | Anonymous access |

### Data Classifications

| Data Type | Classification | Contains PII | Contains Credentials |
|-----------|----------------|--------------|---------------------|
| HTTP Request | Public | No | No |
| User Credentials | Secret | Yes | Yes |
| JWT Token | Sensitive | No | Yes |
| SQL Query | Sensitive | No | No |
| PII Records | Secret | Yes | No |
| Agent Prompt | Sensitive | No | No |
| Tool Output | Sensitive | No | No |
| Log Data | Sensitive | No | No |

## Threat Categories

The model identifies threats across STRIDE:

- **Spoofing**: No auth on agent/API, anonymous LDAP bind
- **Tampering**: SQL injection, prompt injection, data manipulation
- **Repudiation**: Missing audit trails, anonymous Grafana access
- **Information Disclosure**: PII in logs, credential exposure
- **Denial of Service**: Unlimited agent tool calls, no rate limiting
- **Elevation of Privilege**: Agent pivot to internal network, bastion access

## Output Examples

### Data Flow Diagram

```bash
./cyber_range_tm.py --dfd | dot -Tpng -o output/dfd.png
open output/dfd.png
```

### Sequence Diagram

```bash
export PLANTUML_PATH=/path/to/plantuml.jar
./cyber_range_tm.py --seq | java -Djava.awt.headless=true -jar $PLANTUML_PATH -tpng -pipe > output/seq.png
```

### HTML Report

```bash
./cyber_range_tm.py --report templates/report_template.md | pandoc -f markdown -t html > output/report.html
open output/report.html
```

## Customisation

### Adding Custom Threats

Create a `custom_threats.json` file and reference it in your model:

```python
tm = TM("Cyber Range Threat Model")
tm.threatsFile = "custom_threats.json"
```

### Overriding Findings

```python
agent_to_api.overrides = [
    Finding(
        threat_id="INP26",
        cvss="9.8",
        severity="Critical",
        response="Implement approval gate and input sanitisation"
    )
]
```

## Integration with CI/CD

```yaml
threat-model:
  stage: security
  script:
    - pip install pytm
    - python cyber_range_tm.py --json threats.json
    - python cyber_range_tm.py --dfd | dot -Tpng -o dfd.png
  artifacts:
    paths:
      - threats.json
      - dfd.png
```
