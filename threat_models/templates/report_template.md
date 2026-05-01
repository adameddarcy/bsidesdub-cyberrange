# {tm.name}

**Generated**: {tm.assumptions}

## System Description

{tm.description}

---

## Data Flow Diagram

![Data Flow Diagram](dfd.png)

---

## Sequence Diagram

![Sequence Diagram](seq.png)

---

## Trust Boundaries

| Boundary | Description |
|----------|-------------|
{boundaries:repeat:| {{item.name}} | Trust boundary |
}

---

## Assets

| Name | Type | In Scope | Boundary |
|------|------|----------|----------|
{elements:repeat:| {{item.name}} | {{item.__class__.__name__}} | {{item.inScope}} | {{item.inBoundary}} |
}

---

## Data Flows

| Name | From | To | Protocol | Port | Data |
|------|------|----|----------|------|------|
{dataflows:repeat:| {{item.name}} | {{item.source.name}} | {{item.sink.name}} | {{item.protocol}} | {{item.dstPort}} | {{item.data}} |
}

---

## Identified Threats

{findings:repeat:
### {{item.id}} - {{item.threat_id}}

**Target**: {{item.target}}

**Description**: {{item.description}}

**Severity**: {{item.severity}}

**Mitigations**: {{item.mitigations}}

**References**: {{item.references}}

---
}

## Threat Summary by Element

{elements:repeat:{{item.findings:if:
### {{item.name}}

{{item.findings:repeat:
- **{{{{item.threat_id}}}}**: {{{{item.description}}}} (Severity: {{{{item.severity}}}})
}}
}}}

---

## STRIDE Analysis Summary

This threat model covers the following STRIDE categories:

- **Spoofing**: Authentication bypass, credential theft
- **Tampering**: SQL injection, prompt injection, data manipulation
- **Repudiation**: Missing audit logs, anonymous access
- **Information Disclosure**: PII exposure, credential leakage in logs
- **Denial of Service**: Resource exhaustion, unlimited tool calls
- **Elevation of Privilege**: Agent tool abuse, lateral movement

---

*Report generated using pytm*
