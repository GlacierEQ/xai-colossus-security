# xAI Colossus 2 — Master Security Policy
**GlacierEQ APEX Stack | APEX Architecture**
**Classification:** INTERNAL — Infrastructure Security

---

## 1. Governing Principles

1. **Zero Trust**: No implicit trust at any boundary — network, physical, or agent.
2. **Least Privilege**: Every identity gets minimum permissions required and nothing more.
3. **Audit Immutability**: Audit logs are append-only, cryptographically signed, tamper-evident.
4. **Defense in Depth**: Every layer (physical, network, application, agent) has independent controls.
5. **Fail Secure**: All failures default to locked/offline state, never open.

---

## 2. Access Tiers

| Tier | Label | Access Scope | Example Identities |
|---|---|---|---|
| T0 | APEX-OPERATOR | Full read/write all systems | Casey Barton (human operator) |
| T1 | DOMAIN-ADMIN | Full access within one domain repo | Domain lead agents |
| T2 | AGENT-STANDARD | Read + execute within assigned tasks | Cooling agents, telemetry agents |
| T3 | AUDIT-ONLY | Read audit logs only | Aspen Grove audit layer |
| T4 | EXTERNAL | Zero access — deny by default | Any unregistered identity |

---

## 3. Physical Security Zones

| Zone | Description | Access Required |
|---|---|---|
| PERIMETER | Outer fence line | Badge + biometric |
| OPERATIONS | Control room and offices | Badge + PIN |
| COMPUTE | Server halls, rack rows | Badge + MFA + escort |
| CRITICAL | Power/cooling plant cores | Dual-person + badge |
| NETWORK | Core switch/router rooms | T0/T1 only |

---

## 4. Incident Severity Levels

| Level | Label | Response Time | Action |
|---|---|---|---|
| P0 | CRITICAL | Immediate | Full lockdown, notify operator, isolate affected zone |
| P1 | HIGH | < 15 min | Contain, alert domain admin, begin root cause |
| P2 | MEDIUM | < 1 hr | Log, assign, remediate within 24h |
| P3 | LOW | < 24 hr | Log and schedule |

---

## 5. Forbidden Actions (Hard Rules)

- FORBID: Any agent modifying its own audit log
- FORBID: Any shared credentials between compute zones
- FORBID: Any physical access without logged badge scan
- FORBID: Any network path from EXTERNAL → COMPUTE without explicit policy rule
- FORBID: Any secrets stored in plaintext in any repo file

---

*Policy owner: APEX-OPERATOR (Casey Barton)*
*Last updated: 2026-05-28*
