#!/usr/bin/env python3
"""
COLOSSUS ACCESS CONTROL — RBAC Engine
Role-Based Access Control for zero-trust GPU cluster environments.

Roles: OPERATOR, ADMIN, READONLY, AUDITOR
Policies: resource-scoped, time-bounded, MFA-enforced for privileged ops
"""

from __future__ import annotations
import hashlib
import time
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from enum import Enum

logger = logging.getLogger("COLOSSUS.ACCESS_CONTROL")


class Role(Enum):
    READONLY  = "readonly"
    AUDITOR   = "auditor"
    OPERATOR  = "operator"
    ADMIN     = "admin"


class Resource(Enum):
    GPU_NODE       = "gpu_node"
    POWER_GRID     = "power_grid"
    COOLING_SYSTEM = "cooling_system"
    NETWORK_FABRIC = "network_fabric"
    AUDIT_LOGS     = "audit_logs"
    KEY_VAULT      = "key_vault"
    EMISSION_DATA  = "emission_data"


class Action(Enum):
    READ    = "read"
    WRITE   = "write"
    EXECUTE = "execute"
    DELETE  = "delete"


# Policy table: role -> {resource -> allowed_actions}
POLICY_TABLE: Dict[Role, Dict[Resource, Set[Action]]] = {
    Role.READONLY: {
        Resource.GPU_NODE:       {Action.READ},
        Resource.POWER_GRID:     {Action.READ},
        Resource.COOLING_SYSTEM: {Action.READ},
        Resource.NETWORK_FABRIC: {Action.READ},
        Resource.EMISSION_DATA:  {Action.READ},
    },
    Role.AUDITOR: {
        Resource.GPU_NODE:       {Action.READ},
        Resource.POWER_GRID:     {Action.READ},
        Resource.COOLING_SYSTEM: {Action.READ},
        Resource.NETWORK_FABRIC: {Action.READ},
        Resource.AUDIT_LOGS:     {Action.READ},
        Resource.EMISSION_DATA:  {Action.READ},
    },
    Role.OPERATOR: {
        Resource.GPU_NODE:       {Action.READ, Action.WRITE, Action.EXECUTE},
        Resource.POWER_GRID:     {Action.READ, Action.WRITE},
        Resource.COOLING_SYSTEM: {Action.READ, Action.WRITE},
        Resource.NETWORK_FABRIC: {Action.READ, Action.WRITE},
        Resource.AUDIT_LOGS:     {Action.READ},
        Resource.EMISSION_DATA:  {Action.READ, Action.WRITE},
    },
    Role.ADMIN: {
        r: {Action.READ, Action.WRITE, Action.EXECUTE, Action.DELETE}
        for r in Resource
    },
}

# Resources requiring MFA even when role allows
MFA_REQUIRED_RESOURCES: Set[Resource] = {
    Resource.KEY_VAULT,
    Resource.POWER_GRID,
    Resource.NETWORK_FABRIC,
}


@dataclass
class Principal:
    """Represents an authenticated entity requesting access."""
    subject_id: str
    role: Role
    mfa_verified: bool = False
    valid_until: float = field(default_factory=lambda: time.time() + 3600)
    clearance_level: int = 1

    def is_session_valid(self) -> bool:
        return time.time() < self.valid_until


@dataclass
class AccessRequest:
    principal: Principal
    resource: Resource
    action: Action
    context: Optional[Dict] = None


@dataclass
class AccessDecision:
    allowed: bool
    reason: str
    policy_match: Optional[str] = None
    requires_mfa: bool = False


class RBACEngine:
    """
    Evaluates access requests against POLICY_TABLE.
    Enforces MFA requirements for privileged resources.
    All decisions are logged for audit trail.
    """

    def __init__(self):
        self._decision_log: List[Dict] = []

    def evaluate(self, request: AccessRequest) -> AccessDecision:
        principal = request.principal
        resource  = request.resource
        action    = request.action

        # Session validity
        if not principal.is_session_valid():
            decision = AccessDecision(
                allowed=False,
                reason="Session expired",
            )
            self._log(request, decision)
            return decision

        # Role policy lookup
        role_policy = POLICY_TABLE.get(principal.role, {})
        allowed_actions = role_policy.get(resource, set())

        if action not in allowed_actions:
            decision = AccessDecision(
                allowed=False,
                reason=f"Role {principal.role.value} does not permit {action.value} on {resource.value}",
            )
            self._log(request, decision)
            return decision

        # MFA gate for privileged resources
        if resource in MFA_REQUIRED_RESOURCES and not principal.mfa_verified:
            decision = AccessDecision(
                allowed=False,
                reason=f"{resource.value} requires MFA verification",
                requires_mfa=True,
            )
            self._log(request, decision)
            return decision

        decision = AccessDecision(
            allowed=True,
            reason="Policy match",
            policy_match=f"{principal.role.value}:{resource.value}:{action.value}",
        )
        self._log(request, decision)
        return decision

    def _log(self, request: AccessRequest, decision: AccessDecision):
        entry = {
            "ts": time.time(),
            "subject": request.principal.subject_id,
            "role":    request.principal.role.value,
            "resource": request.resource.value,
            "action":   request.action.value,
            "allowed":  decision.allowed,
            "reason":   decision.reason,
        }
        self._decision_log.append(entry)
        level = logging.INFO if decision.allowed else logging.WARNING
        logger.log(level, "ACCESS %s | %s",
                   "GRANTED" if decision.allowed else "DENIED", entry)

    def get_audit_trail(self) -> List[Dict]:
        return list(self._decision_log)

    def clear_audit_trail(self):
        self._decision_log.clear()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(message)s")

    engine = RBACEngine()

    op = Principal(subject_id="operator-01", role=Role.OPERATOR, mfa_verified=True)
    ro = Principal(subject_id="readonly-77", role=Role.READONLY, mfa_verified=False)
    admin = Principal(subject_id="admin-00",  role=Role.ADMIN,    mfa_verified=True)

    tests = [
        (op,    Resource.GPU_NODE,       Action.EXECUTE),  # GRANT
        (ro,    Resource.GPU_NODE,       Action.WRITE),    # DENY — role
        (op,    Resource.KEY_VAULT,      Action.READ),     # DENY — MFA not set on op
        (admin, Resource.KEY_VAULT,      Action.WRITE),    # GRANT — admin + MFA
        (ro,    Resource.AUDIT_LOGS,     Action.READ),     # DENY — role
    ]
    for principal, resource, action in tests:
        d = engine.evaluate(AccessRequest(principal, resource, action))
        print(f"  {'✅' if d.allowed else '❌'}  {principal.subject_id} | {resource.value} | {action.value} → {d.reason}")
