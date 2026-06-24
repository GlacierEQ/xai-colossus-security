#!/usr/bin/env python3
"""
COLOSSUS ACCESS CONTROL — Zone-Based Rack Policy Engine
========================================================
Enforces rack-level access policies with RBAC integration,
time-based access windows, and emergency override capability.

Zero-trust model: every access request is evaluated against the
full policy stack (role → zone → time → MFA → emergency) before
a decision is rendered. No implicit trust.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set

logger = logging.getLogger("COLOSSUS.RACK_POLICY")


# ---------------------------------------------------------------------------
# RBAC primitives (mirrors rbac_engine.py types for zero cross-dir imports)
# ---------------------------------------------------------------------------

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

MFA_REQUIRED_RESOURCES: Set[Resource] = {
    Resource.KEY_VAULT,
    Resource.POWER_GRID,
    Resource.NETWORK_FABRIC,
}


@dataclass
class Principal:
    subject_id: str
    role: Role
    mfa_verified: bool = False
    valid_until: float = field(default_factory=lambda: time.time() + 3600)
    clearance_level: int = 1

    def is_session_valid(self) -> bool:
        return time.time() < self.valid_until


@dataclass
class RBACDecision:
    allowed: bool
    reason: str
    policy_match: Optional[str] = None
    requires_mfa: bool = False


class RBACEngine:
    """Inline RBAC evaluator for rack policy decisions."""

    def __init__(self) -> None:
        self._decision_log: List[Dict] = []

    def evaluate(self, principal: Principal, resource: Resource, action: Action) -> RBACDecision:
        if not principal.is_session_valid():
            d = RBACDecision(allowed=False, reason="Session expired")
            self._log(principal, resource, action, d)
            return d

        allowed_actions = POLICY_TABLE.get(principal.role, {}).get(resource, set())
        if action not in allowed_actions:
            d = RBACDecision(
                allowed=False,
                reason=f"Role {principal.role.value} does not permit {action.value} on {resource.value}",
            )
            self._log(principal, resource, action, d)
            return d

        if resource in MFA_REQUIRED_RESOURCES and not principal.mfa_verified:
            d = RBACDecision(
                allowed=False,
                reason=f"{resource.value} requires MFA verification",
                requires_mfa=True,
            )
            self._log(principal, resource, action, d)
            return d

        d = RBACDecision(
            allowed=True,
            reason="Policy match",
            policy_match=f"{principal.role.value}:{resource.value}:{action.value}",
        )
        self._log(principal, resource, action, d)
        return d

    def _log(
        self, principal: Principal, resource: Resource, action: Action, decision: RBACDecision,
    ) -> None:
        self._decision_log.append({
            "ts": time.time(),
            "subject": principal.subject_id,
            "role": principal.role.value,
            "resource": resource.value,
            "action": action.value,
            "allowed": decision.allowed,
            "reason": decision.reason,
        })


# ---------------------------------------------------------------------------
# Zone taxonomy
# ---------------------------------------------------------------------------

class Zone(Enum):
    COMPUTE_FLOOR  = "compute_floor"
    POWER_RING     = "power_ring"
    COOLING_MAZE   = "cooling_maze"
    NETWORK_NOC    = "network_noc"
    VAULT_BAY      = "vault_bay"
    STAGING_DOCK   = "staging_dock"
    CONTROL_ROOM   = "control_room"


ZONE_SENSITIVITY: Dict[Zone, int] = {
    Zone.COMPUTE_FLOOR: 3,
    Zone.POWER_RING:    5,
    Zone.COOLING_MAZE:  3,
    Zone.NETWORK_NOC:   4,
    Zone.VAULT_BAY:     5,
    Zone.STAGING_DOCK:  2,
    Zone.CONTROL_ROOM:  4,
}


ZONE_TO_RESOURCE: Dict[Zone, Resource] = {
    Zone.COMPUTE_FLOOR: Resource.GPU_NODE,
    Zone.POWER_RING:    Resource.POWER_GRID,
    Zone.COOLING_MAZE:  Resource.COOLING_SYSTEM,
    Zone.NETWORK_NOC:   Resource.NETWORK_FABRIC,
    Zone.VAULT_BAY:     Resource.KEY_VAULT,
    Zone.STAGING_DOCK:  Resource.EMISSION_DATA,
    Zone.CONTROL_ROOM:  Resource.AUDIT_LOGS,
}


class DayOfWeek(Enum):
    MON = 0
    TUE = 1
    WED = 2
    THU = 3
    FRI = 4
    SAT = 5
    SUN = 6


# ---------------------------------------------------------------------------
# Access window & policy data
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AccessWindow:
    allowed_days: frozenset[DayOfWeek]
    start_hour: int
    end_hour: int

    def is_within_window(self, dt: Optional[datetime] = None) -> bool:
        dt = dt or datetime.now(timezone.utc)
        if DayOfWeek(dt.weekday()) not in self.allowed_days:
            return False
        if self.start_hour <= self.end_hour:
            return self.start_hour <= dt.hour < self.end_hour
        return dt.hour >= self.start_hour or dt.hour < self.end_hour


@dataclass(frozen=True)
class EmergencyOverridePolicy:
    enabled: bool = True
    required_role: Role = Role.ADMIN
    max_duration_sec: float = 3600.0
    requires_justification: bool = True
    auto_revoke: bool = True


@dataclass
class ZonePolicy:
    zone: Zone
    minimum_clearance: int
    allowed_roles: frozenset[Role]
    access_window: AccessWindow
    mfa_required: bool = True
    max_concurrent_occupants: int = 10
    current_occupants: int = 0


@dataclass(frozen=True)
class RackZone:
    rack_id: str
    zone: Zone
    label: str = ""


# ---------------------------------------------------------------------------
# Emergency override record
# ---------------------------------------------------------------------------

@dataclass
class EmergencyOverrideRecord:
    override_id: str
    principal_id: str
    zone: Zone
    granted_at: float
    expires_at: float
    justification: str
    revoked: bool = False
    revoked_at: Optional[float] = None


# ---------------------------------------------------------------------------
# Decision type
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RackAccessDecision:
    allowed: bool
    reason: str
    zone: Zone
    rack_id: str
    role_check: bool = False
    time_check: bool = False
    occupancy_check: bool = False
    emergency_override: bool = False
    requires_mfa: bool = False


# ---------------------------------------------------------------------------
# RackPolicyEngine
# ---------------------------------------------------------------------------

class RackPolicyEngine:
    """
    Evaluates rack-level physical access requests against a multi-layer
    policy stack:

        1. RBAC role + resource permission
        2. Zone clearance level
        3. Time-based access window
        4. Occupancy limits
        5. MFA gate
        6. Emergency override (admin-only, time-bounded)

    Every decision is logged with full context for audit trail.
    """

    def __init__(
        self,
        rbac: Optional[RBACEngine] = None,
        override_policy: Optional[EmergencyOverridePolicy] = None,
        clock: Optional[Callable[[], float]] = None,
    ):
        self._rbac = rbac or RBACEngine()
        self._override_policy = override_policy or EmergencyOverridePolicy()
        self._clock = clock or time.time
        self._zone_policies: Dict[Zone, ZonePolicy] = {}
        self._rack_map: Dict[str, RackZone] = {}
        self._active_overrides: List[EmergencyOverrideRecord] = []
        self._decision_log: List[Dict[str, Any]] = []

    def register_zone_policy(self, policy: ZonePolicy) -> None:
        self._zone_policies[policy.zone] = policy

    def register_rack(self, rack: RackZone) -> None:
        self._rack_map[rack.rack_id] = rack

    def register_default_policies(self) -> None:
        for zone, sensitivity in ZONE_SENSITIVITY.items():
            self.register_zone_policy(ZonePolicy(
                zone=zone,
                minimum_clearance=sensitivity,
                allowed_roles=frozenset(Role),
                access_window=AccessWindow(
                    allowed_days=frozenset([DayOfWeek(d) for d in range(5)]),
                    start_hour=6,
                    end_hour=22,
                ),
                mfa_required=sensitivity >= 4,
                max_concurrent_occupants=20,
            ))

    def evaluate(
        self,
        principal: Principal,
        rack_id: str,
        action: Action = Action.READ,
        now: Optional[datetime] = None,
    ) -> RackAccessDecision:
        rack = self._rack_map.get(rack_id)
        if rack is None:
            decision = RackAccessDecision(
                allowed=False,
                reason=f"Unknown rack: {rack_id}",
                zone=Zone.COMPUTE_FLOOR,
                rack_id=rack_id,
            )
            self._log_decision(principal, decision)
            return decision

        zone = rack.zone
        policy = self._zone_policies.get(zone)
        if policy is None:
            decision = RackAccessDecision(
                allowed=False,
                reason=f"No policy defined for zone {zone.value}",
                zone=zone,
                rack_id=rack_id,
            )
            self._log_decision(principal, decision)
            return decision

        # 1. RBAC
        resource = ZONE_TO_RESOURCE.get(zone, Resource.GPU_NODE)
        rbac_ok = self._rbac.evaluate(principal, resource, action).allowed
        if not rbac_ok:
            decision = RackAccessDecision(
                allowed=False,
                reason=f"RBAC denied: role {principal.role.value} cannot {action.value} on {resource.value}",
                zone=zone,
                rack_id=rack_id,
                role_check=False,
            )
            self._log_decision(principal, decision)
            return decision

        # 2. Zone clearance
        if principal.clearance_level < policy.minimum_clearance:
            override = self._try_emergency_override(principal, zone, rack_id)
            if override is not None:
                self._log_decision(principal, override)
                return override
            decision = RackAccessDecision(
                allowed=False,
                reason=(
                    f"Clearance {principal.clearance_level} < "
                    f"minimum {policy.minimum_clearance} for {zone.value}"
                ),
                zone=zone,
                rack_id=rack_id,
                role_check=True,
            )
            self._log_decision(principal, decision)
            return decision

        # 3. Time window
        dt = now or datetime.now(timezone.utc)
        if not policy.access_window.is_within_window(dt):
            override = self._try_emergency_override(principal, zone, rack_id)
            if override is not None:
                self._log_decision(principal, override)
                return override
            decision = RackAccessDecision(
                allowed=False,
                reason=(
                    f"Outside access window ({policy.access_window.start_hour}:00–"
                    f"{policy.access_window.end_hour}:00) for {zone.value}"
                ),
                zone=zone,
                rack_id=rack_id,
                role_check=True,
            )
            self._log_decision(principal, decision)
            return decision

        # 4. Occupancy
        if policy.current_occupants >= policy.max_concurrent_occupants:
            decision = RackAccessDecision(
                allowed=False,
                reason=(
                    f"Zone {zone.value} at capacity "
                    f"({policy.current_occupants}/{policy.max_concurrent_occupants})"
                ),
                zone=zone,
                rack_id=rack_id,
                role_check=True,
                time_check=True,
                occupancy_check=False,
            )
            self._log_decision(principal, decision)
            return decision

        # 5. MFA
        if policy.mfa_required and not principal.mfa_verified:
            decision = RackAccessDecision(
                allowed=False,
                reason=f"MFA required for {zone.value} but not verified",
                zone=zone,
                rack_id=rack_id,
                role_check=True,
                time_check=True,
                occupancy_check=True,
                requires_mfa=True,
            )
            self._log_decision(principal, decision)
            return decision

        # All checks passed
        decision = RackAccessDecision(
            allowed=True,
            reason="All policy checks passed",
            zone=zone,
            rack_id=rack_id,
            role_check=True,
            time_check=True,
            occupancy_check=True,
        )
        self._log_decision(principal, decision)
        return decision

    # ------------------------------------------------------------------
    # Emergency override
    # ------------------------------------------------------------------

    def grant_emergency_override(
        self,
        principal: Principal,
        zone: Zone,
        justification: str,
    ) -> Optional[EmergencyOverrideRecord]:
        op = self._override_policy
        if not op.enabled:
            return None
        if principal.role != op.required_role:
            return None
        if not principal.mfa_verified:
            return None
        if not justification.strip():
            return None

        now = self._clock()
        record = EmergencyOverrideRecord(
            override_id=f"EOVR-{int(now)}-{zone.value[:4].upper()}",
            principal_id=principal.subject_id,
            zone=zone,
            granted_at=now,
            expires_at=now + op.max_duration_sec,
            justification=justification,
        )
        self._active_overrides.append(record)
        logger.warning(
            "EMERGENCY OVERRIDE GRANTED: %s by %s for %s (expires in %.0fs)",
            record.override_id, principal.subject_id,
            zone.value, op.max_duration_sec,
        )
        return record

    def revoke_emergency_override(self, override_id: str) -> bool:
        for rec in self._active_overrides:
            if rec.override_id == override_id and not rec.revoked:
                rec.revoked = True
                rec.revoked_at = self._clock()
                logger.warning("EMERGENCY OVERRIDE REVOKED: %s", override_id)
                return True
        return False

    def _try_emergency_override(
        self,
        principal: Principal,
        zone: Zone,
        rack_id: str,
    ) -> Optional[RackAccessDecision]:
        now = self._clock()
        for rec in self._active_overrides:
            if rec.zone == zone and not rec.revoked and now < rec.expires_at:
                return RackAccessDecision(
                    allowed=True,
                    reason=f"Emergency override {rec.override_id} active",
                    zone=zone,
                    rack_id=rack_id,
                    role_check=True,
                    time_check=True,
                    occupancy_check=True,
                    emergency_override=True,
                )
        return None

    def cleanup_expired_overrides(self) -> int:
        now = self._clock()
        revoked = 0
        for rec in self._active_overrides:
            if not rec.revoked and now >= rec.expires_at:
                rec.revoked = True
                rec.revoked_at = now
                revoked += 1
        return revoked

    # ------------------------------------------------------------------
    # Occupancy tracking
    # ------------------------------------------------------------------

    def enter_zone(self, zone: Zone) -> bool:
        policy = self._zone_policies.get(zone)
        if policy is None:
            return False
        if policy.current_occupants >= policy.max_concurrent_occupants:
            return False
        policy.current_occupants += 1
        return True

    def exit_zone(self, zone: Zone) -> bool:
        policy = self._zone_policies.get(zone)
        if policy is None or policy.current_occupants <= 0:
            return False
        policy.current_occupants -= 1
        return True

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def get_audit_trail(self) -> List[Dict[str, Any]]:
        return list(self._decision_log)

    def get_active_overrides(self) -> List[EmergencyOverrideRecord]:
        now = self._clock()
        return [r for r in self._active_overrides if not r.revoked and now < r.expires_at]

    def _log_decision(self, principal: Principal, decision: RackAccessDecision) -> None:
        entry = {
            "ts": self._clock(),
            "subject": principal.subject_id,
            "role": principal.role.value,
            "zone": decision.zone.value,
            "rack": decision.rack_id,
            "allowed": decision.allowed,
            "reason": decision.reason,
            "emergency_override": decision.emergency_override,
        }
        self._decision_log.append(entry)
        level = logging.INFO if decision.allowed else logging.WARNING
        logger.log(level, "RACK_ACCESS %s | %s", "GRANTED" if decision.allowed else "DENIED", entry)


# ---------------------------------------------------------------------------
# CLI smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    engine = RackPolicyEngine()
    engine.register_default_policies()

    engine.register_rack(RackZone("RACK-A1", Zone.COMPUTE_FLOOR, "GPU Row A"))
    engine.register_rack(RackZone("RACK-P1", Zone.POWER_RING,    "Megapack Ring"))
    engine.register_rack(RackZone("RACK-V1", Zone.VAULT_BAY,     "Key Vault"))

    op = Principal(subject_id="operator-01", role=Role.OPERATOR, mfa_verified=True, clearance_level=3)
    admin = Principal(subject_id="admin-00", role=Role.ADMIN, mfa_verified=True, clearance_level=5)
    ro = Principal(subject_id="readonly-77", role=Role.READONLY, mfa_verified=False, clearance_level=1)

    print("\n--- Rack Policy Engine Test ---")
    for principal, rack, action in [
        (op,    "RACK-A1", Action.READ),
        (op,    "RACK-P1", Action.READ),
        (ro,    "RACK-A1", Action.READ),
        (ro,    "RACK-V1", Action.READ),
        (admin, "RACK-V1", Action.WRITE),
    ]:
        d = engine.evaluate(principal, rack, action)
        print(f"  {'✅' if d.allowed else '❌'}  {principal.subject_id} | {rack} | {action.value} → {d.reason}")

    print(f"\nAudit trail: {len(engine.get_audit_trail())} entries")
