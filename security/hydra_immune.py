#!/usr/bin/env python3
"""Bounded threat classification and response-proposal engine.

The engine detects declared suspicious zone signals, records threats, proposes
response methods, and requires an explicit external resolution receipt before a
threat is considered resolved. It does not execute network, credential,
firmware, physical, process, or supply-chain mutations.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from math import isfinite
from typing import Any


class SecurityInputError(ValueError):
    """Raised when security events or engine configuration are invalid."""


class ThreatLevel(Enum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class ThreatType(Enum):
    NETWORK_INTRUSION = "network_intrusion"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DATA_EXFILTRATION = "data_exfiltration"
    FIRMWARE_TAMPER = "firmware_tamper"
    PHYSICAL_BREACH = "physical_breach"
    DDOS = "ddos"
    CRYPTO_MINING = "crypto_mining"
    SUPPLY_CHAIN = "supply_chain"

    # Backward-compatible aliases for historical callers.
    DDoS = "ddos"
    supply_chain = "supply_chain"


@dataclass(slots=True)
class Threat:
    threat_id: str
    threat_type: ThreatType
    level: ThreatLevel
    source: str
    target: str
    timestamp: float = field(default_factory=time.time)
    details: str = ""
    response_proposed: bool = False
    resolved: bool = False
    resolution_ref: str | None = None
    resolved_at: float | None = None

    def __post_init__(self) -> None:
        for field_name, value in (
            ("threat_id", self.threat_id),
            ("source", self.source),
            ("target", self.target),
        ):
            if not isinstance(value, str) or not value.strip():
                raise SecurityInputError(f"{field_name} must be a non-empty string")
        if not isinstance(self.threat_type, ThreatType):
            raise SecurityInputError("threat_type must be a ThreatType")
        if not isinstance(self.level, ThreatLevel):
            raise SecurityInputError("level must be a ThreatLevel")
        if not isfinite(self.timestamp) or self.timestamp < 0:
            raise SecurityInputError("timestamp must be finite and non-negative")

    @property
    def severity_score(self) -> float:
        return self.level.value / ThreatLevel.CRITICAL.value

    @property
    def mitigated(self) -> bool:
        """Compatibility alias: only externally acknowledged resolution counts."""

        return self.resolved

    @mitigated.setter
    def mitigated(self, value: bool) -> None:
        self.resolved = bool(value)


@dataclass
class HydraImmune:
    """Detect threats and propose bounded responses without external mutation."""

    response_threshold: float = 0.7
    max_active_threats: int = 100
    auto_propose: bool = True
    resolved_retention_seconds: float = 3600.0
    clock: Callable[[], float] = field(default=time.time, repr=False)

    threats: list[Threat] = field(default_factory=list)
    response_proposed_count: int = 0
    resolution_count: int = 0
    tick_count: int = 0
    anomalies: list[dict[str, Any]] = field(default_factory=list)
    actions: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not isfinite(self.response_threshold) or not 0.0 <= self.response_threshold <= 1.0:
            raise SecurityInputError("response_threshold must be between 0.0 and 1.0")
        if not isinstance(self.max_active_threats, int) or isinstance(self.max_active_threats, bool):
            raise SecurityInputError("max_active_threats must be an integer")
        if self.max_active_threats < 1:
            raise SecurityInputError("max_active_threats must be at least 1")
        if not isfinite(self.resolved_retention_seconds) or self.resolved_retention_seconds < 0:
            raise SecurityInputError(
                "resolved_retention_seconds must be finite and non-negative"
            )
        if not callable(self.clock):
            raise SecurityInputError("clock must be callable")

    async def tick(
        self,
        zones: Mapping[str, Mapping[str, Any]],
        tick_num: int,
    ) -> dict[str, Any]:
        """Process one declared zone snapshot and return bounded evidence."""

        if not isinstance(tick_num, int) or isinstance(tick_num, bool) or tick_num < 0:
            raise SecurityInputError("tick_num must be a non-negative integer")
        if not isinstance(zones, Mapping):
            raise SecurityInputError("zones must be a mapping")

        self.tick_count = tick_num
        self.anomalies = []
        self.actions = []

        for threat in self._scan_threats(zones):
            self.record_threat(threat)

        if self.auto_propose:
            self._propose_responses()

        self._prune_resolved_history()
        active = self.active_threats()

        if len(active) > self.max_active_threats:
            self.anomalies.append(
                {
                    "type": "THREAT_OVERFLOW",
                    "severity": ThreatLevel.CRITICAL.name,
                    "detail": (
                        f"{len(active)} unresolved threats exceed configured limit "
                        f"{self.max_active_threats}"
                    ),
                }
            )

        level = self.current_threat_level()
        return {
            "anomalies": list(self.anomalies),
            "actions": list(self.actions),
            "active_threats": len(active),
            "responses_proposed": self.response_proposed_count,
            "resolutions_acknowledged": self.resolution_count,
            "threat_level": level.name,
            "threat_level_value": level.value,
            "external_actions_executed": 0,
        }

    def record_threat(self, threat: Threat) -> bool:
        """Record a unique threat. Duplicate threat ids are ignored deterministically."""

        if not isinstance(threat, Threat):
            raise SecurityInputError("threat must be a Threat instance")
        if any(existing.threat_id == threat.threat_id for existing in self.threats):
            return False
        self.threats.append(threat)
        return True

    def mark_resolved(self, threat_id: str, resolution_ref: str) -> Threat:
        """Acknowledge resolution only when an external receipt is supplied."""

        if not isinstance(threat_id, str) or not threat_id.strip():
            raise SecurityInputError("threat_id must be a non-empty string")
        if not isinstance(resolution_ref, str) or not resolution_ref.strip():
            raise SecurityInputError("resolution_ref must be a non-empty string")

        for threat in self.threats:
            if threat.threat_id != threat_id:
                continue
            if not threat.resolved:
                threat.resolved = True
                threat.resolution_ref = resolution_ref
                threat.resolved_at = self.clock()
                self.resolution_count += 1
            return threat

        raise SecurityInputError(f"unknown threat id: {threat_id}")

    def active_threats(self) -> list[Threat]:
        return [threat for threat in self.threats if not threat.resolved]

    def current_threat_level(self) -> ThreatLevel:
        active = self.active_threats()
        if not active:
            return ThreatLevel.NONE
        return ThreatLevel(max(threat.level.value for threat in active))

    def _scan_threats(
        self,
        zones: Mapping[str, Mapping[str, Any]],
    ) -> list[Threat]:
        detected: list[Threat] = []
        for zone_id, zone_data in zones.items():
            if not isinstance(zone_id, str) or not zone_id.strip():
                raise SecurityInputError("zone ids must be non-empty strings")
            if not isinstance(zone_data, Mapping):
                raise SecurityInputError(f"zone {zone_id} data must be a mapping")
            if zone_data.get("suspicious_activity") is True:
                detected.append(
                    Threat(
                        threat_id=f"THREAT-{self.tick_count}-{zone_id}",
                        threat_type=ThreatType.NETWORK_INTRUSION,
                        level=ThreatLevel.HIGH,
                        source=f"zone:{zone_id}",
                        target="network",
                        timestamp=self.clock(),
                        details=f"Declared suspicious activity in {zone_id}",
                    )
                )
        return detected

    def _propose_responses(self) -> None:
        for threat in self.active_threats():
            if threat.response_proposed:
                continue
            if threat.severity_score < self.response_threshold:
                continue

            threat.response_proposed = True
            self.response_proposed_count += 1
            self.actions.append(
                {
                    "action": "PROPOSE_RESPONSE",
                    "executed": False,
                    "requires_external_authority": True,
                    "threat_id": threat.threat_id,
                    "threat_type": threat.threat_type.value,
                    "level": threat.level.name,
                    "method": self.response_method(threat.threat_type),
                }
            )

    @staticmethod
    def response_method(threat_type: ThreatType) -> str:
        methods = {
            ThreatType.NETWORK_INTRUSION: "BLOCK_IP",
            ThreatType.UNAUTHORIZED_ACCESS: "REVOKE_CREDENTIALS",
            ThreatType.DATA_EXFILTRATION: "BLOCK_EGRESS",
            ThreatType.FIRMWARE_TAMPER: "ROLLBACK_FIRMWARE",
            ThreatType.PHYSICAL_BREACH: "LOCKDOWN_ZONE",
            ThreatType.DDOS: "RATE_LIMIT",
            ThreatType.CRYPTO_MINING: "KILL_PROCESS",
            ThreatType.SUPPLY_CHAIN: "ISOLATE_COMPONENT",
        }
        if not isinstance(threat_type, ThreatType):
            raise SecurityInputError("threat_type must be a ThreatType")
        return methods[threat_type]

    def _prune_resolved_history(self) -> None:
        cutoff = self.clock() - self.resolved_retention_seconds
        self.threats = [
            threat
            for threat in self.threats
            if not (
                threat.resolved
                and threat.resolved_at is not None
                and threat.resolved_at < cutoff
            )
        ]

    def summary(self) -> dict[str, Any]:
        active = self.active_threats()
        return {
            "threat_level": self.current_threat_level().name,
            "active_threats": len(active),
            "total_threats": len(self.threats),
            "responses_proposed": self.response_proposed_count,
            "resolutions_acknowledged": self.resolution_count,
            "external_actions_executed": 0,
            "threat_breakdown": {
                threat_type.value: sum(
                    1
                    for threat in active
                    if threat.threat_type is threat_type
                )
                for threat_type in ThreatType
            },
            "tick_count": self.tick_count,
        }
