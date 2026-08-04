from __future__ import annotations

from dataclasses import dataclass

import pytest

from security.hydra_immune import (
    HydraImmune,
    SecurityInputError,
    Threat,
    ThreatLevel,
    ThreatType,
)


@dataclass
class FakeClock:
    value: float = 1_000.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def hydra(clock: FakeClock) -> HydraImmune:
    return HydraImmune(clock=clock)


@pytest.mark.asyncio
async def test_initial_state_has_no_threats(hydra: HydraImmune) -> None:
    result = await hydra.tick({}, 1)

    assert result["active_threats"] == 0
    assert result["threat_level"] == ThreatLevel.NONE.name
    assert result["threat_level_value"] == ThreatLevel.NONE.value
    assert result["external_actions_executed"] == 0


@pytest.mark.asyncio
async def test_detection_proposes_but_does_not_claim_execution(
    hydra: HydraImmune,
) -> None:
    result = await hydra.tick({"zone-1": {"suspicious_activity": True}}, 1)

    assert result["active_threats"] == 1
    assert result["responses_proposed"] == 1
    assert result["resolutions_acknowledged"] == 0
    assert result["threat_level"] == ThreatLevel.HIGH.name
    assert result["actions"] == [
        {
            "action": "PROPOSE_RESPONSE",
            "executed": False,
            "requires_external_authority": True,
            "threat_id": "THREAT-1-zone-1",
            "threat_type": ThreatType.NETWORK_INTRUSION.value,
            "level": ThreatLevel.HIGH.name,
            "method": "BLOCK_IP",
        }
    ]
    assert hydra.threats[0].response_proposed is True
    assert hydra.threats[0].resolved is False


@pytest.mark.asyncio
async def test_replaying_the_same_tick_does_not_duplicate_threats(
    hydra: HydraImmune,
) -> None:
    zones = {"zone-1": {"suspicious_activity": True}}

    await hydra.tick(zones, 5)
    second = await hydra.tick(zones, 5)

    assert len(hydra.threats) == 1
    assert second["responses_proposed"] == 1
    assert second["actions"] == []


@pytest.mark.asyncio
async def test_auto_proposal_can_be_disabled(clock: FakeClock) -> None:
    engine = HydraImmune(auto_propose=False, clock=clock)

    result = await engine.tick({"zone-1": {"suspicious_activity": True}}, 1)

    assert result["active_threats"] == 1
    assert result["responses_proposed"] == 0
    assert result["actions"] == []


@pytest.mark.asyncio
async def test_low_severity_threat_stays_below_response_threshold(
    hydra: HydraImmune,
    clock: FakeClock,
) -> None:
    hydra.record_threat(
        Threat(
            "low-1",
            ThreatType.UNAUTHORIZED_ACCESS,
            ThreatLevel.LOW,
            "source",
            "target",
            timestamp=clock(),
        )
    )

    result = await hydra.tick({}, 1)

    assert result["active_threats"] == 1
    assert result["responses_proposed"] == 0
    assert result["threat_level"] == ThreatLevel.LOW.name


def test_record_threat_is_idempotent(hydra: HydraImmune, clock: FakeClock) -> None:
    threat = Threat(
        "T-1",
        ThreatType.FIRMWARE_TAMPER,
        ThreatLevel.CRITICAL,
        "source",
        "target",
        timestamp=clock(),
    )

    assert hydra.record_threat(threat) is True
    assert hydra.record_threat(threat) is False
    assert len(hydra.threats) == 1


@pytest.mark.asyncio
async def test_resolution_requires_external_receipt_and_changes_active_state(
    hydra: HydraImmune,
) -> None:
    await hydra.tick({"zone-1": {"suspicious_activity": True}}, 1)

    threat = hydra.mark_resolved("THREAT-1-zone-1", "incident:INC-42")

    assert threat.resolved is True
    assert threat.mitigated is True
    assert threat.resolution_ref == "incident:INC-42"
    assert hydra.summary()["active_threats"] == 0
    assert hydra.summary()["resolutions_acknowledged"] == 1
    assert hydra.summary()["threat_level"] == ThreatLevel.NONE.name


@pytest.mark.parametrize("resolution_ref", ["", "   "])
def test_resolution_rejects_empty_receipt(
    hydra: HydraImmune,
    clock: FakeClock,
    resolution_ref: str,
) -> None:
    hydra.record_threat(
        Threat(
            "T-1",
            ThreatType.PHYSICAL_BREACH,
            ThreatLevel.HIGH,
            "source",
            "target",
            timestamp=clock(),
        )
    )

    with pytest.raises(SecurityInputError, match="resolution_ref"):
        hydra.mark_resolved("T-1", resolution_ref)


def test_resolution_rejects_unknown_threat(hydra: HydraImmune) -> None:
    with pytest.raises(SecurityInputError, match="unknown threat id"):
        hydra.mark_resolved("missing", "incident:1")


@pytest.mark.asyncio
async def test_resolved_history_is_pruned_after_retention(
    clock: FakeClock,
) -> None:
    hydra = HydraImmune(clock=clock, resolved_retention_seconds=10)
    await hydra.tick({"zone-1": {"suspicious_activity": True}}, 1)
    hydra.mark_resolved("THREAT-1-zone-1", "incident:1")

    clock.advance(11)
    await hydra.tick({}, 2)

    assert hydra.threats == []


@pytest.mark.asyncio
async def test_unresolved_threat_is_not_silently_pruned(
    clock: FakeClock,
) -> None:
    hydra = HydraImmune(clock=clock, resolved_retention_seconds=10)
    await hydra.tick({"zone-1": {"suspicious_activity": True}}, 1)

    clock.advance(10_000)
    await hydra.tick({}, 2)

    assert len(hydra.threats) == 1
    assert hydra.threats[0].resolved is False


@pytest.mark.asyncio
async def test_active_threat_overflow_is_explicit(clock: FakeClock) -> None:
    hydra = HydraImmune(clock=clock, max_active_threats=1, auto_propose=False)

    result = await hydra.tick(
        {
            "zone-1": {"suspicious_activity": True},
            "zone-2": {"suspicious_activity": True},
        },
        1,
    )

    assert result["active_threats"] == 2
    assert result["anomalies"] == [
        {
            "type": "THREAT_OVERFLOW",
            "severity": ThreatLevel.CRITICAL.name,
            "detail": "2 unresolved threats exceed configured limit 1",
        }
    ]


@pytest.mark.parametrize(
    "threat_type,expected",
    [
        (ThreatType.NETWORK_INTRUSION, "BLOCK_IP"),
        (ThreatType.UNAUTHORIZED_ACCESS, "REVOKE_CREDENTIALS"),
        (ThreatType.DATA_EXFILTRATION, "BLOCK_EGRESS"),
        (ThreatType.FIRMWARE_TAMPER, "ROLLBACK_FIRMWARE"),
        (ThreatType.PHYSICAL_BREACH, "LOCKDOWN_ZONE"),
        (ThreatType.DDOS, "RATE_LIMIT"),
        (ThreatType.CRYPTO_MINING, "KILL_PROCESS"),
        (ThreatType.SUPPLY_CHAIN, "ISOLATE_COMPONENT"),
    ],
)
def test_response_method_is_deterministic(
    threat_type: ThreatType,
    expected: str,
) -> None:
    assert HydraImmune.response_method(threat_type) == expected


@pytest.mark.parametrize(
    "kwargs,message",
    [
        ({"response_threshold": -0.1}, "response_threshold"),
        ({"response_threshold": 1.1}, "response_threshold"),
        ({"max_active_threats": 0}, "max_active_threats"),
        ({"resolved_retention_seconds": -1}, "resolved_retention_seconds"),
    ],
)
def test_invalid_configuration_fails_closed(kwargs: dict, message: str) -> None:
    with pytest.raises(SecurityInputError, match=message):
        HydraImmune(**kwargs)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "zones,tick_num,message",
    [
        ([], 1, "zones must be a mapping"),
        ({"": {}}, 1, "zone ids"),
        ({"zone-1": []}, 1, "data must be a mapping"),
        ({}, -1, "tick_num"),
    ],
)
async def test_invalid_tick_inputs_fail_closed(zones, tick_num, message: str) -> None:
    with pytest.raises(SecurityInputError, match=message):
        await HydraImmune().tick(zones, tick_num)


def test_threat_severity_and_compatibility_alias(clock: FakeClock) -> None:
    threat = Threat(
        "T-1",
        ThreatType.NETWORK_INTRUSION,
        ThreatLevel.HIGH,
        "source",
        "target",
        timestamp=clock(),
    )

    assert threat.severity_score == 0.75
    assert threat.mitigated is False
    threat.mitigated = True
    assert threat.resolved is True
