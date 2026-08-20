"""Integration-contract tests for the public Security composition package."""

import asyncio
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from xai_colossus_security import (
    ColossusSecurityAdapter,
    HydraImmune,
    SecurityAdapterInputError,
    ThreatLevel,
)


@dataclass
class FakeClock:
    value: float = 10_000.0

    def __call__(self) -> float:
        return self.value


def test_adapter_maps_declared_suspicion_to_hydra_without_external_action() -> None:
    adapter = ColossusSecurityAdapter(engine=HydraImmune(clock=FakeClock()))

    receipt = asyncio.run(
        adapter.analyze_traffic_patterns(
            [
                {
                    "node_id": "node-hot",
                    "zone_id": "ZONE-A",
                    "entropy": 0.97,
                    "suspicious_activity": True,
                },
                {
                    "node_id": "node-calm",
                    "zone_id": "ZONE-B",
                    "entropy": 0.10,
                },
            ],
            tick_num=7,
        )
    )

    assert receipt["adapter"] == "colossus_security_hydra_immune"
    assert receipt["source_engine"] == "HydraImmune"
    assert receipt["analysis_tick"] == 7
    assert receipt["active_threats"] == 1
    assert receipt["threat_level"] == ThreatLevel.HIGH.name
    assert receipt["declared_suspicious_nodes"] == ["node-hot"]
    assert receipt["external_actions_executed"] == 0
    assert receipt["actions"][0]["executed"] is False
    assert adapter.last_analysis == receipt


def test_entropy_is_evidence_not_an_unfounded_intrusion_claim() -> None:
    adapter = ColossusSecurityAdapter(engine=HydraImmune(clock=FakeClock()))

    receipt = asyncio.run(
        adapter.analyze_traffic_patterns(
            [{"node_id": "node-observed", "entropy": 1.0}], tick_num=1
        )
    )

    assert receipt["active_threats"] == 0
    assert receipt["declared_suspicious_nodes"] == []
    assert receipt["traffic_evidence"] == [
        {
            "node_id": "node-observed",
            "zone_id": "node-observed",
            "suspicious_activity": False,
            "entropy": 1.0,
        }
    ]


def test_adapter_aggregates_multiple_nodes_by_declared_zone() -> None:
    adapter = ColossusSecurityAdapter(engine=HydraImmune(clock=FakeClock()))

    receipt = asyncio.run(
        adapter.analyze_traffic_patterns(
            [
                {"node_id": "node-a", "zone_id": "ZONE-A"},
                {
                    "node_id": "node-b",
                    "zone_id": "ZONE-A",
                    "suspicious_activity": True,
                },
            ]
        )
    )

    assert receipt["analysis_tick"] == 1
    assert receipt["active_threats"] == 1
    assert receipt["declared_suspicious_nodes"] == ["node-b"]


@pytest.mark.parametrize(
    "patterns",
    [
        "not-a-sequence",
        [{}],
        [{"node_id": "node-a", "suspicious_activity": "yes"}],
        [{"node_id": "node-a", "entropy": 1.1}],
        [{"node_id": "node-a", "entropy": float("nan")}],
    ],
)
def test_adapter_rejects_ambiguous_traffic_evidence(patterns) -> None:
    adapter = ColossusSecurityAdapter(engine=HydraImmune(clock=FakeClock()))

    with pytest.raises(SecurityAdapterInputError):
        asyncio.run(adapter.analyze_traffic_patterns(patterns))


@pytest.mark.parametrize("tick_num", [-1, True])
def test_adapter_rejects_invalid_explicit_tick(tick_num) -> None:
    adapter = ColossusSecurityAdapter(engine=HydraImmune(clock=FakeClock()))

    with pytest.raises(SecurityAdapterInputError):
        asyncio.run(adapter.analyze_traffic_patterns([], tick_num=tick_num))
