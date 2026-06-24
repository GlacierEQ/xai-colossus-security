#!/usr/bin/env python3
"""Tests for Colossus Security Hydra Immune"""
import asyncio
import pytest
from security.hydra_immune import HydraImmune, Threat, ThreatType, ThreatLevel


@pytest.fixture
def hydra():
    return HydraImmune()


class TestHydraImmune:
    @pytest.mark.asyncio
    async def test_initial_state_no_threats(self, hydra):
        result = await hydra.tick({}, 1)
        assert result["active_threats"] == 0
        assert result["threat_level"] == ThreatLevel.NONE.value

    @pytest.mark.asyncio
    async def test_tick_returns_valid_structure(self, hydra):
        result = await hydra.tick({}, 1)
        assert "anomalies" in result
        assert "actions" in result
        assert "active_threats" in result
        assert "threat_level" in result

    @pytest.mark.asyncio
    async def test_threat_detection(self, hydra):
        zones = {"Z001": {"suspicious_activity": True}}
        result = await hydra.tick(zones, 1)
        assert result["mitigated_count"] >= 1

    @pytest.mark.asyncio
    async def test_auto_mitigation(self, hydra):
        zones = {"Z001": {"suspicious_activity": True}}
        await hydra.tick(zones, 1)
        assert hydra.mitigated_count >= 1

    @pytest.mark.asyncio
    async def test_summary_structure(self, hydra):
        await hydra.tick({}, 1)
        s = hydra.summary()
        assert "threat_level" in s
        assert "active_threats" in s
        assert "threat_breakdown" in s

    def test_threat_severity_score(self):
        t = Threat("T1", ThreatType.NETWORK_INTRUSION, ThreatLevel.HIGH, "src", "tgt")
        assert t.severity_score == 0.75
