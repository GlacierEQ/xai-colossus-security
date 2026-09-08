from __future__ import annotations

from dataclasses import dataclass

import pytest

from omega.security_event_bus import EventCategory, EventPersistenceError, EventSeverity
from src.security_event_runtime import (
    ColossusSecurityRuntime,
    RuntimeActivationError,
    RuntimeConfig,
    make_mcp_dispatcher,
)


@dataclass
class FakeResponse:
    status_code: int


class RecordingHttpClient:
    def __init__(self, statuses: list[int]) -> None:
        self.statuses = list(statuses)
        self.calls: list[dict] = []

    def post(self, url: str, *, json: dict, headers: dict) -> FakeResponse:
        self.calls.append({"url": url, "json": json, "headers": headers})
        if not self.statuses:
            raise AssertionError("unexpected HTTP call")
        return FakeResponse(self.statuses.pop(0))


def config() -> RuntimeConfig:
    return RuntimeConfig(
        supabase_url="https://example.supabase.co",
        supabase_key="test-key",
    )


def test_start_requires_successful_connector_heartbeat() -> None:
    client = RecordingHttpClient([503])
    runtime = ColossusSecurityRuntime(config(), client, lambda event: None)

    with pytest.raises(RuntimeActivationError, match="heartbeat rejected"):
        runtime.start()

    with pytest.raises(RuntimeActivationError, match="has not been started"):
        _ = runtime.bus

    assert client.calls[0]["url"].endswith("/rest/v1/connector_jobs")
    assert client.calls[0]["json"]["status"] == "running"


def test_critical_event_persists_before_p0_dispatch() -> None:
    # First response accepts connector heartbeat; second persists the event.
    client = RecordingHttpClient([201, 201])
    dispatched: list[dict] = []
    runtime = ColossusSecurityRuntime(
        config(),
        client,
        make_mcp_dispatcher(lambda **payload: dispatched.append(payload)),
    )

    bus = runtime.start()
    event = bus.emit(
        severity=EventSeverity.CRITICAL,
        category=EventCategory.PERIMETER_BREACH,
        source="gate-a",
        title="Perimeter breach",
        detail={"sensor": "A-17"},
    )

    assert len(client.calls) == 2
    assert client.calls[1]["url"].endswith("/rest/v1/security_events")
    assert client.calls[1]["json"]["event_id"] == event.event_id
    assert dispatched == [{"priority": "P0", "event": event.to_dict()}]


def test_failed_event_persistence_blocks_p0_dispatch() -> None:
    # Heartbeat succeeds, but durable event persistence fails.
    client = RecordingHttpClient([204, 500])
    dispatched: list[object] = []
    runtime = ColossusSecurityRuntime(config(), client, dispatched.append)
    bus = runtime.start()

    with pytest.raises(EventPersistenceError):
        bus.emit(
            severity=EventSeverity.CRITICAL,
            category=EventCategory.NETWORK_EVENT,
            source="fabric",
            title="Network isolation failure",
            detail={"segment": "prod"},
        )

    assert dispatched == []
    assert bus.get_stats()["persistence_failure_count"] == 1


def test_noncritical_event_is_persisted_without_p0_dispatch() -> None:
    client = RecordingHttpClient([200, 201])
    dispatched: list[object] = []
    runtime = ColossusSecurityRuntime(config(), client, dispatched.append)
    bus = runtime.start()

    bus.emit(
        severity=EventSeverity.INFO,
        category=EventCategory.SYSTEM_LIFECYCLE,
        source="runtime",
        title="Service healthy",
        detail={"state": "ready"},
    )

    assert len(client.calls) == 2
    assert client.calls[1]["url"].endswith("/rest/v1/security_events")
    assert dispatched == []
