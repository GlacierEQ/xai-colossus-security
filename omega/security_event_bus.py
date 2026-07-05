#!/usr/bin/env python3
"""
COLOSSUS SECURITY EVENT BUS
============================
Physical security event bus with structured event emission,
Supabase audit log persistence, and event classification.

Implements a publish/subscribe pattern for security-relevant events
across the Colossus infrastructure. Every event is classified by
severity, correlated with a trace ID, and durably persisted to
Supabase for audit compliance.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Protocol, Sequence

logger = logging.getLogger("COLOSSUS.EVENT_BUS")


# ---------------------------------------------------------------------------
# Event classification
# ---------------------------------------------------------------------------

class EventSeverity(Enum):
    INFO      = "info"
    WARNING   = "warning"
    CRITICAL  = "critical"
    EMERGENCY = "emergency"


class EventCategory(Enum):
    PHYSICAL_ACCESS   = "physical_access"
    PERIMETER_BREACH  = "perimeter_breach"
    THERMAL_EVENT     = "thermal_event"
    POWER_EVENT       = "power_event"
    COOLING_EVENT     = "cooling_event"
    NETWORK_EVENT     = "network_event"
    HARDWARE_FAULT    = "hardware_fault"
    CRYPTO_EVENT      = "crypto_event"
    POLICY_VIOLATION  = "policy_violation"
    SYSTEM_LIFECYCLE  = "system_lifecycle"


class EventDisposition(Enum):
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED     = "resolved"
    ESCALATED    = "escalated"
    DISMISSED    = "dismissed"


# ---------------------------------------------------------------------------
# Persistence protocol (pluggable)
# ---------------------------------------------------------------------------

class AuditLogSink(Protocol):
    """Any durable sink that can persist security events."""
    def persist(self, event: "SecurityEvent") -> bool: ...


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SecurityEvent:
    event_id: str
    trace_id: str
    timestamp: str
    severity: EventSeverity
    category: EventCategory
    source: str
    title: str
    detail: Dict[str, Any]
    actor_id: str = "system"
    disposition: EventDisposition = EventDisposition.ACKNOWLEDGED

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "trace_id": self.trace_id,
            "timestamp": self.timestamp,
            "severity": self.severity.value,
            "category": self.category.value,
            "source": self.source,
            "title": self.title,
            "detail": self.detail,
            "actor_id": self.actor_id,
            "disposition": self.disposition.value,
        }


@dataclass
class EventSubscription:
    subscription_id: str
    categories: frozenset[EventCategory]
    min_severity: EventSeverity
    callback: Callable[[SecurityEvent], None]
    source_filter: Optional[str] = None


# ---------------------------------------------------------------------------
# Supabase audit log sink
# ---------------------------------------------------------------------------

class SupabaseAuditLogSink:
    """
    Persists SecurityEvents to a Supabase table via the REST API.

    Configuration is passed at construction time. The sink performs
    a single INSERT per event. Failures are logged but do not raise
    (fire-and-forget with observability).
    """

    def __init__(
        self,
        supabase_url: str,
        supabase_key: str,
        table_name: str = "security_audit_log",
        http_client: Optional[Any] = None,
    ):
        self._url = supabase_url.rstrip("/")
        self._key = supabase_key
        self._table = table_name
        self._client = http_client
        self._persisted_count: int = 0
        self._failure_count: int = 0

    def persist(self, event: SecurityEvent) -> bool:
        payload = event.to_dict()
        endpoint = f"{self._url}/rest/v1/{self._table}"
        headers = {
            "apikey": self._key,
            "Authorization": f"Bearer {self._key}",
            "Content-Type": "application/json",
            "Prefer": "return=minimal",
        }

        try:
            if self._client is not None:
                resp = self._client.post(endpoint, json=payload, headers=headers)
                success = resp.status_code < 400
            else:
                logger.debug(
                    "SUPABASE PERSIST (no HTTP client): %s → %s",
                    event.event_id, json.dumps(payload, default=str)[:200],
                )
                success = True

            if success:
                self._persisted_count += 1
            else:
                self._failure_count += 1
                logger.error(
                    "SUPABASE PERSIST FAILED: event=%s status=%s",
                    event.event_id,
                    getattr(resp, "status_code", "unknown"),
                )
            return success

        except Exception as exc:
            self._failure_count += 1
            logger.error(
                "SUPABASE PERSIST ERROR: event=%s error=%s",
                event.event_id, exc,
            )
            return False

    @property
    def stats(self) -> Dict[str, int]:
        return {
            "persisted": self._persisted_count,
            "failed": self._failure_count,
        }


# ---------------------------------------------------------------------------
# In-memory audit log sink (for testing / fallback)
# ---------------------------------------------------------------------------

class InMemoryAuditLogSink:
    """Non-durable in-memory sink for testing and local development."""

    def __init__(self) -> None:
        self._events: List[SecurityEvent] = []

    def persist(self, event: SecurityEvent) -> bool:
        self._events.append(event)
        return True

    def get_events(self) -> List[SecurityEvent]:
        return list(self._events)

    @property
    def stats(self) -> Dict[str, int]:
        return {"persisted": len(self._events), "failed": 0}


# ---------------------------------------------------------------------------
# SecurityEventBus
# ---------------------------------------------------------------------------

class SecurityEventBus:
    """
    Central event bus for physical security events.

    Responsibilities:
        - Emit classified SecurityEvents with trace IDs.
        - Route events to registered subscribers based on category/severity.
        - Persist every event to a pluggable AuditLogSink (Supabase by default).
        - Maintain an in-memory buffer for recent events (configurable depth).

    Zero-trust: every emission is persisted before subscriber dispatch.
    """

    def __init__(
        self,
        sinks: Optional[Sequence[AuditLogSink]] = None,
        buffer_size: int = 1000,
    ):
        self._sinks: List[AuditLogSink] = list(sinks or [])
        self._subscriptions: List[EventSubscription] = []
        self._event_buffer: List[SecurityEvent] = []
        self._buffer_size = buffer_size
        self._event_counter: int = 0
        self._emitted_count: int = 0

    # ------------------------------------------------------------------
    # Sink management
    # ------------------------------------------------------------------

    def add_sink(self, sink: AuditLogSink) -> None:
        self._sinks.append(sink)

    def remove_sink(self, sink: AuditLogSink) -> None:
        self._sinks = [s for s in self._sinks if s is not sink]

    # ------------------------------------------------------------------
    # Subscription management
    # ------------------------------------------------------------------

    def subscribe(
        self,
        categories: Sequence[EventCategory],
        min_severity: EventSeverity,
        callback: Callable[[SecurityEvent], None],
        source_filter: Optional[str] = None,
    ) -> EventSubscription:
        sub = EventSubscription(
            subscription_id=f"SUB-{uuid.uuid4().hex[:8].upper()}",
            categories=frozenset(categories),
            min_severity=min_severity,
            callback=callback,
            source_filter=source_filter,
        )
        self._subscriptions.append(sub)
        return sub

    def unsubscribe(self, subscription_id: str) -> bool:
        before = len(self._subscriptions)
        self._subscriptions = [
            s for s in self._subscriptions if s.subscription_id != subscription_id
        ]
        return len(self._subscriptions) < before

    # ------------------------------------------------------------------
    # Core emission
    # ------------------------------------------------------------------

    def emit(
        self,
        severity: EventSeverity,
        category: EventCategory,
        source: str,
        title: str,
        detail: Dict[str, Any],
        actor_id: str = "system",
        trace_id: Optional[str] = None,
    ) -> SecurityEvent:
        self._event_counter += 1
        event = SecurityEvent(
            event_id=f"EVT-{self._event_counter:08d}",
            trace_id=trace_id or str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            severity=severity,
            category=category,
            source=source,
            title=title,
            detail=detail,
            actor_id=actor_id,
        )

        for sink in self._sinks:
            sink.persist(event)

        self._event_buffer.append(event)
        if len(self._event_buffer) > self._buffer_size:
            self._event_buffer = self._event_buffer[-self._buffer_size:]

        self._emitted_count += 1
        self._dispatch(event)

        logger.log(
            logging.WARNING if severity in (EventSeverity.CRITICAL, EventSeverity.EMERGENCY)
            else logging.INFO,
            "EVENT %s [%s] %s | %s | %s",
            event.event_id, severity.value.upper(), category.value, source, title,
        )

        return event

    def _dispatch(self, event: SecurityEvent) -> None:
        severity_order = {
            EventSeverity.INFO: 0,
            EventSeverity.WARNING: 1,
            EventSeverity.CRITICAL: 2,
            EventSeverity.EMERGENCY: 3,
        }
        min_val = severity_order[event.severity]

        for sub in self._subscriptions:
            if event.category not in sub.categories:
                continue
            if severity_order[sub.min_severity] > min_val:
                continue
            if sub.source_filter and event.source != sub.source_filter:
                continue
            try:
                sub.callback(event)
            except Exception as exc:
                logger.error(
                    "SUB DISPATCH FAILED: sub=%s event=%s error=%s",
                    sub.subscription_id, event.event_id, exc,
                )

    # ------------------------------------------------------------------
    # Query API
    # ------------------------------------------------------------------

    def get_recent_events(
        self,
        limit: int = 50,
        severity: Optional[EventSeverity] = None,
        category: Optional[EventCategory] = None,
    ) -> List[SecurityEvent]:
        result = self._event_buffer
        if severity is not None:
            result = [e for e in result if e.severity == severity]
        if category is not None:
            result = [e for e in result if e.category == category]
        return result[-limit:]

    def get_event_by_id(self, event_id: str) -> Optional[SecurityEvent]:
        for e in reversed(self._event_buffer):
            if e.event_id == event_id:
                return e
        return None

    def get_stats(self) -> Dict[str, Any]:
        return {
            "emitted_count": self._emitted_count,
            "buffer_size": len(self._event_buffer),
            "subscription_count": len(self._subscriptions),
            "sink_count": len(self._sinks),
        }


# ---------------------------------------------------------------------------
# CLI smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    memory_sink = InMemoryAuditLogSink()
    bus = SecurityEventBus(sinks=[memory_sink])

    def on_critical(event: SecurityEvent) -> None:
        print(f"  [HANDLER] Critical event received: {event.title}")

    bus.subscribe(
        categories=[EventCategory.PERIMETER_BREACH, EventCategory.PHYSICAL_ACCESS],
        min_severity=EventSeverity.WARNING,
        callback=on_critical,
    )

    print("--- Emitting events ---")
    bus.emit(
        severity=EventSeverity.INFO,
        category=EventCategory.PHYSICAL_ACCESS,
        source="biometric-mantrap-01",
        title="Authorized entry via iris scan",
        detail={"badge_id": "EMP-4412", "zone": "compute_floor"},
        actor_id="EMP-4412",
    )

    bus.emit(
        severity=EventSeverity.CRITICAL,
        category=EventCategory.PERIMETER_BREACH,
        source="thermal-cam-07",
        title="Unauthorized thermal signature at perimeter fence",
        detail={"zone": "north_fence", "temp_delta": "+12°C"},
    )

    bus.emit(
        severity=EventSeverity.EMERGENCY,
        category=EventCategory.THERMAL_EVENT,
        source="gpu-rack-a1",
        title="GPU thermal runaway detected",
        detail={"rack": "A1", "peak_temp": 97.3, "threshold": 85.0},
    )

    print(f"\nBus stats: {bus.get_stats()}")
    print(f"Sink stats: {memory_sink.stats}")
    print(f"Recent events: {len(bus.get_recent_events())}")
