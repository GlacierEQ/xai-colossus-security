# Omega (How) — Controllers | Alpha (What) — Pure Physics | 1337.
#!/usr/bin/env python3
"""Colossus security event bus with receipt-truthful durable persistence."""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Protocol, Sequence

logger = logging.getLogger("COLOSSUS.EVENT_BUS")


class EventSeverity(Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    EMERGENCY = "emergency"


class EventCategory(Enum):
    PHYSICAL_ACCESS = "physical_access"
    PERIMETER_BREACH = "perimeter_breach"
    THERMAL_EVENT = "thermal_event"
    POWER_EVENT = "power_event"
    COOLING_EVENT = "cooling_event"
    NETWORK_EVENT = "network_event"
    HARDWARE_FAULT = "hardware_fault"
    CRYPTO_EVENT = "crypto_event"
    POLICY_VIOLATION = "policy_violation"
    SYSTEM_LIFECYCLE = "system_lifecycle"


class EventDisposition(Enum):
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    ESCALATED = "escalated"
    DISMISSED = "dismissed"


class EventPersistenceError(RuntimeError):
    """Raised when a security event cannot be durably persisted."""


class AuditLogSink(Protocol):
    def persist(self, event: "SecurityEvent") -> bool: ...


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


class SupabaseAuditLogSink:
    """Persist SecurityEvents to Supabase REST without inventing write success."""

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
        self._persisted_count = 0
        self._failure_count = 0

    def persist(self, event: SecurityEvent) -> bool:
        if self._client is None:
            self._failure_count += 1
            logger.error(
                "SUPABASE PERSIST BLOCKED: event=%s reason=http_client_unavailable",
                event.event_id,
            )
            return False

        endpoint = f"{self._url}/rest/v1/{self._table}"
        headers = {
            "apikey": self._key,
            "Authorization": f"Bearer {self._key}",
            "Content-Type": "application/json",
            "Prefer": "return=minimal",
        }
        try:
            response = self._client.post(endpoint, json=event.to_dict(), headers=headers)
            success = 200 <= response.status_code < 300
            if success:
                self._persisted_count += 1
            else:
                self._failure_count += 1
                logger.error(
                    "SUPABASE PERSIST FAILED: event=%s status=%s",
                    event.event_id,
                    getattr(response, "status_code", "unknown"),
                )
            return success
        except Exception as exc:
            self._failure_count += 1
            logger.error("SUPABASE PERSIST ERROR: event=%s error=%s", event.event_id, exc)
            return False

    @property
    def stats(self) -> Dict[str, int]:
        return {"persisted": self._persisted_count, "failed": self._failure_count}


class InMemoryAuditLogSink:
    """Non-durable sink for tests and explicitly local development."""

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


class SecurityEventBus:
    """Persist-before-dispatch event bus with explicit failure semantics."""

    def __init__(
        self,
        sinks: Optional[Sequence[AuditLogSink]] = None,
        buffer_size: int = 1000,
        require_persistence: bool = True,
    ):
        if buffer_size <= 0:
            raise ValueError("buffer_size must be positive")
        self._sinks = list(sinks or [])
        self._subscriptions: List[EventSubscription] = []
        self._event_buffer: List[SecurityEvent] = []
        self._buffer_size = buffer_size
        self._event_counter = 0
        self._emitted_count = 0
        self._persistence_failure_count = 0
        self._require_persistence = require_persistence

    def add_sink(self, sink: AuditLogSink) -> None:
        self._sinks.append(sink)

    def remove_sink(self, sink: AuditLogSink) -> None:
        self._sinks = [item for item in self._sinks if item is not sink]

    def subscribe(
        self,
        categories: Sequence[EventCategory],
        min_severity: EventSeverity,
        callback: Callable[[SecurityEvent], None],
        source_filter: Optional[str] = None,
    ) -> EventSubscription:
        subscription = EventSubscription(
            subscription_id=f"SUB-{uuid.uuid4().hex[:8].upper()}",
            categories=frozenset(categories),
            min_severity=min_severity,
            callback=callback,
            source_filter=source_filter,
        )
        self._subscriptions.append(subscription)
        return subscription

    def unsubscribe(self, subscription_id: str) -> bool:
        before = len(self._subscriptions)
        self._subscriptions = [
            subscription
            for subscription in self._subscriptions
            if subscription.subscription_id != subscription_id
        ]
        return len(self._subscriptions) < before

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

        results = [sink.persist(event) for sink in self._sinks]
        persistence_ok = bool(results) and all(results)
        if self._require_persistence and not persistence_ok:
            self._persistence_failure_count += 1
            logger.error(
                "EVENT NOT DISPATCHED: event=%s persistence_results=%s",
                event.event_id,
                json.dumps(results),
            )
            raise EventPersistenceError(
                f"event {event.event_id} was not durably persisted to every configured sink"
            )

        self._event_buffer.append(event)
        if len(self._event_buffer) > self._buffer_size:
            self._event_buffer = self._event_buffer[-self._buffer_size :]

        self._emitted_count += 1
        self._dispatch(event)
        logger.log(
            logging.WARNING
            if severity in (EventSeverity.CRITICAL, EventSeverity.EMERGENCY)
            else logging.INFO,
            "EVENT %s [%s] %s | %s | %s",
            event.event_id,
            severity.value.upper(),
            category.value,
            source,
            title,
        )
        return event

    def _dispatch(self, event: SecurityEvent) -> None:
        severity_order = {
            EventSeverity.INFO: 0,
            EventSeverity.WARNING: 1,
            EventSeverity.CRITICAL: 2,
            EventSeverity.EMERGENCY: 3,
        }
        event_rank = severity_order[event.severity]
        for subscription in self._subscriptions:
            if event.category not in subscription.categories:
                continue
            if severity_order[subscription.min_severity] > event_rank:
                continue
            if subscription.source_filter and event.source != subscription.source_filter:
                continue
            try:
                subscription.callback(event)
            except Exception as exc:
                logger.error(
                    "SUB DISPATCH FAILED: sub=%s event=%s error=%s",
                    subscription.subscription_id,
                    event.event_id,
                    exc,
                )

    def get_recent_events(
        self,
        limit: int = 50,
        severity: Optional[EventSeverity] = None,
        category: Optional[EventCategory] = None,
    ) -> List[SecurityEvent]:
        result = self._event_buffer
        if severity is not None:
            result = [event for event in result if event.severity == severity]
        if category is not None:
            result = [event for event in result if event.category == category]
        return result[-limit:]

    def get_event_by_id(self, event_id: str) -> Optional[SecurityEvent]:
        return next(
            (event for event in reversed(self._event_buffer) if event.event_id == event_id),
            None,
        )

    def get_stats(self) -> Dict[str, Any]:
        return {
            "emitted_count": self._emitted_count,
            "persistence_failure_count": self._persistence_failure_count,
            "buffer_size": len(self._event_buffer),
            "subscription_count": len(self._subscriptions),
            "sink_count": len(self._sinks),
            "require_persistence": self._require_persistence,
        }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    sink = InMemoryAuditLogSink()
    bus = SecurityEventBus(sinks=[sink])
    bus.emit(
        severity=EventSeverity.INFO,
        category=EventCategory.PHYSICAL_ACCESS,
        source="local-smoke-test",
        title="Event bus smoke test",
        detail={"mode": "local"},
    )
    print(json.dumps(bus.get_stats(), indent=2, sort_keys=True))
