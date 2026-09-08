"""Canonical import surface for the Colossus security event bus.

The implementation remains owned by ``omega.security_event_bus``.  This module
provides the stable runtime path advertised by the repository without copying
or forking event-bus logic.
"""

from omega.security_event_bus import (
    AuditLogSink,
    EventCategory,
    EventDisposition,
    EventPersistenceError,
    EventSeverity,
    EventSubscription,
    InMemoryAuditLogSink,
    SecurityEvent,
    SecurityEventBus,
    SupabaseAuditLogSink,
)

__all__ = [
    "AuditLogSink",
    "EventCategory",
    "EventDisposition",
    "EventPersistenceError",
    "EventSeverity",
    "EventSubscription",
    "InMemoryAuditLogSink",
    "SecurityEvent",
    "SecurityEventBus",
    "SupabaseAuditLogSink",
]
