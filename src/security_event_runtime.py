"""Production adapter for the Colossus security event bus.

This module binds the existing persist-before-dispatch engine to the two
external runtime obligations that should not live inside the core event model:
Supabase connector heartbeats and P0 dispatch for critical security events.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from src.security_event_bus import (
    EventCategory,
    EventSeverity,
    SecurityEvent,
    SecurityEventBus,
    SupabaseAuditLogSink,
)


class RuntimeActivationError(RuntimeError):
    """Raised when the external runtime cannot establish its required state."""


@dataclass(frozen=True)
class RuntimeConfig:
    supabase_url: str
    supabase_key: str
    event_table: str = "security_events"
    connector_jobs_table: str = "connector_jobs"
    connector_name: str = "xai-colossus-security"


class ColossusSecurityRuntime:
    """External-runtime binding with receipt-truthful startup and P0 dispatch."""

    def __init__(
        self,
        config: RuntimeConfig,
        http_client: Any,
        p0_dispatch: Callable[[SecurityEvent], None],
    ) -> None:
        self._config = config
        self._http = http_client
        self._p0_dispatch = p0_dispatch
        self._bus: Optional[SecurityEventBus] = None

    @property
    def bus(self) -> SecurityEventBus:
        if self._bus is None:
            raise RuntimeActivationError("runtime has not been started")
        return self._bus

    def start(self) -> SecurityEventBus:
        """Write the connector heartbeat before exposing an active event bus."""
        endpoint = (
            f"{self._config.supabase_url.rstrip('/')}/rest/v1/"
            f"{self._config.connector_jobs_table}"
        )
        now = datetime.now(timezone.utc).isoformat()
        payload = {
            "connector_name": self._config.connector_name,
            "status": "running",
            "heartbeat_at": now,
        }
        headers = {
            "apikey": self._config.supabase_key,
            "Authorization": f"Bearer {self._config.supabase_key}",
            "Content-Type": "application/json",
            "Prefer": "resolution=merge-duplicates,return=minimal",
        }
        try:
            response = self._http.post(endpoint, json=payload, headers=headers)
        except Exception as exc:
            raise RuntimeActivationError(f"connector heartbeat failed: {exc}") from exc
        if not 200 <= response.status_code < 300:
            raise RuntimeActivationError(
                f"connector heartbeat rejected with HTTP {response.status_code}"
            )

        sink = SupabaseAuditLogSink(
            self._config.supabase_url,
            self._config.supabase_key,
            table_name=self._config.event_table,
            http_client=self._http,
        )
        bus = SecurityEventBus(sinks=[sink], require_persistence=True)
        bus.subscribe(
            categories=list(EventCategory),
            min_severity=EventSeverity.CRITICAL,
            callback=self._dispatch_p0,
        )
        self._bus = bus
        return bus

    def _dispatch_p0(self, event: SecurityEvent) -> None:
        """Dispatch only after the core bus has durably persisted the event."""
        self._p0_dispatch(event)


def make_mcp_dispatcher(send: Callable[..., Any]) -> Callable[[SecurityEvent], None]:
    """Adapt an MCP sender to the event-bus callback contract.

    The supplied sender owns provider-specific routing. This adapter guarantees
    that critical alerts carry explicit P0 priority and the complete structured
    event payload without embedding provider credentials in event state.
    """

    def dispatch(event: SecurityEvent) -> None:
        send(priority="P0", event=event.to_dict())

    return dispatch
