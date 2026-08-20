"""HydraImmune adapter for the Cooling composition contract.

The adapter preserves HydraImmune's explicit detection model: traffic is only
treated as suspicious when a caller declares ``suspicious_activity: true``.
Observed entropy is carried as bounded evidence, not converted into an
unfounded claim of intrusion.  Response proposals remain non-executing and
resolution remains receipt-gated by HydraImmune.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from math import isfinite
from typing import Any

from security.hydra_immune import HydraImmune


class SecurityAdapterInputError(ValueError):
    """Raised when composition traffic evidence is malformed or ambiguous."""


@dataclass(slots=True)
class ColossusSecurityAdapter:
    """Adapt declared traffic evidence to HydraImmune's zone snapshot contract."""

    engine: HydraImmune = field(default_factory=HydraImmune)
    analysis_tick: int = 0
    last_analysis: dict[str, Any] | None = field(default=None, init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.engine, HydraImmune):
            raise SecurityAdapterInputError("engine must be a HydraImmune instance")
        if (
            not isinstance(self.analysis_tick, int)
            or isinstance(self.analysis_tick, bool)
            or self.analysis_tick < 0
        ):
            raise SecurityAdapterInputError(
                "analysis_tick must be a non-negative integer"
            )

    async def analyze_traffic_patterns(
        self,
        traffic_patterns: Sequence[Mapping[str, Any]],
        *,
        tick_num: int | None = None,
    ) -> dict[str, Any]:
        """Analyze declared traffic evidence through HydraImmune.

        Each entry requires a non-empty ``node_id``.  An optional ``zone_id``
        groups nodes; otherwise the node id is used as a stable one-node zone.
        ``suspicious_activity`` must be a boolean if supplied.  Optional
        ``entropy`` is validated as a normalized observation and reported in
        the receipt but cannot by itself create a threat.
        """

        if isinstance(traffic_patterns, (str, bytes)) or not isinstance(
            traffic_patterns, Sequence
        ):
            raise SecurityAdapterInputError("traffic_patterns must be a sequence")

        effective_tick = self._next_tick(tick_num)
        zones: dict[str, dict[str, bool]] = {}
        evidence: list[dict[str, Any]] = []
        declared_suspicious_nodes: list[str] = []

        for index, pattern in enumerate(traffic_patterns):
            if not isinstance(pattern, Mapping):
                raise SecurityAdapterInputError(
                    f"traffic pattern {index} must be a mapping"
                )

            node_id = pattern.get("node_id")
            if not isinstance(node_id, str) or not node_id.strip():
                raise SecurityAdapterInputError(
                    f"traffic pattern {index} node_id must be a non-empty string"
                )

            zone_id = pattern.get("zone_id", node_id)
            if not isinstance(zone_id, str) or not zone_id.strip():
                raise SecurityAdapterInputError(
                    f"traffic pattern {index} zone_id must be a non-empty string"
                )

            suspicious = pattern.get("suspicious_activity", False)
            if not isinstance(suspicious, bool):
                raise SecurityAdapterInputError(
                    f"traffic pattern {index} suspicious_activity must be a boolean"
                )

            record: dict[str, Any] = {
                "node_id": node_id,
                "zone_id": zone_id,
                "suspicious_activity": suspicious,
            }
            if "entropy" in pattern:
                entropy = pattern["entropy"]
                if (
                    not isinstance(entropy, (int, float))
                    or isinstance(entropy, bool)
                    or not isfinite(float(entropy))
                    or not 0.0 <= float(entropy) <= 1.0
                ):
                    raise SecurityAdapterInputError(
                        f"traffic pattern {index} entropy must be finite and normalized"
                    )
                record["entropy"] = float(entropy)

            evidence.append(record)
            zones.setdefault(zone_id, {"suspicious_activity": False})
            zones[zone_id]["suspicious_activity"] |= suspicious
            if suspicious:
                declared_suspicious_nodes.append(node_id)

        result = await self.engine.tick(zones, effective_tick)
        receipt = {
            **result,
            "adapter": "colossus_security_hydra_immune",
            "source_engine": "HydraImmune",
            "analysis_tick": effective_tick,
            "traffic_records_analyzed": len(evidence),
            "declared_suspicious_nodes": sorted(declared_suspicious_nodes),
            "traffic_evidence": evidence,
        }
        self.last_analysis = receipt
        return receipt

    def _next_tick(self, requested_tick: int | None) -> int:
        if requested_tick is None:
            self.analysis_tick += 1
            return self.analysis_tick
        if (
            not isinstance(requested_tick, int)
            or isinstance(requested_tick, bool)
            or requested_tick < 0
        ):
            raise SecurityAdapterInputError("tick_num must be a non-negative integer")
        self.analysis_tick = requested_tick
        return requested_tick
