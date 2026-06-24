#!/usr/bin/env python3
"""
GHOST-EMBER — Anomaly Detection Engine
========================================
Baseline-learning anomaly detector for physical security telemetry.

Uses Exponential Moving Average (EMA) for baseline computation with
configurable decay, sensitivity thresholds, and drift alerting.
Designed for real-time streaming of temperature, power, vibration,
and biometric signals from Colossus sensor arrays.
"""

from __future__ import annotations

import logging
import math
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Deque, Dict, List, Optional, Tuple

logger = logging.getLogger("GHOST-EMBER.ANOMALY")


# ---------------------------------------------------------------------------
# Anomaly classification
# ---------------------------------------------------------------------------

class AnomalySeverity(Enum):
    INFO      = "info"
    WARNING   = "warning"
    CRITICAL  = "critical"


class DriftDirection(Enum):
    NONE    = "none"
    UP      = "up"
    DOWN    = "down"
    BIVALENT = "bivalent"


class SensorType(Enum):
    TEMPERATURE = "temperature"
    POWER_DRAW  = "power_draw"
    VIBRATION   = "vibration"
    BIOMETRIC   = "biometric"
    NETWORK     = "network"
    COOLANT     = "coolant"


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AnomalyThresholds:
    warning_sigma: float = 2.0
    critical_sigma: float = 3.5
    min_samples: int = 30
    drift_threshold: float = 0.15
    drift_window: int = 50
    ema_alpha: float = 0.05


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SensorReading:
    sensor_id: str
    sensor_type: SensorType
    value: float
    timestamp: float


@dataclass
class AnomalyEvent:
    event_id: str
    sensor_id: str
    sensor_type: SensorType
    severity: AnomalySeverity
    value: float
    baseline_mean: float
    baseline_std: float
    z_score: float
    timestamp: float
    message: str


@dataclass
class DriftAlert:
    sensor_id: str
    sensor_type: SensorType
    direction: DriftDirection
    magnitude: float
    baseline_mean: float
    current_trend: float
    timestamp: float
    message: str


@dataclass
class SensorBaseline:
    sensor_id: str
    sensor_type: SensorType
    ema_mean: float = 0.0
    ema_variance: float = 0.0
    sample_count: int = 0
    last_update: float = 0.0
    recent_values: Deque[float] = field(default_factory=lambda: deque(maxlen=200))
    trend_buffer: Deque[float] = field(default_factory=lambda: deque(maxlen=50))

    @property
    def is_ready(self) -> bool:
        return self.sample_count >= 30

    @property
    def std_dev(self) -> float:
        return math.sqrt(self.ema_variance) if self.ema_variance > 0 else 0.0


# ---------------------------------------------------------------------------
# AnomalyDetector
# ---------------------------------------------------------------------------

class AnomalyDetector:
    """
    Real-time anomaly detector with EMA baseline learning.

    Lifecycle:
        1. Feed sensor readings via `ingest()`.
        2. After `min_samples` observations, the detector begins
           scoring new readings against the learned baseline.
        3. Readings exceeding `warning_sigma` or `critical_sigma`
           standard deviations generate AnomalyEvents.
        4. Sustained trend shifts exceeding `drift_threshold` generate
           DriftAlerts.

    Thread-safety: all mutable state is per-instance and not thread-safe.
    Use external synchronization if sharing across threads.
    """

    def __init__(self, thresholds: Optional[AnomalyThresholds] = None):
        self._thresholds = thresholds or AnomalyThresholds()
        self._baselines: Dict[str, SensorBaseline] = {}
        self._anomaly_events: List[AnomalyEvent] = []
        self._drift_alerts: List[DriftAlert] = []
        self._event_counter: int = 0
        self._clock: Callable[[], float] = time.time

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ingest(self, reading: SensorReading) -> List[AnomalyEvent]:
        key = reading.sensor_id
        baseline = self._baselines.get(key)

        if baseline is None:
            baseline = SensorBaseline(
                sensor_id=key,
                sensor_type=reading.sensor_type,
            )
            self._baselines[key] = baseline

        anomalies: List[AnomalyEvent] = []
        self._update_baseline(baseline, reading.value, reading.timestamp)

        if baseline.is_ready:
            z_score = self._compute_z_score(baseline, reading.value)
            anomaly = self._classify_anomaly(reading, baseline, z_score)
            if anomaly is not None:
                anomalies.append(anomaly)
                self._anomaly_events.append(anomaly)
                logger.warning(
                    "ANOMALY DETECTED: %s | %s | z=%.2f | %s",
                    anomaly.severity.value.upper(),
                    anomaly.sensor_id,
                    anomaly.z_score,
                    anomaly.message,
                )

            drift = self._detect_drift(baseline, reading.value, reading.timestamp)
            if drift is not None:
                self._drift_alerts.append(drift)
                logger.warning(
                    "DRIFT ALERT: %s | %s | %s | mag=%.4f",
                    drift.sensor_type.value,
                    drift.sensor_id,
                    drift.direction.value,
                    drift.magnitude,
                )

        return anomalies

    def get_baseline(self, sensor_id: str) -> Optional[SensorBaseline]:
        return self._baselines.get(sensor_id)

    def get_anomaly_events(
        self,
        sensor_id: Optional[str] = None,
        min_severity: Optional[AnomalySeverity] = None,
    ) -> List[AnomalyEvent]:
        severity_order = {
            AnomalySeverity.INFO: 0,
            AnomalySeverity.WARNING: 1,
            AnomalySeverity.CRITICAL: 2,
        }
        result = self._anomaly_events
        if sensor_id is not None:
            result = [e for e in result if e.sensor_id == sensor_id]
        if min_severity is not None:
            min_val = severity_order[min_severity]
            result = [e for e in result if severity_order[e.severity] >= min_val]
        return result

    def get_drift_alerts(
        self,
        sensor_id: Optional[str] = None,
    ) -> List[DriftAlert]:
        if sensor_id is not None:
            return [a for a in self._drift_alerts if a.sensor_id == sensor_id]
        return list(self._drift_alerts)

    def reset_sensor(self, sensor_id: str) -> bool:
        if sensor_id in self._baselines:
            del self._baselines[sensor_id]
            return True
        return False

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _update_baseline(
        self,
        baseline: SensorBaseline,
        value: float,
        timestamp: float,
    ) -> None:
        alpha = self._thresholds.ema_alpha
        baseline.recent_values.append(value)
        baseline.trend_buffer.append(value)
        baseline.sample_count += 1
        baseline.last_update = timestamp

        if baseline.sample_count == 1:
            baseline.ema_mean = value
            baseline.ema_variance = 0.0
            return

        delta = value - baseline.ema_mean
        baseline.ema_mean += alpha * delta
        baseline.ema_variance = (1 - alpha) * (
            baseline.ema_variance + alpha * delta * delta
        )

    def _compute_z_score(
        self,
        baseline: SensorBaseline,
        value: float,
    ) -> float:
        std = baseline.std_dev
        if std < 1e-10:
            return 0.0
        return (value - baseline.ema_mean) / std

    def _classify_anomaly(
        self,
        reading: SensorReading,
        baseline: SensorBaseline,
        z_score: float,
    ) -> Optional[AnomalyEvent]:
        abs_z = abs(z_score)
        t = self._thresholds

        if abs_z >= t.critical_sigma:
            severity = AnomalySeverity.CRITICAL
        elif abs_z >= t.warning_sigma:
            severity = AnomalySeverity.WARNING
        else:
            return None

        self._event_counter += 1
        return AnomalyEvent(
            event_id=f"ANOM-{self._event_counter:06d}",
            sensor_id=reading.sensor_id,
            sensor_type=reading.sensor_type,
            severity=severity,
            value=reading.value,
            baseline_mean=baseline.ema_mean,
            baseline_std=baseline.std_dev,
            z_score=z_score,
            timestamp=reading.timestamp,
            message=(
                f"{reading.sensor_type.value} reading {reading.value:.2f} "
                f"deviates {abs_z:.2f}σ from baseline "
                f"(μ={baseline.ema_mean:.2f}, σ={baseline.std_dev:.2f})"
            ),
        )

    def _detect_drift(
        self,
        baseline: SensorBaseline,
        value: float,
        timestamp: float,
    ) -> Optional[DriftAlert]:
        buf = baseline.trend_buffer
        if len(buf) < self._thresholds.drift_window:
            return None

        window = list(buf)
        half = len(window) // 2
        first_half = window[:half]
        second_half = window[half:]

        mean_first = sum(first_half) / len(first_half)
        mean_second = sum(second_half) / len(second_half)

        if mean_first == 0:
            return None

        magnitude = (mean_second - mean_first) / abs(mean_first)
        threshold = self._thresholds.drift_threshold

        if abs(magnitude) < threshold:
            return None

        direction = DriftDirection.UP if magnitude > 0 else DriftDirection.DOWN

        return DriftAlert(
            sensor_id=baseline.sensor_id,
            sensor_type=baseline.sensor_type,
            direction=direction,
            magnitude=abs(magnitude),
            baseline_mean=baseline.ema_mean,
            current_trend=mean_second,
            timestamp=timestamp,
            message=(
                f"Drift detected: {baseline.sensor_type.value} trending "
                f"{direction.value} ({abs(magnitude)*100:.1f}% shift) "
                f"over {self._thresholds.drift_window} samples"
            ),
        )


# ---------------------------------------------------------------------------
# CLI smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import random

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    detector = AnomalyDetector(AnomalyThresholds(
        warning_sigma=2.0,
        critical_sigma=3.0,
        min_samples=20,
        drift_threshold=0.10,
        drift_window=30,
        ema_alpha=0.05,
    ))

    print("--- Training baseline (60 normal readings) ---")
    for i in range(60):
        value = random.gauss(72.0, 1.5)
        reading = SensorReading(
            sensor_id="TEMP-RACK-A1",
            sensor_type=SensorType.TEMPERATURE,
            value=value,
            timestamp=time.time() + i,
        )
        detector.ingest(reading)

    baseline = detector.get_baseline("TEMP-RACK-A1")
    print(f"Baseline: μ={baseline.ema_mean:.2f}, σ={baseline.std_dev:.2f}, n={baseline.sample_count}")

    print("\n--- Injecting anomalous readings ---")
    anomaly_values = [82.0, 85.0, 55.0, 48.0, 90.0]
    for v in anomaly_values:
        reading = SensorReading(
            sensor_id="TEMP-RACK-A1",
            sensor_type=SensorType.TEMPERATURE,
            value=v,
            timestamp=time.time(),
        )
        events = detector.ingest(reading)
        for e in events:
            print(f"  {e.severity.value.upper()}: {e.message}")

    print(f"\nTotal anomaly events: {len(detector.get_anomaly_events())}")
    print(f"Critical events:     {len(detector.get_anomaly_events(min_severity=AnomalySeverity.CRITICAL))}")
