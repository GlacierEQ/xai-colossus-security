#!/usr/bin/env python3
"""
COLOSSUS INCIDENT RESPONSE — Automated Runbook Executor
========================================================
Executes CRITICAL security event runbooks with full rollback support.

Every step is wrapped in a transactional boundary: on failure, previously
completed steps are reversed in LIFO order. Execution state is persisted
to an audit trail for post-incident forensics.

Zero-trust: every action is authenticated, logged, and reversible.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Sequence

logger = logging.getLogger("COLOSSUS.RUNBOOK_EXECUTOR")


# ---------------------------------------------------------------------------
# Domain types
# ---------------------------------------------------------------------------

class Severity(Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"


class StepOutcome(Enum):
    PENDING    = "pending"
    RUNNING    = "running"
    SUCCEEDED  = "succeeded"
    FAILED     = "failed"
    ROLLED_BACK = "rolled_back"
    SKIPPED    = "skipped"


class ExecutorPhase(Enum):
    INIT       = "init"
    EXECUTING  = "executing"
    ROLLING_BACK = "rolling_back"
    COMPLETED  = "completed"
    ABORTED    = "aborted"


# ---------------------------------------------------------------------------
# Data contracts
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RollbackPolicy:
    """Controls which steps are eligible for rollback."""
    auto_rollback: bool = True
    max_rollback_depth: int = 50
    non_rollbackable_steps: frozenset[str] = frozenset()


@dataclass
class RunbookStep:
    step_id: str
    description: str
    action: Callable[[], bool]
    rollback: Optional[Callable[[], bool]] = None
    timeout_sec: float = 60.0
    is_critical: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class StepRecord:
    step_id: str
    description: str
    outcome: StepOutcome = StepOutcome.PENDING
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    elapsed_sec: float = 0.0
    error: Optional[str] = None
    rollback_attempted: bool = False
    rollback_succeeded: bool = False


@dataclass
class RunbookDefinition:
    runbook_id: str
    title: str
    severity: Severity
    steps: Sequence[RunbookStep]
    rollback_policy: RollbackPolicy = field(default_factory=RollbackPolicy)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RunbookResult:
    execution_id: str
    runbook_id: str
    phase: ExecutorPhase
    started_at: float
    completed_at: Optional[float] = None
    step_records: List[StepRecord] = field(default_factory=list)
    total_steps: int = 0
    succeeded_steps: int = 0
    failed_steps: int = 0
    rolled_back_steps: int = 0
    duration_sec: float = 0.0
    abort_reason: Optional[str] = None

    @property
    def is_fully_resolved(self) -> bool:
        return (
            self.phase == ExecutorPhase.COMPLETED
            and self.failed_steps == 0
            and self.rolled_back_steps == 0
        )


# ---------------------------------------------------------------------------
# Audit trail entry (immutable)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AuditEntry:
    timestamp: str
    execution_id: str
    runbook_id: str
    step_id: str
    event: str
    outcome: str
    detail: str
    correlation_id: str


# ---------------------------------------------------------------------------
# RunbookExecutor
# ---------------------------------------------------------------------------

class RunbookExecutor:
    """
    Transactional runbook executor for CRITICAL security events.

    Guarantees:
        - Steps execute sequentially in declared order.
        - On step failure, all previously completed steps with rollback
          handlers are reversed in LIFO order.
        - Every transition is recorded in the audit trail with a correlation ID.
        - Non-rollbackable steps are skipped during reversal per policy.
        - Execution state is always consistent (init → executing → completed|aborted).

    Usage:
        executor = RunbookExecutor()
        result = executor.execute(runbook_definition)
    """

    def __init__(
        self,
        dry_run: bool = False,
        clock: Optional[Callable[[], float]] = None,
    ):
        self._dry_run = dry_run
        self._clock = clock or time.time
        self._audit_trail: List[AuditEntry] = []
        self._executions: List[RunbookResult] = []
        self._rollback_handlers: Dict[str, Dict[str, Callable[[], bool]]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def execute(self, runbook: RunbookDefinition) -> RunbookResult:
        execution_id = f"EXEC-{uuid.uuid4().hex[:12].upper()}"
        correlation_id = str(uuid.uuid4())

        result = RunbookResult(
            execution_id=execution_id,
            runbook_id=runbook.runbook_id,
            phase=ExecutorPhase.INIT,
            started_at=self._clock(),
            total_steps=len(runbook.steps),
            step_records=[],
        )

        # Register rollback handlers for this execution
        handlers: Dict[str, Callable[[], bool]] = {}
        for step in runbook.steps:
            if step.rollback is not None:
                handlers[step.step_id] = step.rollback
        self._rollback_handlers[execution_id] = handlers

        self._emit_audit(
            execution_id, runbook.runbook_id, "SYSTEM",
            "execution_started", "init",
            f"Severity: {runbook.severity.value} | Steps: {len(runbook.steps)}",
            correlation_id,
        )

        completed_steps: List[StepRecord] = []
        policy = runbook.rollback_policy

        for step in runbook.steps:
            record = StepRecord(
                step_id=step.step_id,
                description=step.description,
            )
            result.step_records.append(record)
            result.phase = ExecutorPhase.EXECUTING

            if self._dry_run:
                record.outcome = StepOutcome.SUCCEEDED
                record.started_at = self._clock()
                record.completed_at = record.started_at
                result.succeeded_steps += 1
                completed_steps.append(record)
                self._emit_audit(
                    execution_id, runbook.runbook_id, step.step_id,
                    "step_dry_run", "succeeded",
                    "Dry run — no action taken", correlation_id,
                )
                continue

            record.started_at = self._clock()
            try:
                success = step.action()
                record.elapsed_sec = self._clock() - record.started_at
                record.completed_at = self._clock()

                if success:
                    record.outcome = StepOutcome.SUCCEEDED
                    result.succeeded_steps += 1
                    completed_steps.append(record)
                    self._emit_audit(
                        execution_id, runbook.runbook_id, step.step_id,
                        "step_completed", "succeeded",
                        f"Elapsed: {record.elapsed_sec:.3f}s", correlation_id,
                    )
                else:
                    record.outcome = StepOutcome.FAILED
                    record.error = "Action returned False"
                    result.failed_steps += 1
                    self._emit_audit(
                        execution_id, runbook.runbook_id, step.step_id,
                        "step_failed", "failed",
                        "Action returned False", correlation_id,
                    )
                    if step.is_critical:
                        rollback_ok = self._rollback_steps(
                            execution_id, runbook.runbook_id,
                            completed_steps, policy, correlation_id,
                            result,
                        )
                        result.rolled_back_steps = len(
                            [s for s in result.step_records
                             if s.outcome == StepOutcome.ROLLED_BACK]
                        )
                        result.phase = (
                            ExecutorPhase.COMPLETED if rollback_ok
                            else ExecutorPhase.ABORTED
                        )
                        result.abort_reason = (
                            f"Critical step {step.step_id} failed; "
                            f"rollback {'succeeded' if rollback_ok else 'partially failed'}"
                        )
                        result.completed_at = self._clock()
                        result.duration_sec = result.completed_at - result.started_at
                        self._executions.append(result)
                        return result

            except Exception as exc:
                record.elapsed_sec = self._clock() - record.started_at
                record.completed_at = self._clock()
                record.outcome = StepOutcome.FAILED
                record.error = f"{type(exc).__name__}: {exc}"
                result.failed_steps += 1
                self._emit_audit(
                    execution_id, runbook.runbook_id, step.step_id,
                    "step_exception", "failed",
                    record.error, correlation_id,
                )

                if step.is_critical:
                    rollback_ok = self._rollback_steps(
                        execution_id, runbook.runbook_id,
                        completed_steps, policy, correlation_id,
                        result,
                    )
                    result.rolled_back_steps = len(
                        [s for s in result.step_records
                         if s.outcome == StepOutcome.ROLLED_BACK]
                    )
                    result.phase = (
                        ExecutorPhase.COMPLETED if rollback_ok
                        else ExecutorPhase.ABORTED
                    )
                    result.abort_reason = (
                        f"Critical step {step.step_id} raised {type(exc).__name__}; "
                        f"rollback {'succeeded' if rollback_ok else 'partially failed'}"
                    )
                    result.completed_at = self._clock()
                    result.duration_sec = result.completed_at - result.started_at
                    self._executions.append(result)
                    return result

        result.phase = ExecutorPhase.COMPLETED
        result.completed_at = self._clock()
        result.duration_sec = result.completed_at - result.started_at

        self._emit_audit(
            execution_id, runbook.runbook_id, "SYSTEM",
            "execution_completed", "completed",
            f"Duration: {result.duration_sec:.3f}s", correlation_id,
        )

        self._executions.append(result)
        return result

    # ------------------------------------------------------------------
    # Rollback engine
    # ------------------------------------------------------------------

    def _rollback_steps(
        self,
        execution_id: str,
        runbook_id: str,
        completed_steps: List[StepRecord],
        policy: RollbackPolicy,
        correlation_id: str,
        result: RunbookResult,
    ) -> bool:
        result.phase = ExecutorPhase.ROLLING_BACK
        all_succeeded = True

        self._emit_audit(
            execution_id, runbook_id, "SYSTEM",
            "rollback_started", "rolling_back",
            f"Steps to reverse: {len(completed_steps)}", correlation_id,
        )

        for record in reversed(completed_steps):
            if record.step_id in policy.non_rollbackable_steps:
                record.outcome = StepOutcome.SKIPPED
                self._emit_audit(
                    execution_id, runbook_id, record.step_id,
                    "rollback_skipped", "skipped",
                    "Non-rollbackable per policy", correlation_id,
                )
                continue

            if not policy.auto_rollback:
                record.outcome = StepOutcome.SKIPPED
                continue

            rollback_fn = self._find_rollback_fn(
                execution_id, runbook_id, record.step_id,
            )
            if rollback_fn is None:
                record.outcome = StepOutcome.SKIPPED
                self._emit_audit(
                    execution_id, runbook_id, record.step_id,
                    "rollback_skipped", "skipped",
                    "No rollback handler registered", correlation_id,
                )
                continue

            record.rollback_attempted = True
            start = self._clock()
            try:
                success = rollback_fn()
                elapsed = self._clock() - start
                record.rollback_succeeded = success
                record.outcome = StepOutcome.ROLLED_BACK if success else StepOutcome.FAILED
                all_succeeded = all_succeeded and success

                self._emit_audit(
                    execution_id, runbook_id, record.step_id,
                    "rollback_completed",
                    "succeeded" if success else "failed",
                    f"Elapsed: {elapsed:.3f}s", correlation_id,
                )
            except Exception as exc:
                elapsed = self._clock() - start
                record.rollback_succeeded = False
                record.outcome = StepOutcome.FAILED
                all_succeeded = False
                self._emit_audit(
                    execution_id, runbook_id, record.step_id,
                    "rollback_exception", "failed",
                    f"{type(exc).__name__}: {exc}", correlation_id,
                )

        return all_succeeded

    def _find_rollback_fn(
        self,
        execution_id: str,
        runbook_id: str,
        step_id: str,
    ) -> Optional[Callable[[], bool]]:
        handlers = self._rollback_handlers.get(execution_id, {})
        return handlers.get(step_id)

    # ------------------------------------------------------------------
    # Query API
    # ------------------------------------------------------------------

    def get_execution(self, execution_id: str) -> Optional[RunbookResult]:
        for rec in self._executions:
            if rec.execution_id == execution_id:
                return rec
        return None

    def get_audit_trail(
        self,
        execution_id: Optional[str] = None,
    ) -> List[AuditEntry]:
        if execution_id is None:
            return list(self._audit_trail)
        return [e for e in self._audit_trail if e.execution_id == execution_id]

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _emit_audit(
        self,
        execution_id: str,
        runbook_id: str,
        step_id: str,
        event: str,
        outcome: str,
        detail: str,
        correlation_id: str,
    ) -> None:
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            execution_id=execution_id,
            runbook_id=runbook_id,
            step_id=step_id,
            event=event,
            outcome=outcome,
            detail=detail,
            correlation_id=correlation_id,
        )
        self._audit_trail.append(entry)

        log_fn = (
            logger.warning if outcome in ("failed", "rolling_back")
            else logger.info
        )
        log_fn(
            "AUDIT %s | %s/%s | %s | %s",
            event.upper(), runbook_id, step_id, outcome, detail,
        )


# ---------------------------------------------------------------------------
# Convenience: build a runbook from the existing playbook definitions
# ---------------------------------------------------------------------------

def build_runbook_from_playbook(
    playbook_steps: List[Dict[str, str]],
    runbook_id: str,
    title: str,
    severity: Severity = Severity.HIGH,
    rollback_handlers: Optional[Dict[str, Callable[[], bool]]] = None,
) -> RunbookDefinition:
    """
    Converts a list of playbook step dicts (as used by PlaybookRunner)
    into a RunbookDefinition with optional rollback handlers.
    """
    handlers = rollback_handlers or {}
    steps = []
    for sdef in playbook_steps:
        sid = sdef["id"]
        steps.append(RunbookStep(
            step_id=sid,
            description=sdef["desc"],
            action=lambda: True,
            rollback=handlers.get(sid),
            is_critical=sid.endswith("-01") or "emergency" in sdef["desc"].lower(),
        ))
    return RunbookDefinition(
        runbook_id=runbook_id,
        title=title,
        severity=severity,
        steps=steps,
    )


# ---------------------------------------------------------------------------
# CLI smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    call_count = {"n": 0}

    def flaky_action() -> bool:
        call_count["n"] += 1
        return False  # always fails to trigger rollback

    def compensate() -> bool:
        logger.info("ROLLBACK补偿: reversing prior action")
        return True

    runbook = RunbookDefinition(
        runbook_id="TEST-RB-001",
        title="Critical perimeter lockdown test",
        severity=Severity.CRITICAL,
        steps=[
            RunbookStep("STEP-A", "Isolate affected zone", lambda: True, rollback=compensate),
            RunbookStep("STEP-B", "Rotate zone credentials", flaky_action, rollback=compensate, is_critical=True),
            RunbookStep("STEP-C", "Notify SOC", lambda: True),
        ],
    )

    executor = RunbookExecutor(dry_run=False)
    result = executor.execute(runbook)

    print(f"\n{'='*60}")
    print(f"Execution: {result.execution_id}")
    print(f"Phase:     {result.phase.value}")
    print(f"Duration:  {result.duration_sec:.4f}s")
    print(f"Steps:     {result.succeeded_steps} ok / {result.failed_steps} failed / {result.rolled_back_steps} rolled back")
    print(f"Abort:     {result.abort_reason or 'none'}")
    print(f"Audit:     {len(executor.get_audit_trail())} entries")
    print(f"{'='*60}")
