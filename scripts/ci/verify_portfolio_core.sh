#!/usr/bin/env bash
set -euo pipefail

ARTIFACT_DIR=".verification-artifacts"
mkdir -p "${ARTIFACT_DIR}"

python -m pip install --disable-pip-version-check pytest pytest-asyncio
python -m compileall -q security/hydra_immune.py

python -m pytest \
  tests/test_hydra.py \
  tests/test_portfolio_truth_surface.py \
  --junitxml="${ARTIFACT_DIR}/pytest-junit.xml" \
  -q \
  | tee "${ARTIFACT_DIR}/pytest-core.txt"

python - <<'PY' | tee ".verification-artifacts/threat-lifecycle-scenario.json"
import asyncio
import json

from security.hydra_immune import HydraImmune


async def run() -> dict:
    now = 1_000.0

    def clock() -> float:
        return now

    engine = HydraImmune(clock=clock)
    detection = await engine.tick(
        {"zone-7": {"suspicious_activity": True}},
        tick_num=7,
    )

    assert detection["active_threats"] == 1
    assert detection["responses_proposed"] == 1
    assert detection["external_actions_executed"] == 0
    assert detection["actions"][0]["executed"] is False
    assert detection["actions"][0]["requires_external_authority"] is True
    assert detection["threat_level"] == "HIGH"

    before_resolution = engine.summary()
    assert before_resolution["active_threats"] == 1
    assert before_resolution["threat_level"] == "HIGH"

    resolved = engine.mark_resolved(
        "THREAT-7-zone-7",
        "incident:SEC-2026-0007",
    )
    assert resolved.resolved is True
    assert resolved.resolution_ref == "incident:SEC-2026-0007"

    after_resolution = engine.summary()
    assert after_resolution["active_threats"] == 0
    assert after_resolution["threat_level"] == "NONE"
    assert after_resolution["external_actions_executed"] == 0

    return {
        "schema": "glaciereq.security-threat-lifecycle.v1",
        "evidence_state": "PROPOSAL_AND_RECEIPTED_RESOLUTION_VERIFIED",
        "detection": detection,
        "before_resolution": before_resolution,
        "resolution": {
            "threat_id": resolved.threat_id,
            "resolution_ref": resolved.resolution_ref,
            "resolved": resolved.resolved,
        },
        "after_resolution": after_resolution,
        "limits": [
            "declared suspicious-zone input only",
            "response proposal only",
            "no external security control executed",
            "resolution reference is not externally validated by this core",
            "no live cluster or physical-security integration",
        ],
    }


print(json.dumps(asyncio.run(run()), indent=2))
PY

python - <<'PY'
import hashlib
import json
import os
import platform
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path

artifact_dir = Path(".verification-artifacts")
junit_path = artifact_dir / "pytest-junit.xml"
scenario_path = artifact_dir / "threat-lifecycle-scenario.json"

for path in (junit_path, scenario_path):
    if not path.exists() or path.stat().st_size == 0:
        raise SystemExit(f"Missing or empty verification output: {path}")

root = ET.parse(junit_path).getroot()
if root.tag == "testsuites":
    tests = sum(int(suite.attrib.get("tests", 0)) for suite in root.findall("testsuite"))
    failures = sum(int(suite.attrib.get("failures", 0)) for suite in root.findall("testsuite"))
    errors = sum(int(suite.attrib.get("errors", 0)) for suite in root.findall("testsuite"))
    skipped = sum(int(suite.attrib.get("skipped", 0)) for suite in root.findall("testsuite"))
else:
    tests = int(root.attrib.get("tests", 0))
    failures = int(root.attrib.get("failures", 0))
    errors = int(root.attrib.get("errors", 0))
    skipped = int(root.attrib.get("skipped", 0))

if tests < 1 or failures or errors:
    raise SystemExit(
        f"Invalid pytest receipt: tests={tests} failures={failures} errors={errors}"
    )

receipt = {
    "schema": "glaciereq.security.portfolio-core-receipt.v1",
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "repository": os.environ.get("GITHUB_REPOSITORY", "GlacierEQ/xai-colossus-security"),
    "tested_commit_or_merge_ref": os.environ.get("GITHUB_SHA", "local"),
    "source_head_commit": os.environ.get("GITHUB_HEAD_SHA", os.environ.get("GITHUB_SHA", "local")),
    "python": platform.python_version(),
    "evidence_state": "BOUNDED_SECURITY_PROPOSAL_ENGINE_TEST_VERIFIED",
    "tests": {
        "passed": tests - failures - errors - skipped,
        "total": tests,
        "failures": failures,
        "errors": errors,
        "skipped": skipped,
    },
    "verified": {
        "declared_signal_detection": True,
        "duplicate_suppression": True,
        "bounded_response_proposals": True,
        "external_authority_required": True,
        "external_actions_executed": 0,
        "receipt_required_for_resolution": True,
        "unresolved_threats_are_not_silently_pruned": True,
        "scenario_sha256": hashlib.sha256(scenario_path.read_bytes()).hexdigest(),
    },
    "private_related_repositories": {
        "alpha": {
            "repository": "GlacierEQ/xai-colossus-security-alpha",
            "inspected_commit": "a38d6b705b7e11ac6ecee927fce9ba884cb3723e",
            "state": "PRIVATE_PHYSICS_EXPERIMENT_BLOCKED_VALIDATION_AND_SAFETY_REVIEW",
        },
        "omega": {
            "repository": "GlacierEQ/xai-colossus-security-omega",
            "inspected_commit": "6e3b97637dec2c15a32eb87248f272ee4cd8e6bd",
            "state": "PRIVATE_PHYSICAL_ACCESS_EXPERIMENT_BLOCKED_HARDWARE_AND_SAFETY_REVIEW",
        },
    },
    "not_verified": [
        "authenticated telemetry sources",
        "network or IAM enforcement",
        "firmware rollback",
        "physical lockdown or mantrap control",
        "mTLS certificate authority management",
        "immutable production audit logging",
        "MCP, Mastermind, or APEX connectivity",
        "production security effectiveness",
        "private Alpha or Omega composition",
    ],
}

(artifact_dir / "portfolio-core-receipt.json").write_text(
    json.dumps(receipt, indent=2) + "\n",
    encoding="utf-8",
)
print(json.dumps(receipt, indent=2))
PY
