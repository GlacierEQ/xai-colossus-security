#!/usr/bin/env python3
"""Unit tests for PlaybookRunner."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import unittest
from incident_response.playbook_runner import PlaybookRunner, IncidentType, StepStatus


class TestPlaybookRunner(unittest.TestCase):

    def setUp(self):
        self.runner = PlaybookRunner(dry_run=True)

    def test_thermal_runaway_all_steps_complete(self):
        rec = self.runner.run(IncidentType.THERMAL_RUNAWAY)
        self.assertTrue(rec.resolved)
        self.assertTrue(all(s.status == StepStatus.COMPLETED for s in rec.steps))

    def test_breach_detected_step_count(self):
        rec = self.runner.run(IncidentType.BREACH_DETECTED)
        self.assertEqual(len(rec.steps), 7)

    def test_emissions_violation_step_count(self):
        rec = self.runner.run(IncidentType.EMISSIONS_VIOLATION)
        self.assertEqual(len(rec.steps), 6)

    def test_power_anomaly_resolved(self):
        rec = self.runner.run(IncidentType.POWER_ANOMALY)
        self.assertTrue(rec.resolved)

    def test_incident_retrieval_by_id(self):
        rec = self.runner.run(IncidentType.COOLING_FAILURE, incident_id="TEST-001")
        fetched = self.runner.get_incident("TEST-001")
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.incident_id, "TEST-001")

    def test_unknown_incident_type_raises(self):
        # Construct a fake type not in PLAYBOOKS
        from unittest.mock import MagicMock
        fake_type = MagicMock()
        fake_type.value = "UNKNOWN"
        with self.assertRaises((ValueError, KeyError)):
            self.runner.run(fake_type)


if __name__ == "__main__":
    unittest.main()
