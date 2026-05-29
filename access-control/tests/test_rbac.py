#!/usr/bin/env python3
"""Unit tests for RBAC engine."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import unittest
from access_control.rbac_engine import (
    RBACEngine, Principal, AccessRequest, Role, Resource, Action
)


class TestRBACEngine(unittest.TestCase):

    def setUp(self):
        self.engine = RBACEngine()

    def _make_op(self, mfa=True):
        return Principal("op-1", Role.OPERATOR, mfa_verified=mfa)

    def _make_ro(self):
        return Principal("ro-1", Role.READONLY, mfa_verified=False)

    def _make_admin(self):
        return Principal("admin-1", Role.ADMIN, mfa_verified=True)

    def test_operator_can_execute_gpu(self):
        req = AccessRequest(self._make_op(), Resource.GPU_NODE, Action.EXECUTE)
        d = self.engine.evaluate(req)
        self.assertTrue(d.allowed)

    def test_readonly_cannot_write_gpu(self):
        req = AccessRequest(self._make_ro(), Resource.GPU_NODE, Action.WRITE)
        d = self.engine.evaluate(req)
        self.assertFalse(d.allowed)

    def test_operator_blocked_keyvault_without_mfa(self):
        op_no_mfa = Principal("op-2", Role.OPERATOR, mfa_verified=False)
        req = AccessRequest(op_no_mfa, Resource.KEY_VAULT, Action.READ)
        d = self.engine.evaluate(req)
        self.assertFalse(d.allowed)
        self.assertTrue(d.requires_mfa)

    def test_admin_can_delete_keyvault_with_mfa(self):
        req = AccessRequest(self._make_admin(), Resource.KEY_VAULT, Action.DELETE)
        d = self.engine.evaluate(req)
        self.assertTrue(d.allowed)

    def test_expired_session_denied(self):
        import time
        expired = Principal("exp-1", Role.ADMIN, mfa_verified=True,
                            valid_until=time.time() - 1)
        req = AccessRequest(expired, Resource.GPU_NODE, Action.READ)
        d = self.engine.evaluate(req)
        self.assertFalse(d.allowed)
        self.assertIn("expired", d.reason.lower())

    def test_audit_trail_populated(self):
        req = AccessRequest(self._make_ro(), Resource.GPU_NODE, Action.READ)
        self.engine.evaluate(req)
        trail = self.engine.get_audit_trail()
        self.assertEqual(len(trail), 1)
        self.assertEqual(trail[0]["subject"], "ro-1")


if __name__ == "__main__":
    unittest.main()
