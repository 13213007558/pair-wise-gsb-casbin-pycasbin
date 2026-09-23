# Copyright 2026 The casbin Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import tempfile
import unittest

import casbin
from tests.test_enforcer import get_examples

MODEL = get_examples("rbac_with_domains_model.conf")

POLICY_LINES = [
    "p, employee, finance, voucher, read",
    "p, maker, finance, voucher, create",
    "p, checker, finance, voucher, approve",
    "p, alice, finance, report, read",
    "p, maker, audit, log, read",
    "g, alice, maker, finance",
    "g, alice, checker, finance",
    "g, maker, employee, finance",
    "g, checker, employee, finance",
    "g, alice, maker, audit",
]


def new_enforcer():
    """builds an in-memory enforcer with the maker/checker/employee graph.

    alice owns both maker and checker in domain "finance"; maker and checker
    both inherit employee. alice also owns maker in domain "audit".
    """
    e = casbin.Enforcer(MODEL)
    for line in POLICY_LINES:
        sec, rule = line.split(", ", 1)
        if sec == "p":
            e.add_policy(*rule.split(", "))
        else:
            e.add_grouping_policy(*rule.split(", "))
    return e


class TestRoleSession(unittest.TestCase):
    def test_single_role_session(self):
        e = new_enforcer()
        session = e.new_role_session("alice", ["maker"], "finance")

        self.assertTrue(e.enforce(session, "alice", "finance", "voucher", "create"))
        # employee permission is reachable through inheritance
        self.assertTrue(e.enforce(session, "alice", "finance", "voucher", "read"))
        # checker was not activated in this session
        self.assertFalse(e.enforce(session, "alice", "finance", "voucher", "approve"))

    def test_checker_session(self):
        e = new_enforcer()
        session = e.new_role_session("alice", ["checker"], "finance")

        self.assertTrue(e.enforce(session, "alice", "finance", "voucher", "approve"))
        self.assertTrue(e.enforce(session, "alice", "finance", "voucher", "read"))
        self.assertFalse(e.enforce(session, "alice", "finance", "voucher", "create"))

    def test_conflicting_double_roles(self):
        e = new_enforcer()
        e.add_exclusive_role_group(["maker", "checker"], max_active=1)

        with self.assertRaises(ValueError):
            e.new_role_session("alice", ["maker", "checker"], "finance")

        # each role on its own is still fine
        e.new_role_session("alice", ["maker"], "finance")
        e.new_role_session("alice", ["checker"], "finance")

    def test_inheritance_caused_conflict(self):
        e = new_enforcer()
        # employee is only reachable through inheritance, never activated directly
        e.add_exclusive_role_group(["employee", "checker"], max_active=1)

        # maker inherits employee, checker is activated: effective roles are
        # {maker, checker, employee}, which puts 2 group members in the session
        with self.assertRaises(ValueError):
            e.new_role_session("alice", ["maker", "checker"], "finance")

        # maker alone only pulls in employee: exactly 1 group member, allowed
        session = e.new_role_session("alice", ["maker"], "finance")
        self.assertTrue(e.enforce(session, "alice", "finance", "voucher", "create"))

    def test_cross_domain_same_name_role(self):
        e = new_enforcer()
        audit_session = e.new_role_session("alice", ["maker"], "audit")
        finance_session = e.new_role_session("alice", ["maker"], "finance")

        # the "maker" role exists in both domains but permissions stay separate
        self.assertTrue(e.enforce(audit_session, "alice", "audit", "log", "read"))
        self.assertFalse(e.enforce(audit_session, "alice", "finance", "voucher", "create"))
        self.assertTrue(e.enforce(finance_session, "alice", "finance", "voucher", "create"))
        self.assertFalse(e.enforce(finance_session, "alice", "audit", "log", "read"))

        # alice has no checker in the audit domain
        with self.assertRaises(ValueError):
            e.new_role_session("alice", ["checker"], "audit")

    def test_mid_session_revocation(self):
        e = new_enforcer()
        session = e.new_role_session("alice", ["maker"], "finance")
        self.assertTrue(e.enforce(session, "alice", "finance", "voucher", "create"))

        # the grant is revoked after the session was created
        e.delete_roles_for_user_in_domain("alice", "maker", "finance")

        # the old session must not keep working
        self.assertFalse(e.enforce(session, "alice", "finance", "voucher", "create"))
        with self.assertRaises(ValueError):
            e.new_role_session("alice", ["maker"], "finance")

    def test_inheritance_revocation_mid_session(self):
        e = new_enforcer()
        session = e.new_role_session("alice", ["maker"], "finance")
        self.assertTrue(e.enforce(session, "alice", "finance", "voucher", "read"))

        # maker no longer inherits employee: the inherited permission is gone
        e.delete_roles_for_user_in_domain("maker", "employee", "finance")
        self.assertFalse(e.enforce(session, "alice", "finance", "voucher", "read"))
        # the directly activated role still works
        self.assertTrue(e.enforce(session, "alice", "finance", "voucher", "create"))

    def test_direct_permissions_switch(self):
        e = new_enforcer()

        # by default, permissions assigned to the user directly are not available
        session = e.new_role_session("alice", ["maker"], "finance")
        self.assertFalse(e.enforce(session, "alice", "finance", "report", "read"))

        # the explicit switch turns them on
        session = e.new_role_session("alice", ["maker"], "finance", allow_direct_permissions=True)
        self.assertTrue(e.enforce(session, "alice", "finance", "report", "read"))
        self.assertTrue(e.enforce(session, "alice", "finance", "voucher", "create"))

    def test_request_without_session_keeps_original_behavior(self):
        e = new_enforcer()
        e.add_exclusive_role_group(["maker", "checker"], max_active=1)

        # no session: the original RBAC behavior sees every role of the user
        self.assertTrue(e.enforce("alice", "finance", "voucher", "create"))
        self.assertTrue(e.enforce("alice", "finance", "voucher", "approve"))
        self.assertTrue(e.enforce("alice", "finance", "report", "read"))

    def test_concurrent_sessions_do_not_rewrite_role_graph(self):
        e = new_enforcer()
        maker_session = e.new_role_session("alice", ["maker"], "finance")
        checker_session = e.new_role_session("alice", ["checker"], "finance")

        for _ in range(3):
            self.assertTrue(e.enforce(maker_session, "alice", "finance", "voucher", "create"))
            self.assertFalse(e.enforce(maker_session, "alice", "finance", "voucher", "approve"))
            self.assertTrue(e.enforce(checker_session, "alice", "finance", "voucher", "approve"))
            self.assertFalse(e.enforce(checker_session, "alice", "finance", "voucher", "create"))

        # the shared role manager is untouched by the sessions
        self.assertEqual(
            sorted(e.get_roles_for_user_in_domain("alice", "finance")),
            ["checker", "maker"],
        )
        self.assertEqual(e.get_roles_for_user_in_domain("maker", "finance"), ["employee"])
        self.assertTrue(e.enforce("alice", "finance", "voucher", "approve"))

    def test_unowned_role_rejected(self):
        e = new_enforcer()

        # a role alice never had
        with self.assertRaises(ValueError):
            e.new_role_session("alice", ["admin"], "finance")

        # employee is only inherited through maker, not directly assigned
        with self.assertRaises(ValueError):
            e.new_role_session("alice", ["employee"], "finance")

        # a session carrying an unowned role is denied at enforce time too
        session = casbin.RoleSession("alice", ["admin"], "finance")
        self.assertFalse(e.enforce(session, "alice", "finance", "voucher", "create"))

    def test_session_bound_to_its_user_and_domain(self):
        e = new_enforcer()
        session = e.new_role_session("alice", ["maker"], "finance")

        # the session only answers for its own user and domain
        self.assertFalse(e.enforce(session, "bob", "finance", "voucher", "create"))
        self.assertFalse(e.enforce(session, "alice", "audit", "log", "read"))

    def test_adapter_policy_not_mutated_by_sessions(self):
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as f:
            f.write("\n".join(POLICY_LINES) + "\n")
            policy_path = f.name
        self.addCleanup(os.remove, policy_path)

        with open(policy_path) as f:
            original_content = f.read()

        e = casbin.Enforcer(MODEL, policy_path)
        p_before = e.get_policy()
        g_before = e.get_grouping_policy()

        e.add_exclusive_role_group(["maker", "checker"], max_active=1)
        maker_session = e.new_role_session("alice", ["maker"], "finance")
        checker_session = e.new_role_session("alice", ["checker"], "finance")
        direct_session = e.new_role_session("alice", ["maker"], "finance", allow_direct_permissions=True)

        e.enforce(maker_session, "alice", "finance", "voucher", "create")
        e.enforce(checker_session, "alice", "finance", "voucher", "approve")
        e.enforce(direct_session, "alice", "finance", "report", "read")

        # neither the in-memory policy nor the persisted file may change
        self.assertEqual(e.get_policy(), p_before)
        self.assertEqual(e.get_grouping_policy(), g_before)
        with open(policy_path) as f:
            self.assertEqual(f.read(), original_content)

        # saving after session use must round-trip the original policy
        e.save_policy()
        with open(policy_path) as f:
            self.assertEqual(f.read().splitlines(), original_content.splitlines())


if __name__ == "__main__":
    unittest.main()
