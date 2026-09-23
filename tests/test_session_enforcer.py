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
from unittest import TestCase

import casbin
from casbin import RoleSession, SessionError
from casbin.persist.adapters import FileAdapter


def get_examples(path):
    examples_path = os.path.split(os.path.realpath(__file__))[0] + "/../examples/"
    return os.path.abspath(examples_path + path)


# 制单员(maker) and 复核员(reviewer) both inherit 员工(employee).
# alice owns maker and reviewer in "finance"; bob owns chief, which inherits
# both maker and reviewer; carol only owns maker in "hr".
DOMAIN_POLICY = """p, employee, finance, ledger, read
p, maker, finance, voucher, create
p, reviewer, finance, voucher, approve
p, maker, hr, ticket, read
p, alice, finance, profile, read

g, alice, maker, finance
g, alice, reviewer, finance
g, maker, employee, finance
g, reviewer, employee, finance
g, bob, chief, finance
g, chief, maker, finance
g, chief, reviewer, finance
g, carol, maker, hr
"""


class RecordingAdapter(FileAdapter):
    """records every policy mutation that would reach the persistent storage."""

    def __init__(self, file_path):
        super().__init__(file_path)
        self.mutations = []

    def add_policy(self, sec, ptype, rule):
        self.mutations.append(("add", ptype, list(rule)))
        return super().add_policy(sec, ptype, rule)

    def remove_policy(self, sec, ptype, rule):
        self.mutations.append(("remove", ptype, list(rule)))
        return super().remove_policy(sec, ptype, rule)

    def remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        self.mutations.append(("remove_filtered", ptype, [field_index, list(field_values)]))
        return super().remove_filtered_policy(sec, ptype, field_index, *field_values)

    def save_policy(self, model):
        self.mutations.append(("save", "", []))
        return super().save_policy(model)


def new_domain_enforcer(adapter=None):
    if adapter is None:
        fd, path = tempfile.mkstemp(prefix="pycasbin-session-", suffix=".csv")
        with os.fdopen(fd, "w") as f:
            f.write(DOMAIN_POLICY)
        adapter = FileAdapter(path)
    return casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)


class TestRoleSession(TestCase):
    def test_valid_single_role_uses_inheritance_only(self):
        e = new_domain_enforcer()
        session = e.new_role_session("alice", ["maker"], domain="finance")

        # maker permission
        self.assertTrue(e.enforce(session, "alice", "finance", "voucher", "create"))
        # reviewer permission is not active
        self.assertFalse(e.enforce(session, "alice", "finance", "voucher", "approve"))
        # employee permission is inherited by maker
        self.assertTrue(e.enforce(session, "alice", "finance", "ledger", "read"))

    def test_direct_permissions_require_explicit_switch(self):
        e = new_domain_enforcer()
        session = e.new_role_session("alice", ["maker"], domain="finance")
        # direct policy p, alice... must not silently act as a default role
        self.assertFalse(e.enforce(session, "alice", "finance", "profile", "read"))

        session_with_direct = e.new_role_session("alice", ["maker"], domain="finance", allow_direct_permissions=True)
        self.assertTrue(e.enforce(session_with_direct, "alice", "finance", "profile", "read"))

    def test_conflicting_roles_are_rejected(self):
        e = new_domain_enforcer()
        e.add_session_role_mutex_group(["maker", "reviewer"], max_active=1)

        with self.assertRaises(SessionError):
            e.new_role_session("alice", ["maker", "reviewer"], domain="finance")

        # one of them alone is fine
        session = e.new_role_session("alice", ["maker"], domain="finance")
        self.assertTrue(e.enforce(session, "alice", "finance", "voucher", "create"))

    def test_inherited_roles_participate_in_conflict(self):
        e = new_domain_enforcer()
        e.add_session_role_mutex_group(["maker", "reviewer"], max_active=1)

        # chief inherits both maker and reviewer, so activating chief alone conflicts
        with self.assertRaises(SessionError):
            e.new_role_session("bob", ["chief"], domain="finance")

        # no restriction without mutex groups
        e.clear_session_role_mutex_groups()
        session = e.new_role_session("bob", ["chief"], domain="finance")
        self.assertTrue(e.enforce(session, "bob", "finance", "voucher", "create"))

    def test_conflict_introduced_later_is_rechecked(self):
        e = new_domain_enforcer()
        e.add_session_role_mutex_group(["maker", "reviewer"], max_active=1)
        session = e.new_role_session("alice", ["maker"], domain="finance")
        self.assertTrue(e.enforce(session, "alice", "finance", "voucher", "create"))

        e.enable_auto_save(False)
        # maker now also inherits reviewer: the effective roles become conflicting
        self.assertTrue(e.add_grouping_policy("maker", "reviewer", "finance"))
        self.assertFalse(e.enforce(session, "alice", "finance", "voucher", "create"))

    def test_cross_domain_same_named_role(self):
        e = new_domain_enforcer()

        # carol owns maker in hr, not in finance
        with self.assertRaises(SessionError):
            e.new_role_session("carol", ["maker"], domain="finance")

        hr_session = e.new_role_session("carol", ["maker"], domain="hr")
        self.assertTrue(e.enforce(hr_session, "carol", "hr", "ticket", "read"))
        # same-named role in another domain grants nothing
        self.assertFalse(e.enforce(hr_session, "carol", "finance", "voucher", "create"))

        finance_session = e.new_role_session("alice", ["maker"], domain="finance")
        self.assertFalse(e.enforce(finance_session, "alice", "hr", "ticket", "read"))

    def test_activation_is_rechecked_after_revocation(self):
        e = new_domain_enforcer()
        session = e.new_role_session("alice", ["maker"], domain="finance")
        self.assertTrue(e.enforce(session, "alice", "finance", "voucher", "create"))

        e.enable_auto_save(False)
        # the maker grant is revoked while the old session is still around
        self.assertTrue(e.remove_filtered_grouping_policy(0, "alice", "maker", "finance"))
        self.assertFalse(e.enforce(session, "alice", "finance", "voucher", "create"))
        with self.assertRaises(SessionError):
            e.new_role_session("alice", ["maker"], domain="finance")

    def test_unowned_role_cannot_be_activated(self):
        e = new_domain_enforcer()
        with self.assertRaises(SessionError):
            e.new_role_session("alice", ["ghost"], domain="finance")
        with self.assertRaises(SessionError):
            e.new_role_session("carol", ["reviewer"], domain="hr")

    def test_sessions_do_not_interfere(self):
        e = new_domain_enforcer()
        maker_session = e.new_role_session("alice", ["maker"], domain="finance")
        reviewer_session = e.new_role_session("alice", ["reviewer"], domain="finance")

        for _ in range(3):
            self.assertTrue(e.enforce(maker_session, "alice", "finance", "voucher", "create"))
            self.assertFalse(e.enforce(maker_session, "alice", "finance", "voucher", "approve"))
            self.assertFalse(e.enforce(reviewer_session, "alice", "finance", "voucher", "create"))
            self.assertTrue(e.enforce(reviewer_session, "alice", "finance", "voucher", "approve"))

        # shared role graph is untouched
        self.assertEqual(set(e.get_roles_for_user_in_domain("alice", "finance")), {"maker", "reviewer"})
        self.assertEqual(e.get_roles_for_user_in_domain("bob", "finance"), ["chief"])

    def test_request_without_session_keeps_rbac_behavior(self):
        e = new_domain_enforcer()
        # both roles active under normal RBAC
        self.assertTrue(e.enforce("alice", "finance", "voucher", "create"))
        self.assertTrue(e.enforce("alice", "finance", "voucher", "approve"))
        self.assertTrue(e.enforce("alice", "finance", "ledger", "read"))
        # directly assigned permissions work without a session
        self.assertTrue(e.enforce("alice", "finance", "profile", "read"))
        self.assertFalse(e.enforce("alice", "finance", "ticket", "read"))

    def test_persistent_policy_is_not_mutated_by_sessions(self):
        fd, path = tempfile.mkstemp(prefix="pycasbin-session-", suffix=".csv")
        with os.fdopen(fd, "w") as f:
            f.write(DOMAIN_POLICY)
        with open(path, "r") as f:
            original_file = f.read()

        adapter = RecordingAdapter(path)
        e = casbin.Enforcer(get_examples("rbac_with_domains_model.conf"), adapter)
        e.add_session_role_mutex_group(["maker", "reviewer"], max_active=1)

        policy_before = sorted(tuple(p) for p in e.get_policy())
        grouping_before = sorted(tuple(g) for g in e.get_grouping_policy())

        maker_session = e.new_role_session("alice", ["maker"], domain="finance")
        direct_session = e.new_role_session("alice", ["reviewer"], domain="finance", allow_direct_permissions=True)
        e.enforce(maker_session, "alice", "finance", "voucher", "create")
        e.enforce(maker_session, "alice", "finance", "voucher", "approve")
        e.enforce(direct_session, "alice", "finance", "profile", "read")
        try:
            e.new_role_session("alice", ["maker", "reviewer"], domain="finance")
        except SessionError:
            pass

        self.assertEqual(adapter.mutations, [])
        self.assertEqual(policy_before, sorted(tuple(p) for p in e.get_policy()))
        self.assertEqual(grouping_before, sorted(tuple(g) for g in e.get_grouping_policy()))
        with open(path, "r") as f:
            self.assertEqual(original_file, f.read())

    def test_session_without_domain_model(self):
        e = casbin.Enforcer(get_examples("rbac_model.conf"), get_examples("rbac_policy.csv"))
        session = e.new_role_session("alice", ["data2_admin"])
        self.assertTrue(e.enforce(session, "alice", "data2", "read"))
        self.assertFalse(e.enforce(session, "alice", "data1", "read"))
        with self.assertRaises(SessionError):
            e.new_role_session("alice", ["nobody"])

    def test_role_session_is_value_object(self):
        e = new_domain_enforcer()
        session = e.new_role_session("alice", ["maker", "reviewer"], domain="finance")
        self.assertEqual(session.roles, frozenset(["maker", "reviewer"]))
        self.assertIsInstance(session, RoleSession)
