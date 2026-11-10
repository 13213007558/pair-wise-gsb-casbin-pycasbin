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
import json
import logging
import unittest

from casbin import (
    preview_policy_change,
    PolicyPreviewError,
    STATUS_RELIABLE,
    STATUS_UNRELIABLE,
    KIND_ADDED_ALLOW,
    KIND_WITHDRAWN_DENIAL,
    KIND_PRIORITY_ONLY,
)
from casbin.persist.adapters.string_adapter import StringAdapter

# Keep casbin's model/policy dump quiet during these tests without disabling
# loggers globally (other suites assert on casbin log records).
logging.getLogger("casbin").addHandler(logging.NullHandler())
logging.getLogger("casbin").setLevel(logging.CRITICAL)

BASIC_MODEL = """
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[role_definition]
g = _, _
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
"""

DENY_MODEL = """
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act, eft
[role_definition]
g = _, _
[policy_effect]
e = some(where (p.eft == allow)) && !some(where (p.eft == deny))
[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
"""

DOMAIN_MODEL = """
[request_definition]
r = sub, dom, obj, act
[policy_definition]
p = sub, dom, obj, act
[role_definition]
g = _, _, _
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act
"""

PRIORITY_MODEL = """
[request_definition]
r = sub, obj, act
[policy_definition]
p = priority, sub, obj, act, eft
[role_definition]
g = _, _
[policy_effect]
e = priority(p.eft) || deny
[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
"""

FUNCTION_MODEL = """
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = startsWith(r.sub, p.sub) && r.obj == p.obj && p.act == r.act
"""


class TestPolicyPreview(unittest.TestCase):
    def test_added_allow_with_rule_and_role_evidence(self):
        old_policy = """
p, alice, data1, read
g, alice, data1_owner
"""
        new_policy = """
p, alice, data1, read
p, alice, data1, write
g, alice, data1_owner
"""
        report = preview_policy_change(
            old_policy,
            new_policy,
            [("alice", "data1", "read"), ("alice", "data1", "write"), ("bob", "data1", "read")],
            model=BASIC_MODEL,
        )
        self.assertEqual(report["status"], STATUS_RELIABLE)
        self.assertEqual(report["summary"][KIND_ADDED_ALLOW], 1)
        self.assertEqual(report["summary"]["unchanged"], 2)
        self.assertEqual(report["sample_size"], 3)

        change = report["changes"][0]
        self.assertEqual(change["kind"], KIND_ADDED_ALLOW)
        self.assertEqual(change["old_decision"], "deny")
        self.assertEqual(change["new_decision"], "allow")
        self.assertEqual(change["new_evidence"]["basis"]["rule"], ["alice", "data1", "write"])
        self.assertEqual(change["new_evidence"]["role_chain"], ["data1_owner"])
        self.assertEqual(
            change["new_evidence"]["grouping_rules"], [["g", "alice", "data1_owner"]]
        )
        self.assertIn("新增允许", change["kind_label"])
        self.assertIn("data1", change["reasons"][0])
        self.assertEqual(
            report["policy_diff"]["added_rules"], [("p", "alice", "data1", "write")]
        )
        # Unchanged requests are aggregated, not listed in full.
        self.assertEqual(
            {(group["decision"], group["count"]) for group in report["unchanged"]},
            {("allow", 1), ("deny", 1)},
        )
        self.assertNotIn("等价", report["scope_note"].replace("不代表两套策略完全等价", ""))

    def test_withdrawn_denial_explicit_deny_rule(self):
        old_policy = """
p, alice, data1, write, allow
g, alice, writers
"""
        new_policy = """
p, alice, data1, write, allow
p, writers, data1, write, deny
g, alice, writers
"""
        report = preview_policy_change(
            old_policy, new_policy, [("alice", "data1", "write")], model=DENY_MODEL
        )
        self.assertEqual(report["status"], STATUS_RELIABLE)
        change = report["changes"][0]
        self.assertEqual(change["kind"], KIND_WITHDRAWN_DENIAL)
        self.assertEqual(change["old_decision"], "allow")
        self.assertEqual(change["new_decision"], "deny")
        self.assertEqual(change["new_evidence"]["basis"]["effect"], "deny")
        self.assertEqual(
            change["new_evidence"]["basis"]["rule"], ["writers", "data1", "write", "deny"]
        )
        self.assertEqual(change["new_evidence"]["role_chain"], ["writers"])

    def test_withdrawn_denial_implicit_when_rule_removed(self):
        old_policy = "p, alice, data1, read"
        new_policy = "p, alice, data2, read"
        report = preview_policy_change(
            old_policy, new_policy, [("alice", "data1", "read")], model=BASIC_MODEL
        )
        change = report["changes"][0]
        self.assertEqual(change["kind"], KIND_WITHDRAWN_DENIAL)
        self.assertEqual(change["new_evidence"]["basis"]["type"], "no_matching_policy")
        self.assertIn("隐式拒绝", change["reasons"][0])

    def test_priority_only_keeps_decision_switches_rule(self):
        old_policy = """
p, 1, alice, data1, read, allow
p, 10, staff, data1, read, allow
g, alice, staff
"""
        new_policy = """
p, 1, alice, data1, read, allow
p, 0, staff, data1, read, allow
g, alice, staff
"""
        report = preview_policy_change(
            old_policy, new_policy, [("alice", "data1", "read")], model=PRIORITY_MODEL
        )
        self.assertEqual(report["status"], STATUS_RELIABLE)
        self.assertEqual(len(report["changes"]), 1)
        change = report["changes"][0]
        self.assertEqual(change["kind"], KIND_PRIORITY_ONLY)
        self.assertEqual(change["old_decision"], change["new_decision"])
        self.assertEqual(change["old_evidence"]["basis"]["rule"][1], "alice")
        self.assertEqual(change["new_evidence"]["basis"]["rule"][1], "staff")
        self.assertEqual(change["new_evidence"]["basis"]["priority"], 0)

    def test_domain_scoped_role_inheritance(self):
        old_policy = """
p, admin, tenant1, data1, read
g, alice, admin, tenant1
"""
        new_policy = """
p, admin, tenant1, data1, read
p, admin, tenant2, data1, read
g, alice, admin, tenant1
g, bob, admin, tenant2
"""
        report = preview_policy_change(
            old_policy,
            new_policy,
            [("alice", "tenant1", "data1", "read"), ("bob", "tenant2", "data1", "read")],
            model=DOMAIN_MODEL,
        )
        self.assertEqual(report["summary"][KIND_ADDED_ALLOW], 1)
        change = next(item for item in report["changes"] if item["request"][0] == "bob")
        self.assertEqual(change["request"][1], "tenant2")
        self.assertEqual(change["new_evidence"]["role_chain"], ["admin"])
        self.assertEqual(
            change["new_evidence"]["grouping_rules"], [["g", "bob", "admin", "tenant2"]]
        )
        # alice's tenant1 link must not leak into the tenant2 explanation.
        alice = next(group for group in report["unchanged"] if group["decision"] == "allow")
        self.assertEqual(alice["request_indices"], [0])

    def test_inherited_role_chain_is_transitive(self):
        old_policy = """
p, admin, data1, read
g, alice, editor
g, editor, admin
"""
        new_policy = """
p, admin, data1, read
p, admin, data1, write
g, alice, editor
g, editor, admin
"""
        report = preview_policy_change(
            old_policy, new_policy, [("alice", "data1", "write")], model=BASIC_MODEL
        )
        self.assertEqual(report["status"], STATUS_RELIABLE)
        change = report["changes"][0]
        self.assertEqual(change["kind"], KIND_ADDED_ALLOW)
        self.assertEqual(change["new_evidence"]["role_chain"], ["editor", "admin"])

    def test_custom_function_success_is_isolated_and_reliable(self):
        def starts_with(subject, prefix):
            return subject.startswith(prefix)

        report = preview_policy_change(
            "p, al, data1, read",
            "p, al, data1, read\np, al, data1, write",
            [("alice", "data1", "read"), ("alice", "data1", "write")],
            model=FUNCTION_MODEL,
            functions={"startsWith": starts_with},
        )
        self.assertEqual(report["status"], STATUS_RELIABLE)
        self.assertEqual(report["summary"][KIND_ADDED_ALLOW], 1)
        json.dumps(report, ensure_ascii=False)

    def test_custom_function_failure_makes_preview_unreliable(self):
        def boom(subject, obj):
            raise RuntimeError("redis connection lost")

        policy = "p, alice, data1, read"
        report = preview_policy_change(
            policy,
            policy,
            [("alice", "data1", "read")],
            model="""
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = customCheck(r.sub, r.obj) && p.sub == r.sub
""",
            functions={"customCheck": boom},
        )
        self.assertEqual(report["status"], STATUS_UNRELIABLE)
        self.assertEqual(report["summary"]["error"], 1)
        self.assertEqual(report["changes"], [])
        self.assertTrue(
            any(reason.get("function") == "customCheck" for reason in report["unreliable_reasons"])
        )

    def test_declared_stateful_function_is_unreliable(self):
        def stateful(subject, obj):
            return True

        policy = "p, alice, data1, read"
        report = preview_policy_change(
            policy,
            policy,
            [("alice", "data1", "read")],
            model="""
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = customCheck(r.sub, r.obj) && p.sub == r.sub
""",
            functions={"customCheck": stateful},
            stateful_functions=["customCheck"],
        )
        self.assertEqual(report["status"], STATUS_UNRELIABLE)
        self.assertTrue(
            any(
                reason.get("reason") == "function_depends_on_external_state"
                for reason in report["unreliable_reasons"]
            )
        )

    def test_broken_policy_reports_load_or_enforcement_failure(self):
        policy = "p, alice, data1, read"
        report = preview_policy_change(
            policy,
            "p, only, two\np, alice, data1, read",
            [("alice", "data1", "read")],
            model=BASIC_MODEL,
        )
        self.assertEqual(report["status"], STATUS_UNRELIABLE)
        self.assertEqual(report["summary"]["error"], 1)
        self.assertTrue(report["unreliable_reasons"])

    def test_broken_model_attributes_failing_side(self):
        report = preview_policy_change(
            "p, alice, data1, read",
            "p, alice, data1, read",
            [("alice", "data1", "read")],
            old_model=BASIC_MODEL,
            new_model="[request_definition]\nr = sub, obj, act\n[matchers]\nm = p.sub\n",
        )
        self.assertEqual(report["status"], STATUS_UNRELIABLE)
        reason = report["unreliable_reasons"][0]
        self.assertEqual(reason["side"], "new")
        self.assertEqual(reason["reason"], "policy_or_model_load_failed")

    def test_missing_model_raises_validation_error(self):
        with self.assertRaises(PolicyPreviewError):
            preview_policy_change("p, a, b, c", "p, a, b, c", [("a", "b", "c")])

    def test_enforcer_instance_cannot_be_smuggled_in_as_function(self):
        from casbin import Enforcer, Model
        from casbin.persist.adapters.string_adapter import StringAdapter

        model = Model()
        model.load_model_from_text(BASIC_MODEL)
        enforcer = Enforcer(model, StringAdapter("p, alice, data1, read"))
        with self.assertRaises(PolicyPreviewError):
            preview_policy_change(
                "p, alice, data1, read",
                "p, alice, data1, read",
                [("alice", "data1", "read")],
                model=BASIC_MODEL,
                functions={"g": enforcer},
            )

    def test_policy_rules_accepted_as_lists(self):
        report = preview_policy_change(
            [["p", "alice", "data1", "read"]],
            [["p", "alice", "data1", "read"], ["p", "alice", "data1", "write"]],
            [("alice", "data1", "write")],
            model="""
[request_definition]
r = sub, obj, act
[policy_definition]
p = sub, obj, act
[policy_effect]
e = some(where (p.eft == allow))
[matchers]
m = p.sub == r.sub && p.obj == r.obj && p.act == r.act
""",
        )
        self.assertEqual(report["summary"][KIND_ADDED_ALLOW], 1)

    def test_preview_never_writes_through_adapter(self):
        class FailingAdapter(StringAdapter):
            def save_policy(self, model):
                raise AssertionError("preview must not save policy")

            def add_policy(self, sec, ptype, rule):
                raise AssertionError("preview must not write policy")

        # The preview builds its own in-memory adapters; an adapter instance
        # passed nowhere must remain untouched, and no watcher exists.
        sentinel = FailingAdapter("p, alice, data1, read")
        report = preview_policy_change(
            "p, alice, data1, read",
            "p, alice, data1, read\np, alice, data1, write",
            [("alice", "data1", "write")],
            model=BASIC_MODEL,
        )
        self.assertEqual(report["status"], STATUS_RELIABLE)
        self.assertEqual(sentinel.line, "p, alice, data1, read")

    def test_model_change_is_detected_and_compared(self):
        new_model = BASIC_MODEL.replace("r.obj == p.obj", "keyMatch(r.obj, p.obj)")
        policy = "p, alice, /data/*, read"
        report = preview_policy_change(
            policy,
            policy,
            [("alice", "/data/1", "read"), ("alice", "/other", "read")],
            old_model=BASIC_MODEL,
            new_model=new_model,
        )
        self.assertEqual(report["status"], STATUS_RELIABLE)
        self.assertTrue(report["model_changed"])
        self.assertEqual(report["summary"][KIND_ADDED_ALLOW], 1)
        change = report["changes"][0]
        self.assertEqual(change["request"], ["alice", "/data/1", "read"])

    def test_sample_scope_is_never_claimed_equivalent(self):
        report = preview_policy_change(
            "p, alice, data1, read",
            "p, alice, data1, read",
            [("alice", "data1", "read")],
            model=BASIC_MODEL,
        )
        self.assertEqual(report["scope"], "sample_only")
        self.assertIn("仅覆盖提供的请求样本", report["scope_note"])
        self.assertEqual(report["changes"], [])
        self.assertEqual(report["summary"]["unchanged"], 1)


if __name__ == "__main__":
    unittest.main()
