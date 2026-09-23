# Copyright 2021 The casbin Authors. All Rights Reserved.
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
import os
import tempfile
from unittest import TestCase

import casbin
from casbin.rbac import default_role_manager

MODEL_TEXT = """
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = priority, sub, obj, act, eft

[role_definition]
g = _, _, _, (_, _)

[policy_effect]
e = priority(p.eft) || deny

[matchers]
m = g(r.sub, p.sub, r.dom) && tenant_ok(r.dom) && r.obj == p.obj && r.act == p.act
"""

# alice inherits data_admin via two paths in domain1:
#   alice -> team_a -> data_admin            (conditional edge team_a -> data_admin)
#   alice -> team_b -> group_b -> data_admin
POLICY_TEXT = """
p, 1, data_admin, data1, read, allow
p, 2, alice, data1, read, deny
p, 1, data_admin, data2, read, deny

g, alice, team_a, domain1, _, _
g, team_a, data_admin, domain1, _, _
g, alice, team_b, domain1, _, _
g, team_b, group_b, domain1, _, _
g, group_b, data_admin, domain1, _, _
"""


class TestExplain(TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.model_path = os.path.join(self._tmpdir.name, "model.conf")
        self.policy_path = os.path.join(self._tmpdir.name, "policy.csv")
        with open(self.model_path, "w") as f:
            f.write(MODEL_TEXT)
        with open(self.policy_path, "w") as f:
            f.write(POLICY_TEXT)

        self.cond_calls = 0
        self.custom_calls = 0

    def tearDown(self):
        self._tmpdir.cleanup()

    def _new_enforcer(self):
        e = casbin.Enforcer(self.model_path, self.policy_path)

        def cond(*args):
            self.cond_calls += 1
            return True

        def tenant_ok(dom):
            self.custom_calls += 1
            return dom == "domain1"

        e.add_named_domain_link_condition_func("g", "team_a", "data_admin", "domain1", cond)
        e.add_function("tenant_ok", tenant_ok)
        return e

    def test_explain_matches_enforce_and_callback_counts(self):
        e = self._new_enforcer()
        req = ("alice", "domain1", "data1", "read")

        plain_result = e.enforce(*req)
        plain_cond_calls = self.cond_calls
        plain_custom_calls = self.custom_calls
        self.assertGreater(plain_cond_calls, 0)
        self.assertGreater(plain_custom_calls, 0)

        self.cond_calls = 0
        self.custom_calls = 0
        result, explain_rule, report = e.enforce_explain(*req)

        self.assertEqual(result, plain_result)
        self.assertTrue(result)
        self.assertEqual(report.result, result)

        # explaining must not run condition/custom callbacks extra times
        self.assertEqual(self.cond_calls, plain_cond_calls)
        self.assertEqual(self.custom_calls, plain_custom_calls)

        # enforce_ex keeps its (result, explain_rule) contract
        ex_result, ex_rule = e.enforce_ex(*req)
        self.assertEqual((ex_result, ex_rule), (result, explain_rule))

    def test_report_traces_policies_roles_and_effect(self):
        e = self._new_enforcer()
        result, _, report = e.enforce_explain("alice", "domain1", "data1", "read")
        self.assertTrue(result)

        data = report.to_dict()

        # request attributes default to field names only
        self.assertEqual(data["request"]["fields"], ["sub", "dom", "obj", "act"])
        self.assertNotIn("values", data["request"])

        # the priority allow at index 0 terminates the evaluation,
        # later matchers are marked not_executed
        policies = {p["index"]: p for p in data["policies"]}
        self.assertEqual(policies[0]["status"], "matched")
        self.assertEqual(policies[0]["effect"], "allow")
        self.assertEqual(policies[1]["status"], "not_executed")
        self.assertEqual(policies[2]["status"], "not_executed")
        self.assertNotIn("rule", policies[0])
        self.assertEqual(data["effect"]["terminated_by"], 0)
        self.assertEqual(data["effect"]["intermediate_effect"], "allow")

        # the matched role path carries its domain and uses stable node ids
        self.assertEqual(len(data["roles"]), 1)
        query = data["roles"][0]
        self.assertEqual(query["subject"], "alice")
        self.assertEqual(query["target"], "data_admin")
        self.assertEqual(query["domain"], "domain1")
        self.assertTrue(query["result"])
        path_names = [query["nodes"][node_id]["name"] for node_id in query["path"]]
        self.assertEqual(path_names, ["alice", "team_a", "data_admin"])
        for node_id in query["path"]:
            self.assertIsInstance(node_id, str)
            self.assertTrue(node_id.endswith("@domain1"))
            self.assertEqual(query["nodes"][node_id]["domain"], "domain1")
        self.assertIn(
            {"from": "team_a", "to": "data_admin", "domain": "domain1", "passed": True},
            query["condition_edges"],
        )

        # custom matcher functions are counted, not re-run
        functions = {f["name"]: f["calls"] for f in data["functions"]}
        self.assertEqual(functions["tenant_ok"], 1)
        self.assertEqual(functions["g"], 1)

        self.assertEqual(data["decision"], {"result": True, "final_effect": "allow", "reason": "allow"})

        # the report is serializable
        self.assertEqual(json.loads(report.to_json()), data)
        json.dumps(data)

    def test_explicit_deny_is_distinguished_from_no_match(self):
        e = self._new_enforcer()

        result, _, report = e.enforce_explain("alice", "domain1", "data2", "read")
        self.assertFalse(result)
        self.assertFalse(e.enforce("alice", "domain1", "data2", "read"))
        self.assertEqual(report.reason, "explicit_deny")
        self.assertEqual(report.to_dict()["decision"]["final_effect"], "deny")
        deny_records = [p for p in report.to_dict()["policies"] if p["effect"] == "deny"]
        self.assertEqual(len(deny_records), 1)
        self.assertEqual(deny_records[0]["status"], "matched")

        result, _, report = e.enforce_explain("alice", "domain1", "data3", "read")
        self.assertFalse(result)
        self.assertFalse(e.enforce("alice", "domain1", "data3", "read"))
        self.assertEqual(report.reason, "no_matching_policy")
        self.assertTrue(all(p["status"] == "unmatched" for p in report.to_dict()["policies"]))

    def test_explain_does_not_leak_into_plain_enforce(self):
        e = self._new_enforcer()
        req = ("alice", "domain1", "data1", "read")

        _, _, first_report = e.enforce_explain(*req)
        self.assertIsNone(default_role_manager.get_link_tracer())

        # plain enforce after an explained request must not accumulate records
        for _ in range(3):
            self.assertTrue(e.enforce(*req))
        self.assertIsNone(default_role_manager.get_link_tracer())

        _, _, second_report = e.enforce_explain(*req)
        first = first_report.to_dict()
        second = second_report.to_dict()
        self.assertEqual(len(second["roles"]), len(first["roles"]))
        second_functions = {f["name"]: f["calls"] for f in second["functions"]}
        first_functions = {f["name"]: f["calls"] for f in first["functions"]}
        self.assertEqual(second_functions, first_functions)

    def test_explain_options_select_fields_and_detail(self):
        e = self._new_enforcer()
        req = ("alice", "domain1", "data1", "read")

        _, _, report = e.enforce_explain(*req, options=casbin.ExplainOptions(fields=["decision"]))
        self.assertEqual(list(report.to_dict().keys()), ["decision"])

        _, _, report = e.enforce_explain(
            *req,
            options=casbin.ExplainOptions(include_request_values=True, include_policy_text=True),
        )
        data = report.to_dict()
        self.assertEqual(data["request"]["values"]["sub"], "alice")
        self.assertEqual(data["request"]["values"]["dom"], "domain1")
        self.assertIn("rule", data["policies"][0])
        self.assertEqual(data["policies"][0]["rule"], ["1", "data_admin", "data1", "read", "allow"])
        # not_executed policies also carry their rule when policy text is allowed
        self.assertIn("rule", data["policies"][1])

        with self.assertRaises(ValueError):
            casbin.ExplainOptions(fields=["bogus"])
