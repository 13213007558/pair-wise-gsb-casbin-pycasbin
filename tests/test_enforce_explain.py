import json
import os
from unittest import TestCase

import casbin
from casbin import ExplainOptions, util
from casbin.persist.adapters import FileAdapter


def get_examples(path):
    examples_path = os.path.split(os.path.realpath(__file__))[0] + "/../examples/"
    return os.path.abspath(examples_path + path)


class ConditionCounter:
    def __init__(self, result=True):
        self.result = result
        self.calls = 0

    def __call__(self, *params):
        self.calls += 1
        return self.result


class TestEnforceExplain(TestCase):
    def get_enforcer(self, cond):
        e = casbin.Enforcer(
            get_examples("rbac_with_domain_condition_priority_model.conf"),
            get_examples("rbac_with_domain_condition_priority_policy.csv"),
        )
        e.add_named_domain_link_condition_func("g", "alice", "team_b", "domain1", cond)
        return e

    def test_explain_result_matches_enforce_and_callback_count(self):
        requests = [
            ("alice", "domain1", "data2", "read"),
            ("alice", "domain1", "data1", "read"),
            ("alice", "domain1", "data9", "read"),
            ("bob", "domain1", "data2", "read"),
        ]
        for request in requests:
            plain_cond = ConditionCounter()
            e_plain = self.get_enforcer(plain_cond)
            expected = e_plain.enforce(*request)

            explain_cond = ConditionCounter()
            e_explain = self.get_enforcer(explain_cond)
            result, explain_rule, report = e_explain.enforce_explain(*request)

            self.assertEqual(expected, result)
            self.assertEqual(expected, report.result)
            self.assertEqual(plain_cond.calls, explain_cond.calls)
            self.assertEqual(e_plain.enforce_ex(*request)[1], explain_rule)

    def test_priority_deny_terminates_evaluation(self):
        e = self.get_enforcer(ConditionCounter())
        result, explain_rule, report = e.enforce_explain("alice", "domain1", "data1", "read")

        self.assertFalse(result)
        self.assertEqual(["2", "alice", "domain1", "data1", "read", "deny"], explain_rule)

        data = report.to_dict()
        self.assertEqual("explicit_deny", data["reason"])
        self.assertEqual("deny", data["effect"]["final_effect"])
        self.assertEqual(1, data["effect"]["terminated_by"])
        self.assertEqual("deny", data["effect"]["termination_effect"])

        policies = {p["index"]: p for p in data["policies"]}
        self.assertTrue(policies[0]["executed"])
        self.assertFalse(policies[0]["matched"])
        self.assertTrue(policies[1]["executed"])
        self.assertEqual("deny", policies[1]["effect"])
        self.assertFalse(policies[2]["executed"])
        self.assertIsNone(policies[2]["effect"])

        # r.obj == p.obj fails for policy 0, so the r.act == p.act step short-circuits
        steps = {s["id"]: s for s in policies[0]["matcher_steps"]}
        self.assertEqual("executed", steps[2]["status"])
        self.assertFalse(steps[2]["result"])
        self.assertEqual("not_executed", steps[3]["status"])

        # policy 2 is behind the priority deny, none of its matcher steps ran
        for step in policies[2]["matcher_steps"]:
            self.assertEqual("not_executed", step["status"])

    def test_role_paths_include_domain_and_both_inheritance_paths(self):
        e = self.get_enforcer(ConditionCounter())
        result, _, report = e.enforce_explain("alice", "domain1", "data2", "read")
        self.assertTrue(result)

        data = report.to_dict()
        self.assertEqual("allow", data["reason"])
        self.assertEqual(0, data["effect"]["terminated_by"])

        query = data["role_queries"][0]
        self.assertEqual("g", query["function"])
        self.assertEqual("domain1", query["domain"])
        self.assertTrue(query["result"])

        path = query["path"]
        self.assertEqual("alice", path[0]["name"])
        self.assertEqual("data2_admin", path[-1]["name"])
        self.assertEqual(3, len(path))
        for node in path:
            self.assertEqual("domain1", node["domain"])

        # alice reaches data2_admin through two inheritance paths, both must show up
        edges = {(edge["from"], edge["to"]) for edge in query["edges"]}
        self.assertIn(("alice", "team_a"), edges)
        self.assertIn(("alice", "team_b"), edges)
        self.assertIn(("team_a", "data2_admin"), edges)
        self.assertIn(("team_b", "data2_admin"), edges)
        for edge in query["edges"]:
            self.assertEqual("domain1", edge["domain"])
            self.assertTrue(edge["condition_passed"])

    def test_no_matching_policy_is_distinguished_from_explicit_deny(self):
        e = self.get_enforcer(ConditionCounter())
        result, _, report = e.enforce_explain("alice", "domain1", "data9", "read")
        self.assertFalse(result)

        data = report.to_dict()
        self.assertEqual("no_matching_policy", data["reason"])
        self.assertIsNone(data["effect"]["terminated_by"])
        self.assertEqual([], data["effect"]["matched_effects"])
        for policy in data["policies"]:
            self.assertTrue(policy["executed"])
            self.assertFalse(policy["matched"])

    def test_conditional_edge_failure_is_recorded(self):
        e = self.get_enforcer(ConditionCounter(result=False))
        result, _, report = e.enforce_explain("alice", "domain1", "data2", "read")
        self.assertTrue(result)

        query = report.to_dict()["role_queries"][0]
        edges = {(edge["from"], edge["to"]): edge for edge in query["edges"]}
        self.assertFalse(edges[("alice", "team_b")]["condition_passed"])
        self.assertTrue(edges[("alice", "team_a")]["condition_passed"])

    def test_default_report_hides_values_and_policy_text(self):
        e = self.get_enforcer(ConditionCounter())
        _, _, report = e.enforce_explain("alice", "domain1", "data1", "read")
        data = report.to_dict()

        self.assertEqual(["r_sub", "r_dom", "r_obj", "r_act"], data["request"]["fields"])
        self.assertNotIn("values", data["request"])
        for policy in data["policies"]:
            self.assertNotIn("policy", policy)
            for step in policy["matcher_steps"]:
                self.assertNotIn("text", step)
        for query in data["role_queries"]:
            self.assertNotIn("args", query)

    def test_options_include_values_and_policy_text(self):
        e = self.get_enforcer(ConditionCounter())
        options = ExplainOptions(include_request_values=True, include_policy_text=True)
        _, _, report = e.enforce_explain("alice", "domain1", "data1", "read", options=options)
        data = report.to_dict()

        self.assertEqual("alice", data["request"]["values"]["r_sub"])
        self.assertEqual("data1", data["request"]["values"]["r_obj"])
        self.assertEqual(
            ["2", "alice", "domain1", "data1", "read", "deny"],
            data["policies"][1]["policy"],
        )
        self.assertIn("text", data["policies"][0]["matcher_steps"][0])
        self.assertEqual(["alice", "data2_admin", "domain1"], data["role_queries"][0]["args"])

    def test_field_selection(self):
        e = self.get_enforcer(ConditionCounter())
        options = ExplainOptions(include_role_paths=False, include_function_calls=False, include_effect_trace=False)
        _, _, report = e.enforce_explain("alice", "domain1", "data1", "read", options=options)
        data = report.to_dict()

        self.assertNotIn("role_queries", data)
        self.assertNotIn("function_calls", data)
        self.assertNotIn("effect", data)
        self.assertIn("policies", data)

    def test_report_is_serializable_without_object_addresses(self):
        e = self.get_enforcer(ConditionCounter())
        _, _, report = e.enforce_explain("alice", "domain1", "data1", "read")

        serialized = report.to_json()
        restored = json.loads(serialized)
        self.assertEqual(restored, report.to_dict())
        self.assertNotIn("0x", serialized)

        def assert_ids(value):
            if isinstance(value, dict):
                for key, item in value.items():
                    if key in ("id", "index", "terminated_by"):
                        self.assertTrue(item is None or isinstance(item, int))
                    assert_ids(item)
            elif isinstance(value, list):
                for item in value:
                    assert_ids(item)

        assert_ids(restored)

    def test_plain_enforce_after_explain_keeps_no_trace(self):
        cond = ConditionCounter()
        e = self.get_enforcer(cond)

        _, _, first_report = e.enforce_explain("alice", "domain1", "data9", "read")
        first_queries = len(first_report.to_dict()["role_queries"])

        # a following plain enforce must not accumulate anything
        self.assertFalse(e.enforce("alice", "domain1", "data9", "read"))
        self.assertIsNone(e.cond_rm_map["g"].link_tracer)
        for rm in getattr(e.cond_rm_map["g"], "rm_map", {}).values():
            self.assertIsNone(getattr(rm, "link_tracer", None))
        self.assertIs(e.fm.get_functions()["keyMatch"], util.key_match_func)

        _, _, second_report = e.enforce_explain("alice", "domain1", "data9", "read")
        self.assertEqual(first_queries, len(second_report.to_dict()["role_queries"]))
        self.assertEqual(first_report.to_dict(), second_report.to_dict())

    def test_enforce_ex_contract_unchanged(self):
        e = self.get_enforcer(ConditionCounter())
        result, explain_rule = e.enforce_ex("alice", "domain1", "data1", "read")
        self.assertFalse(result)
        self.assertEqual(["2", "alice", "domain1", "data1", "read", "deny"], explain_rule)

    def test_custom_function_called_once_per_real_evaluation(self):
        model_text = """
[request_definition]
r = sub, obj

[policy_definition]
p = sub, obj

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && myMatch(r.obj, p.obj)
"""
        policy_lines = "p, alice, /data1\n" \
            + "p, alice, /data2\n" \
            + "p, alice, /data3"

        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as policy_file:
            policy_file.write(policy_lines)
        self.addCleanup(os.remove, policy_file.name)

        calls = {"plain": 0, "explain": 0}

        def make_func(which):
            def my_match(key1, key2):
                calls[which] += 1
                return key1 == key2

            return my_match

        m = casbin.Enforcer.new_model(text=model_text)
        e_plain = casbin.Enforcer(m, FileAdapter(policy_file.name))
        e_plain.add_function("myMatch", make_func("plain"))
        self.assertTrue(e_plain.enforce("alice", "/data3"))

        m2 = casbin.Enforcer.new_model(text=model_text)
        e_explain = casbin.Enforcer(m2, FileAdapter(policy_file.name))
        e_explain.add_function("myMatch", make_func("explain"))
        result, _, report = e_explain.enforce_explain("alice", "/data3")

        self.assertTrue(result)
        self.assertEqual(calls["plain"], calls["explain"])

        function_calls = report.to_dict()["function_calls"]
        self.assertEqual(calls["explain"], len(function_calls))
        self.assertTrue(all(entry["function"] == "myMatch" for entry in function_calls))
