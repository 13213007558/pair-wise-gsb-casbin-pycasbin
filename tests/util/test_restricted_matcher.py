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

import os
import unittest

import casbin
from casbin import Enforcer, Model
from casbin.persist.adapters import FileAdapter
from casbin.util.restricted import (
    CallBudgetExhausted,
    EnforceBudget,
    NodeBudgetExhausted,
    RestrictedAttributeError,
    RestrictedFunctionError,
    RestrictedNameError,
    RestrictedSimpleEval,
    RestrictedSyntaxError,
    RestrictionPolicy,
    RestrictionViolation,
    validate_expression,
)


def get_examples(path):
    workspace_root = os.path.split(os.path.split(os.path.dirname(os.path.abspath(__file__)))[0])[0]
    return os.path.join(workspace_root, "examples", path)


def basic_model(matcher=None):
    model = Model()
    model.load_model(get_examples("basic_model.conf"))
    if matcher is not None:
        model.model["m"]["m"].value = matcher
    return model


def counting_callback(calls):
    def count_match(left, right):
        calls.append((left, right))
        return left == right

    return count_match


def callback_policy(callback, **kwargs):
    return RestrictionPolicy(
        allowed_names={"r_sub", "r_obj", "r_act", "p_sub", "p_obj", "p_act"},
        allowed_functions={"count_match": callback},
        **kwargs,
    )


class TestRestrictionPolicyValidation(unittest.TestCase):
    def setUp(self):
        self.policy = RestrictionPolicy.minimal(("r_sub", "r_act"), ("p_sub", "p_act"))

    def test_allows_declared_grammar(self):
        for expression in (
            "r_sub == p_sub",
            "r_sub == p_sub and r_act == p_act",
            "r_sub == p_sub or r_act == p_act",
            "not (r_act == p_act)",
            "r_act if r_sub == p_sub else p_act",
            "r_sub in p_sub",
        ):
            validate_expression(expression, self.policy)

    def test_unknown_name_is_rejected(self):
        with self.assertRaises(RestrictedNameError):
            validate_expression("r_sub == p_sub and hidden == 1", self.policy)

    def test_disallowed_attribute_is_rejected(self):
        with self.assertRaises(RestrictedAttributeError):
            validate_expression("r_sub.secret == 1", self.policy)

    def test_attribute_allow_list(self):
        policy = RestrictionPolicy(
            allowed_names={"r_sub"},
            allow_attribute_access=True,
            allowed_attributes={"r_sub": {"age"}},
        )
        validate_expression("r_sub.age > 18", policy)
        with self.assertRaises(RestrictedAttributeError):
            validate_expression("r_sub.password == 'x'", policy)

    def test_disallowed_function_is_rejected(self):
        with self.assertRaises(RestrictedFunctionError):
            validate_expression("rmrf(r_sub)", self.policy)

    def test_disallowed_grammar_is_rejected(self):
        for expression in (
            "lambda: r_sub",
            "[r_sub]",
            "(r_sub, p_sub)",
            "{r_sub: p_sub}",
            "r_sub[0]",
            "[x for x in r_sub]",
        ):
            with self.assertRaises(RestrictedSyntaxError):
                validate_expression(expression, self.policy)

    def test_unparseable_expression(self):
        with self.assertRaises(RestrictedSyntaxError):
            validate_expression("r_sub ==", self.policy)

    def test_expression_size_cap(self):
        policy = RestrictionPolicy(allowed_names={"r_sub", "p_sub"}, max_expression_nodes=5)
        with self.assertRaises(RestrictedSyntaxError):
            validate_expression("r_sub == p_sub and r_sub == p_sub", policy)

    def test_injected_container_constructors_are_not_callable(self):
        evaluator = RestrictedSimpleEval(self.policy, self.policy.new_budget())
        for name in ("list", "tuple", "dict", "set"):
            self.assertNotIn(name, evaluator.functions)


class TestRestrictedEnforcer(unittest.TestCase):
    def test_minimal_policy_from_model_tokens(self):
        enforcer = Enforcer(get_examples("basic_model.conf"), get_examples("basic_policy.csv"))
        enforcer.enable_restricted_matcher()
        policy = enforcer.get_restriction_policy()
        self.assertTrue({"r_sub", "r_obj", "r_act", "p_sub", "p_obj", "p_act"} <= policy.allowed_names)
        self.assertEqual({"keyMatch", "regexMatch", "globMatch"}, policy.allowed_function_names)

    def test_allowed_matcher_still_enforces(self):
        enforcer = Enforcer(get_examples("basic_model.conf"), get_examples("basic_policy.csv"))
        enforcer.enable_restricted_matcher()
        self.assertTrue(enforcer.enforce("alice", "data1", "read"))
        self.assertFalse(enforcer.enforce("alice", "data2", "read"))
        self.assertIsNone(enforcer.get_last_restriction_violation())

    def test_disabling_restores_default_evaluation(self):
        enforcer = Enforcer(get_examples("basic_model.conf"), get_examples("basic_policy.csv"))
        enforcer.enable_restricted_matcher()
        enforcer.enable_restricted_matcher(False)
        self.assertIsNone(enforcer.get_restriction_policy())
        self.assertTrue(enforcer.enforce("alice", "data1", "read"))

    def test_registered_function_is_unreachable_unless_allowed(self):
        enforcer = Enforcer(basic_model("rmrf(r_sub)"))
        enforcer.add_function("rmrf", lambda value: True)
        enforcer.enable_restricted_matcher()
        self.assertFalse(enforcer.enforce("alice", "data1", "read"))
        self.assertIsInstance(enforcer.get_last_restriction_violation(), RestrictedFunctionError)
        with self.assertRaises(RestrictedFunctionError):
            enforcer.enforce_strict("alice", "data1", "read")

    def test_unknown_name_fails_closed(self):
        enforcer = Enforcer(basic_model("r_sub == p_sub and hidden_name == 1"))
        enforcer.enable_restricted_matcher()
        self.assertFalse(enforcer.enforce("alice", "data1", "read"))
        self.assertIsInstance(enforcer.get_last_restriction_violation(), RestrictedNameError)
        with self.assertRaises(RestrictedNameError):
            enforcer.enforce_strict("alice", "data1", "read")

    def test_attribute_access_fails_closed(self):
        enforcer = Enforcer(basic_model("r_sub.password == 'x'"))
        enforcer.enable_restricted_matcher()
        self.assertFalse(enforcer.enforce(type("Obj", (), {"password": "x"})(), "data1", "read"))
        self.assertIsInstance(enforcer.get_last_restriction_violation(), RestrictedAttributeError)


class TestShortCircuit(unittest.TestCase):
    def _enforcer(self, matcher):
        return Enforcer(basic_model(matcher), FileAdapter(get_examples("basic_policy.csv")))

    def test_skipped_or_branch_does_not_invoke_callback(self):
        calls = []
        enforcer = self._enforcer("r_sub == 'skip' or count_match(r_obj, p_obj)")
        enforcer.set_restriction_policy(callback_policy(counting_callback(calls), node_budget=1000))
        self.assertTrue(enforcer.enforce("skip", "data1", "read"))
        self.assertEqual(calls, [])

    def test_skipped_and_branch_does_not_invoke_callback(self):
        calls = []
        enforcer = self._enforcer("r_sub == 'nope' and count_match(r_obj, p_obj)")
        enforcer.set_restriction_policy(callback_policy(counting_callback(calls), node_budget=1000))
        self.assertFalse(enforcer.enforce("skip", "data1", "read"))
        self.assertEqual(calls, [])

    def test_executed_branch_invokes_callback(self):
        calls = []
        enforcer = self._enforcer("r_sub == 'alice' and count_match(r_obj, p_obj)")
        enforcer.set_restriction_policy(callback_policy(counting_callback(calls), node_budget=1000))
        self.assertTrue(enforcer.enforce("alice", "data1", "read"))
        self.assertEqual(calls, [("data1", "data1")])


class TestBudget(unittest.TestCase):
    def _enforcer(self, matcher="count_match(r_obj, p_obj)"):
        return Enforcer(basic_model(matcher), FileAdapter(get_examples("basic_policy.csv")))

    def test_node_budget_exhaustion_is_denial(self):
        enforcer = Enforcer(get_examples("basic_model.conf"), get_examples("basic_policy.csv"))
        enforcer.set_restriction_policy(RestrictionPolicy.from_enforcer(enforcer, node_budget=3))
        self.assertFalse(enforcer.enforce("alice", "data1", "read"))
        violation = enforcer.get_last_restriction_violation()
        self.assertIsInstance(violation, NodeBudgetExhausted)

    def test_node_budget_boundary_is_inclusive(self):
        # r_sub == p_sub costs exactly three evaluated nodes (Name, Name, Compare).
        evaluator = RestrictedSimpleEval(
            RestrictionPolicy.minimal(("r_sub",), ("p_sub",), node_budget=3),
            EnforceBudget(3, 10),
        )
        evaluator.set_expr("r_sub == p_sub")
        self.assertFalse(evaluator.eval({"r_sub": "a", "p_sub": "b"}))
        with self.assertRaises(NodeBudgetExhausted):
            tight = RestrictedSimpleEval(
                RestrictionPolicy.minimal(("r_sub",), ("p_sub",), node_budget=2),
                EnforceBudget(2, 10),
            )
            tight.set_expr("r_sub == p_sub")
            tight.eval({"r_sub": "a", "p_sub": "b"})

    def test_call_budget_blocks_callback_before_it_runs(self):
        calls = []
        enforcer = self._enforcer()
        # Two candidate policies, only one controlled call is permitted.
        enforcer.set_restriction_policy(callback_policy(counting_callback(calls), call_budget=1, node_budget=1000))
        self.assertFalse(enforcer.enforce("alice", "dataX", "read"))
        self.assertIsInstance(enforcer.get_last_restriction_violation(), CallBudgetExhausted)
        self.assertEqual(len(calls), 1)

    def test_budget_accumulates_across_candidate_policies(self):
        calls = []
        enforcer = self._enforcer()
        enforcer.set_restriction_policy(callback_policy(counting_callback(calls), call_budget=10, node_budget=1000))
        enforcer.enforce("alice", "dataX", "read")
        self.assertEqual(enforcer.get_last_enforce_budget().calls_used, 2)
        self.assertEqual(len(calls), 2)

    def test_budget_is_not_shared_between_requests(self):
        enforcer = Enforcer(get_examples("basic_model.conf"), get_examples("basic_policy.csv"))
        enforcer.set_restriction_policy(RestrictionPolicy.from_enforcer(enforcer, node_budget=4))
        self.assertFalse(enforcer.enforce("alice", "data1", "read"))
        first_budget = enforcer.get_last_enforce_budget()
        self.assertIsInstance(enforcer.get_last_restriction_violation(), NodeBudgetExhausted)
        self.assertFalse(enforcer.enforce("alice", "data1", "read"))
        second_budget = enforcer.get_last_enforce_budget()
        self.assertIsNot(first_budget, second_budget)
        self.assertEqual(second_budget.nodes_used, first_budget.nodes_used)
        self.assertIsInstance(enforcer.get_last_restriction_violation(), NodeBudgetExhausted)


class TestEvalExpansion(unittest.TestCase):
    def test_expanded_policy_expression_is_validated(self):
        enforcer = Enforcer(
            get_examples("abac_rule_model.conf"),
            get_examples("abac_rule_policy.csv"),
        )
        enforcer.enable_restricted_matcher()

        class Subject:
            def __init__(self, age):
                self.age = age

        # The policy rule expands to r_sub.age > 18, which uses attribute access
        # the default minimal policy forbids, even though the outer matcher is fine.
        self.assertFalse(enforcer.enforce(Subject(30), "/data1", "read"))
        self.assertIsInstance(enforcer.get_last_restriction_violation(), RestrictedAttributeError)

    def test_expanded_policy_with_allowed_attributes(self):
        enforcer = Enforcer(
            get_examples("abac_rule_model.conf"),
            get_examples("abac_rule_policy.csv"),
        )
        enforcer.set_restriction_policy(
            RestrictionPolicy.from_enforcer(
                enforcer,
                allow_attribute_access=True,
                allowed_attributes={"r_sub": {"age"}},
            )
        )

        class Subject:
            def __init__(self, age):
                self.age = age

        self.assertTrue(enforcer.enforce(Subject(30), "/data1", "read"))
        self.assertFalse(enforcer.enforce(Subject(10), "/data1", "read"))
        self.assertIsNone(enforcer.get_last_restriction_violation())

    def test_hidden_function_in_policy_rule_fails_closed(self):
        enforcer = Enforcer(get_examples("abac_rule_model.conf"))
        enforcer.add_policy("rmrf(r_sub) > 0", "/data", "read")
        enforcer.set_restriction_policy(RestrictionPolicy.from_enforcer(enforcer, allow_attribute_access=True))

        class Subject:
            age = 1

        self.assertFalse(enforcer.enforce(Subject(), "/data", "read"))
        self.assertIsInstance(enforcer.get_last_restriction_violation(), RestrictedFunctionError)


class TestEnforcerVariants(unittest.TestCase):
    def test_cached_enforcer_does_not_replay_violation(self):
        enforcer = casbin.CachedEnforcer(get_examples("basic_model.conf"), get_examples("basic_policy.csv"))
        enforcer.enable_restricted_matcher()
        self.assertTrue(enforcer.enforce("alice", "data1", "read"))
        enforcer.set_restriction_policy(RestrictionPolicy.from_enforcer(enforcer, node_budget=1))
        self.assertFalse(enforcer.enforce("alice", "data1", "read"))
        self.assertIsInstance(enforcer.get_last_restriction_violation(), NodeBudgetExhausted)
        enforcer.set_restriction_policy(RestrictionPolicy.from_enforcer(enforcer, node_budget=500))
        self.assertTrue(enforcer.enforce("alice", "data1", "read"))
        self.assertIsNone(enforcer.get_last_restriction_violation())

    def test_synced_enforcer_delegates_restriction_api(self):
        enforcer = casbin.SyncedEnforcer(get_examples("basic_model.conf"), get_examples("basic_policy.csv"))
        enforcer.enable_restricted_matcher()
        self.assertTrue(enforcer.enforce("alice", "data1", "read"))
        enforcer.set_restriction_policy(RestrictionPolicy.from_enforcer(enforcer._e, node_budget=1))
        self.assertFalse(enforcer.enforce("alice", "data1", "read"))
        self.assertIsInstance(enforcer.get_last_restriction_violation(), NodeBudgetExhausted)
        with self.assertRaises(NodeBudgetExhausted):
            enforcer.enforce_strict("alice", "data1", "read")


class TestMinimalTenantPolicy(unittest.TestCase):
    def test_minimal_policy_is_ready_to_use(self):
        enforcer = Enforcer(get_examples("basic_model.conf"), get_examples("basic_policy.csv"))
        policy = RestrictionPolicy.from_enforcer(enforcer)
        self.assertFalse(policy.allow_attribute_access)
        self.assertEqual(policy.allowed_function_names, {"keyMatch", "regexMatch", "globMatch"})
        self.assertTrue({"r_sub", "p_sub"} <= policy.allowed_names)

    def test_violation_hierarchy_catches_every_denial(self):
        enforcer = Enforcer(basic_model("hidden(r_sub)"))
        enforcer.enable_restricted_matcher()
        self.assertFalse(enforcer.enforce("alice", "data1", "read"))
        self.assertIsInstance(enforcer.get_last_restriction_violation(), RestrictionViolation)


if __name__ == "__main__":
    unittest.main()
