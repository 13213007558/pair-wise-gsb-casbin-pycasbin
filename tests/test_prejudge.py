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

from unittest import TestCase

import casbin
from casbin import PrejudgeResult, Unknown, Verdict
from casbin.model import Model
from tests.test_enforcer import get_examples

OR_MODEL = """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub || r.obj == p.obj
"""

DENY_OVERRIDE_MODEL = """
[request_definition]
r = sub, obj

[policy_definition]
p = sub, obj, eft

[policy_effect]
e = !some(where (p.eft == deny))

[matchers]
m = r.sub == p.sub && r.obj == p.obj
"""

PRIORITY_OR_MODEL = """
[request_definition]
r = sub, obj

[policy_definition]
p = sub, obj, eft

[policy_effect]
e = priority(p.eft) || deny

[matchers]
m = r.sub == p.sub || r.obj == p.obj
"""

FUNC_MODEL = """
[request_definition]
r = sub, obj

[policy_definition]
p = sub, obj

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = myFunc(r.sub) && r.obj == p.obj
"""

EVAL_MODEL = """
[request_definition]
r = sub, obj

[policy_definition]
p = sub, rule

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && eval(p.rule)
"""


def get_model(text):
    m = Model()
    m.load_model_from_text(text)
    return m


class TestPrejudge(TestCase):
    def get_enforcer(self, model=None, adapter=None):
        return casbin.Enforcer(model, adapter)

    def test_complete_request_agrees_with_enforce(self):
        e = self.get_enforcer(
            get_examples("basic_model.conf"), get_examples("basic_policy.csv")
        )
        self.assertEqual(e.prejudge("alice", "data1", "read"), PrejudgeResult(Verdict.ALLOW))
        self.assertEqual(e.prejudge("alice", "data1", "write"), PrejudgeResult(Verdict.DENY))
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))

    def test_indeterminate_lists_unknown_fields(self):
        e = self.get_enforcer(
            get_examples("basic_model.conf"), get_examples("basic_policy.csv")
        )
        result = e.prejudge("alice", Unknown("r.obj"), "read")
        self.assertEqual(result, PrejudgeResult(Verdict.INDETERMINATE, ("r.obj",)))
        self.assertTrue(result.indeterminate)

    def test_anonymous_unknown_is_named_by_request_token(self):
        e = self.get_enforcer(
            get_examples("basic_model.conf"), get_examples("basic_policy.csv")
        )
        result = e.prejudge(Unknown(), "data1", "read")
        self.assertEqual(result.verdict, Verdict.INDETERMINATE)
        self.assertEqual(result.fields, ("r_sub",))

    def test_none_is_an_actual_value_not_unknown(self):
        e = self.get_enforcer(
            get_examples("basic_model.conf"), get_examples("basic_policy.csv")
        )
        result = e.prejudge("alice", None, "read")
        self.assertEqual(result, PrejudgeResult(Verdict.DENY))
        self.assertFalse(e.enforce("alice", None, "read"))

    def test_false_and_unknown_stays_false(self):
        e = self.get_enforcer(
            get_examples("basic_model.conf"), get_examples("basic_policy.csv")
        )
        # no policy mentions carol, so the unknown object can never matter
        result = e.prejudge("carol", Unknown("r.obj"), "read")
        self.assertEqual(result, PrejudgeResult(Verdict.DENY))

    def test_true_or_unknown_stays_true(self):
        e = self.get_enforcer(get_model(OR_MODEL))
        e.add_policy("alice", "data1", "read")
        result = e.prejudge("alice", Unknown("r.obj"), "write")
        self.assertEqual(result, PrejudgeResult(Verdict.ALLOW))

    def test_not_unknown_is_unknown(self):
        e = self.get_enforcer(get_model(OR_MODEL))
        e.add_policy("alice", "data1", "read")
        result = e.prejudge(Unknown("r.sub"), Unknown("r.obj"), "read")
        self.assertEqual(result.verdict, Verdict.INDETERMINATE)
        self.assertEqual(result.fields, ("r.obj", "r.sub"))

    def test_rbac_g_function(self):
        e = self.get_enforcer(
            get_examples("rbac_model.conf"), get_examples("rbac_policy.csv")
        )
        self.assertEqual(e.prejudge("alice", "data2", "read"), PrejudgeResult(Verdict.ALLOW))
        self.assertEqual(e.prejudge("bob", "data2", "read"), PrejudgeResult(Verdict.DENY))

        result = e.prejudge(Unknown("r.sub"), "data2", "read")
        self.assertEqual(result, PrejudgeResult(Verdict.INDETERMINATE, ("r.sub",)))

    def test_deny_override_effect(self):
        e = self.get_enforcer(get_model(DENY_OVERRIDE_MODEL))
        e.add_policy("alice", "data1", "allow")
        e.add_policy("bob", "data2", "deny")

        self.assertEqual(e.prejudge("alice", "data1"), PrejudgeResult(Verdict.ALLOW))
        self.assertEqual(e.prejudge("bob", "data2"), PrejudgeResult(Verdict.DENY))
        # a matched deny decides even if another rule is still unknown
        self.assertEqual(e.prejudge("bob", "data2"), PrejudgeResult(Verdict.DENY))
        # no rule can deny carol, so the unknown object cannot change the allow
        self.assertEqual(e.prejudge("carol", Unknown("r.obj")), PrejudgeResult(Verdict.ALLOW))
        # bob might be denied depending on the unknown object
        result = e.prejudge("bob", Unknown("r.obj"))
        self.assertEqual(result, PrejudgeResult(Verdict.INDETERMINATE, ("r.obj",)))

    def test_priority_effect(self):
        e = self.get_enforcer(
            get_examples("priority_model.conf"), get_examples("priority_policy.csv")
        )
        self.assertEqual(e.prejudge("alice", "data1", "read"), PrejudgeResult(Verdict.ALLOW))
        self.assertEqual(e.prejudge("alice", "data1", "write"), PrejudgeResult(Verdict.DENY))

    def test_priority_unknown_earlier_rule_blocks_later_allow(self):
        e = self.get_enforcer(get_model(PRIORITY_OR_MODEL))
        e.add_policy("alice", "data1", "deny")
        e.add_policy("bob", "data2", "allow")

        # the first rule is undecided, so the later allow must not be final
        result = e.prejudge("bob", Unknown("r.obj"))
        self.assertEqual(result, PrejudgeResult(Verdict.INDETERMINATE, ("r.obj",)))

        # once the object is known the outcome is decided by rule order
        self.assertEqual(e.prejudge("bob", "data9"), PrejudgeResult(Verdict.ALLOW))
        self.assertEqual(e.prejudge("alice", "data9"), PrejudgeResult(Verdict.DENY))
        self.assertFalse(e.enforce("bob", "data1"))
        self.assertTrue(e.enforce("bob", "data9"))

    def test_ordinary_function_is_not_executed_on_unknown_arguments(self):
        e = self.get_enforcer(get_model(FUNC_MODEL))
        e.add_policy("alice", "data1")
        calls = []

        def my_func(sub):
            calls.append(sub)
            return sub == "alice"

        e.add_function("myFunc", my_func)

        result = e.prejudge(Unknown("r.sub"), "data1")
        self.assertEqual(result, PrejudgeResult(Verdict.INDETERMINATE, ("r.sub",)))
        self.assertEqual(calls, [])

        self.assertEqual(e.prejudge("alice", "data1"), PrejudgeResult(Verdict.ALLOW))
        self.assertEqual(calls, ["alice"])

    def test_unknown_aware_function_adapter(self):
        e = self.get_enforcer(get_model(FUNC_MODEL))
        e.add_policy("alice", "data1")
        e.add_function("myFunc", lambda sub: sub == "alice")

        def adapter(sub):
            if isinstance(sub, Unknown):
                return True
            return sub == "alice"

        e.add_prejudge_function("myFunc", adapter)

        self.assertEqual(e.prejudge(Unknown("r.sub"), "data1"), PrejudgeResult(Verdict.ALLOW))
        self.assertEqual(e.prejudge(Unknown("r.sub"), "data2"), PrejudgeResult(Verdict.DENY))
        # enforce() still uses the original function
        self.assertTrue(e.enforce("alice", "data1"))
        self.assertFalse(e.enforce("bob", "data1"))

    def test_function_errors_are_not_disguised_as_unknown(self):
        e = self.get_enforcer(get_model(FUNC_MODEL))
        e.add_policy("alice", "data1")

        def boom(sub):
            raise ValueError("boom")

        e.add_function("myFunc", boom)

        with self.assertRaises(ValueError):
            e.prejudge("alice", "data1")
        # with an unknown argument the function is not executed at all
        result = e.prejudge(Unknown("r.sub"), "data1")
        self.assertEqual(result.verdict, Verdict.INDETERMINATE)

    def test_determinate_verdicts_hold_for_every_completion(self):
        # True or Unknown: the allow holds no matter how the request is completed
        e = self.get_enforcer(get_model(OR_MODEL))
        e.add_policy("alice", "data1", "read")
        result = e.prejudge("alice", Unknown("r.obj"), "write")
        self.assertEqual(result, PrejudgeResult(Verdict.ALLOW))
        self.assertTrue(e.enforce("alice", "data1", "write"))
        self.assertTrue(e.enforce("alice", "data9", "write"))

        # False and Unknown: the deny holds no matter how the request is completed
        e = self.get_enforcer(
            get_examples("basic_model.conf"), get_examples("basic_policy.csv")
        )
        result = e.prejudge("carol", Unknown("r.obj"), "read")
        self.assertEqual(result, PrejudgeResult(Verdict.DENY))
        self.assertFalse(e.enforce("carol", "data1", "read"))
        self.assertFalse(e.enforce("carol", "data2", "write"))

    def test_indeterminate_fields_explain_where_completions_differ(self):
        e = self.get_enforcer(
            get_examples("rbac_model.conf"), get_examples("rbac_policy.csv")
        )
        result = e.prejudge(Unknown("r.sub"), "data2", "read")
        self.assertEqual(result.verdict, Verdict.INDETERMINATE)
        self.assertEqual(result.fields, ("r.sub",))
        # completing exactly the listed field in two ways flips the outcome
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("bob", "data2", "read"))

    def test_result_is_not_usable_as_a_boolean(self):
        e = self.get_enforcer(
            get_examples("basic_model.conf"), get_examples("basic_policy.csv")
        )
        with self.assertRaises(TypeError):
            bool(e.prejudge("alice", "data1", "read"))
        with self.assertRaises(TypeError):
            bool(Unknown("r.obj"))

    def test_enforce_api_is_unchanged(self):
        e = self.get_enforcer(
            get_examples("basic_model.conf"), get_examples("basic_policy.csv")
        )
        e.prejudge("alice", Unknown("r.obj"), "read")
        result = e.enforce("alice", "data1", "read")
        self.assertIsInstance(result, bool)
        self.assertTrue(result)

    def test_unsupported_effect_is_rejected(self):
        e = self.get_enforcer(
            get_examples("rbac_with_deny_model.conf"),
            get_examples("rbac_with_deny_policy.csv"),
        )
        with self.assertRaises(RuntimeError):
            e.prejudge("alice", "data1", "read")

    def test_eval_in_matcher_is_rejected(self):
        e = self.get_enforcer(get_model(EVAL_MODEL))
        e.add_policy("alice", "r.obj == 'data1'")
        with self.assertRaises(RuntimeError):
            e.prejudge("alice", "data1")
