import os
from unittest import TestCase

import casbin
from casbin import PreviewResult, Unknown, unknown_aware


def get_examples(path):
    examples_path = os.path.split(os.path.realpath(__file__))[0] + "/../examples/"
    return os.path.abspath(examples_path + path)


BASIC_MODEL = """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
"""

OR_MODEL = """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.act == "read" || r.sub == p.sub
"""

ROOT_MODEL = """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == "root" || (r.sub == p.sub && r.obj == p.obj && r.act == p.act)
"""

FUNC_MODEL = """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && my_func(r.obj, p.obj)
"""


def new_enforcer(model_text, policies=()):
    m = casbin.model.Model()
    m.load_model_from_text(model_text)
    e = casbin.Enforcer(m)
    for policy in policies:
        e.add_policy(*policy)
    return e


class TestUnknownMarker(TestCase):
    def test_unknown_has_no_boolean_value(self):
        with self.assertRaises(TypeError):
            bool(Unknown("r_sub"))

    def test_unknown_comparison_returns_unknown_with_fields(self):
        result = Unknown("r_sub") == "alice"
        self.assertIsInstance(result, Unknown)
        self.assertEqual(result.fields, frozenset({"r_sub"}))

    def test_unknown_fields_merge(self):
        result = Unknown("a") < Unknown("b")
        self.assertIsInstance(result, Unknown)
        self.assertEqual(result.fields, frozenset({"a", "b"}))


class TestPreviewResult(TestCase):
    def test_result_is_not_a_boolean(self):
        for decision in (PreviewResult.ALLOW, PreviewResult.DENY, PreviewResult.INDETERMINATE):
            with self.assertRaises(TypeError):
                bool(PreviewResult(decision))

    def test_helpers(self):
        self.assertTrue(PreviewResult(PreviewResult.ALLOW).is_allow)
        self.assertTrue(PreviewResult(PreviewResult.DENY).is_deny)
        result = PreviewResult(PreviewResult.INDETERMINATE, {"b", "a"})
        self.assertTrue(result.is_indeterminate)
        self.assertEqual(result.fields, ("a", "b"))


class TestPreviewBasic(TestCase):
    def get_enforcer(self):
        return casbin.Enforcer(
            get_examples("basic_model.conf"),
            get_examples("basic_policy.csv"),
        )

    def test_complete_request_matches_enforce(self):
        e = self.get_enforcer()
        self.assertEqual(e.preview_enforce("alice", "data1", "read").decision, PreviewResult.ALLOW)
        self.assertEqual(e.preview_enforce("alice", "data2", "read").decision, PreviewResult.DENY)
        self.assertEqual(e.preview_enforce("bob", "data2", "write").decision, PreviewResult.ALLOW)

    def test_unknown_subject_is_indeterminate_with_field(self):
        e = self.get_enforcer()
        result = e.preview_enforce(Unknown("r_sub"), "data1", "read")
        self.assertTrue(result.is_indeterminate)
        self.assertEqual(result.fields, ("r_sub",))

    def test_false_and_unknown_stays_determinate(self):
        e = self.get_enforcer()
        # no policy grants anything on data9, so the unknown subject cannot matter
        result = e.preview_enforce(Unknown("r_sub"), "data9", "read")
        self.assertEqual(result.decision, PreviewResult.DENY)
        self.assertEqual(result.fields, ())

    def test_unknown_fields_union(self):
        e = self.get_enforcer()
        result = e.preview_enforce(Unknown("r_sub"), Unknown("r_obj"), "read")
        self.assertTrue(result.is_indeterminate)
        self.assertEqual(result.fields, ("r_obj", "r_sub"))

    def test_none_is_a_real_value(self):
        e = self.get_enforcer()
        result = e.preview_enforce("alice", None, "read")
        self.assertEqual(result.decision, PreviewResult.DENY)
        self.assertEqual(result.fields, ())
        self.assertEqual(e.enforce("alice", None, "read"), False)

    def test_completion_consistency(self):
        e = self.get_enforcer()
        incomplete = (Unknown("r_sub"), "data9", "read")
        preview = e.preview_enforce(*incomplete)
        self.assertEqual(preview.decision, PreviewResult.DENY)
        completions = [("alice", "data9", "read"), ("bob", "data9", "read")]
        for completion in completions:
            self.assertEqual(e.enforce(*completion), False)


class TestPreviewThreeValuedLogic(TestCase):
    def test_true_or_unknown_is_determinate(self):
        e = new_enforcer(OR_MODEL, [("alice", "data1", "read")])
        result = e.preview_enforce(Unknown("r_sub"), "data1", "read")
        self.assertEqual(result.decision, PreviewResult.ALLOW)
        self.assertEqual(result.fields, ())
        for sub in ("alice", "bob"):
            self.assertEqual(e.enforce(sub, "data1", "read"), True)

    def test_false_or_unknown_is_indeterminate(self):
        e = new_enforcer(OR_MODEL, [("alice", "data1", "read")])
        result = e.preview_enforce(Unknown("r_sub"), "data1", "write")
        self.assertTrue(result.is_indeterminate)
        self.assertEqual(result.fields, ("r_sub",))

    def test_not_unknown_is_unknown(self):
        e = new_enforcer(
            BASIC_MODEL.replace(
                "m = r.sub == p.sub && r.obj == p.obj && r.act == p.act",
                "m = !(r.sub == p.sub) && r.obj == p.obj && r.act == p.act",
            ),
            [("alice", "data1", "read")],
        )
        result = e.preview_enforce(Unknown("r_sub"), "data1", "read")
        self.assertTrue(result.is_indeterminate)
        self.assertEqual(result.fields, ("r_sub",))

    def test_definite_allow_holds_for_completions(self):
        e = new_enforcer(ROOT_MODEL, [("alice", "data1", "read")])
        preview = e.preview_enforce("root", Unknown("r_obj"), Unknown("r_act"))
        self.assertEqual(preview.decision, PreviewResult.ALLOW)
        self.assertEqual(preview.fields, ())
        completions = [("root", "data1", "read"), ("root", "data9", "write")]
        for completion in completions:
            self.assertEqual(e.enforce(*completion), True)


class TestPreviewRbac(TestCase):
    def get_enforcer(self):
        return casbin.Enforcer(
            get_examples("rbac_model.conf"),
            get_examples("rbac_policy.csv"),
        )

    def test_complete_request_matches_enforce(self):
        e = self.get_enforcer()
        self.assertEqual(e.preview_enforce("alice", "data2", "read").decision, PreviewResult.ALLOW)
        self.assertEqual(e.preview_enforce("bob", "data2", "read").decision, PreviewResult.DENY)

    def test_unknown_subject_in_role_check(self):
        e = self.get_enforcer()
        result = e.preview_enforce(Unknown("r_sub"), "data2", "read")
        self.assertTrue(result.is_indeterminate)
        self.assertEqual(result.fields, ("r_sub",))
        completions = [("alice", "data2", "read"), ("bob", "data2", "read")]
        self.assertEqual([e.enforce(*c) for c in completions], [True, False])

    def test_unknown_object(self):
        e = self.get_enforcer()
        result = e.preview_enforce("alice", Unknown("r_obj"), "read")
        self.assertTrue(result.is_indeterminate)
        self.assertEqual(result.fields, ("r_obj",))

    def test_unknown_beyond_role_and_policy_is_determinate(self):
        e = self.get_enforcer()
        result = e.preview_enforce(Unknown("r_sub"), "data9", "read")
        self.assertEqual(result.decision, PreviewResult.DENY)
        completions = [("alice", "data9", "read"), ("bob", "data9", "read")]
        for completion in completions:
            self.assertEqual(e.enforce(*completion), False)


class TestPreviewDenyOverride(TestCase):
    def get_enforcer(self):
        return casbin.Enforcer(
            get_examples("rbac_with_not_deny_model.conf"),
            get_examples("rbac_with_deny_policy.csv"),
        )

    def test_complete_request_matches_enforce(self):
        e = self.get_enforcer()
        self.assertEqual(e.preview_enforce("alice", "data1", "read").decision, PreviewResult.ALLOW)
        self.assertEqual(e.preview_enforce("alice", "data2", "write").decision, PreviewResult.DENY)

    def test_unknown_deny_rule_is_indeterminate(self):
        e = self.get_enforcer()
        # p, alice, data2, write, deny: with unknown action the deny rule cannot be decided
        result = e.preview_enforce("alice", "data2", Unknown("r_act"))
        self.assertTrue(result.is_indeterminate)
        self.assertEqual(result.fields, ("r_act",))
        completions = [("alice", "data2", "read"), ("alice", "data2", "write")]
        self.assertEqual([e.enforce(*c) for c in completions], [True, False])

    def test_irrelevant_unknown_allow_rule_stays_determinate(self):
        e = self.get_enforcer()
        # the unknown action only affects allow rules here; no deny rule can match data1
        result = e.preview_enforce("alice", "data1", Unknown("r_act"))
        self.assertEqual(result.decision, PreviewResult.ALLOW)
        completions = [("alice", "data1", "read"), ("alice", "data1", "write")]
        for completion in completions:
            self.assertEqual(e.enforce(*completion), True)


class TestPreviewPriority(TestCase):
    def get_enforcer(self):
        return casbin.Enforcer(
            get_examples("priority_model.conf"),
            get_examples("priority_policy.csv"),
        )

    def test_complete_request_matches_enforce(self):
        e = self.get_enforcer()
        self.assertEqual(e.preview_enforce("alice", "data1", "read").decision, PreviewResult.ALLOW)
        self.assertEqual(e.preview_enforce("bob", "data2", "write").decision, PreviewResult.DENY)

    def test_earlier_unknown_blocks_later_allow(self):
        e = self.get_enforcer()
        # the first data2 rule (allow for data2_allow_group) is undecided, so
        # the later deny for bob must not decide the outcome either way
        result = e.preview_enforce(Unknown("r_sub"), "data2", "read")
        self.assertTrue(result.is_indeterminate)
        self.assertEqual(result.fields, ("r_sub",))
        completions = [("bob", "data2", "read"), ("alice", "data2", "read")]
        self.assertEqual([e.enforce(*c) for c in completions], [True, False])

    def test_first_rule_unknown_blocks_everything(self):
        e = self.get_enforcer()
        result = e.preview_enforce(Unknown("r_sub"), "data1", "read")
        self.assertTrue(result.is_indeterminate)
        self.assertEqual(result.fields, ("r_sub",))

    def test_no_matching_rule_is_deny(self):
        e = self.get_enforcer()
        result = e.preview_enforce("alice", "data9", "read")
        self.assertEqual(result.decision, PreviewResult.DENY)


class TestPreviewFunctions(TestCase):
    def test_plain_function_is_not_executed_on_unknown(self):
        e = new_enforcer(FUNC_MODEL, [("alice", "data1", "read")])
        calls = []

        def my_func(a, b):
            calls.append((a, b))
            return a == b

        e.add_function("my_func", my_func)

        result = e.preview_enforce("alice", Unknown("r_obj"), "read")
        self.assertTrue(result.is_indeterminate)
        self.assertEqual(result.fields, ("r_obj",))
        self.assertEqual(calls, [])

        self.assertEqual(e.preview_enforce("alice", "data1", "read").decision, PreviewResult.ALLOW)
        self.assertEqual(len(calls), 1)

    def test_unknown_aware_function_adapter(self):
        e = new_enforcer(FUNC_MODEL, [("alice", "data1", "read")])

        @unknown_aware
        def my_func(a, b):
            if isinstance(a, Unknown):
                return Unknown(a.fields)
            return a == b

        e.add_function("my_func", my_func)

        result = e.preview_enforce("alice", Unknown("r_obj"), "read")
        self.assertTrue(result.is_indeterminate)
        self.assertEqual(result.fields, ("r_obj",))

    def test_unknown_aware_function_can_decide(self):
        e = new_enforcer(FUNC_MODEL, [("alice", "data1", "read")])

        @unknown_aware
        def my_func(a, b):
            # understands Unknown: every object is accessible in this model
            return True

        e.add_function("my_func", my_func)

        result = e.preview_enforce("alice", Unknown("r_obj"), "read")
        self.assertEqual(result.decision, PreviewResult.ALLOW)
        self.assertEqual(result.fields, ())
        completions = [("alice", "data1", "read"), ("alice", "data9", "read")]
        for completion in completions:
            self.assertEqual(e.enforce(*completion), True)

    def test_builtin_function_is_indeterminate_on_unknown(self):
        e = casbin.Enforcer(
            get_examples("keymatch_model.conf"),
            get_examples("keymatch_policy.csv"),
        )
        result = e.preview_enforce("alice", Unknown("r_obj"), "GET")
        self.assertTrue(result.is_indeterminate)
        self.assertEqual(result.fields, ("r_obj",))


class TestPreviewUnsupportedEffect(TestCase):
    def test_allow_and_deny_effect_is_rejected(self):
        e = casbin.Enforcer(
            get_examples("rbac_with_deny_model.conf"),
            get_examples("rbac_with_deny_policy.csv"),
        )
        with self.assertRaises(RuntimeError):
            e.preview_enforce("alice", "data1", "read")
