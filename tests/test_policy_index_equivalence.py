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

"""Semantic-equivalence tests for the policy index (partitioned enforcement).

Every case builds two enforcers from the *same* model text and policy rows:

* one runs the index-enabled execution path (a :class:`PolicyIndex` is set);
* the other runs the index-disabled path (full policy scan).

The two must return the same boolean decision, the same ``enforce_ex`` rule and
scan the same semantics. The index is only allowed to skip rules whose matcher
could never match the request; in particular an empty index bucket must still
fall through to the model's own default effect instead of being assumed to be a
default-deny.

Work reduction is proven through *candidate scan counts* (how many policy
matchers were actually evaluated), never through wall-clock timings.
"""

import os
import random
from unittest import TestCase

import casbin
from casbin.persist.adapters import FilteredFileAdapter
from casbin.persist.adapters.filtered_file_adapter import Filter

EXAMPLES = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "examples"))

# Fixed seed: the generated cases are deterministic and can be re-run verbatim.
SEED = 20261110
GENERATED_CASES = 40


def example(name):
    return os.path.join(EXAMPLES, name)


# --------------------------------------------------------------------------- #
# Shared builders
# --------------------------------------------------------------------------- #
class Probe:
    """Counts matcher evaluations for one enforcer.

    ``record`` is invoked as the first term of every matcher, so the counter is
    incremented once per candidate rule that the enforcer actually evaluates.
    Rules skipped by the index never reach the matcher and are not counted.
    """

    def __init__(self):
        self.calls = 0

    def record(self, *args):
        self.calls += 1
        return True

    def reset(self):
        self.calls = 0


def _build_partitioned_model(effect, with_eft=True):
    """The shared model used for the allow/deny, priority and bucket tests.

    ``p.obj_type`` is the partition key: rules with ``"*"`` match every bucket.
    """
    model = casbin.Model()
    model.add_def("r", "r", "sub, obj_type, obj, act")
    if with_eft:
        model.add_def("p", "p", "sub, obj_type, obj, act, eft")
    else:
        model.add_def("p", "p", "sub, obj_type, obj, act")
    model.add_def("g", "g", "_, _")
    model.add_def("e", "e", effect)
    model.add_def(
        "m",
        "m",
        "probe() && g(r.sub, p.sub) "
        "&& (p.obj_type == '*' || p.obj_type == r.obj_type) "
        "&& p.obj == r.obj && r.act == p.act",
    )
    return model


def new_pair(effect, rules, grouping=(), with_eft=True):
    """Builds index-enabled and index-disabled enforcers from identical input."""
    indexed = casbin.Enforcer(_build_partitioned_model(effect, with_eft))
    plain = casbin.Enforcer(_build_partitioned_model(effect, with_eft))

    indexed_probe = Probe()
    plain_probe = Probe()
    indexed.add_function("probe", indexed_probe.record)
    plain.add_function("probe", plain_probe.record)

    if rules:
        indexed.add_policies([rule[:] for rule in rules])
        plain.add_policies([rule[:] for rule in rules])
    for link in grouping:
        indexed.add_grouping_policy(*link)
        plain.add_grouping_policy(*link)

    indexed.set_policy_index(
        "p",
        casbin.PolicyIndex(
            request_key=lambda rvals: (rvals[1], True),
            policy_key=lambda rule: rule[1],
        ),
    )
    return indexed, plain, indexed_probe, plain_probe


def assert_same(test_case, indexed, plain, request, ctx=None):
    """Runs one request on both enforcers and compares decision and explanation."""
    args = (ctx, *request) if ctx is not None else request
    indexed_result, indexed_explain = indexed.enforce_ex(*args)
    plain_result, plain_explain = plain.enforce_ex(*args)
    test_case.assertEqual(indexed_result, plain_result, format_case(request))
    test_case.assertEqual(list(indexed_explain), list(plain_explain), format_case(request))
    return indexed_result, indexed_explain


def format_case(request):
    return "request={!r} is not equivalent between indexed and unindexed execution".format(request)


# Effect expressions reused across the suite.
ALLOW_OVERRIDE = "some(where (p.eft == allow))"
DENY_OVERRIDE = "!some(where (p.eft == deny))"
ALLOW_AND_DENY = "some(where (p.eft == allow)) && !some(where (p.eft == deny))"
PRIORITY = "priority(p.eft) || deny"


class PolicyIndexEquivalenceTest(TestCase):
    # ------------------------------------------------------------------ #
    # allow / deny effect combinations
    # ------------------------------------------------------------------ #
    def test_allow_deny_effect_combinations(self):
        rules = [
            ["alice", "doc", "doc1", "read", "allow"],
            ["alice", "doc", "doc2", "read", "allow"],
            ["alice", "doc", "doc3", "read", "deny"],
            ["alice", "img", "img1", "read", "allow"],
            ["alice", "*", "video1", "read", "allow"],
            ["bob", "doc", "doc1", "read", "deny"],
        ]
        requests = [
            ("alice", "doc", "doc1", "read"),       # allow in doc bucket
            ("alice", "doc", "doc3", "read"),       # explicit deny in doc bucket
            ("alice", "doc", "missing", "read"),    # no rule matches
            ("alice", "img", "img1", "read"),       # allow in img bucket
            ("alice", "audio", "video1", "read"),   # only the wildcard rule
            ("alice", "audio", "missing", "read"),  # bucket with no rule at all
            ("alice", "doc", "doc1", "write"),      # action mismatch
            ("bob", "doc", "doc1", "read"),         # deny reachable through bucket
            ("bob", "img", "img1", "read"),         # no bob rule in img bucket
        ]

        for effect in (ALLOW_OVERRIDE, DENY_OVERRIDE, ALLOW_AND_DENY, PRIORITY):
            indexed, plain, _, _ = new_pair(effect, rules)
            for request in requests:
                assert_same(self, indexed, plain, request)

    def test_wildcard_partition_deny_is_reachable_from_every_bucket(self):
        # A rule whose policy key is "*" lives in every partition. A deny rule
        # there must still override an allow in a specific bucket.
        wildcard_deny = ["alice", "*", "doc1", "read", "deny"]
        rules = [
            wildcard_deny,
            ["alice", "doc", "doc1", "read", "allow"],
            ["alice", "img", "img1", "read", "allow"],
        ]
        indexed, plain, indexed_probe, plain_probe = new_pair(ALLOW_AND_DENY, rules)

        indexed_probe.reset()
        plain_probe.reset()
        result, explain = assert_same(self, indexed, plain, ("alice", "doc", "doc1", "read"))
        self.assertFalse(result)
        self.assertEqual(explain, wildcard_deny)
        # The deny lives in the wildcard partition so the indexed path still
        # reaches it, while scanning no more rules than the full path.
        self.assertLessEqual(indexed_probe.calls, plain_probe.calls)
        self.assertLess(plain_probe.calls, len(rules))

    def test_deny_override_empty_bucket_defaults_to_allow(self):
        # DenyOverride is a default-ALLOW model: an empty bucket must not be
        # turned into a denial just because the index found no candidate.
        rules = [
            ["alice", "doc", "doc1", "read", "deny"],
            ["alice", "img", "img1", "read", "allow"],
        ]
        indexed, plain, _, _ = new_pair(DENY_OVERRIDE, rules)

        # "audio" exists in neither the policy nor any wildcard rule.
        self.assertEqual(plain.enforce("alice", "audio", "whatever", "read"), True)
        result, explain = assert_same(self, indexed, plain, ("alice", "audio", "whatever", "read"))
        self.assertTrue(result)
        self.assertEqual(explain, [])

    def test_each_effect_empty_bucket_keeps_model_default(self):
        rules = [["alice", "doc", "doc1", "read", "allow"]]
        request = ("alice", "audio", "missing", "read")
        expectations = {
            ALLOW_OVERRIDE: False,
            DENY_OVERRIDE: True,     # default allow, even with an empty bucket
            ALLOW_AND_DENY: False,
            PRIORITY: False,
        }
        for effect, expected in expectations.items():
            indexed, plain, _, _ = new_pair(effect, rules)
            result, _ = assert_same(self, indexed, plain, request)
            self.assertEqual(result, expected, effect)

    # ------------------------------------------------------------------ #
    # priority ordering
    # ------------------------------------------------------------------ #
    def test_priority_order_is_preserved_within_bucket(self):
        rules = [
            ["alice", "doc", "doc1", "read", "allow"],
            ["alice", "doc", "doc1", "read", "deny"],
            ["alice", "doc", "doc2", "read", "deny"],
            ["alice", "doc", "doc2", "read", "allow"],
        ]
        indexed, plain, _, _ = new_pair(PRIORITY, rules)
        for request in (
            ("alice", "doc", "doc1", "read"),
            ("alice", "doc", "doc2", "read"),
        ):
            assert_same(self, indexed, plain, request)

    def test_explicit_priority_token_model(self):
        # File loading sorts rules by the p_priority token, so the lower
        # priority value is evaluated first. The index must not disturb that.
        def build():
            return casbin.Enforcer(
                example("priority_model_explicit.conf"),
                example("priority_policy_explicit.csv"),
            )

        indexed = build()
        plain = build()
        # Partition on the object token p.obj (request r.obj is index 1).
        index = casbin.PolicyIndex(
            request_key=lambda rvals: (rvals[1], True),
            policy_key=lambda rule: rule[2],
        )
        indexed.set_policy_index("p", index)

        # alice is in data1_deny_group; priority-1 allow precedes the
        # priority-10 deny, so data1/read is allowed via the earlier rule.
        result, explain = assert_same(self, indexed, plain, ("alice", "data1", "read"))
        self.assertTrue(result)
        self.assertEqual(explain[0], "1")
        # bob's deny (priority 1) beats his inherited allow group.
        result, explain = assert_same(self, indexed, plain, ("bob", "data2", "read"))
        self.assertFalse(result)

        # Prove pruning independently of timings: data1 lives in its own
        # bucket, so its candidates are a strict subset of the full policy.
        bucket_ids = index.ensure_built(indexed.model["p"]["p"])
        request_bucket, enabled = index.request_bucket(("alice", "data1", "read"))
        self.assertTrue(enabled)
        candidates = [
            rule for rule, bucket in zip(indexed.get_policy(), bucket_ids)
            if bucket == request_bucket
        ]
        self.assertLess(len(candidates), len(plain.get_policy()))
        self.assertTrue(all(rule[2] == "data1" for rule in candidates))

    # ------------------------------------------------------------------ #
    # empty policy
    # ------------------------------------------------------------------ #
    def test_empty_policy(self):
        for effect in (ALLOW_OVERRIDE, DENY_OVERRIDE, ALLOW_AND_DENY, PRIORITY):
            indexed, plain, _, _ = new_pair(effect, [])
            # The index is built lazily on the first request, which here runs
            # against zero policy rules and must still reach the model default.
            assert_same(self, indexed, plain, ("alice", "doc", "doc1", "read"))

    # ------------------------------------------------------------------ #
    # duplicate rules
    # ------------------------------------------------------------------ #
    def test_duplicate_rules_are_deduped_identically(self):
        rules = [
            ["alice", "doc", "doc1", "read", "allow"],
            ["alice", "doc", "doc1", "read", "allow"],
            ["alice", "img", "img1", "read", "deny"],
            ["alice", "img", "img1", "read", "deny"],
        ]
        indexed, plain, _, _ = new_pair(ALLOW_AND_DENY, rules)
        self.assertEqual(indexed.get_policy(), plain.get_policy())
        self.assertEqual(len(indexed.get_policy()), 2)
        for request in (
            ("alice", "doc", "doc1", "read"),
            ("alice", "img", "img1", "read"),
        ):
            assert_same(self, indexed, plain, request)

    # ------------------------------------------------------------------ #
    # multiple policy definitions (ptypes) through an EnforceContext
    # ------------------------------------------------------------------ #
    def test_multiple_policy_types_via_enforce_context(self):
        indexed = casbin.Enforcer(
            example("multiple_policy_definitions_model.conf"),
            example("multiple_policy_definitions_policy.csv"),
        )
        plain = casbin.Enforcer(
            example("multiple_policy_definitions_model.conf"),
            example("multiple_policy_definitions_policy.csv"),
        )

        class Subject:
            def __init__(self, name, age):
                self.name = name
                self.age = age

        # Index p2 (the ABAC policy) on its object token p2.obj. A custom
        # index is required because p2 is paired with request type r2 rather
        # than the default r.
        indexed.set_policy_index(
            "p2",
            casbin.PolicyIndex(
                request_key=lambda rvals: (rvals[1] if len(rvals) > 1 else "", True),
                policy_key=lambda rule: rule[1],
            ),
        )
        ctx = indexed.new_enforce_context("2")
        ctx.etype = "e"

        requests = [
            (Subject("alice", 70), "/data1", "read"),
            (Subject("bob", 30), "/data1", "read"),
            (Subject("bob", 30), "/data1", "write"),
            (Subject("alice", 70), "/data2", "read"),
            (Subject("carol", 45), "/unindexed", "read"),  # bucket missing
        ]
        for request in requests:
            assert_same(self, indexed, plain, request, ctx=ctx)

        # The default "r/p" enforcer must be unaffected by the p2 index.
        assert_same(self, indexed, plain, ("alice", "data2", "read"))

    # ------------------------------------------------------------------ #
    # domain matching
    # ------------------------------------------------------------------ #
    def test_domain_matching(self):
        indexed = casbin.Enforcer(
            example("rbac_with_domains_model.conf"),
            example("rbac_with_domains_policy.csv"),
        )
        plain = casbin.Enforcer(
            example("rbac_with_domains_model.conf"),
            example("rbac_with_domains_policy.csv"),
        )
        # Partition the policy on its domain token.
        indexed.set_policy_index_by_token("p", "r_dom", "p_dom")

        requests = [
            ("alice", "domain1", "data1", "read"),
            ("alice", "domain1", "data1", "write"),
            ("alice", "domain1", "data2", "read"),
            ("bob", "domain2", "data2", "write"),
            ("alice", "domain2", "data2", "read"),   # alice has no domain2 role
            ("nobody", "domain1", "data1", "read"),
            ("alice", "domain_missing", "data1", "read"),
        ]
        for request in requests:
            assert_same(self, indexed, plain, request)

    # ------------------------------------------------------------------ #
    # dynamic role conditions (deterministic, fixed inputs, no wall clock)
    # ------------------------------------------------------------------ #
    def test_dynamic_role_conditions_with_fixed_inputs(self):
        indexed = casbin.Enforcer(
            example("rbac_with_temporal_roles_model.conf"),
            example("rbac_with_temporal_roles_condition_policy.csv"),
        )
        plain = casbin.Enforcer(
            example("rbac_with_temporal_roles_model.conf"),
            example("rbac_with_temporal_roles_condition_policy.csv"),
        )

        # A pure function of its string argument: no datetime / external state.
        def true_func(*args):
            return args[0] in ("_", "true")

        def false_func(*args):
            return args[0] in ("_", "false")

        for enforcer in (indexed, plain):
            enforcer.add_named_link_condition_func("g", "alice", "data2_admin", true_func)
            enforcer.add_named_link_condition_func("g", "alice", "data3_admin", true_func)
            enforcer.add_named_link_condition_func("g", "alice", "data4_admin", false_func)
            enforcer.add_named_link_condition_func("g", "alice", "data5_admin", false_func)
            enforcer.set_named_link_condition_func_params("g", "alice", "data2_admin", "true")
            enforcer.set_named_link_condition_func_params("g", "alice", "data3_admin", "not true")
            enforcer.set_named_link_condition_func_params("g", "alice", "data4_admin", "false")
            enforcer.set_named_link_condition_func_params("g", "alice", "data5_admin", "not false")

        # Partition on the object token; the condition lives in g(), so the
        # index remains a sound partition of the policy rules.
        indexed.set_policy_index_by_token("p", "r_obj", "p_obj")

        requests = [
            ("alice", "data1", "read"),
            ("alice", "data2", "read"),
            ("alice", "data3", "read"),
            ("alice", "data4", "read"),
            ("alice", "data5", "read"),
            ("alice", "data_unknown", "read"),
        ]
        for request in requests:
            assert_same(self, indexed, plain, request)

    # ------------------------------------------------------------------ #
    # request type unsuitable for the index -> fallback to full scan
    # ------------------------------------------------------------------ #
    def test_unsuitable_request_falls_back_to_full_scan(self):
        rules = [
            ["alice", "doc", "doc1", "read", "allow"],
            ["alice", "doc", "doc2", "read", "allow"],
            ["alice", "img", "img1", "read", "allow"],
        ]
        indexed, plain, indexed_probe, plain_probe = new_pair(ALLOW_AND_DENY, rules)
        # Replace the index with one that rejects non-string request keys.
        indexed.set_policy_index(
            "p",
            casbin.PolicyIndex(
                request_key=lambda rvals: (rvals[1], isinstance(rvals[1], str)),
                policy_key=lambda rule: rule[1],
            ),
        )

        good_request = ("alice", "img", "img1", "read")
        odd_request = ("alice", 12345, "img1", "read")  # non-string key -> disabled

        indexed_probe.reset()
        plain_probe.reset()
        assert_same(self, indexed, plain, good_request)
        indexed_good, plain_good = indexed_probe.calls, plain_probe.calls
        self.assertLess(indexed_good, plain_good)  # index genuinely prunes work

        indexed_probe.reset()
        plain_probe.reset()
        assert_same(self, indexed, plain, odd_request)
        self.assertEqual(indexed_probe.calls, plain_probe.calls)  # fallback scans all
        self.assertEqual(indexed_probe.calls, len(plain.get_policy()))

    # ------------------------------------------------------------------ #
    # candidate scan counts prove the index reduces real work
    # ------------------------------------------------------------------ #
    def test_index_reduces_candidate_scan_count(self):
        # A deny rule keeps allow-and-deny from short-circuiting, so every
        # reachable candidate is evaluated and scan counts are deterministic.
        rules = [
            ["alice", "doc", "doc1", "read", "allow"],
            ["alice", "doc", "doc2", "read", "allow"],
            ["alice", "doc", "doc3", "read", "allow"],
            ["alice", "img", "img1", "read", "allow"],
            ["alice", "img", "img2", "read", "allow"],
            ["alice", "*", "shared", "read", "allow"],
            ["alice", "doc", "docX", "read", "deny"],
        ]
        indexed, plain, indexed_probe, plain_probe = new_pair(ALLOW_AND_DENY, rules)
        total = len(rules)

        indexed_probe.reset()
        plain_probe.reset()
        indexed.enforce("alice", "img", "img1", "read")
        plain.enforce("alice", "img", "img1", "read")
        # img bucket (2 rules) + wildcard rule (1) vs full scan of all seven.
        self.assertEqual(plain_probe.calls, total)
        self.assertEqual(indexed_probe.calls, 3)
        self.assertLess(indexed_probe.calls, plain_probe.calls)

        indexed_probe.reset()
        plain_probe.reset()
        indexed.enforce("alice", "doc", "doc1", "read")
        plain.enforce("alice", "doc", "doc1", "read")
        self.assertEqual(indexed_probe.calls, 5)  # four doc rules + wildcard
        self.assertEqual(plain_probe.calls, total)

    # ------------------------------------------------------------------ #
    # mutations: add / update / delete
    # ------------------------------------------------------------------ #
    def test_mutations_keep_indexed_and_plain_equivalent(self):
        rules = [
            ["alice", "doc", "doc1", "read", "allow"],
            ["alice", "img", "img1", "read", "allow"],
        ]
        indexed, plain, _, _ = new_pair(ALLOW_AND_DENY, rules)
        requests = [
            ("alice", "doc", "doc1", "read"),
            ("alice", "doc", "doc2", "read"),
            ("alice", "img", "img1", "read"),
        ]

        def check(label):
            for request in requests:
                assert_same(self, indexed, plain, request)

        check("initial")

        # add: a rule into an existing bucket and a brand-new bucket.
        added_doc = ["alice", "doc", "doc2", "read", "allow"]
        added_audio = ["alice", "audio", "a1", "read", "deny"]
        self.assertTrue(indexed.add_policy(*added_doc) and plain.add_policy(*added_doc))
        self.assertTrue(indexed.add_policy(*added_audio) and plain.add_policy(*added_audio))
        check("after add")
        result, explain = indexed.enforce_ex("alice", "audio", "a1", "read")
        self.assertFalse(result)
        self.assertEqual(explain, added_audio)

        # update: move a rule between buckets (doc -> img).
        old_rule = ["alice", "doc", "doc2", "read", "allow"]
        new_rule = ["alice", "img", "img2", "read", "allow"]
        self.assertTrue(indexed.update_policy(old_rule, new_rule))
        self.assertTrue(plain.update_policy(old_rule, new_rule))
        requests.append(("alice", "img", "img2", "read"))
        check("after update")
        result, explain = indexed.enforce_ex("alice", "img", "img2", "read")
        self.assertTrue(result)
        self.assertEqual(explain, new_rule)

        # delete: remove the remaining doc rule, emptying that bucket.
        self.assertTrue(indexed.remove_policy(*rules[0]))
        self.assertTrue(plain.remove_policy(*rules[0]))
        check("after remove")
        self.assertEqual(indexed.enforce_ex("alice", "doc", "doc1", "read"),
                         plain.enforce_ex("alice", "doc", "doc1", "read"))

    def test_bulk_mutations_keep_equivalent(self):
        rules = [
            ["alice", "doc", "doc1", "read", "allow"],
            ["alice", "img", "img1", "read", "allow"],
        ]
        indexed, plain, _, _ = new_pair(ALLOW_OVERRIDE, rules)
        batch = [
            ["alice", "doc", "doc2", "read", "allow"],
            ["alice", "audio", "a1", "read", "allow"],
        ]
        self.assertTrue(indexed.add_policies([r[:] for r in batch]))
        self.assertTrue(plain.add_policies([r[:] for r in batch]))
        self.assertTrue(
            indexed.remove_filtered_policy(1, "doc")
            and plain.remove_filtered_policy(1, "doc")
        )
        for request in (
            ("alice", "doc", "doc1", "read"),
            ("alice", "doc", "doc2", "read"),
            ("alice", "audio", "a1", "read"),
            ("alice", "img", "img1", "read"),
        ):
            assert_same(self, indexed, plain, request)

    # ------------------------------------------------------------------ #
    # filtered loading
    # ------------------------------------------------------------------ #
    def test_filtered_load_rebuilds_index_equivalently(self):
        policy_path = example("rbac_with_domains_policy.csv")

        def build():
            adapter = FilteredFileAdapter(policy_path)
            enforcer = casbin.Enforcer(example("rbac_with_domains_model.conf"), adapter)
            return enforcer

        indexed = build()
        plain = build()
        indexed.set_policy_index_by_token("p", "r_dom", "p_dom")

        domain_filter = Filter()
        domain_filter.P = ["", "domain1"]
        domain_filter.G = ["", "", "domain1"]
        indexed.load_filtered_policy(domain_filter)
        plain.load_filtered_policy(domain_filter)

        self.assertEqual(indexed.get_policy(), plain.get_policy())
        for request in (
            ("alice", "domain1", "data1", "read"),
            ("alice", "domain1", "data1", "write"),
            ("bob", "domain2", "data2", "write"),  # filtered out -> bucket missing
        ):
            assert_same(self, indexed, plain, request)

    # ------------------------------------------------------------------ #
    # first request after the model is replaced
    # ------------------------------------------------------------------ #
    def test_first_request_after_model_change(self):
        rules = [
            ["alice", "doc", "doc1", "read", "allow"],
            ["alice", "img", "img1", "read", "allow"],
        ]
        indexed, plain, _, _ = new_pair(ALLOW_OVERRIDE, rules, with_eft=False)

        def replacement_model():
            model = casbin.Model()
            model.add_def("r", "r", "sub, obj_type, obj, act")
            model.add_def("p", "p", "sub, obj_type, obj, act")
            model.add_def("g", "g", "_, _")
            model.add_def("e", "e", ALLOW_OVERRIDE)
            model.add_def(
                "m",
                "m",
                "probe() && g(r.sub, p.sub) "
                "&& (p.obj_type == '*' || p.obj_type == r.obj_type) "
                "&& p.obj == r.obj && r.act == p.act",
            )
            return model

        new_rules = [
            ["alice", "img", "img1", "read"],
            ["alice", "doc", "doc1", "read"],
            ["carol", "audio", "a1", "read"],
        ]
        indexed_model = replacement_model()
        plain_model = replacement_model()
        for rule in new_rules:
            indexed_model.add_policy("p", "p", rule[:])
            plain_model.add_policy("p", "p", rule[:])

        indexed.set_model(indexed_model)
        plain.set_model(plain_model)
        indexed_probe = Probe()
        plain_probe = Probe()
        indexed.add_function("probe", indexed_probe.record)
        plain.add_function("probe", plain_probe.record)

        # The index registration survives set_model; its cache was reset, so the
        # very first request must rebuild against the new policy correctly.
        self.assertIn("p", indexed._policy_indexes)
        for request in (
            ("alice", "img", "img1", "read"),
            ("alice", "doc", "doc1", "read"),
            ("carol", "audio", "a1", "read"),
            ("alice", "audio", "a1", "read"),
        ):
            assert_same(self, indexed, plain, request)

    # ------------------------------------------------------------------ #
    # fixed-seed generated combinations, bounded number of cases
    # ------------------------------------------------------------------ #
    def test_generated_combinations_are_equivalent(self):
        rng = random.Random(SEED)
        obj_types = ["doc", "img", "audio"]
        objects = ["o1", "o2", "o3"]
        actions = ["read", "write"]
        subjects = ["alice", "bob"]
        effects = ["allow", "deny"]

        mismatches = []
        reductions = 0
        total_generated = 0

        for case_id in range(GENERATED_CASES):
            rule_count = rng.randint(0, 8)
            rules = []
            for _ in range(rule_count):
                rule = [
                    rng.choice(subjects),
                    rng.choice(obj_types + ["*"]),
                    rng.choice(objects),
                    rng.choice(actions),
                    rng.choice(effects),
                ]
                if rule not in rules:
                    rules.append(rule)

            effect = rng.choice([ALLOW_OVERRIDE, DENY_OVERRIDE, ALLOW_AND_DENY, PRIORITY])
            indexed, plain, indexed_probe, plain_probe = new_pair(effect, rules)

            requests = []
            for _ in range(4):
                requests.append((
                    rng.choice(subjects + ["nobody"]),
                    rng.choice(obj_types + ["video"]),  # "video" may miss every bucket
                    rng.choice(objects + ["oX"]),
                    rng.choice(actions),
                ))

            for request in requests:
                total_generated += 1
                indexed_probe.reset()
                plain_probe.reset()
                indexed_result, indexed_explain = indexed.enforce_ex(*request)
                plain_result, plain_explain = plain.enforce_ex(*request)

                if indexed_probe.calls < plain_probe.calls:
                    reductions += 1
                # The index may never scan more rules than the full path.
                if indexed_probe.calls > plain_probe.calls:
                    mismatches.append(
                        rerunnable_case(case_id, effect, rules, request,
                                        "index scanned {} > plain {}".format(
                                            indexed_probe.calls, plain_probe.calls))
                    )
                if indexed_result != plain_result or list(indexed_explain) != list(plain_explain):
                    mismatches.append(
                        rerunnable_case(
                            case_id, effect, rules, request,
                            "indexed=({},{!r}) plain=({},{!r})".format(
                                indexed_result, indexed_explain, plain_result, plain_explain),
                        )
                    )

        self.assertGreater(total_generated, 0)
        # At least one generated request must demonstrate a real scan reduction,
        # proving the index does work rather than only matching decisions.
        self.assertGreater(reductions, 0)
        if mismatches:
            self.fail("{} mismatch(es); re-runnable cases:\n{}".format(
                len(mismatches), "\n".join(mismatches)))


def rerunnable_case(case_id, effect, rules, request, detail):
    return (
        "[case {}] effect={!r}\n  rules={!r}\n  request={!r}\n  -> {}"
        .format(case_id, effect, rules, request, detail)
    )
