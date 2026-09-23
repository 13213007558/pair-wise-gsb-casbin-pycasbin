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
from casbin.shadow import (
    PathPattern,
    ShadowChecker,
    UnsupportedError,
    check_shadowing,
)
from casbin.shadow.patterns import find_path_outside


def get_examples(path):
    examples_path = os.path.split(os.path.realpath(__file__))[0] + "/../examples/"
    return os.path.abspath(examples_path + path)


PRIORITY_PATH_MODEL = """
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act, eft

[role_definition]
g = _, _

[policy_effect]
e = priority(p.eft) || deny

[matchers]
m = g(r.sub, p.sub) && pathMatch(r.obj, p.obj) && r.act == p.act
"""

PRIORITY_EXPLICIT_MODEL = """
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


def write_tmp(directory, name, text):
    path = os.path.join(directory, name)
    with open(path, "w") as f:
        f.write(text)
    return path


class TestPathPattern(TestCase):
    def test_single_star_matches_exactly_one_segment(self):
        pattern = PathPattern.parse("/a/*")
        self.assertTrue(pattern.matches("/a/x"))
        self.assertFalse(pattern.matches("/a"))
        # the counterexample: /a/* must not cover /a/x/y
        self.assertFalse(pattern.matches("/a/x/y"))
        self.assertFalse(pattern.covers(PathPattern.parse("/a/x/y")))

    def test_double_star_matches_zero_or_more_segments(self):
        pattern = PathPattern.parse("/a/**")
        self.assertTrue(pattern.matches("/a"))
        self.assertTrue(pattern.matches("/a/x"))
        self.assertTrue(pattern.matches("/a/x/y"))
        self.assertFalse(pattern.matches("/ab/x"))

    def test_double_star_only_allowed_at_end(self):
        with self.assertRaises(ValueError):
            PathPattern.parse("/a/**/b")

    def test_star_must_occupy_whole_segment(self):
        with self.assertRaises(ValueError):
            PathPattern.parse("/a/x*")

    def test_intersection(self):
        self.assertEqual(
            PathPattern.parse("/a/*").intersect(PathPattern.parse("/a/**")),
            PathPattern.parse("/a/*"),
        )
        self.assertEqual(
            PathPattern.parse("/a/*/c").intersect(PathPattern.parse("/a/b/*")),
            PathPattern.parse("/a/b/c"),
        )
        self.assertIsNone(PathPattern.parse("/a/x").intersect(PathPattern.parse("/a/y")))
        self.assertIsNone(PathPattern.parse("/a").intersect(PathPattern.parse("/a/b")))

    def test_joint_coverage_by_two_patterns(self):
        # /a alone does not cover /a/**, /a/*/** alone does not either,
        # but together they do.
        target = PathPattern.parse("/a/**")
        self.assertIsNotNone(find_path_outside(target, [PathPattern.parse("/a")]))
        self.assertIsNotNone(find_path_outside(target, [PathPattern.parse("/a/*/**")]))
        self.assertIsNone(
            find_path_outside(target, [PathPattern.parse("/a"), PathPattern.parse("/a/*/**")])
        )

    def test_star_not_coverable_by_finitely_many_literals(self):
        witness = find_path_outside(
            PathPattern.parse("/a/*"), [PathPattern.parse("/a/b"), PathPattern.parse("/a/c")]
        )
        self.assertIsNotNone(witness)
        self.assertTrue(PathPattern.parse("/a/*").matches(witness))

    def test_tail_pattern_needs_deeper_witness(self):
        witness = find_path_outside(PathPattern.parse("/a/b/**"), [PathPattern.parse("/a/b")])
        self.assertEqual("/a/b/x", witness)


class TestShadowChecker(TestCase):
    def run_checker(self, model_text, policy_text):
        with tempfile.TemporaryDirectory() as tmp:
            model = write_tmp(tmp, "model.conf", model_text)
            policy = write_tmp(tmp, "policy.csv", policy_text)
            return ShadowChecker(model_path=model, policy_path=policy).check()

    def test_exact_duplicate_is_shadowed(self):
        report = self.run_checker(
            PRIORITY_PATH_MODEL,
            "p, alice, /data1, read, allow\n"
            "p, alice, /data1, read, deny\n",
        )
        self.assertFalse(report.reports[0].shadowed)
        self.assertTrue(report.reports[1].shadowed)
        self.assertEqual([0], report.reports[1].covered_by)

    def test_two_earlier_patterns_jointly_cover_later_one(self):
        # the required example: neither /data nor /data/*/** alone covers
        # /data/**, together they do.
        report = self.run_checker(
            PRIORITY_PATH_MODEL,
            "p, alice, /data, read, allow\n"
            "p, alice, /data/*/**, read, allow\n"
            "p, alice, /data/**, read, deny\n",
        )
        covered = report.reports[2]
        self.assertTrue(covered.shadowed)
        self.assertEqual([0, 1], covered.covered_by)

    def test_single_star_does_not_shadow_deeper_rule(self):
        # the required counterexample: /a/* cannot cover /a/x/y.
        report = self.run_checker(
            PRIORITY_PATH_MODEL,
            "p, alice, /a/*, read, deny\n"
            "p, alice, /a/x/y, read, allow\n",
        )
        self.assertFalse(report.reports[1].shadowed)
        self.assertEqual([], report.reports[1].overlaps)

    def test_partial_overlap_reports_verified_witness(self):
        report = self.run_checker(
            PRIORITY_PATH_MODEL,
            "p, alice, /data/*, read, deny\n"
            "p, alice, /data/**, read, allow\n",
        )
        later = report.reports[1]
        self.assertFalse(later.shadowed)
        self.assertEqual(1, len(later.overlaps))
        overlap = later.overlaps[0]
        self.assertEqual(0, overlap.earlier_index)
        self.assertEqual("alice", overlap.witness["sub"])
        self.assertEqual("read", overlap.witness["act"])
        self.assertTrue(PathPattern.parse("/data/*").matches(overlap.witness["obj"]))
        # the earlier deny rule decides at the witness point
        self.assertFalse(overlap.enforcer_result)
        self.assertTrue(overlap.verified)

    def test_role_members_shadowed_by_role_rule(self):
        report = self.run_checker(
            PRIORITY_PATH_MODEL,
            "p, admin, /data1, read, allow\n"
            "p, alice, /data1, read, deny\n"
            "\n"
            "g, alice, admin\n",
        )
        self.assertTrue(report.reports[1].shadowed)
        self.assertEqual([0], report.reports[1].covered_by)

    def test_role_rule_jointly_covered_by_two_patterns(self):
        # two earlier patterns jointly cover the role's rule, including
        # requests from the role's member alice.
        report = self.run_checker(
            PRIORITY_PATH_MODEL,
            "p, admin, /data, read, deny\n"
            "p, admin, /data/*/**, read, deny\n"
            "p, admin, /data/**, read, allow\n"
            "\n"
            "g, alice, admin\n",
        )
        covered = report.reports[2]
        self.assertTrue(covered.shadowed)
        self.assertEqual([0, 1], covered.covered_by)

    def test_role_itself_is_a_subject(self):
        # g(r.sub, p.sub) also matches p.sub itself, so a rule for the role
        # is not covered by rules that only mention the role's members.
        report = self.run_checker(
            PRIORITY_PATH_MODEL,
            "p, alice, /data1, read, allow\n"
            "p, admin, /data1, read, deny\n"
            "\n"
            "g, alice, admin\n",
        )
        self.assertFalse(report.reports[1].shadowed)

    def test_explicit_priority_order_and_stability(self):
        # explicit priorities are honoured (5 before 10) ...
        report = self.run_checker(
            PRIORITY_EXPLICIT_MODEL,
            "p, 10, alice, data1, read, allow\n"
            "p, 5, alice, data1, read, deny\n",
        )
        self.assertEqual("deny", report.reports[0].effect)
        self.assertTrue(report.reports[1].shadowed)
        self.assertEqual([0], report.reports[1].covered_by)

        # ... and equal priorities keep the original file order (stable sort).
        report = self.run_checker(
            PRIORITY_EXPLICIT_MODEL,
            "p, 5, alice, data1, read, deny\n"
            "p, 5, alice, data1, read, allow\n",
        )
        self.assertEqual("deny", report.reports[0].effect)
        self.assertTrue(report.reports[1].shadowed)

    def test_domains_are_isolated(self):
        report = check_shadowing(
            get_examples("shadow_domain_model.conf"),
            self._write_policy(
                "p, alice, domain1, /data/**, read, allow\n"
                "p, alice, domain2, /data/**, read, deny\n"
                "p, alice, domain1, /data/x, read, deny\n"
            ),
        )
        self.assertFalse(report.reports[1].shadowed)
        self.assertTrue(report.reports[2].shadowed)
        self.assertEqual([0], report.reports[2].covered_by)

    def test_domain_overlap_witness_is_verified(self):
        report = check_shadowing(
            get_examples("shadow_domain_model.conf"),
            self._write_policy(
                "p, alice, domain1, /data/*, read, deny\n"
                "p, alice, domain1, /data/**, read, allow\n"
            ),
        )
        overlaps = report.reports[1].overlaps
        self.assertEqual(1, len(overlaps))
        self.assertEqual("domain1", overlaps[0].witness["dom"])
        self.assertFalse(overlaps[0].enforcer_result)
        self.assertTrue(overlaps[0].verified)

    def _write_policy(self, text):
        fd, path = tempfile.mkstemp(suffix=".csv")
        with os.fdopen(fd, "w") as f:
            f.write(text)
        self.addCleanup(os.remove, path)
        return path

    def test_shipped_example(self):
        report = check_shadowing(
            get_examples("shadow_path_model.conf"), get_examples("shadow_path_policy.csv")
        )
        # p, alice, /data/**, read, deny is jointly covered by the two
        # earlier allow rules (/data and /data/*/**).
        self.assertTrue(report.reports[2].shadowed)
        self.assertEqual([0, 1], report.reports[2].covered_by)
        # /a/* does not cover /a/x/y: bob's deep rule stays live.
        self.assertFalse(report.reports[4].shadowed)
        self.assertTrue(report.policy_order_preserved)

    def test_existing_priority_model_example(self):
        report = check_shadowing(
            get_examples("priority_model.conf"), get_examples("priority_policy.csv")
        )
        shadowed = {r.index for r in report.shadowed}
        # alice's allow on data1/write is pre-empted by the deny group rule;
        # bob's deny on data2/read is pre-empted by the allow group rule.
        self.assertEqual({3, 5}, shadowed)
        self.assertEqual([2], report.reports[3].covered_by)
        self.assertEqual([4], report.reports[5].covered_by)
        # rule 1 (deny) overlaps rule 0 (allow) for alice on data1/read.
        overlaps = report.reports[1].overlaps
        self.assertEqual(1, len(overlaps))
        self.assertEqual("alice", overlaps[0].witness["sub"])
        self.assertTrue(overlaps[0].enforcer_result)
        self.assertTrue(overlaps[0].verified)
        self.assertTrue(report.policy_order_preserved)

    def test_policy_order_is_not_modified(self):
        e = casbin.Enforcer(
            get_examples("priority_model.conf"), get_examples("priority_policy.csv")
        )
        before = e.get_policy()
        ShadowChecker(enforcer=e).check()
        self.assertEqual(before, e.get_policy())

    def test_unknown_matcher_is_unsupported(self):
        model = PRIORITY_PATH_MODEL.replace(
            "pathMatch(r.obj, p.obj)", "regexMatch(r.obj, p.obj)"
        )
        with self.assertRaises(UnsupportedError):
            self.run_checker(model, "p, alice, /data1, read, allow\n")

    def test_abac_matcher_is_unsupported(self):
        model = PRIORITY_PATH_MODEL.replace(
            "pathMatch(r.obj, p.obj) && r.act == p.act",
            "r.obj.Owner == p.sub && r.act == p.act",
        )
        with self.assertRaises(UnsupportedError):
            self.run_checker(model, "p, alice, /data1, read, allow\n")

    def test_non_priority_effect_is_unsupported(self):
        model = PRIORITY_PATH_MODEL.replace(
            "priority(p.eft) || deny", "some(where (p.eft == allow))"
        )
        with self.assertRaises(UnsupportedError):
            self.run_checker(model, "p, alice, /data1, read, allow\n")

    def test_conditional_role_is_unsupported(self):
        policy = "p, alice, /data1, read, allow\n\ng, alice, admin, domain1\n"
        with self.assertRaises(UnsupportedError):
            self.run_checker(PRIORITY_PATH_MODEL, policy)

    def test_role_matching_function_is_unsupported(self):
        with tempfile.TemporaryDirectory() as tmp:
            model = write_tmp(tmp, "model.conf", PRIORITY_PATH_MODEL)
            policy = write_tmp(
                tmp,
                "policy.csv",
                "p, admin, /data1, read, allow\n\ng, alice, adm\n",
            )
            e = casbin.Enforcer(model, policy)
            e.get_role_manager().add_matching_func(lambda a, b: a.startswith(b))
            with self.assertRaises(UnsupportedError):
                ShadowChecker(enforcer=e)

    def test_wildcards_rejected_for_exact_object_matcher(self):
        model = PRIORITY_PATH_MODEL.replace("pathMatch(r.obj, p.obj)", "r.obj == p.obj")
        with self.assertRaises(UnsupportedError):
            self.run_checker(model, "p, alice, /data/*, read, allow\n")
