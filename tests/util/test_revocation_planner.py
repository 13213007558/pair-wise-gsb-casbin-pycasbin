from unittest import TestCase

import casbin
from casbin.util import plan_revocation, verify_plan_on_copy

MODEL = "examples/rbac_with_domains_model.conf"
DOM = "domain1"


def new_enforcer():
    # no adapter: policies live in memory only
    return casbin.Enforcer(MODEL)


def diamond_enforcer():
    """alice -> {role_a, role_b} -> role_c -> role_d -[p]-> data1.read"""
    e = new_enforcer()
    e.add_policy("role_d", DOM, "data1", "read")
    e.add_grouping_policy("alice", "role_a", DOM)
    e.add_grouping_policy("alice", "role_b", DOM)
    e.add_grouping_policy("role_a", "role_c", DOM)
    e.add_grouping_policy("role_b", "role_c", DOM)
    e.add_grouping_policy("role_c", "role_d", DOM)
    return e


DIAMOND_COSTS = {
    ("alice", "role_a", DOM): 5,
    ("alice", "role_b", DOM): 5,
    ("role_a", "role_c", DOM): 4,
    ("role_b", "role_c", DOM): 4,
    ("role_c", "role_d", DOM): 3,  # common exit: cheaper than both entries
}


class RecordingWatcher:
    def __init__(self):
        self.calls = 0

    def update(self):
        self.calls += 1


class TestRevocationPlanner(TestCase):
    def test_diamond_cut_common_exit(self):
        e = diamond_enforcer()
        self.assertTrue(e.enforce("alice", DOM, "data1", "read"))

        plan = plan_revocation(e, "alice", DOM, "data1", "read", DIAMOND_COSTS)

        self.assertTrue(plan.feasible)
        self.assertEqual(plan.policies, [("role_c", "role_d", DOM)])
        self.assertEqual(plan.total_cost, 3)
        # every plan item maps back to an existing grouping policy
        existing = {tuple(rule) for rule in e.get_grouping_policy()}
        for policy in plan.policies:
            self.assertIn(policy, existing)
        # planning must not mutate the enforcer
        self.assertTrue(e.enforce("alice", DOM, "data1", "read"))
        self.assertEqual(len(e.get_grouping_policy()), 5)
        # verification happens on a copy and revokes the permission there
        self.assertTrue(verify_plan_on_copy(e, plan, "alice", DOM, "data1", "read"))
        self.assertTrue(e.enforce("alice", DOM, "data1", "read"))

    def test_bypass_path_is_cut_too(self):
        # three role paths reach the same permission; all three must be cut
        e = diamond_enforcer()
        e.add_grouping_policy("alice", "role_e", DOM)
        e.add_grouping_policy("role_e", "role_d", DOM)  # undeletable bypass exit
        costs = dict(DIAMOND_COSTS)
        costs[("alice", "role_e", DOM)] = 2

        plan = plan_revocation(e, "alice", DOM, "data1", "read", costs)

        self.assertTrue(plan.feasible)
        # common exit (3) + bypass entry (2); items follow stable policy order
        self.assertEqual(
            plan.policies,
            [("role_c", "role_d", DOM), ("alice", "role_e", DOM)],
        )
        self.assertEqual(plan.total_cost, 5)
        self.assertTrue(verify_plan_on_copy(e, plan, "alice", DOM, "data1", "read"))

    def test_undeletable_direct_grant_is_infeasible(self):
        e = diamond_enforcer()
        e.add_policy("alice", DOM, "data1", "read")  # direct grant, not a g edge

        plan = plan_revocation(e, "alice", DOM, "data1", "read", DIAMOND_COSTS)

        self.assertFalse(plan.feasible)
        self.assertEqual(plan.items, [])
        self.assertIn("directly", plan.reason)
        self.assertIn("INFEASIBLE", plan.report())

    def test_undeletable_only_path_is_infeasible(self):
        e = new_enforcer()
        e.add_policy("role_x", DOM, "data1", "read")
        e.add_grouping_policy("alice", "role_x", DOM)  # undeletable

        plan = plan_revocation(e, "alice", DOM, "data1", "read", {})

        self.assertFalse(plan.feasible)
        self.assertIn("undeletable", plan.reason)

    def test_role_graph_cycle(self):
        e = diamond_enforcer()
        e.add_grouping_policy("role_c", "role_a", DOM)  # cycle role_a <-> role_c
        costs = dict(DIAMOND_COSTS)
        costs[("role_c", "role_a", DOM)] = 1

        plan = plan_revocation(e, "alice", DOM, "data1", "read", costs)

        self.assertTrue(plan.feasible)
        self.assertEqual(plan.policies, [("role_c", "role_d", DOM)])
        self.assertEqual(plan.total_cost, 3)

    def test_shared_edge_costed_once(self):
        e = new_enforcer()
        e.add_policy("role_h1", DOM, "data1", "read")
        e.add_policy("role_h2", DOM, "data1", "read")
        e.add_grouping_policy("alice", "role_m", DOM)
        e.add_grouping_policy("role_m", "role_h1", DOM)  # undeletable
        e.add_grouping_policy("role_m", "role_h2", DOM)  # undeletable

        plan = plan_revocation(
            e, "alice", DOM, "data1", "read", {("alice", "role_m", DOM): 4}
        )

        self.assertTrue(plan.feasible)
        self.assertEqual(plan.policies, [("alice", "role_m", DOM)])
        self.assertEqual(plan.total_cost, 4)  # not 8: the shared edge is paid once

    def test_tie_broken_by_stable_policy_order(self):
        e = new_enforcer()
        e.add_policy("role_h", DOM, "data1", "read")
        e.add_grouping_policy("alice", "role_t", DOM)
        e.add_grouping_policy("role_t", "role_h", DOM)
        costs = {("alice", "role_t", DOM): 1, ("role_t", "role_h", DOM): 1}

        plan = plan_revocation(e, "alice", DOM, "data1", "read", costs)

        self.assertTrue(plan.feasible)
        # either edge alone costs 1; the earlier policy line wins
        self.assertEqual(plan.policies, [("alice", "role_t", DOM)])
        self.assertEqual(plan.total_cost, 1)

    def test_no_permission_is_empty_plan(self):
        e = diamond_enforcer()

        plan = plan_revocation(e, "bob", DOM, "data1", "read", DIAMOND_COSTS)

        self.assertTrue(plan.feasible)
        self.assertEqual(plan.items, [])
        self.assertEqual(plan.total_cost, 0)

    def test_unknown_permission_is_empty_plan(self):
        e = diamond_enforcer()

        plan = plan_revocation(e, "alice", DOM, "data9", "write", DIAMOND_COSTS)

        self.assertTrue(plan.feasible)
        self.assertEqual(plan.items, [])

    def test_report_lists_policy_lines_and_total(self):
        e = diamond_enforcer()

        plan = plan_revocation(e, "alice", DOM, "data1", "read", DIAMOND_COSTS)
        text = plan.report()

        self.assertIn("g, role_c, role_d, domain1", text)
        self.assertIn("total cost 3", text)

    def test_deletable_edge_must_exist(self):
        e = diamond_enforcer()
        costs = dict(DIAMOND_COSTS)
        costs[("alice", "ghost", DOM)] = 1
        with self.assertRaises(ValueError):
            plan_revocation(e, "alice", DOM, "data1", "read", costs)

    def test_deny_policy_rejected(self):
        e = diamond_enforcer()
        e.add_policy("role_d", DOM, "data2", "read", "deny")
        with self.assertRaises(ValueError):
            plan_revocation(e, "alice", DOM, "data1", "read", DIAMOND_COSTS)

    def test_verify_does_not_touch_adapter_or_watcher(self):
        import os
        import tempfile

        fd, path = tempfile.mkstemp(suffix=".csv")
        os.close(fd)
        try:
            with open(path, "w") as f:
                f.write("p, role_d, domain1, data1, read\n")
                f.write("g, alice, role_a, domain1\n")
                f.write("g, alice, role_b, domain1\n")
                f.write("g, role_a, role_c, domain1\n")
                f.write("g, role_b, role_c, domain1\n")
                f.write("g, role_c, role_d, domain1\n")
            before = open(path).read()

            e = casbin.Enforcer(MODEL, path)
            watcher = RecordingWatcher()
            e.set_watcher(watcher)
            self.assertTrue(e.enforce("alice", DOM, "data1", "read"))

            plan = plan_revocation(e, "alice", DOM, "data1", "read", DIAMOND_COSTS)
            self.assertTrue(verify_plan_on_copy(e, plan, "alice", DOM, "data1", "read"))

            # original enforcer, policy file and watcher are untouched
            self.assertTrue(e.enforce("alice", DOM, "data1", "read"))
            self.assertEqual(open(path).read(), before)
            self.assertEqual(watcher.calls, 0)
        finally:
            os.unlink(path)

    def test_verify_rejects_bogus_plan_item(self):
        from casbin.util import RevocationPlan, RevocationPlanItem

        e = diamond_enforcer()
        bogus = RevocationPlan(
            feasible=True,
            items=[RevocationPlanItem(policy=("alice", "ghost", DOM), cost=1)],
            total_cost=1,
        )
        with self.assertRaises(ValueError):
            verify_plan_on_copy(e, bogus, "alice", DOM, "data1", "read")
