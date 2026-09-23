from casbin.persist.adapters import StringAdapter
from casbin.revocation_planner import (
    RevocationPlan,
    RevocationPlanner,
    verify_plan_on_copy,
)
from tests.test_enforcer import TestCaseBase, get_examples

MODEL = get_examples("rbac_with_domains_model.conf")

# Diamond inheritance: alice -> role_a -> role_c -+
#                    alice -> role_b -> role_c -+-> role_d (holds data1.read)
# plus a bypass path alice -> role_e -> role_d, a cycle edge
# role_b -> role_a, and an irrevocable direct grant of data2.read.
DIAMOND_POLICY = "\n".join(
    [
        "p, role_d, dom1, data1, read",
        "p, alice, dom1, data2, read",
        "g, alice, role_a, dom1",
        "g, alice, role_b, dom1",
        "g, role_a, role_c, dom1",
        "g, role_b, role_c, dom1",
        "g, role_c, role_d, dom1",
        "g, alice, role_e, dom1",
        "g, role_e, role_d, dom1",
        "g, role_b, role_a, dom1",
    ]
)

# Deleting the shared exit role_c -> role_d (3) beats deleting both
# diamond entries (5 + 5) or both middle edges (4 + 4).
DIAMOND_COSTS = {
    ("alice", "role_a", "dom1"): 5,
    ("alice", "role_b", "dom1"): 5,
    ("role_a", "role_c", "dom1"): 4,
    ("role_b", "role_c", "dom1"): 4,
    ("role_c", "role_d", "dom1"): 3,
    ("alice", "role_e", "dom1"): 2,
    ("role_e", "role_d", "dom1"): 9,
    ("role_b", "role_a", "dom1"): 100,
}


class TestRevocationPlanner(TestCaseBase):
    def get_diamond_enforcer(self):
        return self.get_enforcer(MODEL, StringAdapter(DIAMOND_POLICY))

    def test_optimal_plan_prefers_shared_exit(self):
        e = self.get_diamond_enforcer()
        self.assertTrue(e.enforce("alice", "dom1", "data1", "read"))

        planner = RevocationPlanner(e)
        plan = planner.plan_revocation("alice", "dom1", "data1", "read", DIAMOND_COSTS)

        self.assertTrue(plan.feasible)
        # The shared exit edge is cut once, the bypass is cut at its
        # cheap entry; the shared edge cost is not charged twice.
        self.assertEqual(
            plan.rules,
            [["role_c", "role_d", "dom1"], ["alice", "role_e", "dom1"]],
        )
        self.assertEqual(plan.total_cost, 5)
        # Every planned deletion maps back to an existing grouping policy.
        grouping = e.get_grouping_policy()
        for rule in plan.rules:
            self.assertIn(rule, grouping)
        # Planning is read-only: the enforcer still grants the permission.
        self.assertTrue(e.enforce("alice", "dom1", "data1", "read"))

    def test_bypass_path_is_cut(self):
        e = self.get_diamond_enforcer()
        planner = RevocationPlanner(e)
        plan = planner.plan_revocation("alice", "dom1", "data1", "read", DIAMOND_COSTS)

        # Cutting only the shared diamond exit leaves the bypass alive.
        partial_plan = RevocationPlan(True, [["role_c", "role_d", "dom1"]], 3)
        self.assertFalse(
            verify_plan_on_copy(e, partial_plan, "alice", "dom1", "data1", "read")
        )

        # The full plan severs the bypass too and verifies on a copy.
        self.assertIn(["alice", "role_e", "dom1"], plan.rules)
        self.assertTrue(verify_plan_on_copy(e, plan, "alice", "dom1", "data1", "read"))
        # Verification did not touch the original enforcer.
        self.assertTrue(e.enforce("alice", "dom1", "data1", "read"))
        self.assertEqual(len(e.get_grouping_policy()), 8)

    def test_direct_grant_is_infeasible(self):
        e = self.get_diamond_enforcer()
        planner = RevocationPlanner(e)
        plan = planner.plan_revocation("alice", "dom1", "data2", "read", DIAMOND_COSTS)

        self.assertFalse(plan.feasible)
        self.assertEqual(plan.rules, [])
        self.assertIn("directly", plan.reason)

    def test_undeletable_bridge_is_infeasible(self):
        policy = "\n".join(
            [
                "p, role_x, dom1, data3, read",
                "g, alice, role_x, dom1",
            ]
        )
        e = self.get_enforcer(MODEL, StringAdapter(policy))
        planner = RevocationPlanner(e)

        # The only edge is undeletable (absent from the cost map).
        plan = planner.plan_revocation("alice", "dom1", "data3", "read", {})
        self.assertFalse(plan.feasible)

        # Once deletable, the same edge becomes the plan.
        plan = planner.plan_revocation(
            "alice", "dom1", "data3", "read", {("alice", "role_x", "dom1"): 7}
        )
        self.assertTrue(plan.feasible)
        self.assertEqual(plan.rules, [["alice", "role_x", "dom1"]])
        self.assertEqual(plan.total_cost, 7)
        self.assertTrue(verify_plan_on_copy(e, plan, "alice", "dom1", "data3", "read"))

    def test_tie_break_follows_stable_edge_order(self):
        # Two diamond entries (1 + 1) and both middle edges (1 + 1) are
        # equally cheap cuts; the shared exit is expensive.
        policy = "\n".join(
            [
                "p, role_x, dom1, data1, read",
                "g, alice, role_a, dom1",
                "g, alice, role_b, dom1",
                "g, role_a, role_c, dom1",
                "g, role_b, role_c, dom1",
                "g, role_c, role_x, dom1",
            ]
        )
        costs = {
            ("alice", "role_a", "dom1"): 1,
            ("alice", "role_b", "dom1"): 1,
            ("role_a", "role_c", "dom1"): 1,
            ("role_b", "role_c", "dom1"): 1,
            ("role_c", "role_x", "dom1"): 100,
        }
        e = self.get_enforcer(MODEL, StringAdapter(policy))
        planner = RevocationPlanner(e)

        plan = planner.plan_revocation("alice", "dom1", "data1", "read", costs)
        # The stable-order tie-break keeps the earliest edges and cuts
        # the latest edges among equal-cost plans.
        self.assertEqual(
            plan.rules,
            [["role_a", "role_c", "dom1"], ["role_b", "role_c", "dom1"]],
        )
        self.assertEqual(plan.total_cost, 2)

        again = RevocationPlanner(e).plan_revocation(
            "alice", "dom1", "data1", "read", costs
        )
        self.assertEqual(again.rules, plan.rules)
        self.assertTrue(verify_plan_on_copy(e, plan, "alice", "dom1", "data1", "read"))

    def test_unknown_permission_needs_no_action(self):
        e = self.get_diamond_enforcer()
        planner = RevocationPlanner(e)
        plan = planner.plan_revocation("alice", "dom1", "data9", "read", DIAMOND_COSTS)

        self.assertTrue(plan.feasible)
        self.assertEqual(plan.rules, [])
        self.assertEqual(plan.total_cost, 0)

    def test_report_lists_policy_lines_and_total_cost(self):
        e = self.get_diamond_enforcer()
        planner = RevocationPlanner(e)
        plan = planner.plan_revocation("alice", "dom1", "data1", "read", DIAMOND_COSTS)

        self.assertEqual(
            plan.policy_lines,
            ["g, role_c, role_d, dom1", "g, alice, role_e, dom1"],
        )
        report = plan.report()
        self.assertIn("g, role_c, role_d, dom1", report)
        self.assertIn("g, alice, role_e, dom1", report)
        self.assertIn("total cost: 5", report)
