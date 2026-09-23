"""Minimum-cost permission revocation planner for PyCasbin.

Scope and assumptions:

- finite, exact-match RBAC with domains (r = sub, dom, obj, act,
  g = _, _, _); no wildcards, no keyMatch/globMatch and no custom
  matchers;
- allow-only policies (e = some(where (p.eft == allow)));
- the only permitted operation is deleting existing grouping-policy
  ('g') rules. Adding deny rules or changing the effect is not an
  available operation, so a permission granted directly to the user by
  a 'p' rule makes the request infeasible.

The planner is read-only: it never mutates the given enforcer, its
adapter or its watcher. Use verify_plan_on_copy to check a plan on a
throwaway copy of the model.

Algorithm: the user is the source, every grouping rule inside the
domain becomes a directed edge (deletable edges carry their cost,
undeletable ones get infinite capacity), and every subject holding the
target permission is connected to a super sink with infinite capacity.
The minimum s-t cut is the cheapest set of grouping rules whose
deletion severs every role path to the permission. A shared edge is a
single cut edge, so its cost is counted only once. Cycles in the role
graph are handled naturally by the max-flow computation.

Tie-breaking: among minimum-cost cuts the planner picks the
lexicographically smallest one with respect to the stable edge order
(the order in which grouping rules are returned by the enforcer, i.e.
adapter order). Edges earlier in that order are preferred to be kept;
the cut falls on the latest possible edges. This makes the plan
deterministic.
"""

import copy
from collections import deque

import casbin
from casbin.persist.adapters.string_adapter import StringAdapter

_EPS = 1e-9


class RevocationPlan:
    """The result of planning a revocation.

    'feasible' tells whether the permission can be revoked at all by
    deleting grouping policies only. 'rules' holds the grouping rules to
    delete (each a list like ['alice', 'role_a', 'dom1']), in the
    stable edge order of the enforcer. 'total_cost' is the sum of the
    costs of those rules; every rule appears at most once, so a shared
    edge is never charged twice. 'reason' explains infeasible or
    trivial plans.
    """

    def __init__(self, feasible, rules, total_cost, reason=""):
        self.feasible = feasible
        self.rules = rules
        self.total_cost = total_cost
        self.reason = reason

    @property
    def policy_lines(self):
        """The actual policy lines the plan would delete."""
        return ["g, " + ", ".join(rule) for rule in self.rules]

    def report(self):
        """A human-readable report of the planned deletions."""
        if not self.feasible:
            return "INFEASIBLE: " + self.reason
        if not self.rules:
            return "nothing to delete (" + self.reason + ")"
        lines = ["grouping policies to delete:"]
        lines.extend("  " + line for line in self.policy_lines)
        lines.append("total cost: {}".format(self.total_cost))
        return "\n".join(lines)

    def __repr__(self):
        return "RevocationPlan(feasible={!r}, rules={!r}, total_cost={!r})".format(
            self.feasible, self.rules, self.total_cost
        )


def _maxflow(node_count, arcs, source, sink):
    """Edmonds-Karp max flow. 'arcs' are (u, v, capacity) tuples."""
    graph = [[] for _ in range(node_count)]
    for u, v, cap in arcs:
        fwd = [v, cap, len(graph[v])]
        rev = [u, 0.0, len(graph[u])]
        graph[u].append(fwd)
        graph[v].append(rev)

    flow = 0.0
    while True:
        prev = [None] * node_count
        prev[source] = (source, -1)
        queue = deque([source])
        while queue and prev[sink] is None:
            cur = queue.popleft()
            for index, edge in enumerate(graph[cur]):
                if edge[1] > _EPS and prev[edge[0]] is None:
                    prev[edge[0]] = (cur, index)
                    queue.append(edge[0])
        if prev[sink] is None:
            return flow
        bottleneck = None
        node = sink
        while node != source:
            prev_node, edge_index = prev[node]
            cap = graph[prev_node][edge_index][1]
            bottleneck = cap if bottleneck is None else min(bottleneck, cap)
            node = prev_node
        node = sink
        while node != source:
            prev_node, edge_index = prev[node]
            edge = graph[prev_node][edge_index]
            edge[1] -= bottleneck
            graph[node][edge[2]][1] += bottleneck
            node = prev_node
        flow += bottleneck


class RevocationPlanner:
    """Plans minimum-cost revocations over a read-only policy snapshot.

    The snapshot (grouping rules and policy rules, in adapter order) is
    taken once at construction; the enforcer is never modified.
    """

    def __init__(self, enforcer):
        self._grouping_rules = [list(rule) for rule in enforcer.get_grouping_policy()]
        self._policy_rules = [list(rule) for rule in enforcer.get_policy()]

    def plan_revocation(self, user, domain, obj, act, edge_costs):
        """Plans the cheapest way to revoke (domain, obj, act) from 'user'.

        'edge_costs' maps a grouping rule (sub, role, dom) to the cost
        of deleting it. Grouping rules missing from the mapping are
        undeletable: they still take part in reachability, but the cut
        can never select them. Returns a RevocationPlan.
        """
        costs = {}
        for key, value in edge_costs.items():
            if value < 0:
                raise ValueError("edge cost must be non-negative: {!r}".format(key))
            costs[tuple(key)] = value

        holders = [
            rule[0]
            for rule in self._policy_rules
            if rule[1] == domain and rule[2] == obj and rule[3] == act
        ]
        if user in holders:
            return RevocationPlan(
                False,
                [],
                0,
                "permission is granted directly to {!r} by a p rule and "
                "cannot be revoked by deleting grouping policies".format(user),
            )
        if not holders:
            return RevocationPlan(
                True, [], 0, "no policy grants this permission; nothing to do"
            )

        # Only grouping rules of this domain grant membership here.
        # Each edge is (sub, role, cost, domain); cost None = undeletable.
        edges = []
        for rule in self._grouping_rules:
            if rule[2] != domain:
                continue
            edges.append((rule[0], rule[1], costs.get(tuple(rule)), rule[2]))

        deletable_total = sum(cost for _, _, cost, _ in edges if cost is not None)
        inf = deletable_total + 1

        node_ids = {user: 0}
        source = 0

        def node_id(name):
            if name not in node_ids:
                node_ids[name] = len(node_ids) + 1
            return node_ids[name]

        for sub, role, _, _ in edges:
            node_id(sub)
            node_id(role)
        for holder in holders:
            node_id(holder)
        sink = len(node_ids) + 1
        node_count = len(node_ids) + 2

        def build_arcs(excluded, included):
            arcs = []
            for holder in holders:
                arcs.append((node_ids[holder], sink, inf))
            for index, (sub, role, cost, _) in enumerate(edges):
                if index in included:
                    continue
                if cost is None or index in excluded:
                    arcs.append((node_ids[sub], node_ids[role], inf))
                else:
                    arcs.append((node_ids[sub], node_ids[role], cost))
            return arcs

        def cut_cost(excluded, included):
            return _maxflow(node_count, build_arcs(excluded, included), source, sink)

        optimum = cut_cost(set(), set())
        if optimum >= inf:
            return RevocationPlan(
                False,
                [],
                0,
                "every role path to the permission uses undeletable "
                "grouping policies",
            )

        # Tie-break: greedily keep edges in stable order; an edge joins
        # the cut only if no minimum-cost cut can avoid it.
        included = []
        excluded = set()
        budget = optimum
        for index, (_, _, cost, _) in enumerate(edges):
            if cost is None:
                continue
            if abs(cut_cost(excluded | {index}, included) - budget) <= _EPS:
                excluded.add(index)
            else:
                included.append(index)
                budget -= cost

        rules = [
            [sub, role, domain]
            for sub, role, _, domain in (edges[index] for index in included)
        ]
        total_cost = sum(edges[index][2] for index in included)
        return RevocationPlan(True, rules, total_cost)


def verify_plan_on_copy(enforcer, plan, user, domain, obj, act):
    """Checks a plan on a throwaway copy of the enforcer.

    Builds a new enforcer from a deep copy of the model with the planned
    grouping rules removed, and returns True iff the permission is gone
    there. The given enforcer, its adapter and its watcher are left
    untouched.
    """
    remaining = [list(rule) for rule in enforcer.get_grouping_policy()]
    for rule in plan.rules:
        remaining.remove(list(rule))

    lines = ["p, " + ", ".join(rule) for rule in enforcer.get_policy()]
    lines += ["g, " + ", ".join(rule) for rule in remaining]

    model_copy = copy.deepcopy(enforcer.get_model())
    model_copy.clear_policy()
    if lines:
        copy_enforcer = casbin.Enforcer(model_copy, StringAdapter("\n".join(lines)))
    else:
        copy_enforcer = casbin.Enforcer(model_copy)
    return not copy_enforcer.enforce(user, domain, obj, act)
