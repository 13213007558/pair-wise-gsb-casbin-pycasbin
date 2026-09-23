"""Minimum-cost revocation planning for exact-match, allow-only RBAC with domains.

The planner answers: which existing grouping-policy edges must be deleted, at
minimum total cost, so that user loses permission (obj, act) in domain?
A user may hold the same permission through several role paths; a valid plan
cuts every path at once.

Scope and guarantees:

- finite, exact-match RBAC with domains (g = _, _, _ and
  p = _, _, _, _[, eft]); no wildcards, key-matchers or custom matchers;
- allow-only policies: a deny rule in the model raises ValueError;
- the only permitted operation is deleting an existing grouping policy, so
  every plan item maps back to a real g policy line; adding deny rules or
  changing the effect is never part of a plan;
- undeletable edges still participate in reachability (infinite cut cost);
- a permission granted directly to the user by a p policy cannot be
  revoked here and is reported as infeasible;
- role graphs may contain cycles; equal-cost plans are resolved by picking
  edges in stable policy order; a shared edge is paid for only once;
- planning never mutates the enforcer, its adapter or its watchers;
  verify_plan_on_copy() evaluates a plan on a deep copy only.
"""

import copy
from collections import deque
from dataclasses import dataclass, field

__all__ = ["RevocationPlanItem", "RevocationPlan", "plan_revocation", "verify_plan_on_copy"]

_EPS = 1e-9

_SINK = ("__revocation_planner_sink__",)


@dataclass(frozen=True)
class RevocationPlanItem:
    """One existing grouping-policy edge selected for deletion."""

    policy: tuple
    cost: float

    def line(self):
        """renders the policy line as it appears in a policy file."""
        return "g, " + ", ".join(self.policy)


@dataclass
class RevocationPlan:
    """Result of plan_revocation()."""

    feasible: bool
    items: list = field(default_factory=list)
    total_cost: float = 0.0
    reason: str = ""
    request: tuple = None

    @property
    def policies(self):
        """grouping-policy tuples to delete, in stable policy order."""
        return [item.policy for item in self.items]

    def report(self):
        """human-readable list of the policy lines to delete and the total cost."""
        if self.request:
            head = "revocation plan for ({})".format(", ".join(str(v) for v in self.request))
        else:
            head = "revocation plan"
        if not self.feasible:
            return "{}: INFEASIBLE - {}".format(head, self.reason)
        lines = ["{}: feasible, total cost {:g}".format(head, self.total_cost)]
        if not self.items:
            lines.append("  (no grouping policy needs to be deleted)")
        for item in self.items:
            lines.append("  delete {}  (cost {:g})".format(item.line(), item.cost))
        if self.reason:
            lines.append("  note: " + self.reason)
        return "\n".join(lines)


def _build_residual(edges):
    """edges: iterable of (u, v, capacity). Returns a residual adjacency dict."""
    adj = {}
    for u, v, cap in edges:
        adj.setdefault(u, {})
        adj.setdefault(v, {})
        adj[u][v] = adj[u].get(v, 0.0) + cap
        adj[v].setdefault(u, 0.0)
    return adj


def _max_flow(adj, source, sink):
    """Edmonds-Karp max flow; also the min-cut capacity (max-flow min-cut)."""
    flow = 0.0
    while True:
        parent = {source: None}
        queue = deque([source])
        while queue and sink not in parent:
            u = queue.popleft()
            for v, cap in adj.get(u, {}).items():
                if cap > _EPS and v not in parent:
                    parent[v] = u
                    queue.append(v)
        if sink not in parent:
            return flow
        bottleneck = None
        v = sink
        while parent[v] is not None:
            u = parent[v]
            cap = adj[u][v]
            bottleneck = cap if bottleneck is None else min(bottleneck, cap)
            v = u
        v = sink
        while parent[v] is not None:
            u = parent[v]
            adj[u][v] -= bottleneck
            adj.setdefault(v, {}).setdefault(u, 0.0)
            adj[v][u] += bottleneck
            v = u
        flow += bottleneck


def _reaches(edges, source, targets, removed):
    """True if source can still reach any target via edges not in removed."""
    adj = {}
    for edge in edges:
        if edge in removed:
            continue
        u, v = edge[0], edge[1]
        adj.setdefault(u, []).append(v)
    seen = {source}
    stack = [source]
    while stack:
        u = stack.pop()
        if u in targets:
            return True
        for v in adj.get(u, ()):
            if v not in seen:
                seen.add(v)
                stack.append(v)
    return False


def plan_revocation(enforcer, user, domain, obj, act, deletable_costs):
    """Computes a minimum-cost revocation plan.

    deletable_costs maps an existing grouping-policy tuple, e.g.
    ("alice", "role1", "domain1"), to its non-negative deletion cost.
    Grouping policies not listed are undeletable: they still participate in
    reachability but can never appear in a plan.

    Returns a RevocationPlan; the enforcer is only read, never modified.
    """
    request = (user, domain, obj, act)
    costs = {tuple(edge): float(cost) for edge, cost in deletable_costs.items()}
    for edge, cost in costs.items():
        if cost < 0:
            raise ValueError("negative deletion cost for grouping policy {}".format(edge))

    p_rules = [list(rule) for rule in enforcer.get_policy()]
    for rule in p_rules:
        if len(rule) not in (4, 5):
            raise ValueError(
                "expected domain-scoped policy rules (sub, dom, obj, act[, eft]), got: {}".format(rule)
            )
        if len(rule) == 5 and rule[4] not in ("", "allow"):
            raise ValueError("allow-only scope violated by policy: {}".format(", ".join(rule)))

    g_rules = [tuple(rule) for rule in enforcer.get_grouping_policy()]
    domain_edges = [rule for rule in g_rules if len(rule) == 3 and rule[2] == domain]
    edge_set = set(domain_edges)
    for edge in costs:
        if edge not in edge_set:
            raise ValueError(
                "deletable edge {} is not an existing grouping policy in domain {!r}".format(edge, domain)
            )

    holders = {rule[0] for rule in p_rules if rule[1] == domain and rule[2] == obj and rule[3] == act}
    if user in holders:
        return RevocationPlan(
            feasible=False,
            reason=(
                "permission is granted directly to {!r} by a p policy; "
                "deleting grouping policies cannot revoke it".format(user)
            ),
            request=request,
        )
    if not holders:
        return RevocationPlan(
            feasible=True,
            reason="no policy grants this permission; nothing to revoke",
            request=request,
        )

    deletable = [edge for edge in domain_edges if edge in costs]  # stable policy order
    total_deletable = sum(costs[edge] for edge in deletable)
    inf = total_deletable + 1.0 if total_deletable > 0 else 1.0

    def min_cut_cost(removed):
        caps = []
        for edge in domain_edges:
            if edge in removed:
                continue
            caps.append((edge[0], edge[1], costs.get(edge, inf)))
        for holder in holders:
            caps.append((holder, _SINK, inf))
        return _max_flow(_build_residual(caps), user, _SINK)

    if not _reaches(domain_edges, user, holders, removed=frozenset()):
        return RevocationPlan(
            feasible=True,
            reason="user does not currently reach the permission",
            request=request,
        )

    best = min_cut_cost(frozenset())
    if best >= inf - _EPS:
        return RevocationPlan(
            feasible=False,
            reason="permission remains reachable through undeletable grouping policies only",
            request=request,
        )

    # Among all minimum-cost cuts, pick edges greedily in stable policy order:
    # an edge is kept when some minimum-cost completion still exists after it.
    removed = set()
    chosen_cost = 0.0
    for edge in deletable:
        trial = removed | {edge}
        residual = min_cut_cost(trial)
        if abs(chosen_cost + costs[edge] + residual - best) <= _EPS * max(1.0, best):
            removed = trial
            chosen_cost += costs[edge]

    # Drop redundant picks (only possible for zero-cost edges), latest first,
    # so the surviving set stays minimal and earliest in stable order.
    for edge in sorted(removed, key=lambda e: deletable.index(e), reverse=True):
        trial = removed - {edge}
        if not _reaches(domain_edges, user, holders, removed=trial):
            removed = trial

    items = [RevocationPlanItem(policy=edge, cost=costs[edge]) for edge in deletable if edge in removed]
    return RevocationPlan(
        feasible=True,
        items=items,
        total_cost=sum(item.cost for item in items),
        request=request,
    )


def verify_plan_on_copy(enforcer, plan, user, domain, obj, act):
    """Verifies a plan on a deep copy of the enforcer model only.

    The replica is built from a deep copy of the in-memory model and has no
    adapter and no watcher, so applying the plan cannot trigger persistence
    or notifications; the original enforcer is never touched.

    Returns True if the permission is revoked on the replica.
    """
    import casbin

    model_copy = copy.deepcopy(enforcer.model)
    replica = casbin.Enforcer(model_copy)
    replica.build_role_links()
    for item in plan.items:
        if not replica.remove_grouping_policy(*item.policy):
            raise ValueError("plan item {} is not an existing grouping policy".format(item.policy))
    return not replica.enforce(user, domain, obj, act)
