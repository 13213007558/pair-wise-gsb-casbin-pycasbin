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

"""Offline shadowing analysis for the priority model.

The checker treats the policy as a firewall-style ordered rule list (the
same order the enforcer uses after its stable priority sort) and decides,
for every rule, whether the requests it matches are already completely
covered by earlier rules.  It never enumerates concrete resources: the
request space is analysed symbolically as cartesian products of

- subjects: exact users, or the finite closure of an RBAC role computed
  from the 'g' policy,
- domains: the explicit domain token of each rule,
- actions: the finite set of exact action literals,
- objects: path patterns (literal segments, single-segment '*', trailing
  '**') with intersection and difference decided by the patterns module.

Anything outside that fragment (unknown matcher terms, conditional or
pattern-matching roles, non-priority effects) raises UnsupportedError
instead of guessing.
"""

from dataclasses import dataclass, field

import casbin

from .patterns import PathPattern, PatternError, find_path_outside

MAX_ROLE_HIERARCHY_LEVEL = 10

_SUPPORTED_EFFECT = "priority(p.eft)||deny"

_SUB_EXACT = "r.sub==p.sub"
_SUB_ROLE = "g(r.sub,p.sub)"
_SUB_ROLE_DOM = "g(r.sub,p.sub,r.dom)"
_DOM_EXACT = "r.dom==p.dom"
_OBJ_EXACT = "r.obj==p.obj"
_OBJ_PATH = "pathMatch(r.obj,p.obj)"
_ACT_EXACT = "r.act==p.act"


class UnsupportedError(Exception):
    """raised when the model or policy uses constructs the checker does not support"""


def path_match(obj, pattern):
    """matcher function implementing the checker's resource pattern language."""
    return PathPattern.parse(pattern).matches(obj)


def _path_match_func(*args):
    return path_match(args[0], args[1])


def _normalize(expr):
    # pycasbin stores model expressions with token dots replaced by
    # underscores (r.sub -> r_sub); map them back before comparing.
    compact = "".join(str(expr).split())
    return compact.replace("r_", "r.").replace("p_", "p.")


def _matching_is_plain_equality(func, names):
    """True if a role matching function behaves like plain name equality
    over the finite universe of role and subject names.

    The default DomainManager installs an equality lambda as its matching
    function, which is harmless; genuinely custom (pattern) matching makes
    the finite subject assumption invalid and is rejected.
    """
    try:
        for name in names:
            if not func(name, name):
                return False
            for other in names:
                if other != name and func(name, other):
                    return False
    except Exception:
        return False
    return True


@dataclass
class _Region:
    """a cartesian region of the request space."""

    subjects: frozenset
    doms: frozenset
    path: PathPattern
    acts: frozenset

    def intersect(self, other):
        subjects = self.subjects & other.subjects
        doms = self.doms & other.doms
        acts = self.acts & other.acts
        if not subjects or not doms or not acts:
            return None
        path = self.path.intersect(other.path)
        if path is None:
            return None
        return _Region(subjects, doms, path, acts)


@dataclass
class Overlap:
    """a region where an earlier rule with the opposite effect wins."""

    earlier_index: int
    earlier_rule: list
    witness: dict
    enforcer_result: bool
    verified: bool


@dataclass
class RuleReport:
    """analysis outcome for one policy rule (in effective priority order)."""

    index: int
    rule: list
    priority: object
    effect: str
    shadowed: bool
    covered_by: list = field(default_factory=list)
    overlaps: list = field(default_factory=list)


@dataclass
class ShadowReport:
    """full analysis result; rules are listed in effective priority order."""

    rules: list
    reports: list
    policy_order_preserved: bool

    @property
    def shadowed(self):
        return [report for report in self.reports if report.shadowed]

    @property
    def partial_overlaps(self):
        return [report for report in self.reports if report.overlaps]


class _ModelShape:
    """validated, supported subset of the model configuration."""

    def __init__(self):
        self.p_index = {}
        self.r_index = {}
        self.sub_kind = None  # "exact" | "role" | "role_dom"
        self.obj_kind = None  # "exact" | "path"
        self.has_dom = False


class ShadowChecker:
    """analyses a priority-model enforcer for shadowed and conflicting rules."""

    def __init__(self, model_path=None, policy_path=None, enforcer=None):
        if enforcer is not None:
            self.enforcer = enforcer
        elif model_path is not None and policy_path is not None:
            self.enforcer = casbin.Enforcer(model_path, policy_path)
        else:
            raise ValueError("provide either an enforcer or model_path and policy_path")
        self.shape = self._validate_model()
        if self.shape.obj_kind == "path":
            functions = self.enforcer.fm.get_functions()
            if "pathMatch" not in functions:
                self.enforcer.add_function("pathMatch", _path_match_func)

    # ------------------------------------------------------------------
    # model validation
    # ------------------------------------------------------------------

    def _validate_model(self):
        e = self.enforcer
        shape = _ModelShape()

        effect = _normalize(e.model["e"]["e"].value)
        if effect != _SUPPORTED_EFFECT:
            raise UnsupportedError(
                "unsupported policy effect %r: only 'priority(p.eft) || deny' "
                "is supported" % e.model["e"]["e"].value
            )

        shape.p_index = self._token_index(e.model["p"]["p"].tokens, "p")
        shape.r_index = self._token_index(e.model["r"]["r"].tokens, "r")

        for required in ("sub", "obj", "act", "eft"):
            if required not in shape.p_index:
                raise UnsupportedError("policy definition is missing %r" % ("p_" + required))
        for required in ("sub", "obj", "act"):
            if required not in shape.r_index:
                raise UnsupportedError("request definition is missing %r" % ("r_" + required))
        unknown_p = set(shape.p_index) - {"sub", "dom", "obj", "act", "eft", "priority"}
        if unknown_p:
            raise UnsupportedError("unsupported policy tokens: %s" % sorted(unknown_p))

        shape.has_dom = "dom" in shape.p_index or "dom" in shape.r_index
        if shape.has_dom and ("dom" not in shape.p_index or "dom" not in shape.r_index):
            raise UnsupportedError("domain must appear in both request and policy definitions")

        matcher = _normalize(e.model["m"]["m"].value)
        terms = [term for term in matcher.split("&&") if term]
        sub_terms = []
        obj_terms = []
        act_terms = []
        dom_terms = []
        for term in terms:
            if term in (_SUB_EXACT, _SUB_ROLE, _SUB_ROLE_DOM):
                sub_terms.append(term)
            elif term in (_OBJ_EXACT, _OBJ_PATH):
                obj_terms.append(term)
            elif term == _ACT_EXACT:
                act_terms.append(term)
            elif term == _DOM_EXACT:
                dom_terms.append(term)
            else:
                raise UnsupportedError("unsupported matcher term: %r" % term)

        if len(sub_terms) != 1 or len(obj_terms) != 1 or len(act_terms) != 1:
            raise UnsupportedError(
                "matcher must contain exactly one subject, object and action term"
            )
        if len(dom_terms) > 1:
            raise UnsupportedError("matcher contains duplicate domain terms")

        sub_term = sub_terms[0]
        if sub_term == _SUB_EXACT:
            shape.sub_kind = "exact"
        elif sub_term == _SUB_ROLE:
            shape.sub_kind = "role"
        else:
            shape.sub_kind = "role_dom"
            if not shape.has_dom:
                raise UnsupportedError("domain role matching requires a domain token")
        if bool(dom_terms) != shape.has_dom:
            raise UnsupportedError("matcher and definitions disagree on the domain dimension")
        if shape.sub_kind != "exact" and "g" not in e.model.keys():
            raise UnsupportedError("matcher uses g() but no role definition exists")

        shape.obj_kind = "path" if obj_terms[0] == _OBJ_PATH else "exact"

        self._validate_roles(shape)
        return shape

    @staticmethod
    def _token_index(tokens, prefix):
        index = {}
        head = prefix + "_"
        for i, token in enumerate(tokens):
            if not token.startswith(head):
                raise UnsupportedError("unexpected token %r" % token)
            index[token[len(head):]] = i
        return index

    def _validate_roles(self, shape):
        e = self.enforcer
        if getattr(e, "cond_rm_map", None):
            raise UnsupportedError("conditional roles are not supported")
        names = set()
        for assertion in (
            e.model["g"].values() if "g" in e.model.keys() else []
        ):
            for rule in assertion.policy:
                names.update(rule)
        for rule in e.model["p"]["p"].policy:
            names.add(rule[shape.p_index["sub"]])
        for ptype, rm in getattr(e, "rm_map", {}).items():
            matching_func = getattr(rm, "matching_func", None)
            if matching_func is not None and not _matching_is_plain_equality(
                matching_func, names
            ):
                raise UnsupportedError("role matching functions are not supported")
            if getattr(rm, "domain_matching_func", None) is not None:
                raise UnsupportedError("domain matching functions are not supported")
        for ptype, assertion in (
            e.model["g"].items() if "g" in e.model.keys() else []
        ):
            arity = len(assertion.tokens)
            for rule in assertion.policy:
                if len(rule) != arity:
                    raise UnsupportedError(
                        "conditional role rule %r does not match role definition %r"
                        % (rule, ptype)
                    )

    # ------------------------------------------------------------------
    # regions
    # ------------------------------------------------------------------

    def _ordered_rules(self):
        """policy rules in the enforcer's effective (stably sorted) order."""
        return [list(rule) for rule in self.enforcer.model["p"]["p"].policy]

    def _rule_field(self, rule, name):
        return rule[self.shape.p_index[name]]

    def _role_edges(self):
        """grouping rules as (member, role) edges, per domain when applicable."""
        edges = {}
        role_model = (
            self.enforcer.model["g"] if "g" in self.enforcer.model.keys() else {}
        )
        for assertion in role_model.values():
            for rule in assertion.policy:
                dom = rule[2] if len(rule) > 2 else None
                edges.setdefault(dom, []).append((rule[0], rule[1]))
        return edges

    def _subjects_for(self, p_sub, dom, edges):
        """finite set of request subjects matched by a policy subject."""
        if self.shape.sub_kind == "exact":
            return frozenset({p_sub})
        members = {p_sub}
        frontier = {p_sub}
        edge_list = edges.get(dom if self.shape.sub_kind == "role_dom" else None, [])
        for _ in range(MAX_ROLE_HIERARCHY_LEVEL):
            inherited = {user for user, role in edge_list if role in frontier}
            inherited -= members
            if not inherited:
                break
            members |= inherited
            frontier = inherited
        return frozenset(members)

    def _build_regions(self, rules):
        edges = self._role_edges()
        regions = []
        for rule in rules:
            p_sub = self._rule_field(rule, "sub")
            p_obj = self._rule_field(rule, "obj")
            p_act = self._rule_field(rule, "act")
            p_eft = self._rule_field(rule, "eft")
            dom = self._rule_field(rule, "dom") if self.shape.has_dom else None
            if p_eft not in ("allow", "deny"):
                raise UnsupportedError("unsupported effect %r in rule %s" % (p_eft, rule))
            try:
                path = PathPattern.parse(
                    p_obj, allow_wildcards=self.shape.obj_kind == "path"
                )
            except PatternError as exc:
                raise UnsupportedError(
                    "unsupported resource pattern in rule %s: %s" % (rule, exc)
                )
            regions.append(
                _Region(
                    subjects=self._subjects_for(p_sub, dom, edges),
                    doms=frozenset({dom}),
                    path=path,
                    acts=frozenset({p_act}),
                )
            )
        return regions

    # ------------------------------------------------------------------
    # analysis
    # ------------------------------------------------------------------

    def _find_witness(self, region, others):
        """one concrete request inside 'region' but outside every region in
        'others', or None if 'region' is fully covered by their union."""
        for sub in sorted(region.subjects):
            for dom in sorted(region.doms, key=lambda d: (d is None, d or "")):
                for act in sorted(region.acts):
                    paths = [
                        other.path
                        for other in others
                        if sub in other.subjects and dom in other.doms and act in other.acts
                    ]
                    witness = find_path_outside(region.path, paths)
                    if witness is not None:
                        return {"sub": sub, "dom": dom, "obj": witness, "act": act}
        return None

    def _covering_set(self, region, earlier_regions):
        """an irredundant set of earlier rule indices jointly covering 'region'."""
        candidates = [
            i for i, other in enumerate(earlier_regions) if region.intersect(other) is not None
        ]
        for i in reversed(candidates):
            rest = [earlier_regions[j] for j in candidates if j != i]
            if self._find_witness(region, rest) is None:
                candidates.remove(i)
        return candidates

    def _enforce_witness(self, witness):
        args = [None] * len(self.shape.r_index)
        args[self.shape.r_index["sub"]] = witness["sub"]
        args[self.shape.r_index["obj"]] = witness["obj"]
        args[self.shape.r_index["act"]] = witness["act"]
        if self.shape.has_dom:
            args[self.shape.r_index["dom"]] = witness["dom"]
        return bool(self.enforcer.enforce(*args))

    def check(self):
        """runs the analysis and returns a ShadowReport."""
        rules = self._ordered_rules()
        snapshot_before = [list(rule) for rule in rules]
        regions = self._build_regions(rules)

        reports = []
        for j, rule in enumerate(rules):
            effect = self._rule_field(rule, "eft")
            if "priority" in self.shape.p_index:
                priority = self._rule_field(rule, "priority")
            else:
                priority = j
            report = RuleReport(
                index=j,
                rule=rule,
                priority=priority,
                effect=effect,
                shadowed=False,
            )
            earlier_regions = regions[:j]
            if self._find_witness(regions[j], earlier_regions) is None:
                report.shadowed = True
                report.covered_by = self._covering_set(regions[j], earlier_regions)
            else:
                for i in range(j):
                    if self._rule_field(rules[i], "eft") == effect:
                        continue
                    intersection = regions[j].intersect(regions[i])
                    if intersection is None:
                        continue
                    witness = self._find_witness(intersection, regions[:i])
                    if witness is None:
                        continue
                    result = self._enforce_witness(witness)
                    expected = self._rule_field(rules[i], "eft") == "allow"
                    report.overlaps.append(
                        Overlap(
                            earlier_index=i,
                            earlier_rule=rules[i],
                            witness=witness,
                            enforcer_result=result,
                            verified=result == expected,
                        )
                    )
            reports.append(report)

        snapshot_after = self._ordered_rules()
        return ShadowReport(
            rules=rules,
            reports=reports,
            policy_order_preserved=snapshot_before == snapshot_after,
        )


def check_shadowing(model_path, policy_path):
    """convenience wrapper: analyse a model/policy file pair."""
    return ShadowChecker(model_path=model_path, policy_path=policy_path).check()
