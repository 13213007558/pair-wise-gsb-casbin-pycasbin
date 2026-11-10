"""Offline change preview for pycasbin policies.

This module answers one narrow question before a new policy is rolled out:
for a finite sample of requests, which decisions change between an old and a
new policy, and why?

Both policies are evaluated in separate, in-memory :class:`Enforcer`
instances built from text. No live adapter is read or written and no watcher
is attached, so a preview can never affect an online enforcer. Custom
functions used by the matchers must be supplied explicitly by the caller;
they are wrapped so that any runtime failure (for example a dependency on
unavailable external state) marks the whole preview as unreliable instead of
producing a seemingly valid comparison.

The conclusion only describes the provided request sample. Requests whose
decision does not change are aggregated, and the report never claims two
policies are equivalent.
"""

import json
from copy import deepcopy

from casbin import Enforcer
from casbin.model import Model
from casbin.persist.adapters.string_adapter import StringAdapter

# Preview status.
STATUS_RELIABLE = "reliable"
STATUS_UNRELIABLE = "unreliable"

# Per-request / overall change kinds. The Chinese labels mirror the wording
# requested for the report and stay fixed even if callers use different
# languages in their own UI.
KIND_ADDED_ALLOW = "added_allow"
KIND_WITHDRAWN_DENIAL = "withdrawn_denial"
KIND_PRIORITY_ONLY = "priority_only"
KIND_UNCHANGED = "unchanged"
KIND_ERROR = "error"

CHANGE_KIND_LABELS = {
    KIND_ADDED_ALLOW: "新增允许",
    KIND_WITHDRAWN_DENIAL: "撤回拒绝",
    KIND_PRIORITY_ONLY: "仅调整优先级",
    KIND_UNCHANGED: "无变化",
    KIND_ERROR: "无法判断",
}

DECISION_ALLOW = "allow"
DECISION_DENY = "deny"

SCOPE_NOTE = "结论仅覆盖提供的请求样本，不代表两套策略完全等价。"


class PolicyPreviewError(Exception):
    """Raised for invalid preview inputs (as opposed to evaluation failures,
    which are reported through the unreliable status instead)."""


class _GuardedFunctionError(Exception):
    """Wraps an exception raised by a caller-supplied function so the request
    loop can distinguish a function/state failure from any other enforcement
    error without parsing exception messages."""

    def __init__(self, function_name, original):
        super().__init__(str(original))
        self.function_name = function_name
        self.original = original


def preview_policy_change(
    old_policy,
    new_policy,
    requests,
    model=None,
    old_model=None,
    new_model=None,
    functions=None,
    stateful_functions=None,
):
    """Compare two policies against a finite sample of requests.

    ``old_policy`` / ``new_policy`` are policy texts in the same CSV-like
    format used by the file/string adapter (``p, ...`` and ``g, ...`` lines),
    or lists of rule lists. ``requests`` is a list of request tuples, each one
    matching the model's request definition (typically ``(sub, obj, act)``).

    ``model`` provides a shared model text. Use ``old_model`` / ``new_model``
    instead when the model itself changes. ``functions`` maps matcher function
    names to pure callables supplied by the caller; built-in functions are
    still available. Names listed in ``stateful_functions`` (or any wrapped
    function that raises while a sample request is evaluated) make the preview
    unreliable, because the result would depend on state this offline
    comparison cannot control.

    Returns a plain dict suitable for JSON serialisation.
    """
    functions = dict(functions or {})
    stateful_functions = set(stateful_functions or [])

    _validate_inputs(old_policy, new_policy, requests, model, old_model, new_model, functions)

    model_text_old = old_model if old_model is not None else model
    model_text_new = new_model if new_model is not None else model

    function_failures = []
    wrapped_functions = {
        name: _guard_function(name, fn, function_failures) for name, fn in functions.items()
    }
    for name in stateful_functions:
        if name in functions:
            function_failures.append(
                {
                    "function": name,
                    "reason": "function_depends_on_external_state",
                    "message": "caller declared the function as stateful",
                }
            )

    build_errors = []
    old_side = _build_side(model_text_old, old_policy, wrapped_functions, "old", build_errors)
    new_side = _build_side(model_text_new, new_policy, wrapped_functions, "new", build_errors)

    records = []
    per_request_errors = []
    for index, request in enumerate(requests):
        normalized_request = list(request)
        if old_side is None or new_side is None:
            records.append(
                _error_record(index, normalized_request, "enforcer_unavailable", build_errors)
            )
            continue
        record = _evaluate_request(index, normalized_request, old_side, new_side, per_request_errors)
        records.append(record)

    reliable = not build_errors and not function_failures and not per_request_errors

    changed_records = [r for r in records if r["kind"] != KIND_UNCHANGED and r["kind"] != KIND_ERROR]
    unchanged_records = [r for r in records if r["kind"] == KIND_UNCHANGED]
    error_records = [r for r in records if r["kind"] == KIND_ERROR]

    report = {
        "status": STATUS_RELIABLE if reliable else STATUS_UNRELIABLE,
        "scope": "sample_only",
        "scope_note": SCOPE_NOTE,
        "model_changed": model_text_old != model_text_new,
        "sample_size": len(requests),
        "summary": {
            KIND_ADDED_ALLOW: _count_kind(records, KIND_ADDED_ALLOW),
            KIND_WITHDRAWN_DENIAL: _count_kind(records, KIND_WITHDRAWN_DENIAL),
            KIND_PRIORITY_ONLY: _count_kind(records, KIND_PRIORITY_ONLY),
            KIND_UNCHANGED: len(unchanged_records),
            KIND_ERROR: len(error_records),
        },
        "change_labels": CHANGE_KIND_LABELS,
        "changes": changed_records,
        "unchanged": _summarize_unchanged(unchanged_records),
        "policy_diff": _policy_diff(old_side, new_side),
        "unreliable_reasons": _build_unreliable_reasons(
            build_errors, function_failures, per_request_errors
        ),
    }
    return report


def _validate_inputs(old_policy, new_policy, requests, model, old_model, new_model, functions):
    if model is None and (old_model is None or new_model is None):
        raise PolicyPreviewError(
            "a shared model text or both old_model and new_model texts are required"
        )
    if model is not None and (old_model is not None or new_model is not None):
        raise PolicyPreviewError("use either model or old_model/new_model, not both")
    if not isinstance(requests, (list, tuple)):
        raise PolicyPreviewError("requests must be a list of request tuples")
    for request in requests:
        if not isinstance(request, (list, tuple)) or len(request) == 0:
            raise PolicyPreviewError("each request must be a non-empty tuple of values")
    for name, fn in functions.items():
        if isinstance(fn, Enforcer):
            raise PolicyPreviewError(
                "an online Enforcer cannot be passed as a preview function; "
                "supply an explicit pure function instead"
            )
        if not callable(fn):
            raise PolicyPreviewError("function %r must be callable" % name)
    for text, label in ((old_policy, "old_policy"), (new_policy, "new_policy")):
        if not isinstance(text, (str, list, tuple)):
            raise PolicyPreviewError("%s must be policy text or a list of rules" % label)


def _guard_function(name, fn, failures):
    def guarded(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as exc:  # noqa: BLE001 - any failure means unreliable
            failures.append(
                {
                    "function": name,
                    "reason": "function_evaluation_failed",
                    "message": "%s: %s" % (type(exc).__name__, str(exc)),
                }
            )
            raise _GuardedFunctionError(name, exc) from exc

    guarded.__name__ = getattr(fn, "__name__", name)
    return guarded


def _normalize_policy_text(policy):
    if isinstance(policy, str):
        return policy if policy.strip() else ""
    lines = []
    for rule in policy:
        if not isinstance(rule, (list, tuple)) or len(rule) < 2:
            raise PolicyPreviewError("policy rules must be lists starting with p/g type")
        lines.append(", ".join(str(part) for part in rule))
    return "\n".join(lines)


def _build_side(model_text, policy_text_or_rules, functions, side_name, build_errors):
    try:
        model = Model()
        model.load_model_from_text(model_text)
        adapter = StringAdapter(_normalize_policy_text(policy_text_or_rules) or "\n")
        enforcer = Enforcer(model, adapter)
        # Hard guarantees that the isolated instance cannot touch the world.
        enforcer.enable_auto_save(False)
        enforcer.enable_auto_build_role_links(True)
        enforcer.enable_auto_notify_watcher(False)
        enforcer.watcher = None
        for name, fn in functions.items():
            enforcer.add_function(name, fn)
        return {"name": side_name, "enforcer": enforcer}
    except Exception as exc:  # noqa: BLE001 - reported, never raised
        build_errors.append(
            {
                "side": side_name,
                "reason": "policy_or_model_load_failed",
                "message": "%s: %s" % (type(exc).__name__, str(exc)),
            }
        )
        return None


def _error_record(index, request, reason, build_errors):
    message = build_errors[0]["message"] if build_errors else reason
    return {
        "request_index": index,
        "request": request,
        "kind": KIND_ERROR,
        "kind_label": CHANGE_KIND_LABELS[KIND_ERROR],
        "error": reason,
        "message": message,
    }


def _evaluate_request(index, request, old_side, new_side, per_request_errors):
    try:
        old_eval = _enforce_side(old_side["enforcer"], request)
        new_eval = _enforce_side(new_side["enforcer"], request)
    except _GuardedFunctionError as exc:
        reason = "function_evaluation_failed"
        message = "%s in %s: %s" % (
            type(exc.original).__name__,
            exc.function_name,
            str(exc.original),
        )
        per_request_errors.append(
            {
                "request_index": index,
                "request": request,
                "reason": reason,
                "function": exc.function_name,
                "message": message,
            }
        )
        return {
            "request_index": index,
            "request": request,
            "kind": KIND_ERROR,
            "kind_label": CHANGE_KIND_LABELS[KIND_ERROR],
            "error": reason,
            "message": message,
        }
    except Exception as exc:  # noqa: BLE001 - reported, never raised
        reason = "enforcement_failed"
        message = "%s: %s" % (type(exc).__name__, str(exc))
        per_request_errors.append(
            {
                "request_index": index,
                "request": request,
                "reason": reason,
                "message": message,
            }
        )
        return {
            "request_index": index,
            "request": request,
            "kind": KIND_ERROR,
            "kind_label": CHANGE_KIND_LABELS[KIND_ERROR],
            "error": reason,
            "message": message,
        }

    kind = _classify(old_eval, new_eval)
    record = {
        "request_index": index,
        "request": request,
        "kind": kind,
        "kind_label": CHANGE_KIND_LABELS[kind],
        "old_decision": old_eval["decision"],
        "new_decision": new_eval["decision"],
        "old_evidence": _explain_side(old_side, request, old_eval),
        "new_evidence": _explain_side(new_side, request, new_eval),
        "reasons": _build_reasons(kind, old_eval, new_eval),
    }
    return record


def _enforce_side(enforcer, request):
    allowed, explain_rule = enforcer.enforce_ex(*request)
    decision = DECISION_ALLOW if allowed else DECISION_DENY
    ptype, rule_index = _find_rule_position(enforcer, explain_rule)
    return {
        "decision": decision,
        "explain_rule": explain_rule,
        "ptype": ptype,
        "rule_index": rule_index,
        "priority": _priority_of(enforcer, ptype, rule_index),
    }


def _classify(old_eval, new_eval):
    if old_eval["decision"] == DECISION_DENY and new_eval["decision"] == DECISION_ALLOW:
        return KIND_ADDED_ALLOW
    if old_eval["decision"] == DECISION_ALLOW and new_eval["decision"] == DECISION_DENY:
        return KIND_WITHDRAWN_DENIAL
    if _priority_shift(old_eval, new_eval):
        return KIND_PRIORITY_ONLY
    return KIND_UNCHANGED


def _priority_shift(old_eval, new_eval):
    if old_eval["rule_index"] == -1 or new_eval["rule_index"] == -1:
        return False
    if old_eval["ptype"] != new_eval["ptype"]:
        return False
    if old_eval["explain_rule"] == new_eval["explain_rule"]:
        return False
    return old_eval["priority"] is not None or new_eval["priority"] is not None


def _build_reasons(kind, old_eval, new_eval):
    reasons = []
    if kind == KIND_ADDED_ALLOW:
        reasons.append("旧策略拒绝，新策略由规则 %s 放行" % _format_rule(new_eval["explain_rule"]))
    elif kind == KIND_WITHDRAWN_DENIAL:
        if new_eval["explain_rule"]:
            reasons.append("旧策略放行，新策略由规则 %s 拒绝" % _format_rule(new_eval["explain_rule"]))
        else:
            reasons.append("旧策略放行，新策略无匹配的放行规则（隐式拒绝）")
    elif kind == KIND_PRIORITY_ONLY:
        reasons.append(
            "决定不变，决定性规则由 %s 调整为 %s"
            % (
                _format_rule(old_eval["explain_rule"]),
                _format_rule(new_eval["explain_rule"]),
            )
        )
    return reasons


def _explain_side(side, request, evaluation):
    enforcer = side["enforcer"]
    subject = request[0]
    domain = _request_domain(enforcer, request)

    role_chain = _role_chain(enforcer, subject, domain)
    grouping_rules = _grouping_rules_for(enforcer, subject, domain)
    candidates = _candidate_policies(enforcer, subject, role_chain)

    rule = evaluation["explain_rule"]
    if rule:
        basis = {
            "type": "decisive_rule",
            "ptype": evaluation["ptype"],
            "rule_index": evaluation["rule_index"],
            "rule": rule,
            "effect": _rule_effect(enforcer, evaluation["ptype"], rule),
            "priority": evaluation["priority"],
        }
    else:
        explicit_deny = _explicit_deny_candidates(enforcer, subject, role_chain)
        basis = {
            "type": "explicit_deny_rule" if explicit_deny else "no_matching_policy",
            "rule_index": -1,
            "rule": [],
            "effect": "deny",
            "priority": None,
            "matching_deny_rules": explicit_deny,
        }

    return {
        "decision": evaluation["decision"],
        "basis": basis,
        "role_chain": role_chain,
        "grouping_rules": grouping_rules,
        "candidate_policies": candidates,
    }


def _request_domain(enforcer, request):
    for assertion in enforcer.model.model["r"].values():
        tokens = assertion.tokens
        for index, token in enumerate(tokens):
            if token in ("r.dom", "r.domain") and index < len(request):
                return request[index]
    return None


def _role_chain(enforcer, subject, domain):
    """Builds the transitive role chain from the grouping policy only.

    The role managers are mutable and are touched while ``enforce_ex`` runs, so
    reading them after enforcement would leak evaluation-time state. The
    grouping rules (``g``) are the static source of truth and cover plain RBAC,
    domain-scoped roles and role inheritance alike.
    """
    edges = {}
    if "g" in enforcer.model.model:
        for gtype, assertion in enforcer.model.model["g"].items():
            for rule in assertion.policy:
                if len(rule) < 2:
                    continue
                if domain is not None and len(rule) >= 3 and rule[2] != domain:
                    continue
                edges.setdefault(rule[0], []).append(rule[1])

    chain = []
    queue = [subject]
    while queue:
        current = queue.pop(0)
        for role in edges.get(current, []):
            if role not in chain:
                chain.append(role)
                queue.append(role)
    return chain


def _grouping_rules_for(enforcer, subject, domain):
    result = []
    if "g" not in enforcer.model.model:
        return result
    for gtype in enforcer.model.model["g"].keys():
        for rule in enforcer.get_named_grouping_policy(gtype):
            if rule and rule[0] == subject and (domain is None or len(rule) <= 2 or rule[2] == domain):
                result.append([gtype] + list(rule))
    return result


def _candidate_policies(enforcer, subject, role_chain):
    subjects = {subject}
    subjects.update(role_chain)
    candidates = []
    for ptype, assertion in enforcer.model.model["p"].items():
        for index, rule in enumerate(assertion.policy):
            if not rule:
                continue
            if rule[0] in subjects or rule[0].startswith("r."):
                candidates.append(
                    {
                        "ptype": ptype,
                        "rule_index": index,
                        "rule": list(rule),
                        "effect": _effect_of_rule(assertion, rule),
                    }
                )
    return candidates


def _explicit_deny_candidates(enforcer, subject, role_chain):
    denied = []
    for candidate in _candidate_policies(enforcer, subject, role_chain):
        if candidate["effect"] == "deny":
            denied.append(candidate)
    return denied


def _find_rule_position(enforcer, rule):
    if not rule:
        return None, -1
    for ptype, assertion in enforcer.model.model["p"].items():
        for index, existing in enumerate(assertion.policy):
            if existing == rule:
                return ptype, index
    return None, -1


def _priority_of(enforcer, ptype, rule_index):
    if ptype is None or rule_index < 0:
        return None
    assertion = enforcer.model.model["p"].get(ptype)
    if assertion is None or assertion.priority_index < 0:
        return None
    if not (0 <= rule_index < len(assertion.policy)):
        return None
    value = assertion.policy[rule_index][assertion.priority_index]
    try:
        return int(value)
    except (TypeError, ValueError):
        return value


def _rule_effect(enforcer, ptype, rule):
    assertion = enforcer.model.model["p"].get(ptype)
    if assertion is None:
        return "allow"
    return _effect_of_rule(assertion, rule)


def _effect_of_rule(assertion, rule):
    for index, token in enumerate(assertion.tokens):
        if token.endswith("_eft") and index < len(rule):
            return rule[index]
    return "allow"


def _format_rule(rule):
    if not rule:
        return "(无)"
    return "[" + ", ".join(str(part) for part in rule) + "]"


def _summarize_unchanged(records):
    groups = {}
    for record in records:
        key = record["old_decision"]
        groups.setdefault(key, []).append(record["request_index"])
    return [
        {"decision": decision, "count": len(indices), "request_indices": indices}
        for decision, indices in sorted(groups.items())
    ]


def _policy_diff(old_side, new_side):
    if old_side is None or new_side is None:
        return {"added_rules": [], "removed_rules": [], "added_grouping_rules": [], "removed_grouping_rules": []}
    old_p, old_g = _collect_rules(old_side["enforcer"])
    new_p, new_g = _collect_rules(new_side["enforcer"])
    return {
        "added_rules": sorted(new_p - old_p),
        "removed_rules": sorted(old_p - new_p),
        "added_grouping_rules": sorted(new_g - old_g),
        "removed_grouping_rules": sorted(old_g - new_g),
    }


def _collect_rules(enforcer):
    policy_rules = set()
    grouping_rules = set()
    for ptype, assertion in enforcer.model.model["p"].items():
        for rule in assertion.policy:
            policy_rules.add((ptype, *rule))
    if "g" in enforcer.model.model:
        for gtype, assertion in enforcer.model.model["g"].items():
            for rule in assertion.policy:
                grouping_rules.add((gtype, *rule))
    return policy_rules, grouping_rules


def _build_unreliable_reasons(build_errors, function_failures, per_request_errors):
    reasons = []
    for error in build_errors:
        reasons.append(error)
    for failure in function_failures:
        reasons.append(failure)
    for error in per_request_errors:
        reasons.append(error)
    unique = []
    seen = set()
    for reason in reasons:
        key = json.dumps(reason, sort_keys=True, ensure_ascii=False, default=str)
        if key not in seen:
            seen.add(key)
            unique.append(deepcopy(reason))
    return unique


def _count_kind(records, kind):
    return sum(1 for record in records if record["kind"] == kind)
