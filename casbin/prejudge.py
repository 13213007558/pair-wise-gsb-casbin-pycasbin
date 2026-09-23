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

import ast
import operator
import re
from enum import Enum

from casbin.constant.constants import (
    ALLOW_OVERRIDE_EFFECT,
    DENY_OVERRIDE_EFFECT,
    PRIORITY_EFFECT,
    SUBJECT_PRIORITY_EFFECT,
)
from casbin.util import generate_conditional_g_function, generate_g_function, util


class Unknown:
    """Marks an attribute whose value is not known yet.

    Pass instances as request values to Enforcer.prejudge() to say "this
    attribute still has to be provided". None keeps its ordinary meaning
    of an actual value and is never treated as unknown.
    """

    __slots__ = ("_fields",)

    def __init__(self, field=None):
        if field is None:
            self._fields = frozenset()
        elif isinstance(field, str):
            self._fields = frozenset((field,))
        else:
            self._fields = frozenset(field)

    @property
    def fields(self):
        """names of the missing attributes this marker depends on"""
        return self._fields

    def __bool__(self):
        raise TypeError("Unknown is three-valued and has no boolean value")

    def __eq__(self, other):
        return isinstance(other, Unknown) and self._fields == other._fields

    def __hash__(self):
        return hash(self._fields)

    def __repr__(self):
        if not self._fields:
            return "Unknown()"
        return "Unknown(%s)" % ", ".join(sorted(self._fields))


class Verdict(Enum):
    """Three-valued outcome of prejudge()."""

    ALLOW = "allow"
    DENY = "deny"
    INDETERMINATE = "indeterminate"


class PrejudgeResult:
    """Outcome of prejudge(): a three-valued verdict plus the names of the
    unknown fields that keep it from being determinate.

    The result is deliberately not usable as a boolean: prejudging must
    not be used to directly allow a request.
    """

    __slots__ = ("verdict", "fields")

    def __init__(self, verdict, fields=()):
        self.verdict = verdict
        self.fields = tuple(sorted(fields))

    @property
    def indeterminate(self):
        """whether the verdict depends on attributes that are still unknown"""
        return self.verdict is Verdict.INDETERMINATE

    def __bool__(self):
        raise TypeError(
            "prejudge() returns a three-valued result; inspect .verdict "
            "instead of using it as a boolean to allow a request"
        )

    def __eq__(self, other):
        return (
            isinstance(other, PrejudgeResult)
            and self.verdict is other.verdict
            and self.fields == other.fields
        )

    def __repr__(self):
        if self.indeterminate:
            return "PrejudgeResult(INDETERMINATE, fields=%s)" % (list(self.fields),)
        return "PrejudgeResult(%s)" % self.verdict.name


_COMPARE_OPERATORS = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.In: lambda left, right: left in right,
    ast.NotIn: lambda left, right: left not in right,
}


class _PartialEvaluator:
    """Evaluates a matcher expression under three-valued logic.

    Every node evaluates either to a concrete value or to an Unknown
    carrying the fields the value depends on. Only an explicit subset of
    expressions is supported: boolean operators, comparisons, attribute
    access and function calls (including RBAC functions such as g()).
    Anything else raises instead of being guessed, and exceptions raised
    by functions are never reinterpreted as unknowns.
    """

    def __init__(self, functions, unknown_aware_functions):
        self._functions = functions
        self._unknown_aware_functions = unknown_aware_functions
        self._names = None

    def eval(self, expression, names):
        self._names = names
        node = ast.parse(expression.strip()).body[0].value
        return self._eval(node)

    def _eval(self, node):
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            if node.id not in self._names:
                raise RuntimeError("name %r is not defined in the matcher" % node.id)
            return self._names[node.id]
        if isinstance(node, ast.BoolOp):
            return self._eval_bool_op(node)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return self._eval_not(node.operand)
        if isinstance(node, ast.Compare):
            return self._eval_compare(node)
        if isinstance(node, ast.Call):
            return self._eval_call(node)
        if isinstance(node, ast.Attribute):
            return self._eval_attribute(node)
        raise RuntimeError("prejudge() does not support the matcher expression: %s" % ast.dump(node))

    def _eval_bool_op(self, node):
        # Three-valued logic: "False and Unknown" stays False and
        # "True or Unknown" stays True; otherwise Unknown propagates.
        short_circuit = isinstance(node.op, ast.Or)
        unknown_fields = set()
        for value_node in node.values:
            value = self._eval(value_node)
            if isinstance(value, Unknown):
                unknown_fields |= value.fields
                continue
            if bool(value) is short_circuit:
                return short_circuit
        if unknown_fields:
            return Unknown(unknown_fields)
        return not short_circuit

    def _eval_not(self, operand):
        value = self._eval(operand)
        if isinstance(value, Unknown):
            return value
        return not value

    def _eval_compare(self, node):
        left = self._eval(node.left)
        unknown_fields = set()
        if isinstance(left, Unknown):
            unknown_fields |= left.fields
        for op, comparator in zip(node.ops, node.comparators):
            op_func = _COMPARE_OPERATORS.get(type(op))
            if op_func is None:
                raise RuntimeError(
                    "prejudge() does not support the comparison operator: %s" % ast.dump(op)
                )
            right = self._eval(comparator)
            if isinstance(right, Unknown):
                unknown_fields |= right.fields
            if unknown_fields:
                left = right
                continue
            if not op_func(left, right):
                return False
            left = right
        if unknown_fields:
            return Unknown(unknown_fields)
        return True

    def _eval_call(self, node):
        if not isinstance(node.func, ast.Name) or node.keywords:
            raise RuntimeError("prejudge() only supports direct function calls in the matcher")
        name = node.func.id
        unknown_aware = name in self._unknown_aware_functions
        if unknown_aware:
            func = self._unknown_aware_functions[name]
        elif name in self._functions:
            func = self._functions[name]
        else:
            raise RuntimeError("function %r is not defined" % name)
        args = [self._eval(arg) for arg in node.args]
        unknown_fields = set()
        for arg in args:
            if isinstance(arg, Unknown):
                unknown_fields |= arg.fields
        if unknown_fields and not unknown_aware:
            # Ordinary functions are not executed on unknown arguments.
            return Unknown(unknown_fields)
        return func(*args)

    def _eval_attribute(self, node):
        value = self._eval(node.value)
        if isinstance(value, Unknown):
            return Unknown({field + "." + node.attr for field in value.fields})
        return getattr(value, node.attr)


_ALLOW_OVERRIDE = "allow-override"
_DENY_OVERRIDE = "deny-override"
_PRIORITY = "priority"

_MATCHED_ALLOW = "allow"
_MATCHED_DENY = "deny"
_NO_MATCH = "no-match"
_UNKNOWN = "unknown"


def _normalize_expression(expr):
    expr = expr.replace("&&", "and")
    expr = expr.replace("||", "or")
    expr = re.sub(r"!(?!=)", "not ", expr)
    return expr


def _to_outcome(result, eft):
    if isinstance(result, Unknown):
        return _UNKNOWN, frozenset(result.fields)
    if isinstance(result, bool):
        matched = result
    elif isinstance(result, (int, float)):
        matched = result != 0
    else:
        raise RuntimeError("matcher result should be bool, int or float")
    return (eft if matched else _NO_MATCH), frozenset()


def _resolve(effect_kind, outcomes):
    if effect_kind == _PRIORITY:
        # The first rule that is not a determinate miss decides; an
        # undecided earlier rule blocks any later allow.
        for effect, fields in outcomes:
            if effect == _MATCHED_ALLOW:
                return PrejudgeResult(Verdict.ALLOW)
            if effect == _MATCHED_DENY:
                return PrejudgeResult(Verdict.DENY)
            if effect == _UNKNOWN:
                return PrejudgeResult(Verdict.INDETERMINATE, fields)
        return PrejudgeResult(Verdict.DENY)

    overriding = _MATCHED_ALLOW if effect_kind == _ALLOW_OVERRIDE else _MATCHED_DENY
    unknown_fields = set()
    for effect, fields in outcomes:
        if effect == overriding:
            return PrejudgeResult(Verdict.ALLOW if effect_kind == _ALLOW_OVERRIDE else Verdict.DENY)
        if effect == _UNKNOWN:
            unknown_fields |= fields
    if unknown_fields:
        return PrejudgeResult(Verdict.INDETERMINATE, unknown_fields)
    return PrejudgeResult(Verdict.DENY if effect_kind == _ALLOW_OVERRIDE else Verdict.ALLOW)


def prejudge(enforcer, *rvals):
    """prejudges a request whose attributes may be marked as Unknown.

    Returns a PrejudgeResult with a three-valued verdict (ALLOW, DENY or
    INDETERMINATE) and, for INDETERMINATE, the names of the unknown
    fields the outcome depends on. This never modifies enforce() and its
    result must not be used to directly allow a request.
    """
    from casbin.core_enforcer import EnforceContext

    rtype = "r"
    ptype = "p"
    etype = "e"
    mtype = "m"

    if not enforcer.enabled:
        return PrejudgeResult(Verdict.ALLOW)

    functions = enforcer.fm.get_functions()

    if "g" in enforcer.model.keys():
        for key, ast_ in enforcer.model["g"].items():
            if len(enforcer.rm_map) != 0:
                functions[key] = generate_g_function(ast_.rm)
            if len(enforcer.cond_rm_map) != 0:
                functions[key] = generate_conditional_g_function(ast_.cond_rm)

    if len(rvals) != 0 and isinstance(rvals[0], EnforceContext):
        enforce_context = rvals[0]
        rtype = enforce_context.rtype
        ptype = enforce_context.ptype
        etype = enforce_context.etype
        mtype = enforce_context.mtype
        rvals = rvals[1:]

    if "m" not in enforcer.model.keys():
        raise RuntimeError("model is undefined")

    if "m" not in enforcer.model["m"].keys():
        raise RuntimeError("model is undefined")

    effect_expr = enforcer.model["e"][etype].value
    if effect_expr == ALLOW_OVERRIDE_EFFECT:
        effect_kind = _ALLOW_OVERRIDE
    elif effect_expr == DENY_OVERRIDE_EFFECT:
        effect_kind = _DENY_OVERRIDE
    elif effect_expr in (PRIORITY_EFFECT, SUBJECT_PRIORITY_EFFECT):
        effect_kind = _PRIORITY
    else:
        raise RuntimeError("prejudge() does not support the policy effect: %s" % effect_expr)

    r_tokens = enforcer.model["r"][rtype].tokens
    p_tokens = enforcer.model["p"][ptype].tokens

    if len(r_tokens) != len(rvals):
        raise RuntimeError("invalid request size")

    exp_string = enforcer.model["m"][mtype].value
    if util.has_eval(exp_string):
        raise RuntimeError("prejudge() does not support eval() in matchers")

    evaluator = _PartialEvaluator(functions, enforcer._prejudge_functions)
    expression = _normalize_expression(exp_string)

    r_parameters = {}
    for token, value in zip(r_tokens, rvals):
        if isinstance(value, Unknown) and not value.fields:
            value = Unknown(token)
        r_parameters[token] = value

    outcomes = []
    policy_len = len(enforcer.model["p"][ptype].policy)
    if policy_len != 0:
        for pvals in enforcer.model["p"][ptype].policy:
            if len(p_tokens) != len(pvals):
                raise RuntimeError("invalid policy size")
            p_parameters = dict(zip(p_tokens, pvals))
            parameters = dict(r_parameters, **p_parameters)
            eft = p_parameters.get(ptype + "_eft", "allow")
            if eft not in ("allow", "deny"):
                eft = _NO_MATCH
            outcomes.append(_to_outcome(evaluator.eval(expression, parameters), eft))
    else:
        parameters = r_parameters.copy()
        for token in p_tokens:
            parameters[token] = ""
        outcomes.append(_to_outcome(evaluator.eval(expression, parameters), _MATCHED_ALLOW))

    return _resolve(effect_kind, outcomes)
