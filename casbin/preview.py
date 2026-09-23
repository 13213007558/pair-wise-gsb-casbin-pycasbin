import ast
import functools
import re

from simpleeval import DISALLOW_FUNCTIONS, FeatureNotAvailable, FunctionNotDefined

from casbin.constant.constants import (
    ALLOW_OVERRIDE_EFFECT,
    DENY_OVERRIDE_EFFECT,
    PRIORITY_EFFECT,
)
from casbin.effect import Effector
from casbin.util import (
    SimpleEval,
    generate_conditional_g_function,
    generate_g_function,
    util,
)

__all__ = [
    "Unknown",
    "PreviewResult",
    "PreviewExpression",
    "unknown_aware",
    "unknown_guard",
    "generate_preview_g_function",
    "preview_enforce",
]


class Unknown:
    """Marks a request attribute whose value is not known yet.

    Callers pass Unknown("<field>") in place of the missing attribute when
    calling preview_enforce. None keeps being a real value and is never
    treated as unknown. Unknown propagates through the supported boolean and
    comparison operations following three-valued logic, carrying the names of
    the fields the result depends on.
    """

    __slots__ = ("_fields",)

    def __init__(self, fields=None):
        if fields is None:
            self._fields = frozenset()
        elif isinstance(fields, str):
            self._fields = frozenset((fields,))
        else:
            self._fields = frozenset(fields)

    @property
    def fields(self):
        """the names of the missing attributes this value depends on."""
        return self._fields

    def _merge(self, other):
        if isinstance(other, Unknown):
            return Unknown(self._fields | other._fields)
        return Unknown(self._fields)

    def __bool__(self):
        raise TypeError("Unknown has no boolean value: the attribute it stands for must be completed first")

    def __eq__(self, other):
        return self._merge(other)

    def __ne__(self, other):
        return self._merge(other)

    def __lt__(self, other):
        return self._merge(other)

    def __le__(self, other):
        return self._merge(other)

    def __gt__(self, other):
        return self._merge(other)

    def __ge__(self, other):
        return self._merge(other)

    def __repr__(self):
        if self._fields:
            return "Unknown({})".format(", ".join(sorted(self._fields)))
        return "Unknown()"


class PreviewResult:
    """The three-valued outcome of preview_enforce.

    decision is one of ALLOW, DENY or INDETERMINATE. When the decision is
    indeterminate, fields lists the missing request attributes that the
    outcome depends on. A preview result is not a boolean and must not be
    used to directly allow requests.
    """

    ALLOW = "allow"
    DENY = "deny"
    INDETERMINATE = "indeterminate"

    def __init__(self, decision, fields=()):
        if decision not in (self.ALLOW, self.DENY, self.INDETERMINATE):
            raise ValueError("invalid preview decision: {!r}".format(decision))
        self._decision = decision
        self._fields = tuple(sorted(fields))

    @property
    def decision(self):
        return self._decision

    @property
    def fields(self):
        """the missing attributes the decision depends on; empty when determinate."""
        return self._fields

    @property
    def is_allow(self):
        return self._decision == self.ALLOW

    @property
    def is_deny(self):
        return self._decision == self.DENY

    @property
    def is_indeterminate(self):
        return self._decision == self.INDETERMINATE

    def __bool__(self):
        raise TypeError(
            "PreviewResult is three-valued; inspect .decision instead. "
            "A preview result must not be used to directly allow a request."
        )

    def __eq__(self, other):
        if isinstance(other, PreviewResult):
            return self._decision == other._decision and self._fields == other._fields
        if isinstance(other, str):
            return self._decision == other
        return NotImplemented

    def __hash__(self):
        return hash((self._decision, self._fields))

    def __repr__(self):
        if self._fields:
            return "PreviewResult({}, fields={})".format(self._decision, list(self._fields))
        return "PreviewResult({})".format(self._decision)


def _collect_unknown_fields(values):
    """returns the merged dependency fields if any value is Unknown, else None."""
    found = None
    for value in values:
        if isinstance(value, Unknown):
            if found is None:
                found = set()
            found |= value.fields
    return found


def unknown_aware(func):
    """marks a matcher function as understanding Unknown arguments.

    Such a function is called even when some arguments are Unknown and may
    return either a concrete value or an Unknown. Functions without this
    marker are not executed on unknown input; the expression becomes
    indeterminate instead.
    """
    func.__unknown_aware__ = True
    return func


def unknown_guard(func):
    """adapts a normal function so unknown arguments yield an Unknown result
    instead of executing the function."""

    @unknown_aware
    @functools.wraps(func)
    def guarded(*args, **kwargs):
        unknown_fields = _collect_unknown_fields(list(args) + list(kwargs.values()))
        if unknown_fields is not None:
            return Unknown(unknown_fields)
        return func(*args, **kwargs)

    return guarded


def generate_preview_g_function(rm):
    """the Unknown-aware variant of generate_g_function used by preview_enforce."""
    return unknown_guard(generate_g_function(rm))


class PreviewExpression(SimpleEval):
    """evaluates a matcher expression under three-valued logic with Unknown."""

    def _eval_boolop(self, node):
        if isinstance(node.op, ast.And):
            unknown_fields = None
            result = True
            for value_node in node.values:
                value = self._eval(value_node)
                if isinstance(value, Unknown):
                    unknown_fields = (unknown_fields or set()) | value.fields
                    continue
                if not value:
                    return value
                result = value
            if unknown_fields is not None:
                return Unknown(unknown_fields)
            return result
        if isinstance(node.op, ast.Or):
            unknown_fields = None
            result = False
            for value_node in node.values:
                value = self._eval(value_node)
                if isinstance(value, Unknown):
                    unknown_fields = (unknown_fields or set()) | value.fields
                    continue
                if value:
                    return value
                result = value
            if unknown_fields is not None:
                return Unknown(unknown_fields)
            return result
        return super()._eval_boolop(node)

    def _eval_unaryop(self, node):
        if isinstance(node.op, ast.Not):
            operand = self._eval(node.operand)
            if isinstance(operand, Unknown):
                return operand
            return self.operators[type(node.op)](operand)
        return super()._eval_unaryop(node)

    def _eval_compare(self, node):
        left = self._eval(node.left)
        unknown_fields = None
        for operation, comparator in zip(node.ops, node.comparators):
            right = self._eval(comparator)
            link_unknown = _collect_unknown_fields((left, right))
            if link_unknown is not None:
                unknown_fields = (unknown_fields or set()) | link_unknown
            else:
                result = self.operators[type(operation)](left, right)
                if isinstance(result, Unknown):
                    unknown_fields = (unknown_fields or set()) | result.fields
                elif not result:
                    return False
            left = right
        if unknown_fields is not None:
            return Unknown(unknown_fields)
        return True

    def _eval_call(self, node):
        if isinstance(node.func, ast.Attribute):
            func = self._eval(node.func)
        else:
            try:
                func = self.functions[node.func.id]
            except KeyError:
                raise FunctionNotDefined(node.func.id, self.expr)
            except AttributeError:
                raise FeatureNotAvailable("Lambda Functions not implemented")

            if func in DISALLOW_FUNCTIONS:
                raise FeatureNotAvailable("This function is forbidden")

        args = [self._eval(arg) for arg in node.args]
        kwargs = dict(self._eval(keyword) for keyword in node.keywords)

        unknown_fields = _collect_unknown_fields(list(args) + list(kwargs.values()))
        if unknown_fields is not None and not getattr(func, "__unknown_aware__", False):
            return Unknown(unknown_fields)

        return func(*args, **kwargs)

    def _eval_attribute(self, node):
        if isinstance(node.value, (ast.Name, ast.Attribute)):
            base = self._eval(node.value)
            if isinstance(base, Unknown):
                return base
        return super()._eval_attribute(node)


def _get_preview_expression(expr, functions=None):
    expr = expr.replace("&&", "and")
    expr = expr.replace("||", "or")
    expr = re.sub(r"!(?!=)", "not ", expr)

    return PreviewExpression(expr, functions)


def _rule_effect(parameters, p_eft_key):
    if p_eft_key in parameters:
        eft = parameters[p_eft_key]
        if "allow" == eft:
            return Effector.ALLOW
        if "deny" == eft:
            return Effector.DENY
        return Effector.INDETERMINATE
    return Effector.ALLOW


def _unknown_matters(effect_expression, rule_effect):
    """whether an indeterminate rule with the given effect can change the final decision."""
    if effect_expression == ALLOW_OVERRIDE_EFFECT:
        return rule_effect == Effector.ALLOW
    if effect_expression == DENY_OVERRIDE_EFFECT:
        return rule_effect == Effector.DENY
    return rule_effect in (Effector.ALLOW, Effector.DENY)


def preview_enforce(enforcer, *rvals):
    """previews the enforcement decision for a request that may contain Unknown
    attribute markers.

    Returns a PreviewResult with decision "allow", "deny" or "indeterminate".
    A determinate decision holds for every completion of the unknown
    attributes; an indeterminate decision lists the fields that must be
    completed. This never modifies the boolean enforce() API and must not be
    used to directly allow requests.
    """
    from casbin.core_enforcer import EnforceContext

    rtype = "r"
    ptype = "p"
    etype = "e"
    mtype = "m"

    if not enforcer.enabled:
        return PreviewResult(PreviewResult.ALLOW)

    functions = dict(enforcer.fm.get_functions())

    model = enforcer.model

    if "g" in model.keys():
        for key, assertion in model["g"].items():
            if len(enforcer.rm_map) != 0:
                functions[key] = generate_preview_g_function(assertion.rm)
            if len(enforcer.cond_rm_map) != 0:
                functions[key] = unknown_guard(generate_conditional_g_function(assertion.cond_rm))

    if len(rvals) != 0 and isinstance(rvals[0], EnforceContext):
        enforce_context = rvals[0]
        rtype = enforce_context.rtype
        ptype = enforce_context.ptype
        etype = enforce_context.etype
        mtype = enforce_context.mtype
        rvals = rvals[1:]

    if "m" not in model.keys():
        raise RuntimeError("model is undefined")

    if "m" not in model["m"].keys():
        raise RuntimeError("model is undefined")

    effect_expression = model["e"][etype].value
    if effect_expression not in (ALLOW_OVERRIDE_EFFECT, DENY_OVERRIDE_EFFECT, PRIORITY_EFFECT):
        raise RuntimeError("preview_enforce does not support policy effect: " + effect_expression)

    r_tokens = model["r"][rtype].tokens
    p_tokens = model["p"][ptype].tokens

    if len(r_tokens) != len(rvals):
        raise RuntimeError("invalid request size")

    exp_string = model["m"][mtype].value
    exp_has_eval = util.has_eval(exp_string)
    expression = None
    if not exp_has_eval:
        expression = _get_preview_expression(exp_string, functions)

    r_parameters = dict(zip(r_tokens, rvals))

    policies = model["p"][ptype].policy
    if len(policies) == 0:
        if exp_has_eval:
            raise RuntimeError("please make sure rule exists in policy when using eval() in matcher")
        # Mirror enforce(): with an empty policy the matcher is evaluated once
        # against blank policy attributes.
        policies = [[""] * len(p_tokens)]

    unknown_fields = set()

    for pvals in policies:
        if len(p_tokens) != len(pvals):
            raise RuntimeError("invalid policy size")

        p_parameters = dict(zip(p_tokens, pvals))
        parameters = dict(r_parameters, **p_parameters)

        if exp_has_eval:
            rule_names = util.get_eval_value(exp_string)
            rules = [util.escape_assertion(p_parameters[rule_name]) for rule_name in rule_names]
            expression = _get_preview_expression(util.replace_eval(exp_string, rules), functions)

        result = expression.eval(parameters)

        if isinstance(result, Unknown):
            rule_effect = _rule_effect(parameters, ptype + "_eft")
            if _unknown_matters(effect_expression, rule_effect):
                unknown_fields |= result.fields
                if effect_expression == PRIORITY_EFFECT:
                    # An undecided earlier rule blocks every later rule, so a
                    # later allow cannot be taken as the final decision.
                    return PreviewResult(PreviewResult.INDETERMINATE, unknown_fields)
            continue

        if isinstance(result, bool):
            if not result:
                continue
        elif isinstance(result, float):
            if 0 == result:
                continue
        else:
            raise RuntimeError("matcher result should be bool, int or float")

        rule_effect = _rule_effect(parameters, ptype + "_eft")

        if effect_expression == ALLOW_OVERRIDE_EFFECT:
            if rule_effect == Effector.ALLOW:
                return PreviewResult(PreviewResult.ALLOW)
        elif effect_expression == DENY_OVERRIDE_EFFECT:
            if rule_effect == Effector.DENY:
                return PreviewResult(PreviewResult.DENY)
        else:
            if rule_effect == Effector.ALLOW:
                return PreviewResult(PreviewResult.ALLOW)
            if rule_effect == Effector.DENY:
                return PreviewResult(PreviewResult.DENY)

    if unknown_fields:
        return PreviewResult(PreviewResult.INDETERMINATE, unknown_fields)

    if effect_expression == DENY_OVERRIDE_EFFECT:
        return PreviewResult(PreviewResult.ALLOW)

    return PreviewResult(PreviewResult.DENY)
