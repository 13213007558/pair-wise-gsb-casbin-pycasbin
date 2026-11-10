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

"""Opt-in restricted matcher evaluation for tenant supplied expressions.

The regular :class:`~casbin.util.expression.SimpleEval` evaluator exposes every
registered function and the full Python expression grammar.  When tenants are
allowed to submit parts of a matcher that is unacceptable: a tenant could reach
a function it should not know about or build an expression that is expensive to
evaluate.

This module adds an explicit, opt-in restriction layer built on the same
``simpleeval`` / :mod:`ast` dependencies that pycasbin already uses (no external
sandbox service):

* :class:`RestrictionPolicy` declares the allowed grammar (AST node types), the
  allowed request / policy field names, the allowed function names and whether
  attribute access is permitted at all.
* :func:`validate_expression` statically rejects an expression that uses a
  forbidden node, an unknown name, a forbidden attribute or a forbidden call
  before anything is evaluated.
* :class:`RestrictedSimpleEval` enforces the same policy at run time and charges
  every evaluated node and every controlled function call against a per-enforce
  :class:`EnforceBudget`.  Exhausting the budget denies the request, it never
  turns into an allow.

The budget is a pure-Python counter.  It bounds the number of expression nodes
and function calls the evaluator itself performs, which is the amount of work
pycasbin controls.  The wall-clock time spent inside a trusted custom callback
is deliberately outside this guarantee; no thread timeout is used to pretend an
arbitrary callback can be killed.
"""

import ast

from simpleeval import EvalWithCompoundTypes, NameNotDefined

# ---------------------------------------------------------------------------
# Distinguishable denial results
# ---------------------------------------------------------------------------


class RestrictionViolation(Exception):
    """Base class for every condition that makes a restricted matcher fail.

    Every concrete violation denies the request.  Callers that need to tell the
    different rejection reasons apart can catch the concrete subclasses; callers
    that only care that the expression was rejected can catch this one class.
    """


class RestrictedSyntaxError(RestrictionViolation):
    """The expression uses grammar (an AST node) the policy does not allow,
    or it cannot even be parsed as a single expression."""


class RestrictedNameError(RestrictionViolation):
    """The expression references a name that is not an allowed request field,
    policy field, function or boolean literal."""


class RestrictedAttributeError(RestrictionViolation):
    """The expression performs attribute access that the policy forbids."""


class RestrictedFunctionError(RestrictionViolation):
    """The expression calls a function that is not on the allow list."""


class NodeBudgetExhausted(RestrictionViolation):
    """The per-enforce node evaluation budget has been spent."""

    def __init__(self, budget, limit):
        super().__init__(f"restricted matcher node budget exhausted: {budget} >= {limit}")
        self.budget = budget
        self.limit = limit


class CallBudgetExhausted(RestrictionViolation):
    """The per-enforce controlled function call budget has been spent."""

    def __init__(self, budget, limit):
        super().__init__(f"restricted matcher call budget exhausted: {budget} >= {limit}")
        self.budget = budget
        self.limit = limit


# The ``eval(p...)`` pseudo-function is a pycasbin matcher construct, not a
# Python function.  Static validation treats it specially instead of demanding
# it be registered as a callable.
EVAL_NAME = "eval"
BOOLEAN_NAMES = frozenset(("true", "false", "True", "False", "None"))


# ---------------------------------------------------------------------------
# Per-enforce budget
# ---------------------------------------------------------------------------


class EnforceBudget:
    """Pure-Python counters shared by every candidate rule of one enforce call.

    A fresh instance is created for each request, so budgets accumulate across
    the matcher expressions and expanded ``eval`` expressions evaluated for all
    candidate policies of that request, and never leak across requests.
    """

    def __init__(self, node_limit, call_limit):
        self.node_limit = node_limit
        self.call_limit = call_limit
        self.nodes_used = 0
        self.calls_used = 0

    def charge_node(self):
        self.nodes_used += 1
        if self.nodes_used > self.node_limit:
            raise NodeBudgetExhausted(self.nodes_used, self.node_limit)

    def charge_call(self):
        self.calls_used += 1
        if self.calls_used > self.call_limit:
            raise CallBudgetExhausted(self.calls_used, self.call_limit)


# ---------------------------------------------------------------------------
# Restriction policy
# ---------------------------------------------------------------------------


DEFAULT_ALLOWED_NODES = frozenset(
    (
        ast.BoolOp,
        ast.And,
        ast.Or,
        ast.UnaryOp,
        ast.Not,
        ast.BinOp,
        ast.Add,
        ast.Sub,
        ast.Mult,
        ast.Div,
        ast.Mod,
        ast.Compare,
        ast.Eq,
        ast.NotEq,
        ast.Gt,
        ast.GtE,
        ast.Lt,
        ast.LtE,
        ast.In,
        ast.NotIn,
        ast.IfExp,
        ast.Name,
        ast.Load,
        ast.Attribute,
        ast.Constant,
        ast.Call,
    )
)


def minimal_allowed_functions():
    """The smallest generally useful, side-effect free matcher function set."""
    from casbin import util

    return {
        "keyMatch": util.key_match_func,
        "regexMatch": util.regex_match_func,
        "globMatch": util.glob_match_func,
    }


class RestrictionPolicy:
    """Declarative description of what a tenant matcher is allowed to do.

    Everything is opt-in: a name, attribute or function that is not listed is
    rejected.  The default grammar keeps boolean logic, comparisons, basic
    arithmetic and plain field/constant names; comprehensions, lambdas,
    subscripts, containers and attribute access are disabled unless explicitly
    enabled.
    """

    def __init__(
        self,
        allowed_names,
        allowed_functions=None,
        allowed_nodes=None,
        node_budget=200,
        call_budget=20,
        max_expression_nodes=100,
        allow_attribute_access=False,
        allowed_attributes=None,
    ):
        self.allowed_names = frozenset(allowed_names) | BOOLEAN_NAMES
        self.functions = dict(allowed_functions or {})
        self.allowed_function_names = frozenset(self.functions.keys())
        allowed_node_set = frozenset(allowed_nodes if allowed_nodes is not None else DEFAULT_ALLOWED_NODES)
        self.allowed_nodes = tuple(allowed_node_set)
        self.node_budget = node_budget
        self.call_budget = call_budget
        self.max_expression_nodes = max_expression_nodes
        self.allow_attribute_access = allow_attribute_access
        self.allowed_attributes = dict(allowed_attributes or {})

    def new_budget(self):
        return EnforceBudget(self.node_budget, self.call_budget)

    def is_allowed_name(self, name):
        return name in self.allowed_names or name in self.allowed_function_names or name == EVAL_NAME

    @classmethod
    def minimal(cls, r_tokens, p_tokens, allowed_functions=None, **kwargs):
        """Build the ready-to-use minimal policy for tenant expressions.

        ``r_tokens`` / ``p_tokens`` are the runtime request and policy token
        names (for example ``r_sub`` and ``p_obj``).  Only those flat fields can
        be referenced, and only the small side-effect free function set is
        callable.  This is the policy recommended for handing to tenants.
        """
        names = set(r_tokens) | set(p_tokens)
        return cls(
            allowed_names=names,
            allowed_functions=allowed_functions if allowed_functions is not None else minimal_allowed_functions(),
            **kwargs,
        )

    @classmethod
    def from_enforcer(cls, enforcer, rtype="r", ptype="p", allowed_functions=None, **kwargs):
        """Build a minimal policy from an enforcer's declared model tokens."""
        r_tokens = tuple(enforcer.model["r"][rtype].tokens)
        p_tokens = tuple(enforcer.model["p"][ptype].tokens)
        if allowed_functions is None:
            registered = enforcer.fm.get_functions()
            allowed_functions = {name: fn for name, fn in minimal_allowed_functions().items() if name in registered}
        return cls.minimal(r_tokens, p_tokens, allowed_functions=allowed_functions, **kwargs)


# ---------------------------------------------------------------------------
# Static validation
# ---------------------------------------------------------------------------


def _eval_argument_name(node):
    """Return the dotted field referenced by an ``eval(...)`` argument."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    return ".".join(reversed(parts))


def validate_expression(expression, policy):
    """Statically validate an (already normalized) matcher expression.

    Runs before evaluation so an invalid tenant expression is rejected without
    ever executing.  Returns the parsed AST on success and raises a concrete
    :class:`RestrictionViolation` subclass otherwise.  ``eval(p...)`` is only
    accepted in the outer matcher; the expanded policy expression must be
    validated separately after substitution.
    """
    try:
        tree = ast.parse(expression.strip(), mode="eval").body
    except SyntaxError as exc:
        raise RestrictedSyntaxError(f"matcher is not a valid expression: {exc.msg}") from exc

    node_count = 0
    for node in ast.walk(tree):
        node_count += 1
        if isinstance(node, ast.Attribute):
            _validate_attribute(node, policy)
        elif not isinstance(node, policy.allowed_nodes):
            raise RestrictedSyntaxError(
                f"matcher grammar not allowed: {type(node).__name__} is outside the allowed node set"
            )

        if isinstance(node, ast.Name):
            if not policy.is_allowed_name(node.id):
                raise RestrictedNameError(f"matcher references unknown name {node.id!r}")

        elif isinstance(node, ast.Call):
            _validate_call(node, policy)

    if node_count > policy.max_expression_nodes:
        raise RestrictedSyntaxError(f"matcher too large: {node_count} nodes, limit is {policy.max_expression_nodes}")

    return tree


def _validate_attribute(node, policy):
    if not policy.allow_attribute_access:
        raise RestrictedAttributeError("attribute access is disabled in restricted matchers")
    if not policy.allowed_attributes:
        return
    root = node
    while isinstance(root, ast.Attribute):
        root = root.value
    if isinstance(root, ast.Name):
        allowed = policy.allowed_attributes.get(root.id)
        if allowed is not None and node.attr not in allowed:
            raise RestrictedAttributeError(f"attribute {node.attr!r} is not allowed on {root.id!r}")


def _validate_call(node, policy):
    func = node.func
    if isinstance(func, ast.Attribute):
        raise RestrictedFunctionError("calling methods through attribute access is not allowed")
    if not isinstance(func, ast.Name):
        raise RestrictedFunctionError("only named functions may be called")
    if func.id == EVAL_NAME:
        if node.keywords or len(node.args) != 1 or _eval_argument_name(node.args[0]) is None:
            raise RestrictedSyntaxError("eval() requires exactly one plain r/p field argument")
        return
    if func.id not in policy.allowed_function_names:
        raise RestrictedFunctionError(f"function {func.id!r} is not allowed in restricted matchers")


# ---------------------------------------------------------------------------
# Runtime evaluator
# ---------------------------------------------------------------------------


class RestrictedSimpleEval(EvalWithCompoundTypes):
    """SimpleEval subclass enforcing a :class:`RestrictionPolicy`.

    The evaluator is bound to one :class:`EnforceBudget`; create one per enforce
    call and reuse it across that call's candidate rules so the budget
    accumulates correctly.  Python's ``and`` / ``or`` short-circuit semantics are
    inherited unchanged: a branch that is never evaluated is never charged and
    cannot trigger a side-effecting function.
    """

    def __init__(self, policy, budget, functions=None):
        super().__init__(functions=functions if functions is not None else dict(policy.functions))
        # EvalWithCompoundTypes injects list/tuple/dict/set constructors.  They
        # are not part of the tenant allow list, so drop them: only functions the
        # restriction policy explicitly names may resolve at a Call node.
        for injected in ("list", "tuple", "dict", "set"):
            self.functions.pop(injected, None)
        self.policy = policy
        self.budget = budget
        self.ast_parsed_value = None
        self.expr = ""

    def set_expr(self, expr):
        if expr == "":
            return
        self.expr = expr
        self.ast_parsed_value = validate_expression(expr, self.policy)

    def eval(self, names=None):
        if names is not None:
            self.names = names
        return self._eval(self.ast_parsed_value)

    def _eval(self, node):
        self.budget.charge_node()
        return super()._eval(node)

    def _eval_name(self, node):
        if not self.policy.is_allowed_name(node.id):
            raise RestrictedNameError(f"matcher references unknown name {node.id!r}")
        try:
            return super()._eval_name(node)
        except NameNotDefined as exc:
            raise RestrictedNameError(f"matcher references unknown name {node.id!r}") from exc

    def _eval_attribute(self, node):
        _validate_attribute(node, self.policy)
        return super()._eval_attribute(node)

    def _eval_call(self, node):
        func = node.func
        if isinstance(func, ast.Attribute) or not isinstance(func, ast.Name):
            raise RestrictedFunctionError("only named, allow-listed functions may be called")
        if func.id not in self.functions:
            raise RestrictedFunctionError(f"function {func.id!r} is not allowed in restricted matchers")
        self.budget.charge_call()
        return super()._eval_call(node)
