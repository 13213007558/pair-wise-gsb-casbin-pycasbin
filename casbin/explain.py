import ast
import json

from casbin.effect import Effector
from casbin.util import SimpleEval


class ExplainOptions:
    """ExplainOptions selects which fields an execution explanation report contains.

    include_request_values: record request attribute values. Disabled by default,
        only the request field names (e.g. "r_sub") are recorded.
    include_policy_text: allow policy rule text and matcher expression text to
        appear in the report. Disabled by default.
    include_matcher_trace: record per-policy matcher steps, marking steps that
        were short-circuited as not executed.
    include_role_paths: record the role inheritance paths (with their domain)
        traversed by g() calls.
    include_function_calls: record custom/builtin function calls made by the
        matcher.
    include_effect_trace: record the effector decision, including which matched
        policy terminated the evaluation (e.g. for priority models).
    """

    def __init__(
        self,
        include_request_values=False,
        include_policy_text=False,
        include_matcher_trace=True,
        include_role_paths=True,
        include_function_calls=True,
        include_effect_trace=True,
    ):
        self.include_request_values = include_request_values
        self.include_policy_text = include_policy_text
        self.include_matcher_trace = include_matcher_trace
        self.include_role_paths = include_role_paths
        self.include_function_calls = include_function_calls
        self.include_effect_trace = include_effect_trace


class ExplainReport:
    """ExplainReport is the serializable explanation of one enforce call.

    Node identities inside the report are stable values (policy indexes,
    sequential step/query ids, role names and domains), never Python object
    addresses, so the report can safely be serialized and compared.
    """

    def __init__(self, data):
        self._data = data

    @property
    def result(self):
        return self._data.get("result")

    @property
    def reason(self):
        return self._data.get("reason")

    def to_dict(self):
        """returns the report as a plain dict of JSON-serializable values."""
        return self._data

    def to_json(self, **kwargs):
        """serializes the report to a JSON string."""
        return json.dumps(self._data, **kwargs)

    def __repr__(self):
        return "ExplainReport(result=%r, reason=%r)" % (self.result, self.reason)


def _jsonable(value):
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    return str(value)


class ExplainableSimpleEval(SimpleEval):
    """A SimpleEval that reports which top-level matcher steps were executed.

    Steps are the operands of the top-level boolean operator (or the whole
    matcher when there is none). Because evaluation is the real one, operands
    skipped by short-circuiting are simply never reported as executed.
    """

    def __init__(self, expr, functions=None, recorder=None):
        super().__init__(expr, functions)
        self.recorder = recorder
        self.steps = []
        if self.ast_parsed_value is not None:
            root = self.ast_parsed_value
            if isinstance(root, ast.BoolOp):
                step_nodes = list(root.values)
            else:
                step_nodes = [root]
            unparse = getattr(ast, "unparse", None)
            for step_id, node in enumerate(step_nodes):
                node._explain_step_id = step_id
                text = None
                if unparse is not None:
                    try:
                        text = unparse(node)
                    except Exception:
                        text = None
                self.steps.append({"id": step_id, "text": text})

    def _eval(self, node):
        value = super()._eval(node)
        recorder = self.recorder
        if recorder is not None:
            step_id = getattr(node, "_explain_step_id", None)
            if step_id is not None:
                recorder.record_step(step_id, value)
        return value


class RoleTracer:
    """Collects the role graph edges traversed by one enforce call.

    The tracer is attached to role managers only while an explaining enforce
    runs and is deactivated afterwards, so a later plain enforce() neither
    records nor accumulates anything.
    """

    def __init__(self, include_values=False):
        self.active = True
        self.include_values = include_values
        self.queries = []
        self._current = None
        self._start = None
        self._parents = None
        self._found = None

    def begin_query(self, function, args):
        if not self.active:
            return
        domain = str(args[2]) if len(args) > 2 else None
        self._current = {
            "id": len(self.queries),
            "function": function,
            "domain": domain,
            "result": None,
            "path": None,
            "edges": [],
        }
        if self.include_values:
            self._current["args"] = [_jsonable(arg) for arg in args]
        self._start = (str(args[0]), domain)
        self._parents = {}
        self._found = None

    def record_edge(self, frm, to, passed=True):
        if not self.active or self._current is None:
            return
        domain = self._current["domain"]
        self._current["edges"].append(
            {"from": str(frm), "to": str(to), "domain": domain, "condition_passed": bool(passed)}
        )
        key = (str(to), domain)
        if key not in self._parents:
            self._parents[key] = (str(frm), domain)

    def record_found(self, name):
        if not self.active or self._current is None:
            return
        self._found = (str(name), self._current["domain"])

    def end_query(self, result):
        if not self.active or self._current is None:
            return
        query = self._current
        query["result"] = bool(result)
        if result:
            query["path"] = self._build_path()
        self.queries.append(query)
        self._current = None

    def abort_query(self):
        if self._current is not None:
            self._current["error"] = True
            self.queries.append(self._current)
            self._current = None

    def _build_path(self):
        node = self._found if self._found is not None else self._start
        chain = [node]
        seen = {node}
        while node != self._start and node in self._parents:
            node = self._parents[node]
            if node in seen:
                break
            seen.add(node)
            chain.append(node)
        chain.reverse()
        return [{"name": name, "domain": domain} for name, domain in chain]


class ExplainRecorder:
    """ExplainRecorder is attached to one enforce call and builds the report."""

    def __init__(self, options=None):
        self.options = options or ExplainOptions()
        self.disabled = False
        self.request = None
        self.policies = []
        self.role_tracer = RoleTracer(include_values=self.options.include_request_values)
        self.function_calls = []
        self.matched_effects = []
        self.final_effect = None
        self.result = None
        self.effect_expression = None
        self.terminated_by = None
        self.termination_effect = None
        self._rms = []
        self._current_policy = None
        self._step_results = {}
        self._last_expression = None
        self._policy_len = 0
        self._policy_rows = []

    def record_disabled(self):
        self.disabled = True
        self.result = True

    def attach(self, rm_map, cond_rm_map):
        """attaches the role tracer to the role managers for this enforce call."""
        if not self.options.include_role_paths:
            return
        self._rms = list(rm_map.values()) + list(cond_rm_map.values())
        for rm in self._rms:
            rm.link_tracer = self.role_tracer

    def detach(self):
        """deactivates and removes the tracer so later plain enforce calls record nothing."""
        self.role_tracer.active = False
        for rm in self._rms:
            self._clear_tracer(rm)
            inner = getattr(rm, "rm_map", None)
            if isinstance(inner, dict):
                for sub_rm in inner.values():
                    self._clear_tracer(sub_rm)
        self._rms = []

    @staticmethod
    def _clear_tracer(rm):
        try:
            rm.link_tracer = None
        except Exception:
            pass

    def wrap_functions(self, functions, g_names):
        """returns a copy of the function map with recording wrappers.

        Wrappers only observe the real calls; they never invoke a function
        themselves, so custom functions and conditional role callbacks run
        exactly as often as in a plain enforce call.
        """
        wrapped = {}
        for name, fn in functions.items():
            if name in g_names and self.options.include_role_paths:
                wrapped[name] = self._wrap_g_function(name, fn)
            elif self.options.include_function_calls:
                wrapped[name] = self._wrap_function(name, fn)
            else:
                wrapped[name] = fn
        return wrapped

    def _wrap_g_function(self, name, fn):
        tracer = self.role_tracer

        def g_wrapper(*args):
            tracer.begin_query(name, args)
            try:
                result = fn(*args)
            except Exception:
                tracer.abort_query()
                raise
            tracer.end_query(result)
            return result

        return g_wrapper

    def _wrap_function(self, name, fn):
        recorder = self

        def func_wrapper(*args):
            result = fn(*args)
            entry = {"id": len(recorder.function_calls), "function": name, "result": _jsonable(result)}
            if recorder.options.include_request_values:
                entry["args"] = [_jsonable(arg) for arg in args]
            recorder.function_calls.append(entry)
            return result

        return func_wrapper

    def begin_request(self, r_tokens, rvals):
        self.request = {"fields": list(r_tokens)}
        if self.options.include_request_values:
            self.request["values"] = {token: _jsonable(value) for token, value in zip(r_tokens, rvals)}

    def begin_policy_set(self, policy_len, policy_rows):
        self._policy_len = policy_len
        self._policy_rows = policy_rows

    def begin_policy(self, index, pvals):
        entry = {"index": index, "executed": True, "matched": False, "effect": None}
        if self.options.include_policy_text and pvals is not None:
            entry["policy"] = list(pvals)
        self._current_policy = entry
        self._step_results = {}
        self.policies.append(entry)

    def record_step(self, step_id, value):
        self._step_results[step_id] = bool(value)

    def end_policy(self, expression, matched, effect_label):
        entry = self._current_policy
        if entry is None:
            return
        entry["matched"] = bool(matched)
        entry["effect"] = effect_label
        if matched:
            self.matched_effects.append(effect_label)
        if expression is not None:
            self._last_expression = expression
            if self.options.include_matcher_trace:
                entry["matcher_steps"] = self._build_steps(expression, self._step_results)
        self._current_policy = None
        self._step_results = {}

    def _build_steps(self, expression, step_results):
        steps = getattr(expression, "steps", None)
        if steps is None:
            return []
        include_text = self.options.include_policy_text
        built = []
        for step in steps:
            item = {"id": step["id"]}
            if step["id"] in step_results:
                item["status"] = "executed"
                item["result"] = step_results[step["id"]]
            else:
                item["status"] = "not_executed"
            if include_text and step["text"] is not None:
                item["text"] = step["text"]
            built.append(item)
        return built

    def record_termination(self, index, effect_label):
        self.terminated_by = index
        self.termination_effect = effect_label

    def finish(self, final_effect, result, effect_expression):
        self.final_effect = final_effect
        self.result = bool(result)
        self.effect_expression = effect_expression

    def build_report(self):
        data = {"result": self.result, "reason": self._reason()}
        if self.request is not None:
            data["request"] = self.request
        if self.disabled:
            return ExplainReport(data)

        data["policies"] = self._build_policies()

        if self.options.include_role_paths:
            data["role_queries"] = list(self.role_tracer.queries)
        if self.options.include_function_calls:
            data["function_calls"] = list(self.function_calls)
        if self.options.include_effect_trace:
            data["effect"] = {
                "expression": self.effect_expression,
                "matched_effects": list(self.matched_effects),
                "final_effect": self.final_effect,
                "terminated_by": self.terminated_by,
                "termination_effect": self.termination_effect,
            }
        return ExplainReport(data)

    def _reason(self):
        if self.disabled:
            return "disabled"
        if self.result:
            return "allow"
        if "deny" in self.matched_effects:
            return "explicit_deny"
        return "no_matching_policy"

    def _build_policies(self):
        entries = {entry["index"]: entry for entry in self.policies}
        for index in range(self._policy_len):
            if index in entries:
                continue
            entry = {"index": index, "executed": False, "matched": False, "effect": None}
            if self.options.include_policy_text:
                entry["policy"] = list(self._policy_rows[index])
            if self.options.include_matcher_trace and self._last_expression is not None:
                entry["matcher_steps"] = self._build_steps(self._last_expression, {})
            entries[index] = entry
        return [entries[index] for index in sorted(entries, key=lambda i: (i is None, i))]


EFFECT_LABELS = {Effector.ALLOW: "allow", Effector.INDETERMINATE: "indeterminate", Effector.DENY: "deny"}
