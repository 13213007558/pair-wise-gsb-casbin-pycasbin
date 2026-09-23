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

import json

from casbin.effect import Effector

EFFECT_NAMES = {
    Effector.ALLOW: "allow",
    Effector.INDETERMINATE: "indeterminate",
    Effector.DENY: "deny",
}


class ExplainOptions:
    """ExplainOptions controls which sections an explain report contains and
    how much sensitive detail is exposed.

    fields: iterable of section names to include in the report, any of
        "request", "policies", "roles", "functions", "effect", "decision".
        None (default) includes all sections.
    include_request_values: when False (default) only request attribute names
        are recorded, never their values.
    include_policy_text: when False (default) policy rule text is kept out of
        the report.
    """

    ALL_FIELDS = ("request", "policies", "roles", "functions", "effect", "decision")

    def __init__(self, fields=None, include_request_values=False, include_policy_text=False):
        self.fields = set(fields) if fields is not None else set(self.ALL_FIELDS)
        unknown = self.fields - set(self.ALL_FIELDS)
        if unknown:
            raise ValueError(f"unknown explain fields: {sorted(unknown)}")
        self.include_request_values = include_request_values
        self.include_policy_text = include_policy_text


class ExplainReport:
    """ExplainReport is the serializable explanation of a single enforce call.

    All node identifiers are deterministic strings (never Python object
    addresses), so the report can be safely serialized and compared.
    """

    def __init__(self, recorder):
        self._recorder = recorder

    @property
    def result(self):
        """the boolean enforcement result of the explained call."""
        return self._recorder.result

    @property
    def reason(self):
        """why the decision was reached: "allow", "explicit_deny" or "no_matching_policy"."""
        return self._recorder.reason

    def to_dict(self):
        """returns the report as a plain dict, honoring the configured fields."""
        recorder = self._recorder
        options = recorder.options
        data = {}

        if "request" in options.fields:
            request = {"fields": list(recorder.request_fields)}
            if recorder.request_values is not None:
                request["values"] = dict(recorder.request_values)
            data["request"] = request

        if "policies" in options.fields:
            data["policies"] = [dict(record) for record in recorder.policies]

        if "roles" in options.fields:
            data["roles"] = json.loads(json.dumps(recorder.role_queries, default=str))

        if "functions" in options.fields:
            data["functions"] = [
                {"name": name, "calls": calls} for name, calls in sorted(recorder.function_calls.items())
            ]

        if "effect" in options.fields:
            data["effect"] = {
                "stream": list(recorder.effect_stream),
                "terminated_by": recorder.terminated_by,
                "intermediate_effect": recorder.intermediate_effect,
            }

        if "decision" in options.fields:
            data["decision"] = {
                "result": recorder.result,
                "final_effect": recorder.final_effect,
                "reason": recorder.reason,
            }

        return data

    def to_json(self, **kwargs):
        """serializes the report to a JSON string."""
        return json.dumps(self.to_dict(), default=str, **kwargs)

    def __repr__(self):
        return f"ExplainReport(result={self.result}, reason={self.reason})"


class EnforceRecorder:
    """EnforceRecorder collects explain events during exactly one enforce
    evaluation. It also acts as the role-link tracer observed by role
    managers, so role paths and conditional edges are captured from the real
    traversal without re-invoking any custom or condition function."""

    def __init__(self, options=None):
        self.options = options if options is not None else ExplainOptions()
        self.request_fields = []
        self.request_values = None
        self.policies = []
        self.role_queries = []
        self.function_calls = {}
        self.effect_stream = []
        self.terminated_by = None
        self.intermediate_effect = None
        self.empty_policy_result = None
        self.final_effect = None
        self.result = None
        self.reason = None
        self._evaluated_indexes = set()
        self._current_query = None

    def set_request(self, r_tokens, rvals):
        self.request_fields = [token.split("_", 1)[1] if "_" in token else token for token in r_tokens]
        if self.options.include_request_values:
            self.request_values = dict(zip(self.request_fields, rvals))

    def wrap_functions(self, functions, g_keys):
        """wraps matcher functions in place (on a private copy of the function
        map) so calls are counted without altering how often they run."""
        for name in list(functions.keys()):
            functions[name] = self._wrap_function(name, functions[name], name in g_keys)

    def _wrap_function(self, name, fn, is_role_query):
        recorder = self

        def wrapped(*args):
            recorder.function_calls[name] = recorder.function_calls.get(name, 0) + 1
            if not is_role_query:
                return fn(*args)

            query = {
                "id": f"g{len(recorder.role_queries)}",
                "function": name,
                "subject": str(args[0]) if len(args) > 0 else None,
                "target": str(args[1]) if len(args) > 1 else None,
                "domain": str(args[2]) if len(args) > 2 else None,
                "result": None,
                "path": [],
                "nodes": {},
                "condition_edges": [],
            }
            recorder.role_queries.append(query)
            previous = recorder._current_query
            recorder._current_query = query
            try:
                result = fn(*args)
            finally:
                recorder._current_query = previous
            query["result"] = bool(result)
            return result

        return wrapped

    def role_path(self, path):
        """tracer callback: the role manager reached the target via path."""
        query = self._current_query
        if query is None:
            return
        domain = query["domain"]
        node_ids = []
        for name in path:
            node_id = f"role:{name}@{domain}" if domain else f"role:{name}"
            if node_id not in query["nodes"]:
                query["nodes"][node_id] = {"id": node_id, "name": name, "domain": domain}
            node_ids.append(node_id)
        query["path"] = node_ids

    def condition_edge(self, from_name, to_name, passed, domain=None):
        """tracer callback: a conditional role edge was evaluated (once)."""
        query = self._current_query
        if query is None:
            return
        query["condition_edges"].append(
            {"from": from_name, "to": to_name, "domain": domain, "passed": bool(passed)}
        )

    def policy_evaluated(self, index, pvals, matched, effect):
        record = {
            "id": f"p{index}",
            "index": index,
            "status": "matched" if matched else "unmatched",
            "effect": effect,
        }
        if self.options.include_policy_text:
            record["rule"] = list(pvals)
        self.policies.append(record)
        self._evaluated_indexes.add(index)
        self.effect_stream.append(effect)

    def loop_terminated(self, index, intermediate_effect):
        self.terminated_by = index
        self.intermediate_effect = EFFECT_NAMES.get(intermediate_effect)

    def set_empty_policy_result(self, matched):
        self.empty_policy_result = bool(matched)

    def finalize(self, policy_effects, final_effect, result, policy_rules):
        self.final_effect = EFFECT_NAMES.get(final_effect)
        self.result = bool(result)

        for index in range(len(policy_rules)):
            if index in self._evaluated_indexes:
                continue
            record = {
                "id": f"p{index}",
                "index": index,
                "status": "not_executed",
                "effect": None,
            }
            if self.options.include_policy_text:
                record["rule"] = list(policy_rules[index])
            self.policies.append(record)

        self.policies.sort(key=lambda record: record["index"])

        if self.result:
            self.reason = "allow"
        elif Effector.DENY in policy_effects:
            self.reason = "explicit_deny"
        else:
            self.reason = "no_matching_policy"

    def build_report(self):
        return ExplainReport(self)
