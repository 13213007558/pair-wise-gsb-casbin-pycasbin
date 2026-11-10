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

import copy

from casbin.effect import get_effector
from casbin.rbac import default_role_manager


class ReloadResult:
    """outcome of an atomic hot reload.

    ok tells whether a new state was published. On failure ok is False, error carries the
    reason and the enforcer keeps serving the previous state unchanged. version is the
    generation that is current once the call has returned (the old one on failure).
    """

    def __init__(self, ok, version, error=None):
        self.ok = ok
        self.version = version
        self.error = error

    def __bool__(self):
        return self.ok

    def __repr__(self):
        if self.ok:
            return "ReloadResult(ok=True, version={})".format(self.version)
        return "ReloadResult(ok=False, version={}, error={!r})".format(self.version, self.error)


class PolicyState:
    """one immutable, self-contained authorization state.

    A state bundles everything a single enforce() decision can read: the model holding the
    policies, the role inheritance graphs, the effector and the per-state policy caches.
    States are built off to the side while another state is still current and only become
    visible through one pointer swap, so no request can ever observe a half-loaded state or
    a new policy paired with an old role graph.
    """

    def __init__(self, model, rm_map, cond_rm_map, eft, policy_indexes=None, version=0):
        self.model = model
        self.rm_map = rm_map
        self.cond_rm_map = cond_rm_map
        self.eft = eft
        # the partition descriptions are shared configuration, but each state holds its
        # own snapshot of their built buckets so a rebuild for a new policy never disturbs
        # a request still iterating over the previous state's partition.
        self.policy_indexes = self._snapshot_indexes(policy_indexes)
        self.policy_deny_cache = {}
        self.version = version

    @staticmethod
    def _snapshot_indexes(policy_indexes):
        if not policy_indexes:
            return {}
        return {ptype: index.snapshot() for ptype, index in policy_indexes.items()}

    @staticmethod
    def build_candidate(current_state, model_template):
        """builds the empty candidate state a reload fills in.

        The model is a deep copy with every policy rule dropped, and fresh role managers
        are created from the same definitions as the current state. Custom matching
        functions installed on the current role managers are carried over, since they are
        configuration rather than policy data.
        """
        new_model = copy.deepcopy(model_template)
        new_model.clear_policy()

        new_rm_map = {}
        new_cond_rm_map = {}
        if "g" in new_model.keys():
            for ptype, assertion in new_model["g"].items():
                old_rm = current_state.rm_map.get(ptype)
                old_cond_rm = current_state.cond_rm_map.get(ptype)

                if len(assertion.tokens) <= 2 and len(assertion.params_tokens) == 0:
                    rm = default_role_manager.RoleManager(10)
                    if old_rm is not None:
                        rm.add_matching_func(old_rm.matching_func)
                    assertion.rm = rm
                    new_rm_map[ptype] = rm
                elif len(assertion.tokens) <= 2:
                    cond_rm = default_role_manager.ConditionalRoleManager(10)
                    if old_cond_rm is not None:
                        cond_rm.add_matching_func(old_cond_rm.matching_func)
                    assertion.cond_rm = cond_rm
                    new_cond_rm_map[ptype] = cond_rm
                elif len(assertion.params_tokens) == 0:
                    rm = default_role_manager.DomainManager(10)
                    if old_rm is not None:
                        rm.add_matching_func(old_rm.matching_func)
                        rm.add_domain_matching_func(old_rm.domain_matching_func)
                    assertion.rm = rm
                    new_rm_map[ptype] = rm
                else:
                    cond_rm = default_role_manager.ConditionalDomainManager(10)
                    if old_cond_rm is not None:
                        cond_rm.add_matching_func(old_cond_rm.matching_func)
                        cond_rm.add_domain_matching_func(old_cond_rm.domain_matching_func)
                    assertion.cond_rm = cond_rm
                    new_cond_rm_map[ptype] = cond_rm

        eft = get_effector(new_model["e"]["e"].value)
        return PolicyState(new_model, new_rm_map, new_cond_rm_map, eft, current_state.policy_indexes)

    def validate_rule_shapes(self):
        """checks that every loaded rule has the arity its assertion declares.

        enforce() raises "invalid policy size" on a mismatched row while evaluating a
        request. Doing the same check before publication turns a malformed adapter payload
        into a failed reload that leaves the known-good state serving, instead of a state
        that fails requests after the swap.
        """
        for sec in ("p", "g"):
            if sec not in self.model.keys():
                continue
            for ptype, assertion in self.model[sec].items():
                expected = len(assertion.tokens)
                for rule in assertion.policy:
                    if len(rule) != expected:
                        raise RuntimeError(
                            "invalid policy size: {} rule {} has {} fields, expected {}".format(
                                ptype, rule, len(rule), expected
                            )
                        )

    def build_role_links(self, auto_build_role_links):
        """constructs the role inheritance graphs from the grouping policies, using only
        this candidate's fresh role managers."""
        if not auto_build_role_links:
            return
        if len(self.rm_map) != 0:
            self.model.build_role_links(self.rm_map)
        if len(self.cond_rm_map) != 0:
            self.model.build_conditional_role_links(self.cond_rm_map)

    def prepare_indexes(self):
        """drops any partition buckets carried over from an older policy.

        The buckets are rebuilt lazily on the first enforce() that needs them, keyed on the
        new policy's version, so no index can point at rules that no longer exist.
        """
        for index in self.policy_indexes.values():
            index.reset()
