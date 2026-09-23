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


class SessionError(Exception):
    """raised when a role session is invalid, e.g. the user does not own an
    activated role or the activated roles violate a mutual-exclusion group."""

    pass


class RoleSession:
    """RoleSession carries the roles a user activates for one operation session.

    Pass it as the first element of "rvals" in "enforce"/"enforce_ex" so that
    the request is evaluated only along the activated roles and their
    inherited roles, without mutating the enforcer's shared role graph.
    """

    def __init__(self, user, roles, domain=None, allow_direct_permissions=False):
        self.user = user
        self.roles = frozenset(roles)
        self.domain = domain
        # whether permissions assigned directly to the user (p, user, ...)
        # are visible inside this session.
        self.allow_direct_permissions = allow_direct_permissions

    def __repr__(self):
        return (
            f"RoleSession(user={self.user!r}, roles={sorted(self.roles)!r}, "
            f"domain={self.domain!r}, allow_direct_permissions={self.allow_direct_permissions!r})"
        )
