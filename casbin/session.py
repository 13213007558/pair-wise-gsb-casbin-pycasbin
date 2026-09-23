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


class RoleSession:
    """RoleSession describes a session-scoped role activation.

    It is used as the first element of the parameter "rvals" in method "enforce",
    the same way an EnforceContext is. When a request carries a RoleSession,
    the "g" functions only follow the activated roles (and the roles they
    inherit) instead of every role the user has.

    A RoleSession is a plain snapshot of the caller's intent: the activated
    roles are re-validated against the current role manager on every enforce
    call, so revoking a role grant immediately invalidates old sessions.
    """

    def __init__(self, user, roles, domain=None, allow_direct_permissions=False):
        if isinstance(roles, str):
            roles = [roles]
        self.user = user
        self.roles = frozenset(roles)
        self.domain = domain
        self.allow_direct_permissions = allow_direct_permissions

    def get_cache_key(self):
        """lets CachedEnforcer key a request that carries a RoleSession."""
        return (
            self.user,
            self.domain,
            tuple(sorted(self.roles)),
            self.allow_direct_permissions,
        )
