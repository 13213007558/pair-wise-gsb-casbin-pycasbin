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

"""End-to-end demonstration of the opt-in restricted matcher strategy.

Run with:  python examples/restricted_matcher_example.py

A normal enforcer exposes every registered function and the full Python
expression grammar to whatever matcher it evaluates.  With tenants submitting
parts of a matcher that is unsafe, so this example turns the restriction layer
on and shows that allowed expressions still work while unknown names, forbidden
functions/attributes and exhausted budgets are denied.
"""

import os

import casbin
from casbin import util


def examples_path(name):
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), name)


def main():
    enforcer = casbin.Enforcer(
        examples_path("restricted_matcher_minimal_policy.conf"),
        examples_path("basic_policy.csv"),
    )

    # Explicit opt-in. The minimal policy derives allowed names from the model
    # tokens and only exposes keyMatch / regexMatch / globMatch.
    enforcer.enable_restricted_matcher()

    print("allowed request:", enforcer.enforce("alice", "data1", "read"))  # True
    print("normal deny:     ", enforcer.enforce("alice", "data2", "read"))  # False

    # A function registered on the enforcer is not reachable from a tenant
    # matcher unless the restriction policy explicitly allows it.
    def dangerous(_):
        return True

    enforcer.add_function("dangerous", dangerous)
    tampered = casbin.Model()
    tampered.load_model(examples_path("restricted_matcher_minimal_policy.conf"))
    tampered.model["m"]["m"].value = "dangerous(r_sub)"
    enforcer.set_model(tampered)
    enforcer.enable_restricted_matcher()

    print("forbidden call:  ", enforcer.enforce("alice", "data1", "read"))  # False
    violation = enforcer.get_last_restriction_violation()
    print("  reason:        ", type(violation).__name__, violation)

    # Tight budgets still fail closed instead of turning into allows.
    clean = casbin.Model()
    clean.load_model(examples_path("restricted_matcher_minimal_policy.conf"))
    enforcer.set_model(clean)
    enforcer.enable_restricted_matcher()
    enforcer.set_restriction_policy(util.RestrictionPolicy.from_enforcer(enforcer, node_budget=1))
    print("budget exhausted:", enforcer.enforce("alice", "data1", "read"))  # False
    violation = enforcer.get_last_restriction_violation()
    print("  reason:        ", type(violation).__name__, violation)


if __name__ == "__main__":
    main()
