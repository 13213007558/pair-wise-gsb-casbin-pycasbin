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

import re

_INTERESTING_TOKENS_RE = re.compile(r"[,\[\]\(\)]")


class FilteredPolicyError(RuntimeError):
    """raised when a persistence operation is not safe on a filtered (partial) policy view.

    This keeps mutations that could overwrite or touch rules outside the loaded
    filter scope from being applied. The check happens before any in-memory
    mutation, so callers never get a "false success" where memory was changed but
    persistence was refused.
    """

    pass


def get_section_filter(filter, sec):
    """returns the field-level filter that applies to section ``sec``.

    It follows the existing filtered-adapter convention (``Filter.P`` for policy
    rules and ``Filter.G`` for grouping rules) instead of introducing any new
    query language. Filters given directly as lists are used for every section.
    """
    if filter is None:
        return []

    if isinstance(filter, dict):
        return list(filter.get(sec, []))

    section_filter = getattr(filter, "P", None)
    if section_filter is None and isinstance(filter, (list, tuple)):
        section_filter = filter
    if sec == "g":
        section_filter = getattr(filter, "G", section_filter)

    return list(section_filter or [])


def rule_matches_filter(rule, section_filter):
    """checks whether ``rule`` satisfies one adapter field filter.

    Empty strings and missing entries are wildcards, mirroring the semantics used
    by FilteredFileAdapter.filter_words.
    """
    for index, expected in enumerate(section_filter):
        if expected is None or str(expected).strip() == "":
            continue
        if index >= len(rule) or str(rule[index]).strip() != str(expected).strip():
            return False
    return True


def rule_in_load_scope(rule, sec, load_filters):
    """checks whether ``rule`` stays inside every loaded filter scope.

    ``load_filters`` is the list of filters the current partial view was loaded
    with. When no filtered load happened (``None``), all rules are considered in
    scope. The check fails closed when section-specific filters exist but the
    rule cannot be proven to match them.
    """
    if not load_filters:
        return True

    for load_filter in load_filters:
        section_filter = get_section_filter(load_filter, sec)
        if section_filter and not rule_matches_filter(rule, section_filter):
            return False
    return True


def _extract_tokens(line):
    """Return the list of 'tokens' from the line, or None if this line has none"""

    if line == "":
        return None

    if line[:1] == "#":
        return None

    stack = []
    tokens = []

    # The tokens are separated by commas, but we support nesting so a naive `line.split(",")` is
    # wrong. E.g. `abc(def, ghi), jkl` is two tokens: `abc(def, ghi)` and `jkl`. We do this by
    # iterating over the locations of any tokens of interest, and either:
    #
    # - [](): adjust the nesting depth
    # - ,: slice the line to save the token, if the , is at the top-level, outside all []()
    #
    # `start_idx` represents the start of the current token, that we haven't seen a `,` for yet.
    start_idx = 0
    for match in _INTERESTING_TOKENS_RE.finditer(line):
        c = match.group()
        if c == "[" or c == "(":
            stack.append(c)
        elif c == "]" or c == ")":
            stack.pop()
        elif not stack:
            # must be a comma outside of any nesting: we've found the end of a top level token so
            # save that and start a new one
            tokens.append(line[start_idx : match.start()].strip())
            start_idx = match.end()

    # trailing token after the last ,
    tokens.append(line[start_idx:].strip())

    return tokens


def load_policy_line(line, model):
    """loads a text line as a policy rule to model."""

    tokens = _extract_tokens(line)
    if tokens is None:
        return

    key = tokens[0]
    sec = key[0]

    if sec not in model.model.keys():
        return

    if key not in model.model[sec].keys():
        return

    model.model[sec][key].policy.append(tokens[1:])


class Adapter:
    """the interface for Casbin adapters."""

    def load_policy(self, model):
        """loads all policy rules from the storage."""
        pass

    def save_policy(self, model):
        """saves all policy rules to the storage."""
        pass

    def add_policy(self, sec, ptype, rule):
        """adds a policy rule to the storage."""
        pass

    def remove_policy(self, sec, ptype, rule):
        """removes a policy rule from the storage."""
        pass

    def remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        """removes policy rules that match the filter from the storage.
        This is part of the Auto-Save feature.
        """
        pass
