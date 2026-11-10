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

import os
from unittest import TestCase, IsolatedAsyncioTestCase

import casbin
from casbin.persist.adapter_filtered import FilteredAdapter
from casbin.persist.adapter import FilteredPolicyError
from casbin.persist.adapters.asyncio import AsyncAdapter


def get_examples(path):
    examples_path = os.path.split(os.path.realpath(__file__))[0] + "/../examples/"
    return os.path.abspath(examples_path + path)


class Filter:
    P = []
    G = []


class MemoryFilteredAdapter(FilteredAdapter):
    """in-memory adapter holding rules for several tenants.

    Rules are stored as ``(ptype, rule)`` pairs. The adapter supports complete
    loads/saves as well as the filtered load and every partial write needed by
    auto-save, so it can prove that writes stay inside the loaded filter scope.
    """

    def __init__(self, rules):
        self._rules = [(ptype, list(rule)) for ptype, rule in rules]
        self.filtered = False

    # --- load side ---------------------------------------------------------
    def load_policy(self, model):
        self.filtered = False
        for ptype, rule in self._rules:
            sec = "p" if ptype.startswith("p") else "g"
            model.model[sec][ptype].policy.append(list(rule))

    def load_filtered_policy(self, model, filter):
        if filter is None:
            return self.load_policy(model)

        self.filtered = True
        p_filter = list(getattr(filter, "P", []) or [])
        g_filter = list(getattr(filter, "G", []) or [])
        for ptype, rule in self._rules:
            if ptype.startswith("p"):
                section_filter = p_filter
            else:
                section_filter = g_filter
            if self._matches(rule, section_filter):
                sec = "p" if ptype.startswith("p") else "g"
                model.model[sec][ptype].policy.append(list(rule))

    def is_filtered(self):
        return self.filtered

    # --- full save is intentionally always supported -----------------------
    def save_policy(self, model):
        rules = []
        for sec in ("p", "g"):
            if sec not in model.model:
                continue
            for ptype, ast in model.model[sec].items():
                for rule in ast.policy:
                    rules.append((ptype, list(rule)))
        self._rules = rules

    # --- partial writes ----------------------------------------------------
    def add_policy(self, sec, ptype, rule):
        entry = (ptype, list(rule))
        if entry in self._rules:
            return False
        self._rules.append(entry)
        return True

    def add_policies(self, sec, ptype, rules):
        for rule in rules:
            if (ptype, list(rule)) in self._rules:
                return False
        for rule in rules:
            self._rules.append((ptype, list(rule)))
        return True

    def add_policies_ex(self, sec, ptype, rules):
        added = False
        for rule in rules:
            entry = (ptype, list(rule))
            if entry not in self._rules:
                self._rules.append(entry)
                added = True
        return added

    def remove_policy(self, sec, ptype, rule):
        entry = (ptype, list(rule))
        if entry not in self._rules:
            return False
        self._rules.remove(entry)
        return True

    def remove_policies(self, sec, ptype, rules):
        for rule in rules:
            if (ptype, list(rule)) not in self._rules:
                return False
        for rule in rules:
            self._rules.remove((ptype, list(rule)))
        return True

    def remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        remaining = []
        removed = False
        for stored_ptype, rule in self._rules:
            if stored_ptype != ptype or not self._fields_match(rule, field_index, field_values):
                remaining.append((stored_ptype, rule))
            else:
                removed = True
        self._rules = remaining
        return removed

    def update_policy(self, sec, ptype, old_rule, new_rule):
        entry = (ptype, list(old_rule))
        if entry not in self._rules:
            return False
        index = self._rules.index(entry)
        self._rules[index] = (ptype, list(new_rule))
        return True

    def update_policies(self, sec, ptype, old_rules, new_rules):
        for old_rule in old_rules:
            if (ptype, list(old_rule)) not in self._rules:
                return False
        for old_rule, new_rule in zip(old_rules, new_rules):
            index = self._rules.index((ptype, list(old_rule)))
            self._rules[index] = (ptype, list(new_rule))
        return True

    def update_filtered_policies(self, sec, ptype, new_rules, field_index, *field_values):
        old_rules = [
            list(rule)
            for stored_ptype, rule in self._rules
            if stored_ptype == ptype and self._fields_match(rule, field_index, field_values)
        ]
        self.remove_filtered_policy(sec, ptype, field_index, *field_values)
        for rule in new_rules:
            self._rules.append((ptype, list(rule)))
        return old_rules

    # --- helpers -----------------------------------------------------------
    @staticmethod
    def _matches(rule, section_filter):
        for index, expected in enumerate(section_filter):
            if expected is None or str(expected).strip() == "":
                continue
            if index >= len(rule) or rule[index] != expected:
                return False
        return True

    @staticmethod
    def _fields_match(rule, field_index, field_values):
        for offset, expected in enumerate(field_values):
            if expected is None or str(expected).strip() == "":
                continue
            index = field_index + offset
            if index >= len(rule) or rule[index] != expected:
                return False
        return True

    def snapshot(self):
        return sorted((ptype, tuple(rule)) for ptype, rule in self._rules)


class MemoryFilteredAdapterNoBatch(MemoryFilteredAdapter):
    """filtered adapter that only supports single-rule partial writes."""

    add_policies = None
    remove_policies = None


def domain1_filter():
    filter = Filter()
    filter.P = ["", "domain1"]
    filter.G = ["", "", "domain1"]
    return filter


def build_adapter():
    rules = [
        ("p", ["admin", "domain1", "data1", "read"]),
        ("p", ["admin", "domain1", "data1", "write"]),
        ("p", ["admin", "domain2", "data2", "read"]),
        ("p", ["admin", "domain2", "data2", "write"]),
        ("g", ["alice", "admin", "domain1"]),
        ("g", ["bob", "admin", "domain2"]),
    ]
    return MemoryFilteredAdapter(rules)


class TestFilteredPersistence(TestCase):
    def setUp(self):
        self.model_path = get_examples("rbac_with_domains_model.conf")
        self.initial_snapshot = build_adapter().snapshot()

    def _new_enforcer(self, adapter=None):
        adapter = adapter or build_adapter()
        return casbin.Enforcer(self.model_path, adapter), adapter

    def test_full_to_filtered_to_full_scope_is_tracked(self):
        e, adapter = self._new_enforcer()

        self.assertFalse(e.is_filtered())
        self.assertIsNone(e.get_load_filters())

        e.load_filtered_policy(domain1_filter())

        self.assertTrue(e.is_filtered())
        self.assertEqual(e.get_load_filters()[0].P, ["", "domain1"])
        self.assertTrue(e.has_policy(["admin", "domain1", "data1", "read"]))
        self.assertFalse(e.has_policy(["admin", "domain2", "data2", "read"]))
        # storage still holds both tenants
        self.assertEqual(adapter.snapshot(), self.initial_snapshot)

        e.load_policy()

        self.assertFalse(e.is_filtered())
        self.assertIsNone(e.get_load_filters())
        self.assertTrue(e.has_policy(["admin", "domain2", "data2", "read"]))

    def test_incremental_filtered_load_extends_tracked_scope(self):
        e, adapter = self._new_enforcer()
        e.load_filtered_policy(domain1_filter())

        filter2 = Filter()
        filter2.P = ["", "domain2"]
        filter2.G = ["", "", "domain2"]
        e.load_increment_filtered_policy(filter2)

        self.assertTrue(e.is_filtered())
        self.assertEqual(len(e.get_load_filters()), 2)
        self.assertTrue(e.has_policy(["admin", "domain1", "data1", "read"]))
        self.assertTrue(e.has_policy(["admin", "domain2", "data2", "read"]))
        self.assertEqual(adapter.snapshot(), self.initial_snapshot)

    def test_save_policy_rejected_while_filtered(self):
        e, adapter = self._new_enforcer()
        e.load_filtered_policy(domain1_filter())

        with self.assertRaises(RuntimeError):
            e.save_policy()

        # the partial view must never have been written over the full storage
        self.assertEqual(adapter.snapshot(), self.initial_snapshot)

    def test_in_scope_single_add_and_remove_persist(self):
        e, adapter = self._new_enforcer()
        e.load_filtered_policy(domain1_filter())

        new_rule = ["admin", "domain1", "data3", "read"]
        self.assertTrue(e.add_policy(new_rule))
        self.assertTrue(e.has_policy(new_rule))
        self.assertIn(("p", tuple(new_rule)), adapter.snapshot())

        self.assertTrue(e.remove_policy(new_rule))
        self.assertNotIn(("p", tuple(new_rule)), adapter.snapshot())
        # domain2 stays untouched
        self.assertIn(("p", ("admin", "domain2", "data2", "read")), adapter.snapshot())

    def test_out_of_scope_add_rejected_before_memory_changes(self):
        e, adapter = self._new_enforcer()
        e.load_filtered_policy(domain1_filter())
        memory_before = e.get_policy()

        foreign_rule = ["admin", "domain2", "data3", "read"]
        with self.assertRaises(FilteredPolicyError):
            e.add_policy(foreign_rule)

        self.assertFalse(e.has_policy(foreign_rule))
        self.assertEqual(e.get_policy(), memory_before)
        self.assertNotIn(("p", tuple(foreign_rule)), adapter.snapshot())
        self.assertEqual(adapter.snapshot(), self.initial_snapshot)

    def test_out_of_scope_grouping_rule_rejected(self):
        e, adapter = self._new_enforcer()
        e.load_filtered_policy(domain1_filter())
        memory_before = e.get_grouping_policy()

        foreign_group = ["carol", "admin", "domain2"]
        with self.assertRaises(FilteredPolicyError):
            e.add_grouping_policy(foreign_group)

        self.assertEqual(e.get_grouping_policy(), memory_before)
        self.assertNotIn(("g", tuple(foreign_group)), adapter.snapshot())
        self.assertEqual(adapter.snapshot(), self.initial_snapshot)

    def test_batch_with_one_out_of_scope_rule_rejected_atomically(self):
        e, adapter = self._new_enforcer()
        e.load_filtered_policy(domain1_filter())
        memory_before = e.get_policy()

        rules = [
            ["admin", "domain1", "data4", "read"],
            ["admin", "domain2", "data4", "read"],
        ]
        with self.assertRaises(FilteredPolicyError):
            e.add_policies(rules)

        self.assertEqual(e.get_policy(), memory_before)
        for rule in rules:
            self.assertNotIn(("p", tuple(rule)), adapter.snapshot())
        self.assertEqual(adapter.snapshot(), self.initial_snapshot)

        with self.assertRaises(FilteredPolicyError):
            e.remove_policies(
                [
                    ["admin", "domain1", "data1", "read"],
                    ["admin", "domain2", "data2", "read"],
                ]
            )
        self.assertEqual(adapter.snapshot(), self.initial_snapshot)

    def test_unsupported_partial_write_rejected_without_memory_change(self):
        rules = [(ptype, list(rule)) for ptype, rule in self.initial_snapshot]
        adapter = MemoryFilteredAdapterNoBatch(rules)
        e = casbin.Enforcer(self.model_path, adapter)
        e.load_filtered_policy(domain1_filter())
        memory_before = e.get_policy()

        with self.assertRaises(FilteredPolicyError):
            e.add_policies([["admin", "domain1", "data5", "read"]])

        self.assertEqual(e.get_policy(), memory_before)

    def test_in_scope_update_persists_out_of_scope_update_rejected(self):
        e, adapter = self._new_enforcer()
        e.load_filtered_policy(domain1_filter())

        old_rule = ["admin", "domain1", "data1", "read"]
        in_scope_rule = ["admin", "domain1", "data1", "deny"]
        self.assertTrue(e.update_policy(old_rule, in_scope_rule))
        self.assertIn(("p", tuple(in_scope_rule)), adapter.snapshot())
        self.assertNotIn(("p", tuple(old_rule)), adapter.snapshot())

        with self.assertRaises(FilteredPolicyError):
            e.update_policy(in_scope_rule, ["admin", "domain2", "data9", "read"])
        self.assertIn(("p", tuple(in_scope_rule)), adapter.snapshot())

    def test_filtered_remove_and_update_are_scope_checked(self):
        e, adapter = self._new_enforcer()
        e.load_filtered_policy(domain1_filter())
        memory_before = e.get_policy()

        with self.assertRaises(FilteredPolicyError):
            e.remove_filtered_policy(1, "domain2")
        self.assertEqual(e.get_policy(), memory_before)

        with self.assertRaises(FilteredPolicyError):
            e.remove_filtered_grouping_policy(2, "domain2")
        self.assertEqual(e.get_grouping_policy(), [["alice", "admin", "domain1"]])

        with self.assertRaises(FilteredPolicyError):
            e.update_filtered_policies([["admin", "domainX", "d", "read"]], 1, "domain1")
        self.assertEqual(e.get_policy(), memory_before)

        # in-scope filtered remove persists and cannot touch domain2
        self.assertTrue(e.remove_filtered_policy(1, "domain1"))
        self.assertEqual(e.get_policy(), [])
        self.assertIn(("p", ("admin", "domain2", "data2", "read")), adapter.snapshot())

        self.assertTrue(e.remove_filtered_grouping_policy(2, "domain1"))
        self.assertIn(("g", ("bob", "admin", "domain2")), adapter.snapshot())

        # in-scope filtered update persists
        e2, adapter2 = self._new_enforcer()
        e2.load_filtered_policy(domain1_filter())
        self.assertTrue(e2.update_filtered_policies([["admin", "domain1", "d", "read"]], 1, "domain1"))
        self.assertIn(("p", ("admin", "domain1", "d", "read")), adapter2.snapshot())

    def test_auto_save_off_allows_memory_only_changes_but_save_still_blocked(self):
        e, adapter = self._new_enforcer()
        e.load_filtered_policy(domain1_filter())
        e.enable_auto_save(False)

        # an out-of-scope rule may exist purely in memory without auto-save
        foreign_rule = ["admin", "domain2", "data7", "read"]
        self.assertTrue(e.add_policy(foreign_rule))
        self.assertTrue(e.has_policy(foreign_rule))
        # nothing was persisted
        self.assertEqual(adapter.snapshot(), self.initial_snapshot)

        with self.assertRaises(RuntimeError):
            e.save_policy()

        e.enable_auto_save(True)
        with self.assertRaises(FilteredPolicyError):
            e.add_policy(["admin", "domain2", "data8", "read"])
        self.assertEqual(adapter.snapshot(), self.initial_snapshot)

    def test_switching_back_to_full_load_restores_other_tenant(self):
        e, adapter = self._new_enforcer()
        e.load_filtered_policy(domain1_filter())

        self.assertTrue(e.add_policy(["admin", "domain1", "data6", "read"]))

        e.load_policy()

        self.assertFalse(e.is_filtered())
        self.assertIsNone(e.get_load_filters())
        # after a full reload, ordinary in-memory edits persist again
        self.assertTrue(e.add_policy(["admin", "domain2", "data9", "read"]))
        self.assertIn(("p", ("admin", "domain2", "data9", "read")), adapter.snapshot())

    def test_final_readback_keeps_other_tenant_intact(self):
        e, adapter = self._new_enforcer()
        e.load_filtered_policy(domain1_filter())

        # legal in-scope mutation
        self.assertTrue(e.add_policy(["admin", "domain1", "data3", "read"]))

        # rejected mutations of every shape
        with self.assertRaises(FilteredPolicyError):
            e.add_policy(["admin", "domain2", "data3", "read"])
        with self.assertRaises(FilteredPolicyError):
            e.add_policies(
                [
                    ["admin", "domain1", "data4", "read"],
                    ["admin", "domain2", "data4", "read"],
                ]
            )
        with self.assertRaises(FilteredPolicyError):
            e.add_grouping_policy(["carol", "admin", "domain2"])
        with self.assertRaises(FilteredPolicyError):
            e.update_policy(
                ["admin", "domain1", "data1", "read"],
                ["admin", "domain2", "data1", "read"],
            )
        with self.assertRaises(FilteredPolicyError):
            e.remove_policy(["admin", "domain2", "data2", "read"])
        with self.assertRaises(RuntimeError):
            e.save_policy()

        # full reload and readback
        e.load_policy()
        expected = set(self.initial_snapshot)
        expected.add(("p", ("admin", "domain1", "data3", "read")))
        self.assertEqual(adapter.snapshot(), sorted(expected))

        self.assertTrue(e.has_policy(["admin", "domain2", "data2", "read"]))
        self.assertTrue(e.has_policy(["admin", "domain2", "data2", "write"]))
        self.assertTrue(e.has_grouping_policy(["bob", "admin", "domain2"]))


class AsyncMemoryFilteredAdapter(MemoryFilteredAdapter, AsyncAdapter):
    """async wrapper around the in-memory filtered adapter."""

    async def load_policy(self, model):
        return super().load_policy(model)

    async def load_filtered_policy(self, model, filter):
        return super().load_filtered_policy(model, filter)

    async def save_policy(self, model):
        return super().save_policy(model)

    async def add_policy(self, sec, ptype, rule):
        return super().add_policy(sec, ptype, rule)

    async def add_policies(self, sec, ptype, rules):
        return super().add_policies(sec, ptype, rules)

    async def remove_policy(self, sec, ptype, rule):
        return super().remove_policy(sec, ptype, rule)

    async def remove_policies(self, sec, ptype, rules):
        return super().remove_policies(sec, ptype, rules)

    async def remove_filtered_policy(self, sec, ptype, field_index, *field_values):
        return super().remove_filtered_policy(sec, ptype, field_index, *field_values)

    async def update_policy(self, sec, ptype, old_rule, new_rule):
        return super().update_policy(sec, ptype, old_rule, new_rule)

    async def update_policies(self, sec, ptype, old_rules, new_rules):
        return super().update_policies(sec, ptype, old_rules, new_rules)

    async def update_filtered_policies(self, sec, ptype, new_rules, field_index, *field_values):
        return super().update_filtered_policies(sec, ptype, new_rules, field_index, *field_values)


class TestAsyncFilteredPersistence(IsolatedAsyncioTestCase):
    async def test_async_guard_rejects_out_of_scope_write_without_memory_change(self):
        model_path = get_examples("rbac_with_domains_model.conf")
        rules = [
            ("p", ["admin", "domain1", "data1", "read"]),
            ("p", ["admin", "domain2", "data2", "read"]),
            ("g", ["alice", "admin", "domain1"]),
            ("g", ["bob", "admin", "domain2"]),
        ]
        adapter = AsyncMemoryFilteredAdapter(rules)
        e = casbin.AsyncEnforcer(model_path, adapter)
        await e.load_filtered_policy(domain1_filter())

        self.assertTrue(e.is_filtered())
        memory_before = e.get_policy()

        with self.assertRaises(FilteredPolicyError):
            await e.add_policy(["admin", "domain2", "data3", "read"])

        self.assertEqual(e.get_policy(), memory_before)
        self.assertEqual(
            adapter.snapshot(),
            sorted(
                [
                    ("p", ("admin", "domain1", "data1", "read")),
                    ("p", ("admin", "domain2", "data2", "read")),
                    ("g", ("alice", "admin", "domain1")),
                    ("g", ("bob", "admin", "domain2")),
                ]
            ),
        )

        # an in-scope write still persists through the async path
        self.assertTrue(await e.add_policy(["admin", "domain1", "data3", "read"]))
        self.assertIn(("p", ("admin", "domain1", "data3", "read")), adapter.snapshot())
