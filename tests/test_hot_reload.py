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

import threading
from unittest import TestCase, IsolatedAsyncioTestCase

import casbin
from casbin.persist.adapters import file_adapter
from casbin.persist.adapters.asyncio import AsyncAdapter


BASIC_MODEL = "basic_model.conf"
RBAC_MODEL = "rbac_model.conf"


def example(name):
    from tests.test_enforcer import get_examples

    return get_examples(name)


def feed(model, lines):
    for line in lines:
        file_adapter.load_policy_line(line, model)


class PausableAdapter(casbin.persist.Adapter):
    """an adapter whose load can be frozen in the middle, so a test can drive requests
    while a reload is only half done.

    The first load -- the one the enforcer constructor runs -- always completes, otherwise
    construction could not return. Later loads set entered and then block on release.
    """

    def __init__(self, lines):
        self.lines = list(lines)
        self.entered = threading.Event()
        self.release = threading.Event()
        self.calls = 0
        self._constructed = False

    def mark_constructed(self):
        self._constructed = True

    def load_policy(self, model):
        self.calls += 1
        if not self._constructed:
            # the enforcer constructor's initial load must complete for construction to
            # return; every later (re)load is the one tests may pause.
            feed(model, self.lines)
            return
        self.entered.set()
        self.release.wait(timeout=10)
        feed(model, self.lines)


class FailingAdapter(casbin.persist.Adapter):
    def __init__(self, error):
        self.error = error
        self.calls = 0

    def load_policy(self, model):
        self.calls += 1
        raise self.error


class MalformedAdapter(casbin.persist.Adapter):
    """policies whose grouping rule cannot build a role graph, so role-link construction
    fails after the adapter read succeeds."""

    def load_policy(self, model):
        # g requires at least two fields; a single-field grouping rule cannot be linked
        file_adapter.load_policy_line("g, alice", model)


class RecordingWatcher:
    def __init__(self):
        self.updates = 0
        self.callback = None

    def set_update_callback(self, func):
        self.callback = func

    def update(self):
        self.updates += 1

    def close(self):
        pass


def basic_enforcer(adapter, model=BASIC_MODEL):
    enforcer = casbin.Enforcer(example(model), adapter)
    adapter.mark_constructed()
    return enforcer


def ready_adapter(lines):
    """a pausable adapter whose next reload does not block."""
    adapter = PausableAdapter(lines)
    adapter.mark_constructed()
    adapter.release.set()
    return adapter


class TestAtomicHotReload(TestCase):
    def test_successful_reload_publishes_a_new_version(self):
        e = basic_enforcer(PausableAdapter(["p, alice, data1, read"]))
        self.assertEqual(e.state.version, 0)
        self.assertTrue(e.enforce("alice", "data1", "read"))

        e.set_adapter(ready_adapter(["p, bob, data2, write"]))
        result = e.hot_load_policy(notify_watcher=False)

        self.assertTrue(result.ok)
        self.assertEqual(result.version, 1)
        self.assertEqual(e.state.version, 1)
        self.assertFalse(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))

    def test_request_never_sees_a_half_loaded_policy(self):
        old = PausableAdapter(["p, alice, data1, read"])
        e = casbin.SyncedEnforcer(example(BASIC_MODEL), old)
        old.mark_constructed()

        midpoint = PausableAdapter(["p, bob, data1, read"])
        midpoint.mark_constructed()
        e.set_adapter(midpoint)
        reload_done = threading.Event()

        def reload():
            e.hot_load_policy(notify_watcher=False)
            reload_done.set()

        loader = threading.Thread(target=reload, daemon=True)
        loader.start()
        self.assertTrue(midpoint.entered.wait(timeout=5))

        # capture the state while the adapter read is still in progress, then evaluate the
        # request against that captured snapshot rather than whatever gets published later.
        snapshot = e.state
        self.assertEqual(snapshot.version, 0)
        self.assertTrue(e.enforce_ex_on_state(snapshot, "alice", "data1", "read")[0])
        self.assertFalse(e.enforce_ex_on_state(snapshot, "bob", "data1", "read")[0])

        midpoint.release.set()
        self.assertTrue(reload_done.wait(timeout=5))
        loader.join(timeout=5)

        # after publication the same requests are decided against version 1
        self.assertEqual(e.state.version, 1)
        self.assertFalse(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("bob", "data1", "read"))

    def test_adapter_failure_keeps_the_old_policy_and_reports_reason(self):
        e = basic_enforcer(PausableAdapter(["p, alice, data1, read"]))

        boom = FailingAdapter(RuntimeError("storage is down"))
        e.set_adapter(boom)
        result = e.hot_load_policy(notify_watcher=False)

        self.assertFalse(result.ok)
        self.assertEqual(result.version, e.state.version)
        self.assertIsInstance(result.error, RuntimeError)
        self.assertEqual(str(result.error), "storage is down")
        # the previous state keeps serving unchanged
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertEqual(e.get_policy(), [["alice", "data1", "read"]])

    def test_malformed_rule_fails_before_publication(self):
        e = basic_enforcer(PausableAdapter(["p, alice, data1, read"]))

        class BadRule(casbin.persist.Adapter):
            def load_policy(self, model):
                feed(model, ["p, alice, data1"])  # one field short

        e.set_adapter(BadRule())
        result = e.hot_load_policy(notify_watcher=False)

        self.assertFalse(result.ok)
        self.assertIn("invalid policy size", str(result.error))
        self.assertEqual(e.state.version, 0)
        self.assertTrue(e.enforce("alice", "data1", "read"))

    def test_role_graph_failure_keeps_old_graph_and_policy(self):
        e = basic_enforcer(
            PausableAdapter(["p, admin, data1, read", "g, alice, admin"]),
            model=RBAC_MODEL,
        )
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertEqual(e.get_roles_for_user("alice"), ["admin"])

        e.set_adapter(MalformedAdapter())
        result = e.hot_load_policy(notify_watcher=False)

        self.assertFalse(result.ok)
        self.assertIsNotNone(result.error)
        # no mixing of a new policy with the old role graph: the whole old state survives
        self.assertEqual(e.state.version, 0)
        self.assertEqual(e.get_roles_for_user("alice"), ["admin"])
        self.assertTrue(e.enforce("alice", "data1", "read"))

    def test_two_consecutive_updates_each_publish_distinct_versions(self):
        e = basic_enforcer(PausableAdapter(["p, alice, data1, read"]))

        second = ready_adapter(["p, alice, data1, write"])
        e.set_adapter(second)
        r1 = e.hot_load_policy(notify_watcher=False)
        self.assertTrue(r1.ok)
        self.assertEqual(r1.version, 1)
        self.assertTrue(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data1", "read"))

        third = ready_adapter(["p, alice, data1, read", "p, bob, data1, read"])
        e.set_adapter(third)
        r2 = e.hot_load_policy(notify_watcher=False)
        self.assertTrue(r2.ok)
        self.assertEqual(r2.version, 2)
        self.assertEqual(e.state.version, 2)
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))

    def test_same_request_returns_versions_before_and_after_switch(self):
        request = ("alice", "data1", "read")
        e = basic_enforcer(PausableAdapter(["p, alice, data1, read"]))
        self.assertEqual((e.state.version, e.enforce(*request)), (0, True))

        new = PausableAdapter(["p, bob, data1, read"])  # alice no longer allowed
        e.set_adapter(new)

        # snapshot version 0 and start a slow decision against it
        snapshot = e.state
        decided = {}
        holder = threading.Event()
        gate = threading.Event()

        def slow_decision():
            holder.set()
            gate.wait(timeout=5)
            result, _ = e.enforce_ex_on_state(snapshot, *request)
            decided["result"] = result
            decided["version"] = snapshot.version

        worker = threading.Thread(target=slow_decision, daemon=True)
        worker.start()
        self.assertTrue(holder.wait(timeout=5))
        self.assertEqual(snapshot.version, 0)

        new.release.set()
        reload_result = e.hot_load_policy(notify_watcher=False)
        self.assertTrue(reload_result.ok)
        # a fresh request already observes the new version and verdict
        self.assertEqual(e.state.version, 1)
        self.assertFalse(e.enforce(*request))

        gate.set()
        worker.join(timeout=5)

        # the request bound to the old snapshot still reports the old version's verdict
        self.assertEqual(decided["version"], 0)
        self.assertTrue(decided["result"])

    def test_watcher_is_notified_only_after_publication(self):
        e = basic_enforcer(PausableAdapter(["p, alice, data1, read"]))
        watcher = RecordingWatcher()
        e.set_watcher(watcher)

        e.set_adapter(FailingAdapter(RuntimeError("nope")))
        failed = e.hot_load_policy()
        self.assertFalse(failed.ok)
        self.assertEqual(watcher.updates, 0)

        e.set_adapter(ready_adapter(["p, alice, data1, read"]))
        succeeded = e.hot_load_policy()
        self.assertTrue(succeeded.ok)
        self.assertEqual(watcher.updates, 1)

    def test_rbac_reload_rebuilds_inheritance_graph_from_scratch(self):
        e = basic_enforcer(
            PausableAdapter(["p, admin, data1, read", "g, alice, admin", "g, admin, root"]),
            model=RBAC_MODEL,
        )
        self.assertEqual(e.get_implicit_roles_for_user("alice"), ["admin", "root"])

        new = ready_adapter(["p, admin, data1, read", "g, bob, admin"])
        e.set_adapter(new)
        result = e.hot_load_policy(notify_watcher=False)

        self.assertTrue(result.ok)
        self.assertEqual(e.get_implicit_roles_for_user("bob"), ["admin"])
        self.assertEqual(e.get_implicit_roles_for_user("alice"), [])
        self.assertFalse(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("bob", "data1", "read"))


class TestHotReloadDecisionCache(TestCase):
    def _enforcer(self, lines):
        return casbin.CachedEnforcer(example(BASIC_MODEL), PausableAdapter(lines))

    def test_swap_drops_old_decisions(self):
        e = self._enforcer(["p, alice, data1, read"])
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertEqual(len(e.get_cache()), 1)

        e.set_adapter(ready_adapter(["p, bob, data1, read"]))
        result = e.hot_load_policy(notify_watcher=False)

        self.assertTrue(result.ok)
        self.assertEqual(len(e.get_cache()), 0)
        self.assertFalse(e.enforce("alice", "data1", "read"))

    def test_slow_request_cannot_write_old_result_into_new_cache(self):
        e = self._enforcer(["p, alice, data1, read"])

        entered = threading.Event()
        release = threading.Event()
        armed = {"on": True}
        original = casbin.core_enforcer.CoreEnforcer.enforce_ex

        def barrier_enforce(self_inner, *rvals):
            if armed["on"] and rvals == ("bob", "data1", "read"):
                entered.set()
                release.wait(timeout=5)
            return original(self_inner, *rvals)

        casbin.core_enforcer.CoreEnforcer.enforce_ex = barrier_enforce
        try:
            worker = threading.Thread(target=e.enforce, args=("bob", "data1", "read"), daemon=True)
            worker.start()
            self.assertTrue(entered.wait(timeout=5))
            armed["on"] = False

            new = ready_adapter(
                ["p, alice, data1, read", "p, bob, data1, read"]
            )
            e.set_adapter(new)
            result = e.hot_load_policy(notify_watcher=False)
            self.assertTrue(result.ok)
        finally:
            release.set()
            worker.join(timeout=5)
            casbin.core_enforcer.CoreEnforcer.enforce_ex = original

        # the blocked request's pre-switch "deny" must not be cached; bob is now allowed
        self.assertTrue(e.enforce("bob", "data1", "read"))
        cached = e.get_cache().get(
            casbin.CachedEnforcer.get_cache_key("bob", "data1", "read"), object()
        )
        self.assertEqual(cached[0], True)


class AsyncPausableAdapter(AsyncAdapter):
    def __init__(self, lines):
        self.lines = list(lines)
        self.entered = threading.Event()
        self.release = threading.Event()
        self._constructed = False

    async def load_policy(self, model):
        if not self._constructed:
            feed(model, self.lines)
            self._constructed = True
            return
        self.entered.set()
        self.release.wait(timeout=10)
        feed(model, self.lines)

    async def save_policy(self, model):
        pass

    async def add_policy(self, *args):
        pass

    async def remove_policy(self, *args):
        pass

    async def remove_filtered_policy(self, *args):
        pass


class AsyncFailingAdapter(AsyncAdapter):
    def __init__(self, error):
        self.error = error

    async def load_policy(self, model):
        raise self.error

    async def save_policy(self, model):
        pass

    async def add_policy(self, *args):
        pass

    async def remove_policy(self, *args):
        pass

    async def remove_filtered_policy(self, *args):
        pass


class TestAsyncAtomicHotReload(IsolatedAsyncioTestCase):
    async def test_async_reload_has_the_same_semantics(self):
        first = AsyncPausableAdapter(["p, alice, data1, read"])
        e = casbin.AsyncEnforcer(example(BASIC_MODEL), first)
        await e.load_policy()
        self.assertEqual(e.state.version, 0)
        self.assertTrue(e.enforce("alice", "data1", "read"))

        second = AsyncPausableAdapter(["p, bob, data1, read"])
        second.release.set()
        e.adapter = second
        result = await e.hot_load_policy(notify_watcher=False)
        self.assertTrue(result.ok)
        self.assertEqual(result.version, 1)
        self.assertFalse(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("bob", "data1", "read"))

        e.adapter = AsyncFailingAdapter(RuntimeError("async boom"))
        failed = await e.hot_load_policy(notify_watcher=False)
        self.assertFalse(failed.ok)
        self.assertEqual(str(failed.error), "async boom")
        self.assertEqual(e.state.version, 1)
        self.assertTrue(e.enforce("bob", "data1", "read"))
