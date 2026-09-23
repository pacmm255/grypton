from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import signal
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from grypton import config
from grypton.tools import Goja


@contextmanager
def isolated_goja():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        runtime = root / "runtime"
        logs = runtime / "logs"
        with patch.multiple(config, RUNTIME_DIR=runtime, LOG_DIR=logs):
            runtime.mkdir(parents=True, mode=0o700)
            yield


def managed_state(pid: int, start_time: str = "100") -> dict:
    return {
        "version": 1,
        "pid": pid,
        "start_time": start_time,
        "argv": Goja._expected_argv(),
    }


class GojaLifecycleTests(unittest.TestCase):
    def test_proc_identity_contains_cmdline_and_start_time(self):
        identity = Goja._process_identity(os.getpid())
        self.assertIsNotNone(identity)
        self.assertEqual(identity["pid"], os.getpid())
        self.assertTrue(identity["start_time"].isdigit())
        self.assertTrue(identity["argv"])

    def test_listener_inode_is_tied_to_its_process_and_endpoint(self):
        with isolated_goja(), socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(5)
            endpoint = f"127.0.0.1:{listener.getsockname()[1]}"
            with patch.object(config, "GOJA_SOCKS", endpoint):
                self.assertTrue(Goja._owns_listener(os.getpid()))
                self.assertFalse(Goja._owns_listener(1))

    def test_foreign_listener_is_not_reported_or_adopted_as_managed(self):
        with isolated_goja(), socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(5)
            endpoint = f"127.0.0.1:{listener.getsockname()[1]}"
            with patch.object(config, "GOJA_SOCKS", endpoint), \
                    patch("grypton.tools.subprocess.Popen") as popen:
                status = Goja.status()
                started = Goja.start(wait_s=1)

            self.assertFalse(status["data"]["running"])
            self.assertFalse(status["data"]["managed"])
            self.assertTrue(status["data"]["listener_open"])
            self.assertIsNone(status["data"]["managed_pid"])
            self.assertIn("unmanaged listener", status["summary"])
            self.assertFalse(started["ok"])
            self.assertIn("unmanaged listener", started["summary"])
            popen.assert_not_called()

    def test_listener_must_belong_to_verified_goja_process(self):
        with isolated_goja():
            state = managed_state(4242)
            with Goja._lock():
                Goja._write_state_unlocked(state)
            identity = {
                "pid": 4242,
                "start_time": "100",
                "argv": Goja._expected_argv(),
            }
            with patch.object(Goja, "_process_identity", return_value=identity), \
                    patch.object(Goja, "_owns_listener", return_value=False), \
                    patch("grypton.tools._port_open", return_value=True):
                status = Goja.status()

            self.assertTrue(status["data"]["managed"])
            self.assertFalse(status["data"]["listener_owned"])
            self.assertFalse(status["data"]["running"])

    def test_stale_pid_metadata_is_cleared_without_opening_a_pidfd(self):
        with isolated_goja():
            state = managed_state(os.getpid(), start_time="stale-start-time")
            with Goja._lock():
                Goja._write_state_unlocked(state)
            current = {
                "pid": os.getpid(),
                "start_time": "different-start-time",
                "argv": Goja._expected_argv(),
            }
            with patch.object(Goja, "_process_identity", return_value=current), \
                    patch("grypton.tools._port_open", return_value=False), \
                    patch.object(os, "pidfd_open", create=True) as pidfd_open:
                result = Goja.stop()

            self.assertFalse(result["ok"])
            self.assertFalse(Goja._state_path().exists())
            pidfd_open.assert_not_called()

    def test_identity_is_rechecked_after_pidfd_open_before_any_signal(self):
        with isolated_goja():
            state = managed_state(4242)
            with Goja._lock():
                Goja._write_state_unlocked(state)
            matching = {
                "pid": 4242,
                "start_time": "100",
                "argv": Goja._expected_argv(),
            }
            reused = {
                "pid": 4242,
                "start_time": "101",
                "argv": ["/usr/bin/unrelated"],
            }
            calls = 0

            def process_identity(_pid):
                nonlocal calls
                calls += 1
                return matching if calls == 1 else reused

            descriptor = os.open("/dev/null", os.O_RDONLY)
            with patch.object(Goja, "_process_identity", side_effect=process_identity), \
                    patch.object(Goja, "_owns_listener", return_value=False), \
                    patch("grypton.tools._port_open", return_value=False), \
                    patch.object(os, "pidfd_open", return_value=descriptor, create=True), \
                    patch.object(signal, "pidfd_send_signal", create=True) as send_signal:
                result = Goja.stop()

            self.assertFalse(result["ok"])
            self.assertIn("no longer belongs", result["summary"])
            self.assertFalse(Goja._state_path().exists())
            send_signal.assert_not_called()

    def test_goja_lock_serializes_competing_lifecycle_operations(self):
        with isolated_goja():
            first_entered = threading.Event()
            release_first = threading.Event()
            second_entered = threading.Event()

            def hold_first():
                with Goja._lock():
                    first_entered.set()
                    release_first.wait(timeout=2)

            def enter_second():
                first_entered.wait(timeout=2)
                with Goja._lock():
                    second_entered.set()

            first = threading.Thread(target=hold_first)
            second = threading.Thread(target=enter_second)
            first.start()
            second.start()
            self.assertTrue(first_entered.wait(timeout=1))
            time.sleep(0.05)
            self.assertFalse(second_entered.is_set())
            release_first.set()
            first.join(timeout=2)
            second.join(timeout=2)
            self.assertFalse(first.is_alive())
            self.assertFalse(second.is_alive())
            self.assertTrue(second_entered.is_set())


if __name__ == "__main__":
    unittest.main()
