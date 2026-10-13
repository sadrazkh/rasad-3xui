"""Exercise the real Linux controlling terminal used by curl | sudo bash."""
import errno
import json
import os
from pathlib import Path
import select
import stat
import subprocess
import sys
import tempfile
import time
import unittest

if sys.platform.startswith("linux"):
    import fcntl
    import pty
    import termios

BACKEND = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND))
from server import password_ok


class TerminalSetup:
    """Child has a controlling PTY, while fd 0 remains a pipe as in the installer."""

    def __init__(self, target):
        self.master, slave = pty.openpty()
        self.transcript = bytearray()
        self.cursor = 0

        def controlling_terminal():
            os.setsid()
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)

        try:
            self.process = subprocess.Popen(
                [sys.executable, "-u", str(BACKEND / "configure.py"), str(target)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                pass_fds=(slave,), preexec_fn=controlling_terminal,
            )
        except BaseException:
            os.close(self.master)
            raise
        finally:
            os.close(slave)
        # If configure accidentally reads its piped stdin, these are invalid replies.
        self.process.stdin.write(b"installer script data must not become credentials\n")
        self.process.stdin.flush()

    def read_chunk(self, timeout):
        if not select.select([self.master], [], [], timeout)[0]:
            return False
        try:
            chunk = os.read(self.master, 4096)
        except OSError as error:
            if error.errno != errno.EIO:
                raise
            return False
        self.transcript.extend(chunk)
        return bool(chunk)

    def reply(self, prompt, value):
        marker = prompt.encode()
        deadline = time.monotonic() + 15
        while True:
            found = self.transcript.find(marker, self.cursor)
            if found >= 0:
                self.cursor = found + len(marker)
                os.write(self.master, value.encode() + b"\n")
                return
            if self.process.poll() is not None:
                stdout, stderr = self.process.communicate(timeout=2)
                raise AssertionError(
                    f"Setup exited before prompt {prompt!r}: {stderr.decode(errors='replace')}"
                    f"\n{stdout.decode(errors='replace')}"
                )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError(f"Timed out waiting for setup prompt {prompt!r}")
            self.read_chunk(min(remaining, 0.25))

    def finish(self):
        stdout, stderr = self.process.communicate(timeout=15)
        while self.read_chunk(0.1):
            pass
        return self.process.returncode, stdout, stderr, bytes(self.transcript)

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.communicate(timeout=2)
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            if stream is not None:
                stream.close()
        os.close(self.master)


@unittest.skipUnless(sys.platform.startswith("linux"), "requires a real Linux controlling PTY")
class ConfigureTerminalTests(unittest.TestCase):
    def terminal(self, target):
        setup = TerminalSetup(target)
        self.addCleanup(setup.close)
        return setup

    def finish_config(self, setup, target, password, secrets):
        setup.reply("Browser origin (HTTPS domain or SSH tunnel origin)", "https://rasad.example/")
        setup.reply("Existing Xray access.log absolute path (Enter to skip)", "")
        setup.reply("Xray process timezone (access.log timestamps)", "UTC")
        code, stdout, stderr, terminal = setup.finish()
        self.assertEqual(code, 0, stderr.decode(errors="replace"))
        self.assertIn(b"Configuration saved", stdout)
        self.assertNotIn(b"GetPassWarning", stderr)
        combined = stdout + stderr + terminal
        for secret in secrets:
            self.assertNotIn(secret.encode(), combined, "password/token was echoed")
        config = json.loads(target.read_text())
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        self.assertFalse(target.with_suffix(".tmp").exists())
        self.assertTrue(password_ok(password, config["admin_password_hash"]))
        self.assertNotIn(password, target.read_text())
        self.assertEqual(config["public_origin"], "https://rasad.example")
        self.assertEqual(config["listen"], "127.0.0.1")
        self.assertEqual(config["domain_policy"], "/run/rasad/policy.json")
        return config, terminal

    def test_token_setup_with_piped_stdin_and_hidden_passwords(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "config.json"
            setup = self.terminal(target)
            token = "fixture-api-token-4719"
            password = "fixture-admin-password-4719"
            setup.reply("3x-ui URL including web base path", "http://127.0.0.1:2053/private/")
            setup.reply("3x-ui API token (Enter for username/password)", token)
            setup.reply("Rasad admin username", "site-admin")
            setup.reply("New Rasad admin password (at least 12 characters)", password)
            setup.reply("Repeat admin password", password)
            config, terminal = self.finish_config(setup, target, password, [token, password])
            self.assertEqual(config["panel_token"], token)
            self.assertEqual(config["panel_url"], "http://127.0.0.1:2053/private/")
            self.assertEqual(config["panel_username"], "")
            self.assertEqual(config["panel_password"], "")
            self.assertEqual(config["admin_username"], "site-admin")
            self.assertNotIn(b"3x-ui username:", terminal)

    def test_password_setup_retries_mismatch_without_echo(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "config.json"
            setup = self.terminal(target)
            panel_password = "fixture-panel-secret-6248"
            rejected = "fixture-rejected-password-6248"
            mismatch = "fixture-mismatch-password-6248"
            accepted = "fixture-accepted-password-6248"
            setup.reply("3x-ui URL including web base path", "")
            setup.reply("3x-ui API token (Enter for username/password)", "")
            setup.reply("3x-ui username", "panel-admin")
            setup.reply("3x-ui password", panel_password)
            setup.reply("Rasad admin username", "")
            setup.reply("New Rasad admin password (at least 12 characters)", rejected)
            setup.reply("Repeat admin password", mismatch)
            setup.reply("New Rasad admin password (at least 12 characters)", accepted)
            setup.reply("Repeat admin password", accepted)
            config, terminal = self.finish_config(
                setup, target, accepted, [panel_password, rejected, mismatch, accepted]
            )
            self.assertIn(b"Passwords must match and contain at least 12 characters", terminal)
            self.assertEqual(config["panel_token"], "")
            self.assertEqual(config["panel_username"], "panel-admin")
            self.assertEqual(config["panel_password"], panel_password)
            self.assertEqual(config["admin_username"], "admin")
            self.assertFalse(password_ok(rejected, config["admin_password_hash"]))

    def test_existing_configuration_preserved_without_a_terminal(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "config.json"
            original = b'{"keep": "existing configuration"}\n'
            target.write_bytes(original)
            target.chmod(0o600)
            result = subprocess.run(
                [sys.executable, str(BACKEND / "configure.py"), str(target)],
                stdin=subprocess.DEVNULL, capture_output=True, start_new_session=True,
                timeout=15,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            self.assertIn(b"Existing configuration preserved", result.stdout)
            self.assertEqual(target.read_bytes(), original)
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    def test_missing_terminal_exits_with_reconnect_guidance_without_saving(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "config.json"
            result = subprocess.run(
                [sys.executable, str(BACKEND / "configure.py"), str(target)],
                input=b"pipe content is not configuration\n", capture_output=True,
                start_new_session=True, timeout=15,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"ssh -t", result.stderr)
            self.assertNotIn(b"Traceback", result.stderr)
            self.assertFalse(target.exists())
            self.assertFalse(target.with_suffix(".tmp").exists())


if __name__ == "__main__":
    unittest.main()
