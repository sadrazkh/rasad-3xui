"""Offline fixtures for native discovery guards, toolchain integrity and rollback."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("rasad_sites", ROOT / "deploy/sites.py")
sites = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sites)


class SitesFixtures(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rasad-sites-test-", dir=ROOT.parent)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_supported_protocols_require_user_email(self):
        config = self.root / "xray.json"
        value = {"inbounds": [{"protocol": "vless", "settings": {"clients": [{"email": "one"}]}},
                              {"protocol": "trojan", "settings": {"clients": [{"email": "two"}]}},
                              {"protocol": "dokodemo-door", "tag": "api", "listen": "127.0.0.1"}]}
        config.write_text(json.dumps(value))
        self.assertEqual(sites.protocols(config), ["trojan", "vless"])
        value["inbounds"][0]["settings"]["clients"][0].pop("email")
        config.write_text(json.dumps(value))
        with self.assertRaisesRegex(sites.InstallError, "email"):
            sites.protocols(config)
        value["inbounds"][0] = {"protocol": "wireguard"}
        config.write_text(json.dumps(value))
        with self.assertRaisesRegex(sites.InstallError, "Unsupported"):
            sites.protocols(config)

    def test_unknown_or_multiple_running_config_arguments_are_rejected(self):
        with patch.object(sites, "trusted", side_effect=lambda path: Path(path)):
            self.assertEqual(sites.config_path(["xray", "run", "-c", "/srv/current.json"], Path("/srv")), Path("/srv/current.json"))
            with self.assertRaises(sites.InstallError):
                sites.config_path(["xray", "-confdir", "/srv"], Path("/srv"))
            with self.assertRaises(sites.InstallError):
                sites.config_path(["xray", "-c", "a.json", "-c", "b.json"], Path("/srv"))

    def test_loopback_api_accepts_current_tunnel_and_legacy_alias(self):
        config = self.root / "api-alias.json"
        user = {"protocol": "vless", "settings": {"clients": [{"email": "one"}]}}
        for protocol in ("tunnel", "dokodemo-door"):
            for address in ("127.0.0.1", "::1"):
                with self.subTest(protocol=protocol, address=address):
                    value = {"inbounds": [user, {"protocol": protocol, "tag": "api", "listen": address,
                        "port": 62789, "settings": {"rewriteAddress": "127.0.0.1"}}]}
                    config.write_text(json.dumps(value))
                    original = config.read_bytes()
                    self.assertEqual(sites.protocols(config), ["vless"])
                    self.assertEqual(config.read_bytes(), original)
                    self.assertEqual([row["protocol"] for row in sites.sniffing_summary(config)], ["vless"])

    def test_tunnel_alias_is_not_accepted_for_user_or_exposed_api_inbounds(self):
        config = self.root / "unsupported-tunnel.json"
        user = {"protocol": "vless", "settings": {"clients": [{"email": "one"}]}}
        for inbound in ({"protocol": "tunnel", "tag": "forwarder", "listen": "127.0.0.1"},
                        {"protocol": "tunnel", "tag": "api", "listen": "0.0.0.0"},
                        {"protocol": "tunnel", "tag": "api", "listen": "::"},
                        {"protocol": "tunnel", "tag": "api"}):
            with self.subTest(inbound=inbound):
                config.write_text(json.dumps({"inbounds": [user, inbound]}))
                with self.assertRaisesRegex(sites.InstallError, "Unsupported user inbound protocol"):
                    sites.protocols(config)

    def test_sniffing_preflight_reports_missing_domains_without_changing_config(self):
        config = self.root / "sniffing.json"
        value = {"inbounds": [{"tag": "ready", "protocol": "vless", "sniffing": {"enabled": True, "destOverride": ["http", "tls"], "routeOnly": True}},
                              {"tag": "missing", "protocol": "vmess", "sniffing": {"enabled": True, "destOverride": ["http"]}}]}
        config.write_text(json.dumps(value))
        before = config.read_bytes()
        rows = sites.sniffing_summary(config)
        self.assertTrue(rows[0]["domain_detection_ready"])
        self.assertTrue(rows[0]["routeOnly"])
        self.assertFalse(rows[1]["domain_detection_ready"])
        from contextlib import redirect_stdout
        import io
        message = io.StringIO()
        with redirect_stdout(message):
            sites.print_sniffing({"sniffing": rows})
        self.assertIn("unknown TCP", message.getvalue())
        self.assertEqual(config.read_bytes(), before)

    def test_unknown_or_mismatched_architecture_fails_closed(self):
        binary = self.root / "xray"
        header = bytearray(b"\x7fELF\x02\x01" + b"\0" * 14)
        header[18:20] = (62).to_bytes(2, "little")
        binary.write_bytes(header)
        self.assertEqual(sites.architecture(binary, "x86_64"), "amd64")
        with self.assertRaises(sites.InstallError):
            sites.architecture(binary, "aarch64")
        with self.assertRaises(sites.InstallError):
            sites.architecture(binary, "riscv64")

    def test_toolchain_release_is_same_required_branch_with_checksum(self):
        checksum = "a" * 64
        metadata = [{"stable": True, "version": "go1.24.6", "files": [{"os": "linux", "arch": "amd64", "kind": "archive", "filename": "go1.24.6.linux-amd64.tar.gz", "sha256": checksum}]},
                    {"stable": True, "version": "go1.25.2", "files": [{"os": "linux", "arch": "amd64", "kind": "archive", "filename": "go1.25.2.linux-amd64.tar.gz", "sha256": checksum}]}]
        release = sites.official_go_release(metadata, (1, 24, 0), "amd64")
        self.assertEqual(release["filename"], "go1.24.6.linux-amd64.tar.gz")
        with self.assertRaises(sites.InstallError):
            sites.official_go_release(metadata, (1, 24, 7), "amd64")
        metadata[0]["files"][0]["sha256"] = "invalid"
        with self.assertRaises(sites.InstallError):
            sites.official_go_release(metadata, (1, 24, 0), "amd64")

    def test_bad_go_archive_checksum_never_extracts(self):
        release = {"stable": True, "version": "go1.24.6", "files": [{"os": "linux", "arch": "amd64", "kind": "archive", "filename": "go1.24.6.linux-amd64.tar.gz", "sha256": "0" * 64}]}
        def download(url, destination):
            destination.write_text(json.dumps([release]) if "mode=json" in url else "tampered archive")
        with patch.object(sites.shutil, "which", return_value=None), patch.object(sites, "curl", side_effect=download), patch.object(sites, "run") as execute:
            with self.assertRaisesRegex(sites.InstallError, "checksum mismatch"):
                sites.choose_go((1, 24, 0), "amd64", self.root)
            execute.assert_not_called()

    def test_build_uses_exact_active_version_and_local_verified_toolchain(self):
        calls = []
        plan = {"version": "1.8.24", "arch": "amd64", "config": "/srv/config.json"}
        def execute(args, **kwargs):
            calls.append(([str(arg) for arg in args], kwargs))
            if args[0] == "git":
                source = Path(args[-1])
                source.mkdir()
                (source / "go.mod").write_text("go 1.21\ntoolchain go1.22.2\n")
            elif args[0] == "bash":
                (Path(args[-1]) / "xray-rasad").write_bytes(b"fixture compiled core")
        with patch.object(sites, "run", side_effect=execute), patch.object(sites, "choose_go", return_value="/official/go/bin/go") as choose, patch.object(sites, "version", return_value="1.8.24"), patch.object(sites, "architecture", return_value="amd64"):
            sites.build(plan, self.root)
        self.assertIn("v1.8.24", calls[2][0])
        self.assertNotIn("c77a4d0e4932a53f3eeafafdfef877b56fd660ad", calls[2][0])
        choose.assert_called_once_with((1, 22, 2), "amd64", self.root)
        build_call = next(call for call in calls if call[0][0] == "bash")
        self.assertEqual(build_call[0][-2], "v1.8.24")
        self.assertEqual(build_call[1]["env"]["GOTOOLCHAIN"], "local")
        self.assertEqual(build_call[1]["env"]["RASAD_GO"], "/official/go/bin/go")

    def test_non_native_or_non_root_systemd_layout_is_rejected(self):
        base = "ActiveState=active\nUser=root\nMainPID=42\nRootDirectory=\nRootImage=\nControlGroup=/system.slice/x-ui.service\n"
        for raw in (base.replace("User=root", "User=nobody"), base.replace("RootImage=", "RootImage=/disk.raw"), base.replace("ControlGroup=/system.slice/x-ui.service", "ControlGroup=/docker/xyz")):
            with self.subTest(raw=raw), patch.object(sites, "output", return_value=raw), patch.object(sites, "process_info") as process:
                with self.assertRaises(sites.InstallError):
                    sites.discover()
                process.assert_not_called()

    def transaction_fixture(self):
        base = self.root / "state"
        base.mkdir()
        binary = self.root / "xray"
        binary.write_bytes(b"original binary")
        binary.chmod(0o755)
        candidate = self.root / "candidate"
        candidate.write_bytes(b"patched binary")
        override = self.root / "systemd" / "x-ui.service.d" / "90-rasad-sites.conf"
        override.parent.mkdir(parents=True)
        override.write_text('[Service]\nEnvironment="EXISTING=1"\n')
        runtime = self.root / "run"
        runtime.mkdir()
        plan = {"binary": str(binary), "original_sha256": sites.digest(binary), "version": "1.8.24", "arch": "amd64", "config": str(self.root / "config.json"), "config_sha256": "a" * 64, "protocols": ["vless"]}
        paths = {"domain_policy": str(runtime / "policy.json"), "domain_metrics": str(runtime / "domains.json")}
        return base, binary, candidate, override, runtime, plan, paths

    def transaction_patches(self, fixture, health):
        base, _, _, override, runtime, plan, _ = fixture
        from contextlib import ExitStack
        stack = ExitStack()
        stack.enter_context(patch.multiple(sites, BASE=base, STATE=base / "state.json", OVERRIDE=override, RUNTIME=runtime))
        stack.enter_context(patch.object(sites, "trusted", side_effect=lambda path, directory=False: Path(path)))
        stack.enter_context(patch.object(sites, "discover", return_value=plan))
        stack.enter_context(patch.object(sites, "health", side_effect=health))
        stack.enter_context(patch.object(sites, "run"))
        stack.enter_context(patch.object(sites, "pwd", SimpleNamespace(getpwnam=lambda _: SimpleNamespace(pw_uid=0, pw_gid=0))))
        stack.enter_context(patch.object(sites.os, "chown", create=True))
        return stack

    def test_activation_failure_restores_original_binary_and_override(self):
        fixture = self.transaction_fixture()
        base, binary, candidate, override, _, plan, paths = fixture
        original_override = override.read_bytes()
        def fail_once(value, patched):
            if patched:
                self.assertEqual(binary.read_bytes(), b"patched binary")
                self.assertIn(b"RASAD_METRICS", override.read_bytes())
                raise sites.InstallError("fixture health failure")
            self.assertEqual(binary.read_bytes(), b"original binary")
        with self.transaction_patches(fixture, fail_once):
            with self.assertRaisesRegex(sites.InstallError, "health failure"):
                sites.install_candidate(plan, candidate, paths, {})
            self.assertEqual(binary.read_bytes(), b"original binary")
            self.assertEqual(override.read_bytes(), original_override)
            self.assertFalse((base / "state.json").exists())
            self.assertEqual(len(list(base.glob("backup-*/original-xray"))), 1)

    def test_enable_disable_round_trip_preserves_existing_override(self):
        fixture = self.transaction_fixture()
        base, binary, candidate, override, _, plan, paths = fixture
        original_override = override.read_bytes()
        with self.transaction_patches(fixture, lambda *_args, **_kwargs: None):
            sites.install_candidate(plan, candidate, paths, {})
            self.assertEqual(binary.read_bytes(), b"patched binary")
            self.assertEqual(json.loads((base / "state.json").read_text())["phase"], "active")
            sites.disable()
            self.assertEqual(binary.read_bytes(), b"original binary")
            self.assertEqual(override.read_bytes(), original_override)
            self.assertFalse((base / "state.json").exists())

    def test_disable_refuses_to_overwrite_an_external_core_update(self):
        fixture = self.transaction_fixture()
        _, binary, candidate, _, _, plan, paths = fixture
        with self.transaction_patches(fixture, lambda *_args, **_kwargs: None):
            sites.install_candidate(plan, candidate, paths, {})
            binary.write_bytes(b"external upgraded binary")
            with self.assertRaisesRegex(sites.InstallError, "externally changed"):
                sites.disable()
            self.assertEqual(binary.read_bytes(), b"external upgraded binary")

    def test_runtime_paths_cannot_escape_or_collide(self):
        self.assertEqual(sites.runtime_paths({})["domain_metrics"], "/run/rasad/domains.json")
        for config in ({"domain_metrics": "/etc/passwd"}, {"domain_metrics": "/run/rasad/policy.json"}, {"domain_policy": "/run/rasad/../bad.json"}):
            with self.assertRaises(sites.InstallError):
                sites.runtime_paths(config)

    @unittest.skipUnless(shutil.which("bash"), "Bash validation runs on Ubuntu CI")
    def test_bash_entry_points_reject_unknown_arguments_before_installation(self):
        for path in (ROOT / "install.sh", ROOT / "xray-module/enable.sh"):
            subprocess.run(["bash", "-n", str(path)], check=True)
        result = subprocess.run(["bash", str(ROOT / "install.sh"), "--unsupported"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("Usage:", result.stdout)


if __name__ == "__main__":
    unittest.main()
