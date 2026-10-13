"""Explicit native root x-ui installation; never guess or upgrade the active core."""
import argparse
import hashlib
import json
import os
from pathlib import Path
try:
    import pwd
except ImportError:  # Validation fixtures can run on Windows; deployment is Linux only.
    pwd = None
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import time
from urllib.request import build_opener, ProxyHandler, HTTPRedirectHandler

SERVICE = "x-ui.service"
BASE = Path("/var/lib/rasad-sites")
STATE = BASE / "state.json"
OVERRIDE = Path("/etc/systemd/system/x-ui.service.d/90-rasad-sites.conf")
CONFIG = Path("/etc/rasad/config.json")
RUNTIME = Path("/run/rasad")
MODULE = Path(__file__).resolve().parents[1] / "xray-module"
UPSTREAM = "https://github.com/XTLS/Xray-core.git"
PROTOCOLS = {"vless", "vmess", "trojan", "shadowsocks"}


class InstallError(RuntimeError):
    pass


class LocalHealthOnly(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        return None


def run(args, **kwargs):
    return subprocess.run([str(x) for x in args], check=True, **kwargs)


def output(args):
    return run(args, capture_output=True, text=True).stdout.strip()


def digest(path):
    with Path(path).open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest() if hasattr(hashlib, "file_digest") else hashlib.sha256(file.read()).hexdigest()


def atomic(path, data, mode=0o600):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix=".rasad-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def trusted(path, directory=False):
    """All deployment paths must be real root-owned files/directories, not writable by others."""
    path = Path(path)
    if not path.is_absolute():
        raise InstallError(f"Expected an absolute path: {path}")
    for part in [path, *path.parents]:
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise InstallError(f"Untrusted deployment path: {part}")
    if directory and not path.is_dir() or not directory and not path.is_file():
        raise InstallError(f"Unexpected deployment path type: {path}")
    return path


def version(binary):
    value = output([binary, "version"])
    match = re.match(r"Xray (\d+\.\d+\.\d+)(?:\s|$)", value)
    if not match:
        raise InstallError("Cannot identify an official Xray release version; no replacement made")
    return match[1]


def architecture(binary, machine=None):
    with Path(binary).open("rb") as file:
        head = file.read(20)
    if len(head) != 20 or head[:6] != b"\x7fELF\x02\x01":
        raise InstallError("Only Linux little-endian ELF64 Xray binaries are supported")
    arch = {62: "amd64", 183: "arm64"}.get(int.from_bytes(head[18:20], "little"))
    host = {"x86_64": "amd64", "aarch64": "arm64"}.get(machine or os.uname().machine)
    if not arch or arch != host:
        raise InstallError("Unsupported or mismatched native Xray architecture")
    return arch


def process_info(pid, proc=Path("/proc")):
    directory = proc / str(pid)
    status = {}
    for line in (directory / "status").read_text().splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            status[key] = value.strip()
    if any(int(x) for x in status["Uid"].split()):
        raise InstallError("Native Xray and x-ui must run as root; non-root and containers need separate deployment")
    binary = os.readlink(directory / "exe")
    if binary.endswith(" (deleted)"):
        raise InstallError("The running binary was deleted/replaced; restart and inspect x-ui first")
    return {"pid": int(pid), "parent": int(status["PPid"]), "binary": Path(binary),
            "args": [x.decode() for x in (directory / "cmdline").read_bytes().split(b"\0") if x],
            "cwd": Path(os.readlink(directory / "cwd")),
            "cgroup": (directory / "cgroup").read_text()}


def config_path(args, cwd):
    found = []
    rest = args[1:]
    while rest:
        arg = rest.pop(0)
        if arg == "run":
            continue
        if arg in ("-c", "-config", "--config") and rest:
            found.append(rest.pop(0))
        elif arg.startswith(("-c=", "-config=", "--config=")):
            found.append(arg.split("=", 1)[1])
        else:
            raise InstallError(f"Unsupported running Xray argument {arg!r}; only a single JSON config is supported")
    if len(found) != 1:
        raise InstallError("Cannot discover a single explicit Xray JSON config from the running process")
    path = Path(found[0])
    return trusted(path if path.is_absolute() else cwd / path)


def protocols(path):
    try:
        value = json.loads(Path(path).read_text())
    except (ValueError, OSError) as error:
        raise InstallError("The running Xray config must be readable JSON") from error
    if not isinstance(value, dict) or not isinstance(value.get("inbounds"), list):
        raise InstallError("The running config has no supported inbound list")
    inbound_protocols = set()
    for inbound in value["inbounds"]:
        if not isinstance(inbound, dict):
            raise InstallError("The running config has an unsupported inbound shape")
        protocol = inbound.get("protocol")
        # Current 3x-ui uses Xray's tunnel alias for its loopback API listener.
        # It has no per-user identity and is not a user traffic inbound.
        if protocol in ("dokodemo-door", "tunnel") and inbound.get("tag") == "api" and inbound.get("listen") in ("127.0.0.1", "::1"):
            continue
        if protocol not in PROTOCOLS:
            raise InstallError(f"Unsupported user inbound protocol: {protocol!r}; no replacement made")
        settings = inbound.get("settings", {})
        if not isinstance(settings, dict):
            raise InstallError("The running config has an unsupported user settings shape")
        clients = settings.get("clients", [])
        if not isinstance(clients, list) or any(not isinstance(client, dict) or not isinstance(client.get("email"), str) or not client["email"].strip() for client in clients):
            raise InstallError("Every configured user must have a non-empty email for byte attribution")
        inbound_protocols.add(protocol)
    if not inbound_protocols:
        raise InstallError("No supported user inbound was found in the active Xray config")
    return sorted(inbound_protocols)


def sniffing_summary(path):
    value = json.loads(Path(path).read_text())
    result = []
    for index, inbound in enumerate(value["inbounds"]):
        if inbound.get("protocol") not in PROTOCOLS:
            continue
        sniffing = inbound.get("sniffing", {})
        if not isinstance(sniffing, dict):
            sniffing = {}
        override = sniffing.get("destOverride", [])
        if not isinstance(override, list):
            override = []
        enabled = sniffing.get("enabled") is True
        result.append({"tag": inbound.get("tag", f"inbound-{index}"), "protocol": inbound["protocol"],
                       "enabled": enabled, "http": "http" in override, "tls": "tls" in override,
                       "routeOnly": sniffing.get("routeOnly") is True,
                       "domain_detection_ready": enabled and {"http", "tls"}.issubset(override)})
    return result


def print_sniffing(plan):
    rows = plan.get("sniffing", [])
    print("Current inbound domain detection (configuration is unchanged): " + json.dumps(rows), flush=True)
    if any(not row["domain_detection_ready"] for row in rows):
        print("WARNING: Some inbounds cannot identify HTTP/TLS domains from IP-only client targets. Their bytes will remain unknown TCP until compatible sniffing (enabled, destOverride http/tls) is configured in 3x-ui. routeOnly is reported above; no sniffing setting is changed automatically.", flush=True)
    print("UDP, ECH and nested tunnels can remain unknown even when HTTP/TLS sniffing is enabled.", flush=True)


def discover():
    properties = {}
    raw = output(["systemctl", "show", SERVICE, "--property=MainPID,ActiveState,User,ControlGroup,RootDirectory,RootImage,FragmentPath"])
    for line in raw.splitlines():
        key, value = line.split("=", 1)
        properties[key] = value
    if properties.get("ActiveState") != "active" or properties.get("User") not in ("", "root") or properties.get("RootDirectory") or properties.get("RootImage"):
        raise InstallError("Only an active native root systemd x-ui.service without a root image is supported")
    cgroup = properties.get("ControlGroup", "")
    if not cgroup.startswith("/system.slice/") or not cgroup.endswith("/x-ui.service"):
        raise InstallError("Cannot verify the native x-ui service cgroup")
    main = process_info(int(properties.get("MainPID", "0")))
    if main["binary"].name != "x-ui":
        raise InstallError("x-ui.service MainPID is not the native x-ui binary")
    trusted(main["binary"])
    candidates = []
    for directory in Path("/proc").iterdir():
        if not directory.name.isdigit():
            continue
        try:
            image = os.readlink(directory / "exe")
            if not re.fullmatch(r"xray(?:-linux-(?:amd64|arm64))?", Path(image).name):
                continue
            if not any(line.split(":", 2)[-1] == cgroup for line in (directory / "cgroup").read_text().splitlines()):
                continue
            info = process_info(int(directory.name))
            ancestor = info["parent"]
            for _ in range(32):
                if ancestor == main["pid"]:
                    candidates.append(info)
                    break
                if ancestor <= 1:
                    break
                ancestor = process_info(ancestor)["parent"]
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
    if len(candidates) != 1:
        raise InstallError("Expected exactly one identifiable Xray child of x-ui; Docker and unknown launch layouts are unsupported")
    info = candidates[0]
    binary = trusted(info["binary"])
    config = config_path(info["args"], info["cwd"])
    return {"binary": str(binary), "version": version(binary), "arch": architecture(binary),
            "config": str(config), "config_sha256": digest(config), "original_sha256": digest(binary),
            "protocols": protocols(config), "sniffing": sniffing_summary(config)}


def runtime_paths(config):
    paths = {}
    for key, default in (("domain_policy", "/run/rasad/policy.json"), ("domain_metrics", "/run/rasad/domains.json")):
        path = Path(config.get(key, default))
        if path.parent != Path("/run/rasad") or not re.fullmatch(r"[A-Za-z0-9_.-]+\.json", path.name) or path.is_symlink():
            raise InstallError("Native site metering requires direct non-symlink JSON files inside /run/rasad")
        paths[key] = path.as_posix()
    if paths["domain_policy"] == paths["domain_metrics"]:
        raise InstallError("Policy and metrics paths must be different")
    return paths


def go_version(text):
    match = re.search(r"(?:go)?(\d+)\.(\d+)(?:\.(\d+))?", text)
    if not match:
        raise InstallError("Cannot identify required Go version")
    return tuple(int(x or 0) for x in match.groups())


def required_go(path):
    text = Path(path).read_text()
    requirements = re.findall(r"(?m)^(?:go|toolchain)\s+(?:go)?(\d+\.\d+(?:\.\d+)?)\s*$", text)
    if not requirements:
        raise InstallError("The selected Xray go.mod has no supported Go requirement")
    return max(go_version(value) for value in requirements)


def official_go_release(metadata, required, arch):
    candidates = []
    for release in metadata:
        if not release.get("stable") or not re.fullmatch(r"go\d+\.\d+\.\d+", release.get("version", "")):
            continue
        current = go_version(release["version"])
        if current[:2] != required[:2] or current < required:
            continue
        for file in release.get("files", []):
            expected = f'{release["version"]}.linux-{arch}.tar.gz'
            if file.get("os") == "linux" and file.get("arch") == arch and file.get("kind") == "archive" and file.get("filename") == expected and re.fullmatch(r"[a-f0-9]{64}", file.get("sha256", "")):
                candidates.append((current, file))
    if not candidates:
        raise InstallError("No checksum-verified official Go release satisfies this exact Xray branch")
    return max(candidates, key=lambda item: item[0])[1]


def curl(url, target):
    run(["curl", "--fail", "--silent", "--show-error", "--location", "--proto", "=https", "--proto-redir", "=https", "--tlsv1.2", "--max-time", "300", url, "-o", target])


def choose_go(required, arch, temporary):
    installed = shutil.which("go")
    if installed:
        try:
            installed_version = output([installed, "version"])
            if re.fullmatch(r"go version go\d+\.\d+(?:\.\d+)? linux/(?:amd64|arm64)", installed_version) and go_version(installed_version) >= required:
                return str(Path(installed).resolve())
        except (InstallError, subprocess.CalledProcessError):
            pass
    metadata = temporary / "go-releases.json"
    curl("https://go.dev/dl/?mode=json&include=all", metadata)
    release = official_go_release(json.loads(metadata.read_text()), required, arch)
    archive = temporary / release["filename"]
    curl("https://go.dev/dl/" + release["filename"], archive)
    if digest(archive) != release["sha256"]:
        raise InstallError("Official Go archive checksum mismatch; nothing installed")
    run(["tar", "-xzf", archive, "-C", temporary, "--no-same-owner", "--no-same-permissions"])
    executable = temporary / "go/bin/go"
    if go_version(output([executable, "version"])) < required:
        raise InstallError("Downloaded Go runtime does not satisfy the selected Xray source")
    return str(executable)


def build(plan, temporary):
    print(f'Building Xray v{plan["version"]} with destination byte counters; the active core is still unchanged.', flush=True)
    run(["apt-get", "update", "-qq"])
    run(["apt-get", "install", "-y", "-qq", "git", "curl", "ca-certificates", "build-essential"])
    source = temporary / "source"
    ref = "v" + plan["version"]
    run(["git", "clone", "--depth", "1", "--branch", ref, "--single-branch", UPSTREAM, source])
    required = required_go(source / "go.mod")
    executable = choose_go(required, plan["arch"], temporary)
    environment = dict(os.environ, RASAD_GO=executable, RASAD_EXISTING_SOURCE="1", GOTOOLCHAIN="local", GOMAXPROCS="2")
    run(["bash", MODULE / "build.sh", ref, source], env=environment)
    candidate = source / "xray-rasad"
    if version(candidate) != plan["version"] or architecture(candidate) != plan["arch"]:
        raise InstallError("Built Xray version/architecture differs from the active core; refusing upgrade")
    run([candidate, "run", "-test", "-c", plan["config"]], env=dict(os.environ, RASAD_POLICY="", RASAD_METRICS=""))
    return candidate


def saved_state():
    if not STATE.exists():
        return None
    trusted(STATE)
    return json.loads(STATE.read_text())


def save_state(value):
    atomic(STATE, (json.dumps(value, indent=2) + "\n").encode())


def replace_binary(source, destination):
    destination = trusted(destination)
    original = destination.stat()
    fd, temporary = tempfile.mkstemp(prefix=".rasad-xray-", dir=destination.parent)
    os.close(fd)
    try:
        shutil.copy2(source, temporary)
        os.chown(temporary, original.st_uid, original.st_gid)
        os.chmod(temporary, stat.S_IMODE(original.st_mode))
        with open(temporary, "r+b") as file:
            os.fsync(file.fileno())
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def restore_files(value):
    backup = trusted(value["backup"])
    if digest(backup) != value["original_sha256"]:
        raise InstallError("Original Xray backup checksum failed; manual recovery required")
    replace_binary(backup, value["binary"])
    if value["override_existed"]:
        atomic(OVERRIDE, Path(value["override_backup"]).read_bytes(), value["override_mode"])
    elif OVERRIDE.exists():
        OVERRIDE.unlink()
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "restart", SERVICE])


def health(value, patched, seconds=60):
    deadline = time.monotonic() + seconds
    expected = value["candidate_sha256"] if patched else value["original_sha256"]
    opener = build_opener(ProxyHandler({}), LocalHealthOnly())
    while time.monotonic() < deadline:
        try:
            live = discover()
            if live["binary"] != value["binary"] or live["original_sha256"] != expected:
                raise InstallError("Running Xray image does not match the installed binary")
            if patched:
                # /proc/exe can still point at the previous inode after a failed child restart.
                metrics = Path(value["domain_metrics"])
                snapshot = json.loads(metrics.read_text())
                info = metrics.stat()
                if snapshot.get("version") != 1 or snapshot.get("boot") == value.get("old_boot") or snapshot.get("ts", 0) < value["installed_at"] or not isinstance(snapshot.get("rows"), list) or info.st_gid != pwd.getpwnam("rasad").pw_gid or info.st_mode & 0o007:
                    raise InstallError("The destination counter has no fresh group-readable snapshot")
            with opener.open(value["health_url"], timeout=2) as response:
                if json.load(response).get("ok") is not True:
                    raise InstallError("The Rasad dashboard is not healthy")
            return
        except (OSError, ValueError, KeyError, InstallError, subprocess.CalledProcessError):
            time.sleep(1)
    raise InstallError("x-ui/Xray or destination-counter health check failed")


def install_candidate(plan, candidate, paths, config):
    fresh = discover()
    if fresh != plan:
        raise InstallError("The active core or config changed during compilation; no replacement made")
    backup_dir = Path(tempfile.mkdtemp(prefix="backup-", dir=BASE))
    backup = backup_dir / "original-xray"
    shutil.copy2(plan["binary"], backup)
    value = dict(plan, **paths, backup=str(backup), candidate_sha256=digest(candidate), phase="prepared",
                 installed_at=int(time.time()), override_existed=OVERRIDE.exists(),
                 health_url=f'http://127.0.0.1:{int(config.get("port", 8787))}/api/health')
    if value["override_existed"]:
        trusted(OVERRIDE)
        value["override_mode"] = stat.S_IMODE(OVERRIDE.stat().st_mode)
        override_backup = backup_dir / "original-override.conf"
        shutil.copy2(OVERRIDE, override_backup)
        value["override_backup"] = str(override_backup)
    try:
        value["old_boot"] = json.loads(Path(paths["domain_metrics"]).read_text()).get("boot")
    except (OSError, ValueError):
        value["old_boot"] = None
    OVERRIDE.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    trusted(OVERRIDE.parent, directory=True)
    rasad = pwd.getpwnam("rasad")
    runtime = RUNTIME
    if runtime.is_symlink() or not runtime.is_dir():
        raise InstallError("The existing Rasad runtime directory must be available and not a symlink")
    os.chown(runtime, rasad.pw_uid, rasad.pw_gid)
    os.chmod(runtime, 0o2750)  # root Xray snapshots inherit the rasad group on every rename.
    save_state(value)  # Recoverable even if the process is killed after binary replacement.
    try:
        replace_binary(candidate, plan["binary"])
        content = '[Service]\nEnvironment="RASAD_POLICY=' + paths["domain_policy"] + '"\nEnvironment="RASAD_METRICS=' + paths["domain_metrics"] + '"\n'
        atomic(OVERRIDE, content.encode(), 0o644)
        run(["systemctl", "daemon-reload"])
        run(["systemctl", "restart", SERVICE])
        health(value, patched=True)
        value["phase"] = "active"
        save_state(value)
    except BaseException:
        print("Activation failed; restoring the original Xray and service override.", flush=True)
        try:
            restore_files(value)
            health(value, patched=False)
            value["phase"] = "rolled-back"
            atomic(backup_dir / "result.json", json.dumps(value, indent=2).encode())
            STATE.unlink()
        except BaseException as error:
            value["phase"] = "rollback-failed"
            save_state(value)
            print(f"Automatic rollback failed: {error}. Original binary: {backup}", flush=True)
        raise
    print(f'Destination byte counter enabled on Xray v{plan["version"]}. Select users in Rasad; existing connections need reconnect. Backup: {backup}', flush=True)
    print_sniffing(plan)


def enable():
    previous = saved_state()
    if previous:
        if previous.get("phase") == "active":
            status()
            print("Destination byte counter is already enabled; the running core was not changed.")
            return
        raise InstallError("A saved incomplete installation exists; inspect sudo rasad sites status and disable to recover before reinstalling")
    config = json.loads(trusted(CONFIG).read_text())
    paths = runtime_paths(config)
    plan = discover()
    print_sniffing(plan)
    if output(["systemctl", "is-active", "rasad.service"]) != "active":
        raise InstallError("Rasad must be running before destination counters are enabled")
    if not Path(paths["domain_policy"]).is_file():
        raise InstallError("Rasad has not published its policy yet; wait for its first collection cycle")
    with tempfile.TemporaryDirectory(prefix="rasad-sites-") as directory:
        candidate = build(plan, Path(directory))
        install_candidate(plan, candidate, paths, config)


def disable():
    value = saved_state()
    if not value:
        print("Destination byte counter is already disabled.")
        return
    current = trusted(value["binary"])
    if digest(current) not in (value["candidate_sha256"], value["original_sha256"]):
        raise InstallError("Xray was externally changed after installation; refusing to overwrite it. Inspect the saved backup and current core manually")
    restore_files(value)
    health(value, patched=False)
    value["phase"] = "disabled"
    atomic(Path(value["backup"]).parent / "result.json", json.dumps(value, indent=2).encode())
    STATE.unlink()
    print("Original Xray and service override restored. Site-byte collection disabled; saved reports remain in Rasad.")


def status():
    value = saved_state()
    if not value:
        print("Destination byte counter: disabled (standard 3x-ui does not supply bytes per website).")
        return
    matched = Path(value["binary"]).is_file() and digest(value["binary"]) == value["candidate_sha256"]
    snapshot = {}
    try:
        snapshot = json.loads(Path(value["domain_metrics"]).read_text())
    except (ValueError, OSError):
        pass
    age = int(time.time()) - snapshot["ts"] if isinstance(snapshot.get("ts"), int) else None
    try:
        service_active = output(["systemctl", "is-active", SERVICE]) == "active"
    except subprocess.CalledProcessError:
        service_active = False
    print(json.dumps({"state": value["phase"], "version": value["version"], "binary": value["binary"],
                      "binary_matches": matched, "snapshot_age_seconds": int(time.time()) - snapshot["ts"] if isinstance(snapshot.get("ts"), int) else None,
                      "service_active": service_active, "protocols": value["protocols"], "sniffing": value.get("sniffing", []), "backup": value["backup"]}, indent=2))
    if not matched or value["phase"] != "active" or not service_active or age is None or age > 45:
        raise InstallError("Destination metering needs attention; core may have been overwritten by a 3x-ui update")


def main():
    import fcntl
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("enable", "status", "disable"))
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise InstallError("Run with sudo rasad sites " + args.action)
    BASE.mkdir(mode=0o700, exist_ok=True)
    trusted(BASE, directory=True)
    with (BASE / "lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(InstallError("Installation interrupted")))
        {"enable": enable, "disable": disable, "status": status}[args.action]()


if __name__ == "__main__":
    try:
        main()
    except (InstallError, OSError, ValueError, subprocess.CalledProcessError) as error:
        raise SystemExit("Rasad sites: " + str(error))
