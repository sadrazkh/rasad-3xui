"""Ephemeral Ubuntu CI: native root service activation using the real compiled core."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys
import tempfile
import threading
import time

if sys.platform != "linux" or os.geteuid() != 0 or len(sys.argv) != 2:
    raise SystemExit("Only run with sudo on an ephemeral Ubuntu CI runner and pass the compiled Xray binary")

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sites_smoke", ROOT / "deploy/sites.py")
sites = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sites)
unit = Path("/etc/systemd/system/x-ui.service")
override = sites.OVERRIDE
if unit.exists() or Path("/usr/local/x-ui").exists() or sites.STATE.exists():
    raise SystemExit("This fixture refuses to run on a machine with an existing x-ui installation")


class DashboardHealth(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok":true}')


sites.BASE.mkdir(mode=0o700, exist_ok=True)
fixture = Path(tempfile.mkdtemp(prefix="native-smoke-", dir=sites.BASE))
try:
    try:
        account = pwd.getpwnam("rasad")
    except KeyError:
        subprocess.run(["useradd", "--system", "--shell", "/usr/sbin/nologin", "rasad"], check=True)
        account = pwd.getpwnam("rasad")
    runtime = Path("/run/rasad")
    runtime.mkdir(mode=0o2750, exist_ok=True)
    os.chown(runtime, account.pw_uid, account.pw_gid)
    os.chmod(runtime, 0o2750)
    policy = runtime / "policy.json"
    policy.write_text(json.dumps({"enabled": False, "expires": int(time.time()) + 600, "users": {}}))
    os.chown(policy, account.pw_uid, account.pw_gid)
    policy.chmod(0o640)
    binary = fixture / "xray-linux-amd64"
    shutil.copy2(sys.argv[1], binary)
    binary.chmod(0o755)
    config = fixture / "config.json"
    config.write_text(json.dumps({"log": {"loglevel": "warning"},
        "api": {"tag": "api", "services": ["HandlerService", "StatsService"]},
        "routing": {"rules": [{"type": "field", "inboundTag": ["api"], "outboundTag": "api"}]},
        "inbounds": [{"tag": "api", "listen": "127.0.0.1", "port": 62789, "protocol": "tunnel", "settings": {"rewriteAddress": "127.0.0.1"}},
        {"tag": "fixture-vless", "listen": "127.0.0.1", "port": 18745,
        "protocol": "vless", "settings": {"clients": [{"id": "95891b71-d3e3-4eaa-bf65-dbf29c202f1e", "email": "fixture-user"}], "decryption": "none"},
        "streamSettings": {"network": "tcp"}, "sniffing": {"enabled": True, "destOverride": ["http", "tls"], "routeOnly": True}}],
        "outbounds": [{"protocol": "freedom"}]}))
    launcher_source = fixture / "launcher.c"
    launcher_source.write_text('''#include <unistd.h>
#include <sys/wait.h>
int main(int argc, char **argv) {
    if (argc != 3) return 64;
    pid_t pid = fork();
    if (pid < 0) return 65;
    if (pid == 0) { execl(argv[1], argv[1], "run", "-c", argv[2], (char *)0); _exit(66); }
    int status; if (waitpid(pid, &status, 0) < 0) return 67;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 68;
}
''')
    launcher = fixture / "x-ui"
    subprocess.run(["gcc", str(launcher_source), "-o", str(launcher)], check=True)
    override.parent.mkdir(parents=True, exist_ok=True)
    original_override = b'[Service]\nEnvironment="EXISTING_FIXTURE=1"\n'
    override.write_bytes(original_override)
    override.chmod(0o644)
    unit.write_text(f'[Unit]\nDescription=Ephemeral Rasad native installation fixture\n[Service]\nExecStart={launcher} {binary} {config}\nUser=root\nKillMode=control-group\n')
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    subprocess.run(["systemctl", "start", "x-ui.service"], check=True)
    dashboard = ThreadingHTTPServer(("127.0.0.1", 18787), DashboardHealth)
    threading.Thread(target=dashboard.serve_forever, daemon=True).start()
    for _ in range(15):
        try:
            plan = sites.discover()
            break
        except (sites.InstallError, FileNotFoundError):
            time.sleep(1)
    else:
        raise AssertionError("Native fixture Xray was not discovered")
    assert plan["protocols"] == ["vless"] and plan["sniffing"][0]["routeOnly"]
    sites.install_candidate(plan, Path(sys.argv[1]), sites.runtime_paths({}), {"port": 18787})
    subprocess.run(["bash", str(ROOT / "xray-module/enable.sh"), "status"], check=True)
    subprocess.run(["runuser", "-u", "rasad", "--", "python3", "-c", 'import json; value=json.load(open("/run/rasad/domains.json")); assert value["version"]==1'], check=True)
    assert b"RASAD_METRICS" in override.read_bytes()
    subprocess.run(["bash", str(ROOT / "xray-module/enable.sh"), "disable"], check=True)
    assert override.read_bytes() == original_override
    assert sites.digest(binary) == plan["original_sha256"]
    assert not sites.STATE.exists()
    print("Native root discovery, exact-version core activation, systemd env, group-readable snapshot, health and disable restore: PASS")
finally:
    if "dashboard" in globals():
        dashboard.shutdown()
        dashboard.server_close()
    subprocess.run(["systemctl", "stop", "x-ui.service"], check=False)
    unit.unlink(missing_ok=True)
    override.unlink(missing_ok=True)
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    # The fixture is beneath our explicitly created /var/lib/rasad-sites directory.
    assert fixture.resolve().parent == sites.BASE.resolve()
    shutil.rmtree(fixture)
