"""Run as root on Ubuntu; prompts use the controlling terminal."""
import getpass
from contextlib import ExitStack
import json
import os
from pathlib import Path
import sys
from server import password_hash


def main():
    target = Path(sys.argv[1] if len(sys.argv) > 1 else "/etc/rasad/config.json")
    if target.exists():
        print("Existing configuration preserved. Edit with sudo rasad configure.")
        return
    # Buffered update mode (r+) needs a seekable file. A terminal is a stream;
    # separate readers/writers also work when bash consumes the install pipe.
    with ExitStack() as terminals:
        try:
            tty_input = terminals.enter_context(open("/dev/tty", "r", encoding="utf-8"))
            tty_output = terminals.enter_context(open("/dev/tty", "w", encoding="utf-8"))
        except OSError:
            raise SystemExit("Rasad setup needs an interactive SSH terminal. Reconnect with ssh -t and rerun the installer; no configuration was saved.")
        def ask(label, default=""):
            tty_output.write(f"{label}{' [' + default + ']' if default else ''}: ")
            tty_output.flush()
            answer = tty_input.readline()
            if not answer:
                raise SystemExit("Rasad setup terminal closed; no configuration was saved.")
            return answer.strip() or default
        original = sys.stdin
        sys.stdin = tty_input
        try:
            print("Rasad setup — passwords are never echoed or sent to the browser.")
            panel_url = ask("3x-ui URL including web base path", "http://127.0.0.1:2053")
            token = getpass.getpass("3x-ui API token (Enter for username/password): ", stream=tty_output)
            username = password = ""
            if not token:
                username = ask("3x-ui username")
                password = getpass.getpass("3x-ui password: ", stream=tty_output)
            admin_username = ask("Rasad admin username", "admin")
            while True:
                admin_password = getpass.getpass("New Rasad admin password (at least 12 characters): ", stream=tty_output)
                confirm = getpass.getpass("Repeat admin password: ", stream=tty_output)
                if len(admin_password) >= 12 and admin_password == confirm:
                    break
                tty_output.write("Passwords must match and contain at least 12 characters.\n")
                tty_output.flush()
            origin = ask("Browser origin (HTTPS domain or SSH tunnel origin)", "http://localhost:8787")
            access_log = ask("Existing Xray access.log absolute path (Enter to skip)")
            log_timezone = ask("Xray process timezone (access.log timestamps)", "UTC")
        finally:
            sys.stdin = original
    from core import Panel
    from zoneinfo import ZoneInfo
    config = {"panel_url": panel_url, "panel_token": token, "panel_username": username,
              "panel_password": password, "admin_username": admin_username,
              "admin_password_hash": password_hash(admin_password), "public_origin": origin.rstrip("/"),
              "access_log": access_log, "log_timezone": log_timezone, "timezone": "Asia/Tehran",
              "listen": "127.0.0.1", "port": 8787, "database": "/var/lib/rasad/rasad.db",
              "domain_metrics": "/run/rasad/domains.json", "domain_policy": "/run/rasad/policy.json"}
    Panel(config)
    ZoneInfo(log_timezone)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as file:
        json.dump(config, file, indent=2)
        file.write("\n")
    os.replace(tmp, target)
    print("Configuration saved. Domain monitoring starts disabled.")


if __name__ == "__main__":
    main()
