#!/usr/bin/env bash
set -euo pipefail
RASAD_SITES=false
case "${1:-}" in
  '') [[ $# -eq 0 ]] || { echo 'Usage: sudo bash install.sh [--sites]'; exit 2; } ;;
  --sites) [[ $# -eq 1 ]] || { echo 'Usage: sudo bash install.sh [--sites]'; exit 2; }; RASAD_SITES=true ;;
  *) echo 'Usage: sudo bash install.sh [--sites]'; exit 2 ;;
esac
[[ $EUID -eq 0 ]] || { echo 'Run with sudo bash install.sh'; exit 1; }
source /etc/os-release
[[ "${ID:-}" == ubuntu || "${ID:-}" == debian ]] || { echo 'Ubuntu 22.04+ or Debian 12+ required'; exit 1; }
command -v systemctl >/dev/null || { echo 'systemd is required'; exit 1; }
umask 027
RASAD_SOURCE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-}")" && pwd)"
RASAD_TEMP=''
cleanup() { [[ -z "$RASAD_TEMP" ]] || rm -rf -- "$RASAD_TEMP"; }
trap cleanup EXIT
if [[ ! -f "$RASAD_SOURCE/backend/server.py" ]]; then
  RASAD_TEMP="$(mktemp -d /tmp/rasad-install.XXXXXXXX)"
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
    https://github.com/sadrazkh/rasad-3xui/archive/refs/heads/main.tar.gz -o "$RASAD_TEMP/source.tar.gz"
  mkdir "$RASAD_TEMP/source"
  tar --extract --gzip --file "$RASAD_TEMP/source.tar.gz" --directory "$RASAD_TEMP/source" \
    --strip-components=1 --no-same-owner --no-same-permissions
  RASAD_SOURCE="$RASAD_TEMP/source"
fi
[[ -f "$RASAD_SOURCE/backend/server.py" && -f "$RASAD_SOURCE/dist/index.html" ]] || { echo 'Invalid source bundle'; exit 1; }
apt-get update -qq
apt-get install -y -qq python3 tzdata acl ca-certificates nano
python3 -c 'import sys; assert sys.version_info >= (3,10), "Python 3.10+ required"'
id rasad >/dev/null 2>&1 || useradd --system --home-dir /var/lib/rasad --shell /usr/sbin/nologin rasad
install -d -m 0755 /opt/rasad /opt/rasad/backend /opt/rasad/dist
install -d -m 0750 -o root -g rasad /etc/rasad
install -d -m 0700 -o rasad -g rasad /var/lib/rasad
if [[ -f /var/lib/rasad/rasad.db ]]; then
  python3 - <<'PY'
import datetime, sqlite3
source = sqlite3.connect('/var/lib/rasad/rasad.db')
name = '/var/lib/rasad/backup-' + datetime.datetime.now().strftime('%Y%m%d-%H%M%S') + '.db'
with sqlite3.connect(name) as target: source.backup(target)
source.close()
PY
fi
cp -a "$RASAD_SOURCE/backend/." /opt/rasad/backend/
cp -a "$RASAD_SOURCE/dist/." /opt/rasad/dist/
[[ ! -d "$RASAD_SOURCE/deploy" ]] || cp -a "$RASAD_SOURCE/deploy" /opt/rasad/
[[ ! -d "$RASAD_SOURCE/xray-module" ]] || cp -a "$RASAD_SOURCE/xray-module" /opt/rasad/
chown -R root:root /opt/rasad
find /opt/rasad -type d -exec chmod 0755 {} +
find /opt/rasad -type f -exec chmod 0644 {} +
python3 /opt/rasad/backend/configure.py /etc/rasad/config.json
chown root:rasad /etc/rasad/config.json
chmod 0640 /etc/rasad/config.json
RASAD_LOG="$(python3 -c 'import json; print(json.load(open("/etc/rasad/config.json")).get("access_log", ""))')"
if [[ -n "$RASAD_LOG" && -f "$RASAD_LOG" ]]; then
  setfacl -m u:rasad:r "$RASAD_LOG"
  RASAD_PARENT="$(dirname -- "$RASAD_LOG")"
  while [[ "$RASAD_PARENT" != / && "$RASAD_PARENT" != . ]]; do
    setfacl -m u:rasad:x "$RASAD_PARENT"
    RASAD_PARENT="$(dirname -- "$RASAD_PARENT")"
  done
  echo 'Grant read ACL again after access.log rotation; see README.'
fi
cat > /etc/systemd/system/rasad.service <<'UNIT'
[Unit]
Description=Rasad local traffic dashboard for 3x-ui
After=network.target
[Service]
Type=simple
User=rasad
Group=rasad
WorkingDirectory=/opt/rasad
ExecStart=/usr/bin/python3 -u /opt/rasad/backend/server.py --config /etc/rasad/config.json
Restart=on-failure
RestartSec=5
StateDirectory=rasad
StateDirectoryMode=0700
RuntimeDirectory=rasad
RuntimeDirectoryMode=02750
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/rasad /run/rasad
UMask=0027
MemoryMax=256M
CPUQuota=20%
TasksMax=64
[Install]
WantedBy=multi-user.target
UNIT
cat > /usr/local/bin/rasad <<'CLI'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-status}" in
  status) systemctl status rasad --no-pager ;;
  logs) journalctl -u rasad -n 100 --no-pager ;;
  restart) systemctl restart rasad ;;
  configure) ${EDITOR:-nano} /etc/rasad/config.json; systemctl restart rasad ;;
  sites) [[ $# -eq 2 ]] || { echo 'Usage: sudo rasad sites {enable|status|disable}'; exit 2; }; exec bash /opt/rasad/xray-module/enable.sh "$2" ;;
  *) echo 'Usage: sudo rasad {status|logs|restart|configure|sites {enable|status|disable}}'; exit 1 ;;
esac
CLI
chmod 0755 /usr/local/bin/rasad
systemctl daemon-reload
systemctl enable rasad >/dev/null
systemctl restart rasad
RASAD_PORT="$(python3 -c 'import json; print(int(json.load(open("/etc/rasad/config.json")).get("port", 8787)))')"
for RASAD_ATTEMPT in {1..15}; do
  if python3 -c 'import sys; from urllib.request import build_opener, ProxyHandler; build_opener(ProxyHandler({})).open("http://127.0.0.1:"+sys.argv[1]+"/api/health", timeout=1)' "$RASAD_PORT" 2>/dev/null; then
    echo "Rasad installed. Listening on 127.0.0.1:$RASAD_PORT."
    echo "SSH tunnel: ssh -L $RASAD_PORT:127.0.0.1:$RASAD_PORT root@YOUR_SERVER"
    echo "Open http://localhost:$RASAD_PORT or configure Nginx with HTTPS. See README."
    if $RASAD_SITES; then
      echo 'Enabling destination byte counters: builds the current Xray release, then restarts native x-ui. Recovery: sudo rasad sites disable'
      bash /opt/rasad/xray-module/enable.sh enable
    fi
    exit 0
  fi
  sleep 1
done
echo 'Service did not become healthy. Run sudo rasad logs.'
exit 1
