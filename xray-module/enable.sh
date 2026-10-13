#!/usr/bin/env bash
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'Use sudo rasad sites {enable|status|disable}' >&2; exit 1; }
[[ $# -eq 1 && "$1" =~ ^(enable|status|disable)$ ]] || { echo 'Usage: sudo rasad sites {enable|status|disable}' >&2; exit 2; }
RASAD_MODULE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$RASAD_MODULE_DIR/../deploy/sites.py" "$1"
