#!/usr/bin/env bash
set -euo pipefail
# Deliberately does not replace or restart the live core.
RASAD_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RASAD_REF="${1:-c77a4d0e4932a53f3eeafafdfef877b56fd660ad}"
RASAD_BUILD="${2:-$PWD/rasad-xray-build}"
[[ ! -e "$RASAD_BUILD" ]] || { echo 'Choose a new, empty build path'; exit 1; }
command -v go >/dev/null || { echo 'Install official Go matching the selected Xray go.mod'; exit 1; }
git clone https://github.com/XTLS/Xray-core.git "$RASAD_BUILD"
git -C "$RASAD_BUILD" checkout --detach "$RASAD_REF"
python3 "$RASAD_DIR/apply.py" "$RASAD_BUILD"
cd "$RASAD_BUILD"
gofmt -w app/dispatcher/rasad.go app/dispatcher/rasad_test.go
go test ./app/dispatcher -run Rasad -count=1
go build -trimpath -o xray-rasad ./main
echo "Built $(pwd)/xray-rasad. Test separately before any live replacement."
