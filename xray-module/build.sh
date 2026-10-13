#!/usr/bin/env bash
set -euo pipefail
# Deliberately does not replace or restart the live core.
RASAD_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RASAD_REF="${1:-c77a4d0e4932a53f3eeafafdfef877b56fd660ad}"
RASAD_BUILD="${2:-$PWD/rasad-xray-build}"
RASAD_GO="${RASAD_GO:-go}"
command -v "$RASAD_GO" >/dev/null || { echo 'Set RASAD_GO to official Go matching the selected Xray go.mod'; exit 1; }
if [[ "${RASAD_EXISTING_SOURCE:-0}" == 1 ]]; then
  [[ -d "$RASAD_BUILD/.git" ]] || { echo 'Existing source must be a separate official Xray Git checkout'; exit 1; }
  [[ "$(git -C "$RASAD_BUILD" remote get-url origin)" == https://github.com/XTLS/Xray-core.git ]] || { echo 'Existing source origin must be official Xray'; exit 1; }
  [[ "$(git -C "$RASAD_BUILD" rev-parse HEAD)" == "$(git -C "$RASAD_BUILD" rev-parse --verify "${RASAD_REF}^{commit}")" ]] || { echo 'Existing source must match requested Xray ref'; exit 1; }
  [[ -z "$(git -C "$RASAD_BUILD" status --porcelain)" ]] || { echo 'Existing source must be clean before patching'; exit 1; }
else
  [[ ! -e "$RASAD_BUILD" ]] || { echo 'Choose a new, empty build path'; exit 1; }
  git clone https://github.com/XTLS/Xray-core.git "$RASAD_BUILD"
  git -C "$RASAD_BUILD" checkout --detach "$RASAD_REF"
fi
RASAD_GO_PATH="$(command -v "$RASAD_GO")"
RASAD_GOFMT="${RASAD_GOFMT:-$(dirname -- "$RASAD_GO_PATH")/gofmt}"
command -v "$RASAD_GOFMT" >/dev/null || { echo 'Set RASAD_GOFMT to gofmt from the selected Go toolchain'; exit 1; }
python3 "$RASAD_DIR/apply.py" "$RASAD_BUILD"
cd "$RASAD_BUILD"
"$RASAD_GOFMT" -w app/dispatcher/rasad.go app/dispatcher/rasad_test.go
"$RASAD_GO" test ./app/dispatcher -run Rasad -count=1
"$RASAD_GO" build -trimpath -o xray-rasad ./main
./xray-rasad version > xray-rasad.version.txt
echo "Built $(pwd)/xray-rasad. Test separately before any live replacement."
