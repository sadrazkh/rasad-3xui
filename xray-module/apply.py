"""Prepare a separate Xray checkout; refuse incompatible upstream source."""
import argparse
from pathlib import Path
import shutil

parser = argparse.ArgumentParser()
parser.add_argument("checkout")
args = parser.parse_args()
root = Path(args.checkout).resolve()
file = root / "app/dispatcher/default.go"
text = file.read_text(encoding="utf-8")
stats_text = (root / "app/dispatcher/stats.go").read_text(encoding="utf-8")
if any(marker not in text for marker in (
    "ob.OriginalTarget = destination", "ob.RouteTarget = destination",
    "d.routedDispatch(ctx, outbound, destination)",
)) or any(marker not in stats_text for marker in ("type SizeStatWriter struct", "stats.Counter")):
    raise SystemExit("Unsupported Xray source: destination or native counter contract changed; no files modified")
anchor = "\thandler.Dispatch(ctx, link)"
replacement = "\tctx = rasadWrap(ctx, link, destination)\n" + anchor
if replacement not in text:
    if text.count(anchor) != 1:
        raise SystemExit("Unsupported Xray source: dispatch anchor changed; no files modified")
    file.write_text(text.replace(anchor, replacement), encoding="utf-8", newline="\n")
for name in ("rasad.go", "rasad_test.go"):
    shutil.copyfile(Path(__file__).with_name(name), root / "app/dispatcher" / name)
print("Rasad module applied to separate source checkout. Running Xray not changed.")
