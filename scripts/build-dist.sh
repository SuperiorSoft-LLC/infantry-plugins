#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# NEWS-PLUGIN-1: builds every module listed in dist.json with its own stage.sh into <out>/<tier>/<Module>/ and writes
# <out>/catalog.json in the format the Infantry AI daemon reads for a catalog plugin source:
#   { "modules": [ { "name", "tier", "version", "base": "<tier>/<Module>", "files": [...] } ] }
# Usage: scripts/build-dist.sh <out-dir> [--release]
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
out="${1:?usage: build-dist.sh <out-dir> [--release]}"; shift || true
mkdir -p "$out"; out="$(cd "$out" && pwd)"
for p in $(python -c 'import json,sys; print(" ".join(m["path"] for m in json.load(open(sys.argv[1]))["modules"]))' "$root/dist.json"); do
  case "$p" in *..*|/*) echo "refuse: module path '$p' is outside the repo" >&2; exit 1;; esac
  bash "$root/$p/stage.sh" "$out" --env prod "$@"
done
python - "$root/dist.json" "$out" <<'PY'
import json, os, sys, hashlib
listed, out = json.load(open(sys.argv[1]))["modules"], sys.argv[2]
mods = []
for m in listed:
    tier, name = m["path"].split("/")[0], m["name"]
    d = os.path.join(out, tier, name)
    man = json.load(open(os.path.join(d, "module.json"), encoding="utf-8"))
    files = sorted(os.path.relpath(os.path.join(r, f), d).replace(os.sep, "/") for r, _, fs in os.walk(d) for f in fs)
    sha = {f: hashlib.sha256(open(os.path.join(d, f), "rb").read()).hexdigest() for f in files}
    mods.append({"name": name, "tier": tier, "version": man.get("version", ""), "base": f"{tier}/{name}", "files": files, "sha256": sha})
json.dump({"modules": mods}, open(os.path.join(out, "catalog.json"), "w"), indent=2)
print(f"catalog.json: {len(mods)} module(s)")
PY
