#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Builds the infantry-sites sidecar and lays it out the way the daemon loads it:
#   <out>/official/Infantry_Sites/module.json
#   <out>/official/Infantry_Sites/bin/infantry-sites[.exe]
# The committed module.json writes the account descriptor's URLs as {api} and {site}: the account hub needs absolute
# URLs, so this script renders them from the module's `endpoints` for <env> (prod|staging|dev, default staging).
# Usage: stage.sh <out-dir> [--env prod|staging|dev] [--release] [--api <url> --site <url>]
#   --api/--site point staging and dev (never prod) at a local stack, e.g.
#   --api http://127.0.0.1:18961/api/superiorsoft --site http://127.0.0.1:18961
# Then run a daemon with INFANTRY_PLUGINS_DIR=<out>.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="${1:?usage: stage.sh <out-dir> [--env E] [--release] [--api URL --site URL]}"; shift
env=staging; profile=debug; flag=""; api=""; site=""
while [ $# -gt 0 ]; do
  case "$1" in
    --env) env="$2"; shift 2;; --release) profile=release; flag="--release"; shift;;
    --api) api="$2"; shift 2;; --site) site="$2"; shift 2;; *) echo "unknown arg $1" >&2; exit 2;;
  esac
done
cd "$here"
cargo build $flag
target_dir="$(cargo metadata --format-version 1 --no-deps | python -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
exe="$target_dir/$profile/infantry-sites"; [ -f "$exe.exe" ] && exe="$exe.exe"
dest="$out/official/Infantry_Sites"
rm -rf "$dest"; mkdir -p "$dest/bin"
cp "$exe" "$dest/bin/"
python - "$here/module.json" "$dest/module.json" "$env" "$api" "$site" <<'PY'
import json, sys
src, dst, env, api, site = sys.argv[1:6]
m = json.load(open(src))
ep = m["daemon"]["endpoints"]
if api: ep["api"].update({k: api for k in ep["api"] if k != "prod"})
if site: ep["site"].update({k: site for k in ep["site"] if k != "prod"})
a, s = ep["api"][env].rstrip("/"), ep["site"][env].rstrip("/")
text = json.dumps(m, indent=2).replace("{api}", a).replace("{site}", s)
open(dst, "w").write(text + "\n")
PY
echo "staged Infantry_Sites ($env) -> $dest"
