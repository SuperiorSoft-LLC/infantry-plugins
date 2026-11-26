#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Builds Infantry_News (the daemon half as a wasm32-wasip2 component, the web UI half with the app's plugin build) and
# lays it out the way the daemon loads it:
#   <out>/official/Infantry_News/module.json
#   <out>/official/Infantry_News/daemon.component
#   <out>/official/Infantry_News/ui/dist/index.js, index.css
# Needs a checkout of infantry-ai at <repo>/.infantry-ai (INFANTRY_AI overrides) with `pnpm install` run in its app/.
# Usage: stage.sh <out-dir> [--env prod|staging|dev] [--release]   (--env is accepted for the common contract; unused)
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="${1:?usage: stage.sh <out-dir> [--env E] [--release]}"; shift
profile=debug; flag=""
while [ $# -gt 0 ]; do
  case "$1" in --env) shift 2;; --release) profile=release; flag="--release"; shift;; *) echo "unknown arg $1" >&2; exit 2;; esac
done
ai="${INFANTRY_AI:-$here/../../.infantry-ai}"
[ -f "$ai/app/packages/ui-plugin-api/build/build-plugins.mjs" ] || { echo "refuse: no infantry-ai checkout at $ai (set INFANTRY_AI)" >&2; exit 1; }
[ -d "$ai/app/node_modules" ] || { echo "refuse: run pnpm install in $ai/app first" >&2; exit 1; }
node "$ai/app/packages/ui-plugin-api/build/build-plugins.mjs" "$here"
cd "$here"
cargo build --lib --target wasm32-wasip2 $flag
target_dir="$(cargo metadata --format-version 1 --no-deps | python -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
dest="$out/official/Infantry_News"
rm -rf "$dest"; mkdir -p "$dest/ui"
cp "$here/module.json" "$dest/module.json"
cp "$target_dir/wasm32-wasip2/$profile/infantry_news.wasm" "$dest/daemon.component"
cp -r "$here/ui/dist" "$dest/ui/dist"
echo "staged Infantry_News -> $dest"
