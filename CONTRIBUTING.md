# Contributing a plugin

## Submit

Build your plugin as described in the Infantry AI wiki: Plugins, Create, Build and Publish
(`docs/wiki/plugins/` in the infantry-ai repository). Release the built module folder (`module.json`, its
`daemon.component` or sidecar, `ui/dist`) as an asset of a GitHub release of your repository.

Then open a PR that adds `community/<Id>.json` with `id`, `description`, `tags`, `license`, `repo` (`owner/name`) and one
`versions` entry (`version`, `url` under `https://github.com/<repo>/releases/`, `sha256`, `size`). The shape is
`schema/catalog-entry.schema.json`.

## New version

Append an object to `versions` (never edit an old one's `url` or `sha256`). Its `url` must be under
`https://github.com/<repo>/releases/`.

## Yank

Set `"yanked": true` and `"yankedReason": "..."` on the version. Do not delete it.

## Checks

CI builds the catalog, then downloads each version and checks sha256, size and grants. A mismatch fails the PR.
A missing `license` is a warning, not a failure. Entries tagged `example` (such as `Example_Starter`) have no
versions, so there is nothing to download; they are skipped by the asset check.
