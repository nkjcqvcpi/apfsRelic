# apfsRelic

An APFS image reader — a Rust rewrite of the [drat](https://github.com/jivanpal/drat). Browse, inspect, and recover files from Apple File System images
(`.sparsebundle` Time Machine backups, raw containers, GPT whole-disk images)
without `hdiutil attach`, without mounting, and without writing to the input.

All on-disk structures follow the **Apple File System Reference (2020-06-22)**.

## Workspace layout

apfsRelic is a Cargo workspace ([The Cargo Book — Workspaces][ws]):

| Crate | Path | What it is |
|-------|------|-----------|
| `apfsrelic-core` | [`crates/core`](crates/core) | Read-only APFS engine — parsers, B-trees, recovery. **Dependency-free & auditable.** |
| `apfsrelic-cli`  | [`crates/cli`](crates/cli)   | The `apfsrelic` command-line binary. |
| `apfsrelic-gui`  | [`crates/gui`](crates/gui)   | Tauri v2 desktop GUI (a file explorer that links `core` directly). |

Both the CLI and the GUI depend on the same `core` library — `core → cli` and
`core → gui` in parallel, so the GUI never shells out to the binary.

[ws]: https://doc.rust-lang.org/cargo/reference/workspaces.html

## Build

```sh
# CLI + engine (no GUI toolchain required) -> ./target/release/apfsrelic
cargo build --release -p apfsrelic-cli
make ci                                    # fmt + clippy -D warnings + tests (core + cli)

# Desktop GUI (Tauri v2)
cargo run -p apfsrelic-gui                 # or: make gui
```

`core` and `cli` have **no third-party runtime dependencies**. The GUI crate
pulls in Tauri and is the only part that does; on Linux it needs the usual
WebKitGTK build dependencies (see `.github/workflows/ci.yml`).

## Usage

```sh
apfsrelic inspect   --container tm.sparsebundle --json
apfsrelic volumes   --container tm.sparsebundle --json
apfsrelic snapshots --container tm.sparsebundle --volume 1 --json
apfsrelic history-union --container tm.sparsebundle --volume 1 \
  --path-template '/{snapshot-dir}/Macintosh HD - Data/Users/me' \
  --format jsonl --output history.jsonl --best-effort
apfsrelic ls        --container tm.sparsebundle --volume 1 --path / --json --sizes
apfsrelic stat      --container tm.sparsebundle --volume 1 --path /Users/me/f --json --extents
apfsrelic recover   --container tm.sparsebundle --volume 1 --path /Users/me/f --output ./f
apfsrelic recover-manifest --container tm.sparsebundle --volume 1 \
  --manifest recovery.jsonl --output-root ./restored --fallback-history \
  --path-template '/{snapshot-dir}/Macintosh HD - Data/Users/me' > results.jsonl
apfsrelic verify    --container tm.sparsebundle --volume 1 --json
```

`apfsrelic help` lists every command and option.

`history-union` opens the image once, scans snapshots oldest to newest, and
emits one ordinary-file or symlink row per raw relative path. The latest
observation wins. Rows absent from the latest selected snapshot are marked
`historical_deleted`; paths below an unreadable latest-snapshot prefix are
`unknown_latest_scan`, not falsely classified as deleted. Directories are used
only to detect structural conflicts. `--snapshot` or `--snapshot-xid` sets the
latest boundary. `{snapshot}` expands to the full APFS snapshot name, while
`{snapshot-dir}` removes the `com.apple.TimeMachine.` prefix so it matches the
backup directory name. JSONL and TSV manifests include the selected source path,
snapshot name/XID/date, logical size, decision, and reason. `collision_key` is a
lowercase audit hint only; the raw relative path is the authoritative key.

`recover-manifest` consumes JSONL rows with `snapshot_xid`, `source_path`, and
`output_relative_path`. Optional `snapshot_name`, `fsoid`, and `type` fields are
checked against the selected source. `--fallback-history` also requires
`relative_path`; an error or partial extraction is then retried in each older
snapshot using `--path-template`. Only a complete attempt is installed. Results
are flushed as JSONL and record every attempted snapshot plus the actual source
snapshot. Output paths must remain below `--output-root`; absolute paths, `..`,
and symbolic-link parents are rejected. Existing leaves are skipped unless
`--overwrite` is explicit.

## GUI

`make gui` opens a desktop file-explorer (Tauri v2). It starts on a landing
page with the recently-opened images; opening a `.sparsebundle` or raw image
shows a two-pane explorer plus a metadata dashboard (container superblock,
volumes, sparsebundle band health, snapshots, and per-file details). Rows are
checkbox-selectable and "Recover selected" restores any mix of files and
folders — folders recurse — into a chosen destination with live progress and a
per-file report. Everything calls `apfsrelic-core` in-process — no subprocess,
no local web server. `$APFSRELIC_CONTAINER` / `$APFSRELIC_VOLUME` preseed the
selection for development.

## What it does / doesn't do

- ✅ Sparsebundle/raw/GPT images, checkpoint selection with fallback, object maps,
  B-trees, snapshots, inodes/dir-records/extents/xattrs, sparse files, hard links,
  symlinks, case-insensitive paths, file & folder recovery, structured JSON.
- 🟥 Encryption (detected and refused; `--raw-extents` for forensic dumps),
  writing/repair (never), sealed-volume seal validation, Fusion tier-2,
  compressed/encrypted DMGs.

## Guarantees

- **Read-only**: backends expose no write method and open inputs read-only; the
  only writes are to `--output` via temp-file + atomic rename.
- **No panics on bad input**: every offset/length is bounds-checked; parsers
  return typed errors; a fuzz harness asserts the invariant.

## Documentation

Full user and developer docs are in the project wiki:
Getting Started, Commands, Formats & Features, Recovery, Snapshots, JSON Schema,
Architecture, APFS Internals, Error Model, Testing, Read-only Guarantees.

## License

GPL-3.0-or-later (inherited from the original C prototype).
