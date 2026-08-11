//! Minimal dependency-free command-line parsing.
//!
//! Supports `--flag`, `--key value`, and `--key=value`. Numbers accept decimal
//! or `0x`-prefixed hex (matching the C prototype's `parse_number`). Unknown
//! options are reported as usage errors rather than ignored.

use std::collections::HashMap;
use std::path::PathBuf;

use apfsrelic_core::device::partition::PartitionSelector;
use apfsrelic_core::error::{Error, ErrorKind, Result};

/// Boolean flags that take no value.
const FLAGS: &[&str] = &[
    "json",
    "sizes",
    "best-effort",
    "raw-extents",
    "overwrite",
    "fallback-history",
    "dry-run",
    "records",
    "extents",
    "xattrs",
    "partitions",
    "recursive",
    "help",
];

/// Parsed options shared across commands. Commands read the fields they need.
#[derive(Debug, Clone)]
pub struct Options {
    pub container: Option<PathBuf>,
    pub volume: Option<u32>,
    pub volume_name: Option<String>,
    pub partition: PartitionSelector,
    pub offset: Option<u64>,
    pub max_xid: u64,
    pub json: bool,
    pub sizes: bool,
    pub path: Option<String>,
    /// Per-snapshot root path. `{snapshot}` is replaced with the snapshot name.
    pub path_template: Option<String>,
    pub fsoid: Option<u64>,
    pub output: Option<String>,
    /// JSONL work list consumed by `recover-manifest` (`-` means stdin).
    pub manifest: Option<PathBuf>,
    /// Fixed destination boundary for manifest recovery.
    pub output_root: Option<PathBuf>,
    pub snapshot: Option<String>,
    pub snapshot_xid: Option<u64>,
    pub best_effort: bool,
    pub raw_extents: bool,
    pub overwrite: bool,
    pub fallback_history: bool,
    pub dry_run: bool,
    pub records: bool,
    pub extents: bool,
    pub xattrs: bool,
    pub partitions: bool,
    /// Accepted (so `--recursive` isn't rejected) but not yet consumed by any command.
    #[allow(dead_code)]
    pub recursive: bool,
    pub metadata: Option<String>,
    pub sort: Option<String>,
    /// Streaming manifest format (`jsonl` or `tsv`).
    pub format: Option<String>,
    /// Per-command `--help` is accepted for forward-compat; top-level help is
    /// handled in `main` before options are parsed.
    #[allow(dead_code)]
    pub help: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            container: None,
            volume: None,
            volume_name: None,
            partition: PartitionSelector::Auto,
            offset: None,
            max_xid: u64::MAX,
            json: false,
            sizes: false,
            path: None,
            path_template: None,
            fsoid: None,
            output: None,
            manifest: None,
            output_root: None,
            snapshot: None,
            snapshot_xid: None,
            best_effort: false,
            raw_extents: false,
            overwrite: false,
            fallback_history: false,
            dry_run: false,
            records: false,
            extents: false,
            xattrs: false,
            partitions: false,
            recursive: false,
            metadata: None,
            sort: None,
            format: None,
            help: false,
        }
    }
}

/// Parse a numeric argument: decimal, or `0x`/`0X` hex.
pub fn parse_number(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse::<u64>().ok()
    }
}

/// Parse command options from the argument list (after the command name).
pub fn parse(args: &[String]) -> Result<Options> {
    let mut raw: HashMap<String, String> = HashMap::new();
    let mut flags: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        let name = match arg.strip_prefix("--") {
            Some(n) => n,
            None => {
                return Err(Error::new(
                    ErrorKind::Usage,
                    format!("unexpected argument `{arg}` (options start with `--`)"),
                ));
            }
        };

        if let Some((k, v)) = name.split_once('=') {
            raw.insert(k.to_string(), v.to_string());
            i += 1;
            continue;
        }

        if FLAGS.contains(&name) {
            flags.push(name.to_string());
            i += 1;
            continue;
        }

        // key value
        let value = args.get(i + 1).ok_or_else(|| {
            Error::new(
                ErrorKind::Usage,
                format!("option `--{name}` requires a value"),
            )
        })?;
        raw.insert(name.to_string(), value.clone());
        i += 2;
    }

    let mut opts = Options {
        json: flags.iter().any(|f| f == "json"),
        sizes: flags.iter().any(|f| f == "sizes"),
        best_effort: flags.iter().any(|f| f == "best-effort"),
        raw_extents: flags.iter().any(|f| f == "raw-extents"),
        overwrite: flags.iter().any(|f| f == "overwrite"),
        fallback_history: flags.iter().any(|f| f == "fallback-history"),
        dry_run: flags.iter().any(|f| f == "dry-run"),
        records: flags.iter().any(|f| f == "records"),
        extents: flags.iter().any(|f| f == "extents"),
        xattrs: flags.iter().any(|f| f == "xattrs"),
        partitions: flags.iter().any(|f| f == "partitions"),
        recursive: flags.iter().any(|f| f == "recursive"),
        help: flags.iter().any(|f| f == "help"),
        ..Default::default()
    };

    for (k, v) in raw {
        match k.as_str() {
            "container" => opts.container = Some(PathBuf::from(v)),
            "volume" => {
                opts.volume = Some(
                    parse_number(&v)
                        .and_then(|n| u32::try_from(n).ok())
                        .ok_or_else(|| {
                            Error::new(ErrorKind::Usage, format!("invalid --volume `{v}`"))
                        })?,
                )
            }
            "volume-name" => opts.volume_name = Some(v),
            "partition" => {
                opts.partition = if v == "auto" {
                    PartitionSelector::Auto
                } else {
                    let idx = parse_number(&v)
                        .and_then(|n| u32::try_from(n).ok())
                        .ok_or_else(|| {
                            Error::new(ErrorKind::Usage, format!("invalid --partition `{v}`"))
                        })?;
                    PartitionSelector::Index(idx)
                }
            }
            "offset" => {
                opts.offset = Some(parse_number(&v).ok_or_else(|| {
                    Error::new(ErrorKind::Usage, format!("invalid --offset `{v}`"))
                })?)
            }
            "max-xid" => {
                opts.max_xid = parse_number(&v).ok_or_else(|| {
                    Error::new(ErrorKind::Usage, format!("invalid --max-xid `{v}`"))
                })?
            }
            "path" => opts.path = Some(v),
            "path-template" => opts.path_template = Some(v),
            "fsoid" => {
                opts.fsoid = Some(parse_number(&v).ok_or_else(|| {
                    Error::new(ErrorKind::Usage, format!("invalid --fsoid `{v}`"))
                })?)
            }
            "output" => opts.output = Some(v),
            "manifest" => opts.manifest = Some(PathBuf::from(v)),
            "output-root" => opts.output_root = Some(PathBuf::from(v)),
            "snapshot" => opts.snapshot = Some(v),
            "snapshot-xid" => {
                opts.snapshot_xid = Some(parse_number(&v).ok_or_else(|| {
                    Error::new(ErrorKind::Usage, format!("invalid --snapshot-xid `{v}`"))
                })?)
            }
            "metadata" => opts.metadata = Some(v),
            "sort" => opts.sort = Some(v),
            "format" => opts.format = Some(v),
            // Accepted for backwards compatibility with the GUI/base args; the
            // block size is auto-detected from the container superblock, so any
            // value (including "auto") is honoured only when it is a number.
            "block-size" => {
                if v != "auto" {
                    let _ = parse_number(&v); // tolerate explicit sizes; auto-detect anyway
                }
            }
            other => {
                return Err(Error::new(
                    ErrorKind::Usage,
                    format!("unknown option `--{other}`"),
                ));
            }
        }
    }

    Ok(opts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_numbers() {
        assert_eq!(parse_number("0x10"), Some(16));
        assert_eq!(parse_number("42"), Some(42));
        assert_eq!(parse_number("nope"), None);
    }

    #[test]
    fn parses_mixed_forms() {
        let a = vec![
            "--container".into(),
            "/x".into(),
            "--volume=1".into(),
            "--json".into(),
            "--max-xid".into(),
            "0x1f".into(),
        ];
        let o = parse(&a).unwrap();
        assert_eq!(o.container.unwrap().to_str().unwrap(), "/x");
        assert_eq!(o.volume, Some(1));
        assert!(o.json);
        assert_eq!(o.max_xid, 0x1f);
    }

    #[test]
    fn unknown_option_errors() {
        assert!(parse(&["--bogus".into(), "x".into()]).is_err());
    }

    #[test]
    fn parses_history_manifest_options() {
        let args = vec![
            "--path-template".into(),
            "/{snapshot}/Data/Users/me".into(),
            "--format".into(),
            "tsv".into(),
        ];
        let options = parse(&args).unwrap();
        assert_eq!(
            options.path_template.as_deref(),
            Some("/{snapshot}/Data/Users/me")
        );
        assert_eq!(options.format.as_deref(), Some("tsv"));
    }

    #[test]
    fn parses_recover_manifest_options() {
        let args = vec![
            "--manifest".into(),
            "rows.jsonl".into(),
            "--output-root=/restore".into(),
            "--fallback-history".into(),
        ];
        let options = parse(&args).unwrap();
        assert_eq!(
            options.manifest.as_deref(),
            Some(std::path::Path::new("rows.jsonl"))
        );
        assert_eq!(
            options.output_root.as_deref(),
            Some(std::path::Path::new("/restore"))
        );
        assert!(options.fallback_history);
    }
}
