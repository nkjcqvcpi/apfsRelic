//! `apfsrelic` — read-only, non-`sudo` APFS image reader (Rust rewrite).

use std::process::ExitCode;

mod cli;
mod commands;

use apfsrelic_core::error::{Error, ErrorKind, Result};
use apfsrelic_core::json::Envelope;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage();
        return ExitCode::from(ErrorKind::Usage.exit_code() as u8);
    }

    let command = args[1].as_str();
    if matches!(command, "-h" | "--help" | "help") {
        print_usage();
        return ExitCode::SUCCESS;
    }
    if matches!(command, "-V" | "--version" | "version") {
        println!("apfsrelic {VERSION}");
        return ExitCode::SUCCESS;
    }

    let rest = &args[2..];
    let opts = match cli::parse(rest) {
        Ok(o) => o,
        Err(e) => return finish(command, rest, Err(e)),
    };

    let result = dispatch(command, &opts);
    finish_with_opts(command, &opts, result)
}

fn dispatch(command: &str, opts: &cli::Options) -> Result<i32> {
    match command {
        "inspect" => commands::inspect::run(opts),
        "partitions" => commands::partitions::run(opts),
        "volumes" => commands::volumes::run(opts),
        "snapshots" => commands::snapshots::run(opts),
        "history-union" => commands::history_union::run(opts),
        "ls" => commands::ls::run(opts),
        "stat" => commands::stat::run(opts),
        "recover" => commands::recover::run(opts),
        "recover-manifest" => commands::recover_manifest::run(opts),
        "verify" => commands::verify::run(opts),
        other => Err(Error::new(
            ErrorKind::Usage,
            format!("unknown command `{other}` (try `apfsrelic help`)"),
        )),
    }
}

/// Translate a command result into an exit code, printing a structured error if
/// it failed. `--json` errors are printed as a JSON envelope on stdout.
fn finish_with_opts(command: &str, opts: &cli::Options, result: Result<i32>) -> ExitCode {
    match result {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            if opts.json {
                let env = Envelope::new(command).error(e.kind().code(), &e.to_string());
                println!("{}", env.to_json_string());
            } else {
                eprintln!("apfsrelic: {}: {}", e.kind().code(), e);
            }
            ExitCode::from(e.kind().exit_code() as u8)
        }
    }
}

/// Same as [`finish_with_opts`] but used before options parse (no `--json`
/// context yet); emits a plain-text error.
fn finish(command: &str, rest: &[String], result: Result<i32>) -> ExitCode {
    // If the user asked for JSON even with a parse error, honor it best-effort.
    let json = rest.iter().any(|a| a == "--json");
    match result {
        Ok(code) => ExitCode::from(code as u8),
        Err(e) => {
            if json {
                let env = Envelope::new(command).error(e.kind().code(), &e.to_string());
                println!("{}", env.to_json_string());
            } else {
                eprintln!("apfsrelic: {}: {}", e.kind().code(), e);
            }
            ExitCode::from(e.kind().exit_code() as u8)
        }
    }
}

fn print_usage() {
    eprintln!(
        "apfsrelic {VERSION} — read-only APFS image reader (no sudo, no hdiutil)\n\
\n\
USAGE:\n\
  apfsrelic <command> [options]\n\
\n\
COMMANDS:\n\
  inspect      Container/checkpoint/volume overview (+ --partitions)\n\
  partitions   List GPT partitions of an image\n\
  volumes      List volumes in the container\n\
  snapshots    List a volume's snapshots\n\
  history-union Build a newest-wins leaf manifest across snapshots\n\
  ls           List a directory (machine-readable with --json)\n\
  stat         Show all metadata for a file/dir (--records --extents --xattrs)\n\
  recover      Recover a file or folder by path/FSOID\n\
  recover-manifest Recover JSONL-selected snapshot leaves under one output root\n\
  verify       Structural integrity checks\n\
\n\
COMMON OPTIONS:\n\
  --container <path>     Image: .sparsebundle, raw image, or device\n\
  --volume <n>           1-based volume index (or --volume-name <name>)\n\
  --partition <auto|n>   Choose APFS partition (default: auto via GPT)\n\
  --offset <bytes>       Explicit APFS container byte offset\n\
  --max-xid <xid>        Cap checkpoint selection at this transaction id\n\
  --snapshot <name> | --snapshot-xid <xid>   Browse a snapshot\n\
  --path-template <p>  Per-snapshot root; {{snapshot-dir}} strips the Time Machine prefix\n\
  --format <jsonl|tsv> History manifest format (default: jsonl)\n\
  --path <p> | --fsoid <id>   Filesystem entry point\n\
  --output <p>           Recovery destination (file or folder)\n\
  --manifest <jsonl> --output-root <dir>  Batch recovery input and fixed destination\n\
  --fallback-history     Retry failed/partial rows in older snapshots\n\
  --json                 Emit stable JSON on stdout (logs go to stderr)\n\
\n\
EXAMPLES:\n\
  apfsrelic inspect  --container tm.sparsebundle --json\n\
  apfsrelic history-union --container tm.sparsebundle --volume 1 --path-template '/{{snapshot-dir}}/Macintosh HD - Data/Users/me' --format jsonl --output history.jsonl\n\
  apfsrelic ls       --container tm.sparsebundle --volume 1 --path / --json --sizes\n\
  apfsrelic recover  --container tm.sparsebundle --volume 1 --path /Users/x/f --output ./f\n\
  apfsrelic recover-manifest --container tm.sparsebundle --volume 1 --manifest rows.jsonl --output-root ./restored --fallback-history --path-template '/{{snapshot-dir}}/Data/Users/me'\n"
    );
}
