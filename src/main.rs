//! CLI for sigmaos-sec-audit.

use clap::Parser;
use sigmaos_sec_audit::{render_text, scan};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "sigmaos-sec-audit", about = "SigmaOS security audit scanner")]
struct Cli {
    /// Directory to scan (default: current directory).
    #[arg(default_value = ".")]
    path: PathBuf,
    /// Output JSON instead of text.
    #[arg(long)]
    json: bool,
    /// Exit non-zero if critical findings exist.
    #[arg(long)]
    strict: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let cli = Cli::parse();
    let report = scan(&cli.path)?;

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", render_text(&report));
    }

    if cli.strict && report.has_critical() {
        std::process::exit(2);
    }
    Ok(())
}
