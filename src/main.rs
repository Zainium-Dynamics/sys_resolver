use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use sys_resolver::audit;
use sys_resolver::remap::{self, Roots};

/// sys_resolver — dynamic FHS-path resolution logic for ZainiumOS.
#[derive(Parser)]
#[command(name = "sys-resolver", version)]
struct Cli {
    /// Override the system root (defaults to $ZAINIUM_ZAIROOT, then `/`).
    #[arg(long, global = true)]
    zairoot: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Report what a legacy FHS-shaped path resolves to right now.
    Resolve {
        /// Absolute path to resolve, e.g. /usr/bin/env
        path: PathBuf,
    },
    /// Audit the resolver against the real, live tree.
    Doctor,
}

fn roots_for(cli: &Cli) -> Roots {
    match &cli.zairoot {
        Some(p) => Roots::under(p),
        None => Roots::from_env(),
    }
}

fn main() {
    let cli = Cli::parse();
    let roots = roots_for(&cli);

    match &cli.command {
        Command::Resolve { path } => cmd_resolve(path, &roots),
        Command::Doctor => cmd_doctor(&roots),
    }
}

fn cmd_resolve(path: &Path, roots: &Roots) {
    if !path.is_absolute() {
        eprintln!("not an absolute path: {}", path.display());
        std::process::exit(2);
    }
    match remap::resolve(path, roots) {
        Some(real) => {
            println!("{} -> {}", path.display(), real.display());
        }
        None => {
            if remap::in_scope(path) {
                println!("{} -> (not found under any root)", path.display());
            } else {
                println!("{} -> (out of scope, left alone)", path.display());
            }
            std::process::exit(1);
        }
    }
}

/// Sanity probes — not a destination table, just a short well-known list.
const WELL_KNOWN_PROBES: &[&str] = &[
    "/usr/bin/env",
    "/bin/sh",
    "/usr/bin/bash",
    "/usr/bin/python3",
    "/usr/bin/gcc",
    "/usr/bin/ld",
    "/usr/lib/libc.a",
];

fn cmd_doctor(roots: &Roots) {
    println!("== well-known probes ==");
    let mut probe_misses = 0;
    for p in WELL_KNOWN_PROBES {
        let path = Path::new(p);
        match remap::resolve(path, roots) {
            Some(real) => println!("  ok    {p} -> {}", real.display()),
            None => {
                println!("  MISSING  {p}");
                probe_misses += 1;
            }
        }
    }

    println!();
    println!("== full-tree reachability audit (every real file, all three roots) ==");
    let (results, elapsed) = audit::full_audit(roots);

    let mut total_checked = 0usize;
    let mut total_dangling = 0usize;
    let mut total_gaps = 0usize;
    for r in &results {
        total_checked += r.checked;
        let dangling = r
            .misses
            .iter()
            .filter(|m| matches!(m.reason, audit::MissReason::SourceIsDanglingSymlink))
            .count();
        let gaps = r.misses.len() - dangling;
        total_dangling += dangling;
        total_gaps += gaps;
        println!(
            "  {:<14} checked {:>6}   dangling-symlink {:>4}   genuine-gap {:>4}",
            r.root_label, r.checked, dangling, gaps
        );
    }
    println!(
        "  total: {total_checked} real files checked in {:.2?} ({:.0} files/sec)",
        elapsed,
        total_checked as f64 / elapsed.as_secs_f64().max(0.001)
    );

    if total_dangling > 0 {
        println!();
        println!("  {total_dangling} pre-existing dangling symlinks (not a resolver bug — the source itself points nowhere):");
        for r in &results {
            for m in &r.misses {
                if matches!(m.reason, audit::MissReason::SourceIsDanglingSymlink) {
                    println!("    {}", m.real_path.display());
                }
            }
        }
    }
    if total_gaps > 0 {
        println!();
        println!("  {total_gaps} genuine gaps (real file exists, no legacy alias reaches it):");
        for r in &results {
            for m in &r.misses {
                if matches!(m.reason, audit::MissReason::NoAliasResolved) {
                    println!(
                        "    {}  (tried {})",
                        m.real_path.display(),
                        m.alias_tried.display()
                    );
                }
            }
        }
    }
    if total_dangling == 0 && total_gaps == 0 {
        println!();
        println!("  every real file is reachable through a legacy FHS-shaped alias.");
    }

    if probe_misses > 0 || total_gaps > 0 {
        std::process::exit(1);
    }
}
