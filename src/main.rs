use clap::{Parser, Subcommand};
use std::path::{Path, PathBuf};
use sys_resolver::audit;
use sys_resolver::remap::{self, Roots};
use sys_resolver::toolchain::{self, Libc};

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
    /// Print the shell lines that build with a libc's toolchain:
    /// eval "$(sys-resolver env glibc)". Without an argument, the system's setting.
    Env {
        /// musl or glibc
        libc: Option<String>,
    },
    /// Pick the toolchain the system builds with: elevate sys-resolver set glibc|musl.
    /// With glibc, gcc/cc/g++/c++/cpp start glibc's compiler and pkg-config sees glibc's
    /// libraries; programs keep running with the libc they were linked against.
    Set {
        /// musl or glibc
        libc: String,
    },
    /// Show which toolchain builds use, and why.
    Get,
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
        Command::Env { libc } => cmd_env(libc.as_deref(), &roots),
        Command::Set { libc } => cmd_set(libc, &roots),
        Command::Get => cmd_get(&roots),
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

fn parse_libc(s: &str) -> Libc {
    Libc::parse(s).unwrap_or_else(|| {
        eprintln!("unknown libc '{s}': musl or glibc");
        std::process::exit(2);
    })
}

fn cmd_env(libc: Option<&str>, roots: &Roots) {
    let libc = libc.map_or_else(|| toolchain::system_setting(roots), parse_libc);
    if libc == Libc::Glibc && !toolchain::glibc_toolchain_installed(roots) {
        eprintln!("the glibc toolchain is not installed: elevate zex install glibc-toolchain");
        std::process::exit(1);
    }
    print!("{}", toolchain::env(roots, libc));
}

fn cmd_set(libc: &str, roots: &Roots) {
    let libc = parse_libc(libc);
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("run it as root: elevate sys-resolver set {}", libc.name());
        std::process::exit(1);
    }
    if libc == Libc::Glibc && !toolchain::glibc_toolchain_installed(roots) {
        eprintln!("the glibc toolchain is not installed: elevate zex install glibc-toolchain");
        std::process::exit(1);
    }
    let path = toolchain::setting_path(roots);
    let written = path
        .parent()
        .map_or(Ok(()), std::fs::create_dir_all)
        .and_then(|()| std::fs::write(&path, format!("{}\n", libc.name())));
    if let Err(e) = written {
        eprintln!("cannot write {}: {e}", path.display());
        std::process::exit(1);
    }
    match libc {
        Libc::Glibc => println!(
            "builds use glibc now: gcc, cc, g++, c++ and cpp start {g}-gcc/-g++, pkg-config sees\n\
             only {dir}. Programs keep running with the libc they were linked against.\n\
             musl's compiler stays {m}-gcc. Back to musl: elevate sys-resolver set musl",
            g = toolchain::GNU,
            m = toolchain::MUSL,
            dir = toolchain::glibc_dir(roots).display()
        ),
        Libc::Musl => println!("builds use musl, the base's toolchain"),
    }
}

fn cmd_get(roots: &Roots) {
    let system = toolchain::system_setting(roots);
    match std::env::var(toolchain::ENV).ok().as_deref().and_then(Libc::parse) {
        Some(l) => println!("{} (from {} in this environment; the system's setting is {})", l.name(), toolchain::ENV, system.name()),
        None => println!("{} (the system's setting)", system.name()),
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
