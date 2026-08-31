//! Full-tree reachability audit — `doctor`'s real work.
//!
//! Walks *every* real file under each root (tens of thousands of files —
//! this is the actual, currently-installed set of real packages on the
//! system, not a sample) and checks that a plain `/usr/<remainder>`-shaped
//! legacy alias reaches it through [`crate::remap::resolve`]. That alias
//! shape is exactly what any ordinary FHS-authored package (the "100+
//! FHS-based tools" this resolver exists for) already hardcodes.

use crate::remap::{self, Roots};
use std::path::{Path, PathBuf};
use std::time::Instant;

pub struct AuditResult {
    pub root_label: &'static str,
    pub checked: usize,
    pub misses: Vec<Miss>,
}

pub struct Miss {
    pub real_path: PathBuf,
    pub alias_tried: PathBuf,
    pub reason: MissReason,
}

pub enum MissReason {
    /// The real entry itself is a dangling symlink — no alias could ever
    /// reach it, since there's nothing at the end of it to reach. Not a
    /// resolver bug; a pre-existing issue in the installed tree.
    SourceIsDanglingSymlink,
    /// The alias genuinely doesn't resolve to anything, even though the
    /// real file exists. A real resolver gap.
    NoAliasResolved,
}

/// Recursively collect every file/symlink under `root`, as paths relative
/// to `root`. Does not follow symlinked directories (avoids cycles) and
/// skips `exclude` (an absolute path) entirely, so callers can audit
/// `syshub` and its nested `MUSL_SYSDIR` as two separate, non-overlapping
/// roots.
fn walk_relative(root: &Path, exclude: Option<&Path>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if Some(path.as_path()) == exclude {
                continue;
            }
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.is_dir() {
                stack.push(path);
            } else {
                // Regular file or symlink (dangling or not) — a leaf.
                if let Ok(rel) = path.strip_prefix(root) {
                    out.push(rel.to_path_buf());
                }
            }
        }
    }
    out
}

fn audit_one_root(
    label: &'static str,
    root: &Path,
    exclude: Option<&Path>,
    roots: &Roots,
) -> AuditResult {
    let relatives = walk_relative(root, exclude);
    let mut misses = Vec::new();
    for rel in &relatives {
        let alias = PathBuf::from("/usr").join(rel);
        if remap::resolve(&alias, roots).is_some() {
            continue;
        }
        let real_path = root.join(rel);
        let reason = if std::fs::metadata(&real_path).is_err()
            && std::fs::symlink_metadata(&real_path).is_ok()
        {
            MissReason::SourceIsDanglingSymlink
        } else {
            MissReason::NoAliasResolved
        };
        misses.push(Miss {
            real_path,
            alias_tried: alias,
            reason,
        });
    }
    AuditResult {
        root_label: label,
        checked: relatives.len(),
        misses,
    }
}

/// Audit all three roots. Returns one [`AuditResult`] per root plus the
/// total wall time taken, so callers can report it stayed fast.
pub fn full_audit(roots: &Roots) -> (Vec<AuditResult>, std::time::Duration) {
    let start = Instant::now();
    let results = vec![
        // syshub, excluding the nested MUSL_SYSDIR subtree so it's only
        // counted once, under its own root below.
        audit_one_root("syshub", &roots.syshub, Some(roots.musl_sysdir.as_path()), roots),
        audit_one_root("MUSL_SYSDIR", &roots.musl_sysdir, None, roots),
        audit_one_root("zexlib/union", &roots.union, None, roots),
    ];
    (results, start.elapsed())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn live_roots() -> Roots {
        Roots::under(Path::new("/run/media/alizain/ZAINIUM_DRIVE/zairoot"))
    }

    /// The real, exhaustive test: every real file currently installed
    /// across all three roots — tens of thousands of files, standing in
    /// for "100+ real FHS-authored packages" already unpacked onto this
    /// system — must be reachable through a `/usr/<remainder>`-shaped
    /// alias, unless it's a pre-existing dangling symlink (a real,
    /// separate issue in the tree, not something any resolver can fix).
    #[test]
    fn every_real_file_is_reachable_or_a_known_dangling_symlink() {
        let roots = live_roots();
        let (results, elapsed) = full_audit(&roots);

        let mut total_checked = 0usize;
        let mut genuine_gaps: Vec<String> = Vec::new();
        for r in &results {
            total_checked += r.checked;
            for m in &r.misses {
                if matches!(m.reason, MissReason::NoAliasResolved) {
                    genuine_gaps.push(format!(
                        "{} (tried {})",
                        m.real_path.display(),
                        m.alias_tried.display()
                    ));
                }
            }
        }

        // Sanity: this must actually have walked a large, real tree —
        // fails loudly if the zairoot fixture path ever moves/vanishes,
        // instead of silently "passing" over zero files.
        assert!(
            total_checked > 30_000,
            "expected tens of thousands of real files, only found {total_checked} — \
             is the live zairoot tree still at the expected path?"
        );

        assert!(
            genuine_gaps.is_empty(),
            "{} real files have no working legacy alias:\n{}",
            genuine_gaps.len(),
            genuine_gaps.join("\n")
        );

        // Speed guard — this is meant to stay fast enough to run on every
        // `cargo test`, not become a multi-second integration test.
        assert!(
            elapsed.as_secs() < 5,
            "full audit took {elapsed:?} for {total_checked} files — too slow"
        );
    }
}
