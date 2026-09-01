//! Full-tree reachability audit — `doctor`'s real work.

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
    /// Not a resolver bug — the source itself is a dangling symlink.
    SourceIsDanglingSymlink,
    NoAliasResolved,
}

/// Recursively collect every file/symlink under `root`, relative to it; skips `exclude`.
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
            } else if let Ok(rel) = path.strip_prefix(root) {
                out.push(rel.to_path_buf());
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

pub fn full_audit(roots: &Roots) -> (Vec<AuditResult>, std::time::Duration) {
    let start = Instant::now();
    let results = vec![
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

        assert!(
            total_checked > 30_000,
            "expected tens of thousands of real files, only found {total_checked}"
        );
        assert!(
            genuine_gaps.is_empty(),
            "{} real files have no working legacy alias:\n{}",
            genuine_gaps.len(),
            genuine_gaps.join("\n")
        );
        assert!(elapsed.as_secs() < 5, "full audit took {elapsed:?} — too slow");
    }
}
