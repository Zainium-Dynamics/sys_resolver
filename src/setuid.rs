//! Setuid/setgid reachability audit.
//!
//! sys_resolver works through `LD_PRELOAD`. The dynamic loader sets `AT_SECURE`
//! for setuid/setgid binaries and drops `LD_PRELOAD`/`LD_LIBRARY_PATH`, so the
//! resolver is never loaded into them. On Zainium (no `/lib`, `/usr` at the
//! root) that means the loader must find the program's **interpreter** and its
//! **libraries** entirely on its own, at the literal paths baked into the ELF.
//!
//! This module enumerates every setuid/setgid binary in the base and flags the
//! ones that would fail that start-up resolution — the test harness for the
//! libc-level fallback (see docs/setuid-paths-plan.md). It is pure analysis: it
//! never executes anything and never follows an untrusted path.

use crate::remap::{self, Roots};
use std::path::{Path, PathBuf};

/// `setuid` and `setgid` mode bits.
const S_ISUID: u32 = 0o4000;
const S_ISGID: u32 = 0o2000;

/// What start-up resolution a setuid binary needs, and whether it is met.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Dynamic, interpreter present at its literal path, libraries locatable.
    Ok,
    /// Dynamic, but the `PT_INTERP` loader is not at the literal path it names,
    /// so the kernel cannot start it at all under AT_SECURE.
    InterpMissing { interp: String },
    /// Dynamic and startable, but needed libraries are not guaranteed to load:
    /// no absolute `DT_RUNPATH`/`DT_RPATH`, or one that uses `$ORIGIN` (ignored
    /// under AT_SECURE).
    LibrariesAtRisk { detail: String },
    /// Static binary with the setuid bit: it carries its own libc, so the
    /// libc-level fallback cannot reach it; relies on replant / a dynamic build.
    StaticSetuid,
    /// Not an ELF we could parse (script, data, unsupported class/endianness).
    NotAnElf,
}

impl Verdict {
    pub fn is_failing(&self) -> bool {
        matches!(
            self,
            Verdict::InterpMissing { .. } | Verdict::LibrariesAtRisk { .. } | Verdict::StaticSetuid
        )
    }
}

#[derive(Debug, Clone)]
pub struct SetuidFinding {
    pub path: PathBuf,
    pub setuid: bool,
    pub setgid: bool,
    pub verdict: Verdict,
}

/// Minimal facts we read out of a 64-bit little-endian ELF.
#[derive(Debug, Default)]
struct ElfInfo {
    interp: Option<String>,
    is_dynamic: bool,
    needed: Vec<String>,
    runpaths: Vec<String>,
}

fn u16le(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(o..o + 2)?.try_into().ok()?))
}
fn u64le(b: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(o..o + 8)?.try_into().ok()?))
}

/// Read a NUL-terminated string at `off`.
fn cstr(b: &[u8], off: usize) -> Option<String> {
    let slice = b.get(off..)?;
    let end = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
    Some(String::from_utf8_lossy(&slice[..end]).into_owned())
}

/// Parse only the headers we need. Returns `None` for anything that is not a
/// 64-bit little-endian ELF (callers treat that as `NotAnElf`).
fn parse_elf(b: &[u8]) -> Option<ElfInfo> {
    if b.get(0..4)? != b"\x7fELF" {
        return None;
    }
    if *b.get(4)? != 2 || *b.get(5)? != 1 {
        return None; // not ELFCLASS64 / ELFDATA2LSB
    }
    let phoff = u64le(b, 32)? as usize;
    let phentsize = u16le(b, 54)? as usize;
    let phnum = u16le(b, 56)? as usize;
    if phentsize < 56 {
        return None;
    }

    let mut info = ElfInfo::default();
    // (p_vaddr, p_offset, p_filesz) of PT_LOAD segments, to map vaddr -> file offset.
    let mut loads: Vec<(u64, u64, u64)> = Vec::new();
    let mut dynamic: Option<(usize, usize)> = None; // (offset, filesz)

    for i in 0..phnum {
        let ph = phoff.checked_add(i.checked_mul(phentsize)?)?;
        let p_type = u16le(b, ph)? as u32 | ((u16le(b, ph + 2)? as u32) << 16);
        let p_offset = u64le(b, ph + 8)?;
        let p_vaddr = u64le(b, ph + 16)?;
        let p_filesz = u64le(b, ph + 32)?;
        match p_type {
            1 => loads.push((p_vaddr, p_offset, p_filesz)), // PT_LOAD
            2 => {
                // PT_DYNAMIC
                info.is_dynamic = true;
                dynamic = Some((p_offset as usize, p_filesz as usize));
            }
            3 => {
                // PT_INTERP
                info.is_dynamic = true;
                if let Some(s) = cstr(b, p_offset as usize) {
                    let s = s.trim_end_matches('\0').to_string();
                    if !s.is_empty() {
                        info.interp = Some(s);
                    }
                }
            }
            _ => {}
        }
    }

    // Walk the dynamic section for the string table and the entries we report.
    if let Some((doff, dsz)) = dynamic {
        let vaddr_to_off = |vaddr: u64| -> Option<usize> {
            for &(lv, lo, lsz) in &loads {
                if vaddr >= lv && vaddr < lv.checked_add(lsz)? {
                    return Some((lo + (vaddr - lv)) as usize);
                }
            }
            None
        };

        let mut strtab_vaddr: Option<u64> = None;
        let mut needed_off: Vec<u64> = Vec::new();
        let mut rpath_off: Vec<u64> = Vec::new();
        let mut i = 0usize;
        while i + 16 <= dsz {
            let entry = doff + i;
            let d_tag = u64le(b, entry)?;
            let d_val = u64le(b, entry + 8)?;
            match d_tag {
                0 => break,             // DT_NULL
                1 => needed_off.push(d_val),  // DT_NEEDED
                5 => strtab_vaddr = Some(d_val), // DT_STRTAB
                15 | 29 => rpath_off.push(d_val), // DT_RPATH / DT_RUNPATH
                _ => {}
            }
            i += 16;
        }

        if let Some(stv) = strtab_vaddr.and_then(vaddr_to_off) {
            for off in needed_off {
                if let Some(s) = cstr(b, stv + off as usize) {
                    info.needed.push(s);
                }
            }
            for off in rpath_off {
                if let Some(s) = cstr(b, stv + off as usize) {
                    for part in s.split(':').filter(|p| !p.is_empty()) {
                        info.runpaths.push(part.to_string());
                    }
                }
            }
        }
    }

    Some(info)
}

/// Does the loader find the interpreter at its literal path? Under AT_SECURE the
/// resolver is not loaded, so only the literal path (optionally under a test
/// `zairoot`) counts — never a remapped one.
fn literal_exists(path: &str, roots: &Roots) -> bool {
    let p = Path::new(path);
    // `roots.syshub` is `<zairoot>/overlayer/syshub`; recover `<zairoot>`.
    let zairoot = roots
        .syshub
        .parent()
        .and_then(Path::parent)
        .unwrap_or(Path::new("/"));
    if zairoot == Path::new("/") {
        p.exists()
    } else if let Ok(rel) = p.strip_prefix("/") {
        zairoot.join(rel).exists()
    } else {
        p.exists()
    }
}

fn judge(info: &ElfInfo, roots: &Roots) -> Verdict {
    // Static (no interpreter requested): own libc, fallback can't reach it.
    let Some(interp) = &info.interp else {
        return if info.is_dynamic {
            // static-PIE: has PT_DYNAMIC but no interpreter — still carries libc.
            Verdict::StaticSetuid
        } else {
            Verdict::StaticSetuid
        };
    };

    if !literal_exists(interp, roots) {
        return Verdict::InterpMissing {
            interp: interp.clone(),
        };
    }

    if !info.needed.is_empty() {
        let abs_runpath = info
            .runpaths
            .iter()
            .any(|r| r.starts_with('/') && !r.contains("$ORIGIN"));
        if !abs_runpath {
            let detail = if info.runpaths.is_empty() {
                "no DT_RUNPATH/DT_RPATH; LD_LIBRARY_PATH is dropped under AT_SECURE".to_string()
            } else {
                format!(
                    "runpath(s) {:?} are relative or use $ORIGIN (ignored under AT_SECURE)",
                    info.runpaths
                )
            };
            return Verdict::LibrariesAtRisk { detail };
        }
    }

    Verdict::Ok
}

/// Recursively collect files carrying the setuid or setgid bit under `root`.
fn walk_setxid(root: &Path, out: &mut Vec<(PathBuf, bool, bool)>) {
    use std::os::unix::fs::PermissionsExt;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.file_type().is_symlink() {
                continue; // never follow; judge the real file where it lives
            }
            if meta.is_dir() {
                stack.push(path);
                continue;
            }
            let mode = meta.permissions().mode();
            let suid = mode & S_ISUID != 0;
            let sgid = mode & S_ISGID != 0;
            if suid || sgid {
                out.push((path, suid, sgid));
            }
        }
    }
}

/// Enumerate and judge every setuid/setgid binary across the base roots.
pub fn audit(roots: &Roots) -> Vec<SetuidFinding> {
    let mut found: Vec<(PathBuf, bool, bool)> = Vec::new();
    for root in [&roots.syshub, &roots.union, &roots.zaisys] {
        walk_setxid(root, &mut found);
    }
    found.sort_by(|a, b| a.0.cmp(&b.0));
    found.dedup_by(|a, b| a.0 == b.0);

    found
        .into_iter()
        .map(|(path, setuid, setgid)| {
            let verdict = match std::fs::read(&path) {
                Ok(bytes) => match parse_elf(&bytes) {
                    Some(info) => judge(&info, roots),
                    None => Verdict::NotAnElf,
                },
                Err(_) => Verdict::NotAnElf,
            };
            SetuidFinding {
                path,
                setuid,
                setgid,
                verdict,
            }
        })
        .collect()
}

/// Would `/usr/bin/foo`-style opens this program makes be remapped if the
/// resolver *were* loaded? Used by `doctor` to show the gap the preload covers
/// but AT_SECURE does not. (Pure, no IO beyond `remap::resolve`.)
pub fn preload_would_help(sample: &Path, roots: &Roots) -> bool {
    remap::in_scope(sample) && remap::resolve(sample, roots).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Build a minimal 64-bit LE ELF with optional interp, needed libs and runpath.
    fn build_elf(interp: Option<&str>, needed: &[&str], runpath: Option<&str>) -> Vec<u8> {
        // Layout: [ehdr 64][phdrs][interp str][dynamic][strtab]
        // One PT_LOAD mapping the whole file at vaddr 0, so vaddr == offset.
        let is_dynamic = interp.is_some() || !needed.is_empty() || runpath.is_some();

        let mut phdrs: Vec<(u32, u64, u64, u64)> = Vec::new(); // (type, offset, vaddr, filesz) placeholders
        // We'll fix offsets after we know section positions.

        let ehdr_size = 64usize;
        let phentsize = 56usize;
        // Count program headers: PT_LOAD + optional PT_INTERP + optional PT_DYNAMIC.
        let mut phnum = 1; // PT_LOAD
        if interp.is_some() {
            phnum += 1;
        }
        if is_dynamic {
            phnum += 1; // PT_DYNAMIC
        }
        let phoff = ehdr_size;
        let after_ph = phoff + phnum * phentsize;

        // interp string
        let interp_off = after_ph;
        let interp_bytes = interp.map(|s| {
            let mut v = s.as_bytes().to_vec();
            v.push(0);
            v
        });
        let interp_len = interp_bytes.as_ref().map(|v| v.len()).unwrap_or(0);

        // strtab: index 0 is NUL, then each needed lib, then runpath.
        let strtab_start = interp_off + interp_len;
        let mut strtab = vec![0u8];
        let mut needed_offsets = Vec::new();
        for n in needed {
            needed_offsets.push(strtab.len() as u64);
            strtab.extend_from_slice(n.as_bytes());
            strtab.push(0);
        }
        let runpath_offset = runpath.map(|r| {
            let off = strtab.len() as u64;
            strtab.extend_from_slice(r.as_bytes());
            strtab.push(0);
            off
        });
        // dynamic section goes after strtab
        let strtab_off = strtab_start;
        let dyn_off = strtab_off + strtab.len();

        // Build dynamic entries.
        let mut dynbytes: Vec<u8> = Vec::new();
        let mut push_dyn = |tag: u64, val: u64, buf: &mut Vec<u8>| {
            buf.extend_from_slice(&tag.to_le_bytes());
            buf.extend_from_slice(&val.to_le_bytes());
        };
        if is_dynamic {
            push_dyn(5, strtab_off as u64, &mut dynbytes); // DT_STRTAB (vaddr==offset)
            push_dyn(10, strtab.len() as u64, &mut dynbytes); // DT_STRSZ
            for &no in &needed_offsets {
                push_dyn(1, no, &mut dynbytes); // DT_NEEDED
            }
            if let Some(ro) = runpath_offset {
                push_dyn(29, ro, &mut dynbytes); // DT_RUNPATH
            }
            push_dyn(0, 0, &mut dynbytes); // DT_NULL
        }
        let dyn_size = dynbytes.len();
        let total = dyn_off + dyn_size;

        // Program headers.
        // PT_LOAD over whole file.
        phdrs.push((1, 0, 0, total as u64));
        if let Some(ib) = &interp_bytes {
            phdrs.push((3, interp_off as u64, interp_off as u64, ib.len() as u64));
        }
        if is_dynamic {
            phdrs.push((2, dyn_off as u64, dyn_off as u64, dyn_size as u64));
        }

        let mut out = vec![0u8; total];
        // e_ident
        out[0..4].copy_from_slice(b"\x7fELF");
        out[4] = 2; // ELFCLASS64
        out[5] = 1; // ELFDATA2LSB
        out[6] = 1; // EV_CURRENT
        // e_type = ET_DYN(3) if interp else ET_EXEC(2)
        let e_type: u16 = if interp.is_some() { 3 } else { 2 };
        out[16..18].copy_from_slice(&e_type.to_le_bytes());
        out[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        out[32..40].copy_from_slice(&(phoff as u64).to_le_bytes()); // e_phoff
        out[54..56].copy_from_slice(&(phentsize as u16).to_le_bytes());
        out[56..58].copy_from_slice(&(phnum as u16).to_le_bytes());

        for (i, (t, off, vaddr, filesz)) in phdrs.iter().enumerate() {
            let ph = phoff + i * phentsize;
            out[ph..ph + 4].copy_from_slice(&t.to_le_bytes()); // p_type
            // p_flags @4 (leave 0)
            out[ph + 8..ph + 16].copy_from_slice(&off.to_le_bytes()); // p_offset
            out[ph + 16..ph + 24].copy_from_slice(&vaddr.to_le_bytes()); // p_vaddr
            out[ph + 24..ph + 32].copy_from_slice(&vaddr.to_le_bytes()); // p_paddr
            out[ph + 32..ph + 40].copy_from_slice(&filesz.to_le_bytes()); // p_filesz
            out[ph + 40..ph + 48].copy_from_slice(&filesz.to_le_bytes()); // p_memsz
        }

        if let Some(ib) = &interp_bytes {
            out[interp_off..interp_off + ib.len()].copy_from_slice(ib);
        }
        out[strtab_off..strtab_off + strtab.len()].copy_from_slice(&strtab);
        out[dyn_off..dyn_off + dyn_size].copy_from_slice(&dynbytes);
        out
    }

    fn write_suid(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, bytes).unwrap();
        let mut perm = std::fs::metadata(&p).unwrap().permissions();
        perm.set_mode(0o4755);
        std::fs::set_permissions(&p, perm).unwrap();
        p
    }

    #[test]
    fn parses_interp_needed_and_runpath() {
        let elf = build_elf(
            Some("/overlayer/syshub/x86_64-zainium-linux-musl/lib/ld-musl-x86_64.so.1"),
            &["libc.so", "libz.so.1"],
            Some("/overlayer/syshub/lib"),
        );
        let info = parse_elf(&elf).expect("valid elf");
        assert_eq!(
            info.interp.as_deref(),
            Some("/overlayer/syshub/x86_64-zainium-linux-musl/lib/ld-musl-x86_64.so.1")
        );
        assert_eq!(info.needed, vec!["libc.so", "libz.so.1"]);
        assert_eq!(info.runpaths, vec!["/overlayer/syshub/lib"]);
        assert!(info.is_dynamic);
    }

    #[test]
    fn static_binary_has_no_interp() {
        let elf = build_elf(None, &[], None);
        let info = parse_elf(&elf).unwrap();
        assert!(info.interp.is_none());
        assert!(!info.is_dynamic);
    }

    #[test]
    fn verdict_ok_when_interp_present_and_abs_runpath() {
        let roots = crate::test_fixture::roots();
        // Put a real interpreter file under the fixture's syshub triplet.
        let interp_abs = "/overlayer/syshub/x86_64-zainium-linux-musl/lib/ld-musl-x86_64.so.1";
        let zairoot = crate::test_fixture::root();
        let interp_real = zairoot.join(interp_abs.strip_prefix('/').unwrap());
        std::fs::create_dir_all(interp_real.parent().unwrap()).unwrap();
        std::fs::write(&interp_real, b"loader").unwrap();

        let info = ElfInfo {
            interp: Some(interp_abs.to_string()),
            is_dynamic: true,
            needed: vec!["libc.so".into()],
            runpaths: vec!["/overlayer/syshub/lib".into()],
        };
        assert_eq!(judge(&info, &roots), Verdict::Ok);
    }

    #[test]
    fn verdict_interp_missing_fails() {
        let roots = crate::test_fixture::roots();
        let info = ElfInfo {
            interp: Some("/lib/ld-musl-x86_64.so.1".into()), // classic, absent on Zainium
            is_dynamic: true,
            needed: vec![],
            runpaths: vec![],
        };
        assert!(matches!(judge(&info, &roots), Verdict::InterpMissing { .. }));
    }

    #[test]
    fn verdict_libraries_at_risk_without_abs_runpath() {
        let roots = crate::test_fixture::roots();
        let interp_abs = "/overlayer/syshub/x86_64-zainium-linux-musl/lib/ld-musl-x86_64.so.1";
        let zairoot = crate::test_fixture::root();
        let interp_real = zairoot.join(interp_abs.strip_prefix('/').unwrap());
        std::fs::create_dir_all(interp_real.parent().unwrap()).unwrap();
        std::fs::write(&interp_real, b"loader").unwrap();

        let origin = ElfInfo {
            interp: Some(interp_abs.to_string()),
            is_dynamic: true,
            needed: vec!["libc.so".into()],
            runpaths: vec!["$ORIGIN/../lib".into()],
        };
        assert!(matches!(
            judge(&origin, &roots),
            Verdict::LibrariesAtRisk { .. }
        ));
    }

    #[test]
    fn verdict_static_setuid_flagged() {
        let roots = crate::test_fixture::roots();
        let info = ElfInfo {
            interp: None,
            is_dynamic: false,
            needed: vec![],
            runpaths: vec![],
        };
        assert_eq!(judge(&info, &roots), Verdict::StaticSetuid);
    }

    #[test]
    fn audit_walks_and_classifies_real_files() {
        let roots = crate::test_fixture::roots();
        let bindir = roots.syshub.join("bin");
        std::fs::create_dir_all(&bindir).unwrap();

        // A good one: interp exists under the fixture, abs runpath.
        let interp_abs = "/overlayer/syshub/x86_64-zainium-linux-musl/lib/ld-musl-x86_64.so.1";
        let interp_real = crate::test_fixture::root().join(interp_abs.strip_prefix('/').unwrap());
        std::fs::create_dir_all(interp_real.parent().unwrap()).unwrap();
        std::fs::write(&interp_real, b"loader").unwrap();
        write_suid(
            &bindir,
            "good-suid",
            &build_elf(Some(interp_abs), &["libc.so"], Some("/overlayer/syshub/lib")),
        );
        // A bad one: classic interpreter absent on Zainium.
        write_suid(
            &bindir,
            "bad-suid",
            &build_elf(Some("/lib/ld-musl-x86_64.so.1"), &["libc.so"], None),
        );
        // A static setuid.
        write_suid(&bindir, "static-suid", &build_elf(None, &[], None));

        let findings = audit(&roots);
        let by = |n: &str| {
            findings
                .iter()
                .find(|f| f.path.file_name().unwrap() == n)
                .unwrap_or_else(|| panic!("{n} not found among {findings:?}"))
        };
        assert_eq!(by("good-suid").verdict, Verdict::Ok);
        assert!(by("bad-suid").verdict.is_failing());
        assert_eq!(by("static-suid").verdict, Verdict::StaticSetuid);
        assert!(by("good-suid").setuid);
    }
}
