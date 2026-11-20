//! Live check that the kernel's verifier accepts every embedded eBPF program (#204).
//!
//! Nothing in CI loads the probes, and the verifiers differ a lot between kernels: a program
//! that loads on 6.18 can be refused on 5.15 or 6.1 (`invalid indirect read from stack` for
//! uninitialized padding, an LSM hook with fewer arguments). The agent then only logs a warning
//! and runs without that probe, so the loss is silent. This loads each program once, prints the
//! kernel's processed-instruction count (`verified_insns`, kernel 5.16 and later) and translated
//! size, and exits 1 if any was refused or has a type this check cannot load. A build without
//! the embedded probes exits 2.
//!
//! `inode_setattr` is expected to be refused where the LSM hook has fewer arguments (5.15, 6.1):
//! the loader treats it as optional (#1044). Pass `--allow inode_setattr` to accept that.
//!
//! Build with the eBPF toolchain, then run as root on a Linux lab host:
//! `cargo build -p sensor-linux --example verify_probes`
//! `sudo target/debug/examples/verify_probes [--allow <program>]...`
//!
//! The counts also let a refactor of the probes show what it cost the verifier: compare the
//! output before and after (AS-003).
//!
//! The optional code paths are loaded enabled, the way the agent loads them when BTF resolves
//! their offsets (`src/ebpf.rs`): a gating global left at 0 is a constant in `.rodata`, and the
//! verifier then prunes everything behind it, so the check would pass code it never saw (#310).

#[cfg(all(target_os = "linux", ebpf_embedded))]
mod linux {
    use std::{collections::BTreeSet, error::Error, process::ExitCode};

    use aya::{Btf, EbpfLoader, programs::Program};

    /// Enabled flag for each optional path the agent turns on at load (`src/ebpf.rs`).
    const ENABLED: u32 = 1;
    /// Stand-in for the BTF offsets those paths read through: the verifier bounds them as
    /// scalars added to a pointer handed to `bpf_probe_read_kernel`, so any small value
    /// exercises the same instructions as the kernel's real offsets.
    const OFFSET: u32 = 8;

    pub(crate) fn run() -> Result<ExitCode, Box<dyn Error>> {
        let allowed = allowed_refusals(std::env::args().skip(1))?;
        // `must_exist = true`, as in the agent: a renamed or dropped global fails the check
        // instead of silently loading that path disabled again.
        let mut ebpf = EbpfLoader::new()
            .override_global("EXEC_ARGV_ENABLED", &ENABLED, true)
            .override_global("TASK_MM_OFFSET", &OFFSET, true)
            .override_global("MM_ARG_START_OFFSET", &OFFSET, true)
            .override_global("MM_ARG_END_OFFSET", &OFFSET, true)
            .override_global("INODE_SETATTR_ENABLED", &ENABLED, true)
            .override_global("IATTR_VALID_OFFSET", &OFFSET, true)
            .override_global("IATTR_ATIME_OFFSET", &OFFSET, true)
            .override_global("IATTR_MTIME_OFFSET", &OFFSET, true)
            .override_global("DENTRY_PARENT_OFFSET", &OFFSET, true)
            .override_global("DENTRY_NAME_PTR_OFFSET", &OFFSET, true)
            .load(aya::include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/sensor-linux-ebpf"
            )))?;
        let btf = Btf::from_sys_fs()?;
        let mut names: Vec<String> = ebpf.programs().map(|(name, _)| name.to_string()).collect();
        names.sort();
        if let Some(unknown) = allowed.iter().find(|name| !names.contains(name)) {
            return Err(format!("--allow {unknown}: no such program in the eBPF object").into());
        }

        let mut refused = 0_usize;
        for name in &names {
            let program = ebpf.program_mut(name).ok_or("program listed but missing")?;
            let loaded = match program {
                Program::UProbe(p) => p.load(),
                Program::RawTracePoint(p) => p.load(),
                Program::TracePoint(p) => p.load(),
                // Each LSM program is named after its hook (`#[lsm(hook = "...")]` on a fn of
                // the same name), which is also how `attach_inode_setattr` loads it.
                Program::Lsm(p) => p.load(name, &btf),
                // A program type this check cannot load is a failure, not a pass: otherwise a
                // new kprobe or socket filter would ship without the verifier ever seeing it
                // (#226). `--allow` still accepts it by name.
                other => {
                    if allowed.contains(name.as_str()) {
                        println!("ALLOWED {name}: unsupported type {:?}", other.prog_type());
                    } else {
                        refused += 1;
                        println!("FAIL {name}: unsupported type {:?}", other.prog_type());
                    }
                    continue;
                }
            };
            match loaded {
                Ok(()) => {
                    let info = program.info()?;
                    println!(
                        "OK {name} verified_insns={:?} xlated_bytes={:?}",
                        info.verified_instruction_count(),
                        info.size_translated()
                    );
                }
                Err(error) if allowed.contains(name.as_str()) => {
                    println!("ALLOWED {name}: {error:?}");
                }
                Err(error) => {
                    refused += 1;
                    println!("FAIL {name}: {error:?}");
                }
            }
        }
        println!("failed={refused}");
        Ok(if refused == 0 {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        })
    }

    /// The programs named by `--allow`, which may be refused without failing the run. Any
    /// other argument, or a trailing `--allow` with no name, is an error rather than ignored:
    /// a mistyped flag must not quietly turn a refusal into a pass.
    fn allowed_refusals(
        mut args: impl Iterator<Item = String>,
    ) -> Result<BTreeSet<String>, Box<dyn Error>> {
        let mut allowed = BTreeSet::new();
        while let Some(arg) = args.next() {
            if arg != "--allow" {
                return Err(
                    format!("unknown argument `{arg}` (usage: [--allow <program>]...)").into(),
                );
            }
            let name = args.next().ok_or("--allow needs a program name")?;
            allowed.insert(name);
        }
        Ok(allowed)
    }
}

#[cfg(all(target_os = "linux", ebpf_embedded))]
fn main() -> std::process::ExitCode {
    match linux::run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("verify_probes: {error}");
            std::process::ExitCode::from(2)
        }
    }
}

// Exit 2, not 0: a binary built without the probes loads nothing, and CI must not read that as a
// pass.
#[cfg(not(all(target_os = "linux", ebpf_embedded)))]
fn main() -> std::process::ExitCode {
    eprintln!(
        "verify_probes needs Linux and the embedded eBPF probes (build with the eBPF toolchain)"
    );
    std::process::ExitCode::from(2)
}
