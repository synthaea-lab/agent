//! Live check that the kernel's verifier accepts every embedded eBPF program (#204).
//!
//! Nothing in CI loads the probes, and the verifiers differ a lot between kernels: a program
//! that loads on 6.18 can be refused on 5.15 or 6.1 (`invalid indirect read from stack` for
//! uninitialized padding, an LSM hook with fewer arguments). The agent then only logs a warning
//! and runs without that probe, so the loss is silent. This loads each program once, prints the
//! kernel's processed-instruction count (`verified_insns`, kernel 5.16 and later) and translated
//! size, and exits 1 if any was refused, has a type this check cannot load, or processed more
//! instructions than the ceiling (`--max-verified-insns`, default 700 000; kernels without the
//! count are not checked against it). A build without the embedded probes exits 2.
//!
//! `inode_setattr` is expected to be refused where the LSM hook has fewer arguments (5.15, 6.1):
//! the loader treats it as optional (#1044). Pass `--allow inode_setattr` to accept that.
//!
//! Build with the eBPF toolchain, then run as root on a Linux lab host:
//! `cargo build -p sensor-linux --example verify_probes`
//! `sudo target/debug/examples/verify_probes [--allow <program>]... [--max-verified-insns <n>]`
//!
//! The counts also let a refactor of the probes show what it cost the verifier: compare the
//! output before and after (AS-003).
//!
//! The optional code paths are loaded enabled through `sensor_linux::verifier_loader`, from the
//! same list of gated paths the agent enables when BTF resolves their offsets: a gating global
//! left at 0 is a constant in `.rodata`, and the verifier then prunes everything behind it, so
//! the check would pass code it never saw (#310).

#[cfg(all(target_os = "linux", ebpf_embedded))]
mod linux {
    use std::{collections::BTreeSet, error::Error, process::ExitCode};

    use aya::{Btf, programs::Program};

    /// The kernel refuses a program whose verification processes more than 1M instructions
    /// (`BPF_COMPLEXITY_LIMIT_INSNS`), and the count for the same program moves a lot between
    /// kernels: `getaddrinfo_exit` processed 456 673 on 6.1 and 353 781 on RHEL 9.9's 5.14
    /// (2026-11-20). A program over this ceiling fails the check while there is still room on
    /// the kernels CI loads, instead of on the first one that tips it over the limit.
    const DEFAULT_MAX_VERIFIED_INSNS: u32 = 700_000;

    /// The command line: `[--allow <program>]... [--max-verified-insns <n>]`.
    struct Args {
        /// Programs that may be refused (or exceed the ceiling) without failing the run.
        allowed: BTreeSet<String>,
        /// Verified-instruction ceiling per program (kernel 5.16 and later report the count).
        max_verified_insns: u32,
    }

    pub(crate) fn run() -> Result<ExitCode, Box<dyn Error>> {
        let Args {
            allowed,
            max_verified_insns,
        } = parse_args(std::env::args().skip(1))?;
        let mut ebpf = sensor_linux::verifier_loader().load(aya::include_bytes_aligned!(
            concat!(env!("OUT_DIR"), "/sensor-linux-ebpf")
        ))?;
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
                    let reason = format!("unsupported type {:?}", other.prog_type());
                    refused += report_failure(&allowed, name, &reason);
                    continue;
                }
            };
            match loaded {
                Ok(()) => {
                    let info = program.info()?;
                    let verified = info.verified_instruction_count();
                    match verified {
                        Some(count) if count > max_verified_insns => {
                            let reason =
                                format!("verified_insns={count} over {max_verified_insns}");
                            refused += report_failure(&allowed, name, &reason);
                        }
                        _ => println!(
                            "OK {name} verified_insns={verified:?} xlated_bytes={:?}",
                            info.size_translated()
                        ),
                    }
                }
                Err(error) => refused += report_failure(&allowed, name, &format!("{error:?}")),
            }
        }
        println!("failed={refused}");
        Ok(if refused == 0 {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        })
    }

    /// Prints a failed program and returns 1, or prints it as allowed and returns 0 when
    /// `--allow` names it.
    fn report_failure(allowed: &BTreeSet<String>, name: &str, reason: &str) -> usize {
        if allowed.contains(name) {
            println!("ALLOWED {name}: {reason}");
            0
        } else {
            println!("FAIL {name}: {reason}");
            1
        }
    }

    /// The programs named by `--allow`, which may be refused (or exceed the ceiling) without
    /// failing the run, and the ceiling. Any other argument, a flag with no value, or a ceiling
    /// that is not a positive integer is an error rather than ignored: a mistyped flag must not
    /// quietly turn a refusal into a pass.
    fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Args, Box<dyn Error>> {
        let mut parsed = Args {
            allowed: BTreeSet::new(),
            max_verified_insns: DEFAULT_MAX_VERIFIED_INSNS,
        };
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--allow" => {
                    let name = args.next().ok_or("--allow needs a program name")?;
                    parsed.allowed.insert(name);
                }
                "--max-verified-insns" => {
                    let value = args.next().ok_or("--max-verified-insns needs a number")?;
                    parsed.max_verified_insns =
                        value.parse().ok().filter(|&n: &u32| n > 0).ok_or_else(|| {
                            format!("--max-verified-insns `{value}`: not a positive integer")
                        })?;
                }
                _ => {
                    return Err(format!(
                        "unknown argument `{arg}` (usage: [--allow <program>]... \
                         [--max-verified-insns <n>])"
                    )
                    .into());
                }
            }
        }
        Ok(parsed)
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
