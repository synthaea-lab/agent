//! Lab-only, not for merge (AS-003 verification branch): load every program of the embedded eBPF object and print the
//! kernel verifier's processed-instruction count and the translated size for each.
#[cfg(all(target_os = "linux", ebpf_embedded))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use aya::{Btf, Ebpf, programs::Program};
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/sensor-linux-ebpf")))?;
    let btf = Btf::from_sys_fs()?;
    let mut names: Vec<String> = ebpf.programs().map(|(n, _)| n.to_string()).collect();
    names.sort();
    let mut failed = 0;
    for name in names {
        let prog = ebpf.program_mut(&name).ok_or("missing")?;
        let res = match prog {
            Program::UProbe(p) => p.load(),
            Program::RawTracePoint(p) => p.load(),
            Program::TracePoint(p) => p.load(),
            Program::Lsm(p) => p.load(&name, &btf),
            other => { println!("SKIP {name} {:?}", other.prog_type()); continue; }
        };
        match res {
            Ok(()) => {
                let info = prog.info()?;
                println!("OK {name} verified_insns={:?} xlated_bytes={:?}", info.verified_instruction_count(), info.size_translated());
            }
            Err(e) => { failed += 1; println!("FAIL {name}: {e:?}"); }
        }
    }
    println!("failed={failed}");
    if failed > 0 { std::process::exit(1) }
    Ok(())
}
#[cfg(not(all(target_os = "linux", ebpf_embedded)))]
fn main() {}
