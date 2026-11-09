//! Real-kernel regression for issue #91's first `Done when` item: the `file_open`
//! LSM hook must fire for an `io_uring`-submitted file open/write, the textbook
//! blinding technique against tracepoint-only EDRs (`io_uring` never issues the
//! classic `openat`/`write` syscalls tracepoints watch — it submits opcodes through
//! a shared ring buffer the kernel executes directly).
//!
//! Needs root (to load/attach the eBPF object) and a kernel with `CONFIG_BPF_LSM`
//! *and* `bpf` in the active `lsm=` list — self-skips otherwise, same discipline as
//! `sensor-linux-journal`'s `journalctl`-dependent test. Needs `fio` with the
//! `io_uring` ioengine to submit a real `io_uring` write without hand-rolling the
//! ring-buffer syscalls in the test itself — self-skips if `fio` isn't on `PATH`.

#[cfg(target_os = "linux")]
#[test]
fn file_open_lsm_hook_fires_for_an_io_uring_write() {
    // SAFETY: `geteuid` takes no arguments and has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipping: needs root to load/attach the eBPF object");
        return;
    }
    if std::process::Command::new("fio")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("skipping: fio not on PATH (needed to submit a real io_uring write)");
        return;
    }
    if !sensor_linux_lsm::detect_hook_support("file_open") {
        eprintln!("skipping: kernel has no bpf_lsm_file_open BTF type");
        return;
    }

    let mut ebpf = match sensor_linux::load_ebpf() {
        Ok(ebpf) => ebpf,
        Err(e) => {
            eprintln!("skipping: failed to load the eBPF object: {e}");
            return;
        }
    };
    if let Err(e) = sensor_linux_lsm::attach_file_open(&mut ebpf) {
        // Covers both "no CONFIG_BPF_LSM" and "compiled in but not in the active
        // `lsm=` boot list" — see `LsmAttachError`'s doc. Either way, there is no
        // LSM coverage on this kernel to test against.
        eprintln!("skipping: file_open LSM hook did not attach: {e}");
        return;
    }

    let before = sensor_linux_lsm::file_open_hit_count(&mut ebpf)
        .expect("hit counter must exist once attach succeeded");

    let dir = std::env::temp_dir().join(format!("synthaea-io-uring-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create scratch dir for fio");
    let target = dir.join("write-target");

    // `--ioengine=io_uring` submits the write through the io_uring API rather than
    // a plain `write(2)` syscall — the whole point of this test.
    let status = std::process::Command::new("fio")
        .args([
            "--name=synthaea_lsm_test",
            "--ioengine=io_uring",
            "--rw=write",
            "--size=4k",
            "--bs=4k",
            "--iodepth=1",
            "--direct=1",
            "--minimal",
        ])
        .arg(format!("--filename={}", target.display()))
        .arg(format!("--directory={}", dir.display()))
        .status();
    std::fs::remove_dir_all(&dir).ok();

    match status {
        Ok(status) if status.success() => {}
        Ok(status) => {
            eprintln!(
                "skipping: fio exited with {status} (likely no io_uring support in this kernel/fio build)"
            );
            return;
        }
        Err(e) => {
            eprintln!("skipping: failed to run fio: {e}");
            return;
        }
    }

    let after = sensor_linux_lsm::file_open_hit_count(&mut ebpf)
        .expect("hit counter must exist after the io_uring write");
    assert!(
        after > before,
        "file_open LSM hook did not fire for an io_uring-submitted write \
         (before={before}, after={after}) — the hook must observe regardless of \
         entry path, tracepoints structurally cannot see io_uring submissions"
    );
}
