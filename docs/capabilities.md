# Capabilities

What the agent can do today, area by area, with the code and tests that back each claim. This table is maintained by hand next to the code: when a change builds, extends or removes a capability, update its row in the same pull request. [roadmap.md](roadmap.md) is generated from the `partial` and `planned` rows below.

## Legend

| Status | Meaning |
| --- | --- |
| **built** | The code exists and a test covers it. Platform limits, if any, are named in the evidence. |
| **partial** | Part of it is built: some platforms, some cases, or code that is not wired or not tested yet. The tracking issue says what is missing. |
| **planned** | Not built. The tracking issue holds the design or the work. |

Every `partial` and `planned` row links a tracking issue; `tools/check-docs.py` fails CI otherwise.

Totals: 273 capabilities, 151 built, 81 partial, 41 planned.

## Contents

- [Core and pipeline](#core-and-pipeline)
- [Linux sensors](#linux-sensors)
- [Windows sensors](#windows-sensors)
- [macOS sensors](#macos-sensors)
- [Detection](#detection)
- [Response and self-protection](#response-and-self-protection)
- [Delivery, interfaces and build](#delivery-interfaces-and-build)

## Core and pipeline

### Architecture

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| Dependency-direction enforcement between workspace crates | built | tools/check-deps.py run in .github/workflows/ci.yml on every push |  | [architecture.md#dependency-direction](architecture.md#dependency-direction) |
| Fail-fast config loading with discovery order (--config, SYNTHAEA_CONFIG, OS default) | built | apps/agent/src/main.rs try_main, apps/watchdog/src/main.rs run_cli -&gt; crates/config/src/load.rs load, discovery.rs discover (config crate tests) |  | [architecture.md#binaries](architecture.md#binaries) |

### Event pipeline

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| Shared detection sink fed by the primary sensor and all poller threads | built | crates/schema/src/sensor.rs EventSink for Arc&lt;T&gt;; apps/agent/src/commands/common.rs wire_run_pipeline; test the_health_beacon_and_cli_health_read_the_same_silence_monitor |  | [lifecycle.md#1-sensor-to-schemaevent](lifecycle.md#1-sensor-to-schemaevent) |
| In-memory detection on the capture thread with enrichment off-thread behind a bounded queue that sheds and counts | built | apps/agent/src/enrich_queue.rs EnrichQueue (overflow_sheds_and_counts_instead_of_blocking, a_shed_event_hands_its_gated_alert_back) |  | [lifecycle.md#6-enrichment-output-and-upload](lifecycle.md#6-enrichment-output-and-upload) |
| Finding recording: verdict fusion, complete alert log, escalation, durable detection spool, redacted outputs | built | apps/agent/src/sink/mod.rs record_detection, escalate_if_warranted; sink tests sigma_sees_raw_exec_but_alert_and_event_outputs_are_redacted |  | [lifecycle.md#4-recording-a-finding](lifecycle.md#4-recording-a-finding) |
| Correlator clock advanced without new events | built | apps/agent/src/sink/correlation.rs start_correlator_ticker; test the_correlator_ticker_emits_without_a_following_event |  | [lifecycle.md#threads-in-agent-run](lifecycle.md#threads-in-agent-run) |

### Lifecycle

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| Degrade-not-die: eBPF to audit fallback on Linux, ETW failure keeps supplementary sources on Windows | built | apps/agent/src/commands/linux.rs select_sensor, can_use_ebpf; apps/agent/src/commands/windows.rs hold_after_primary (failed_etw_keeps_supplementary_sensors_running_until_shutdown) |  | [lifecycle.md#degraded-modes](lifecycle.md#degraded-modes) |
| Non-invasive eBPF preflight (agent status) with non-zero exit on verifier rejection | partial | apps/agent/src/commands/linux.rs cmd_status, has_bpf_capabilities; no test or CI job runs `agent status`, so the exit code on a rejected probe is not pinned | [#98](https://github.com/synthaea-lab/agent/issues/98) | [lifecycle.md#linux](lifecycle.md#linux) |
| Bounded graceful shutdown with final upload drain (SIGINT, all platforms) | partial | apps/agent/src/shutdown.rs ShutdownPlan (stop_is_propagated_and_workers_are_joined, the_budget_is_shared_across_workers); apps/agent/src/commands/common.rs finish_run (finish_run_signals_and_joins_every_registered_worker), called by the Linux, Windows and macOS cmd_run (the last two are not run locally) | [#97](https://github.com/synthaea-lab/agent/issues/97) | [lifecycle.md#shutdown](lifecycle.md#shutdown) |
| Termination-signal attribution before exit (kill-loudness) | partial | apps/agent/src/kill_loudness.rs block_termination_signals, spawn_watcher; Linux only, full path not unit-tested (exits the process); SIGKILL attribution only via eBPF sensor | [#97](https://github.com/synthaea-lab/agent/issues/97) | [lifecycle.md#shutdown](lifecycle.md#shutdown) |

### Event schema

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| Normalized cross-platform event model (61 Event variants, per-platform User, container and process-generation metadata) | built | crates/schema/src/lib.rs Event/EventMeta; crates/schema/tests/golden.rs (94 golden tests) |  | [schema.md#event-model](schema.md#event-model) |
| Schema versioning with frozen per-version golden fixtures and backward-compatibility proof | built | SCHEMA_VERSION in crates/schema/src/lib.rs; tests/golden.rs assert_golden (serialize + round trip vs fixtures/v68); tests/v1_compat.rs |  | [schema.md#versioning-and-golden-fixtures](schema.md#versioning-and-golden-fixtures) |
| Detection record with engine provenance, calibrated score, per-feature attributions and ATT&CK techniques | built | crates/schema/src/detection.rs Detection/DetectionSource; golden tests detection_ml_golden, detection_ioc_golden, detection_correlator_golden |  | [schema.md#detections](schema.md#detections) |
| Argv capture budget: truncate (never reject) oversized exec argv and flag the cut | built | bound_argv/ARGV_CAPTURE_BUDGET in crates/schema/src/lib.rs; bound_argv_tests; exec_cmdline_truncated_golden |  | [schema.md#the-exec-event-and-its-command-line](schema.md#the-exec-event-and-its-command-line) |
| Synthetic FileOpen flag bits checked disjoint at compile time | built | SYNTHETIC_FLAGS const assert in crates/schema/src/lib.rs; every_pub_flag_constant_is_in_synthetic_flags |  | [schema.md#fileopeneventflags-and-synthetic-flags](schema.md#fileopeneventflags-and-synthetic-flags) |
| Single write-intent predicate and canonical ML command-line form | built | has_write_intent + write_intent_tests, ExecEvent::ml_cmdline in crates/schema/src/lib.rs |  | [schema.md#fileopeneventflags-and-synthetic-flags](schema.md#fileopeneventflags-and-synthetic-flags) |
| Health beacon with backward-compatible counters | built | HealthBeacon in crates/schema/src/lib.rs; crates/schema/tests/health_beacon.rs |  | [schema.md#event-and-eventmeta](schema.md#event-and-eventmeta) |
| Neutral test-fixture baselines for event literals | built | crates/schema/src/fixtures.rs (feature test-fixtures), used e.g. in crates/store/src/spool.rs spools_schema_events |  | [schema.md#fixture-layout-and-tests](schema.md#fixture-layout-and-tests) |
| Sensor/EventSink contract with declared capabilities | partial | crates/schema/src/sensor.rs Sensor/EventSink/Capabilities; capabilities are self-declared, automated verification against observed behaviour not complete | [#25](https://github.com/synthaea-lab/agent/issues/25) | [schema.md#the-sensor-contract](schema.md#the-sensor-contract) |
| Server-side acceptance policy for agent schema/wire versions (version skew) | planned | SCHEMA_VERSION is metadata only and not stamped on events; no acceptance window defined | [#59](https://github.com/synthaea-lab/agent/issues/59) | [schema.md#failure-modes-and-gaps](schema.md#failure-modes-and-gaps) |

### State and storage

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| LRU-bounded map for detection state with eviction counter | built | crates/store/src/bounded.rs BoundedMap; tests never_exceeds_cap_under_load, evicts_least_recently_used_first |  | [state-and-storage.md#boundedmap](state-and-storage.md#boundedmap) |
| Durable store-and-forward spool with at-least-once two-phase drain and crash recovery | built | crates/store/src/spool.rs EventSpool push/drain_oldest/ack/open; tests two_phase_drain_redelivers_on_crash, idempotent_drain_without_ack, survives_reopen_without_loss_below_cap |  | [state-and-storage.md#two-phase-drain](state-and-storage.md#two-phase-drain) |
| Poison-segment skip and per-detection isolation (one-record detection spool) | built | skip/ack_counting_dropped/open_with_segment_records in crates/store/src/spool.rs; tests skip_poison_segment, one_record_segments_isolate_a_poison_detection; apps/agent/src/upload.rs start |  | [state-and-storage.md#how-the-agent-uses-it](state-and-storage.md#how-the-agent-uses-it) |
| Spool byte cap with oldest-segment shedding and counted loss | partial | enforce_cap + byte_cap_sheds_oldest_segments_and_counts_loss; gaps: dropped_records is in-memory only (reset on restart), unparseable lines skipped without being counted | [#89](https://github.com/synthaea-lab/agent/issues/89) | [state-and-storage.md#bounds-and-back-pressure](state-and-storage.md#bounds-and-back-pressure) |

### Local configuration

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| agent.toml discovery order (--config, SYNTHAEA_CONFIG, OS default path) | built | discover in crates/config/src/discovery.rs; tests cli_arg_wins_over_env, env_wins_over_default, empty_env_falls_through_to_default; missing_file_at_explicit_path_is_io_not_notfound |  | [configuration.md#discovery-order](configuration.md#discovery-order) |
| Fail-fast load with schema-version gate and field-path validation errors | built | parse_and_validate/validate_semantics in crates/config/src/load.rs; tests schema_version_mismatch_is_a_specific_variant, unknown_top_level_field_is_parse_error, non_https_url_fails_validation and ~40 more |  | [configuration.md#load-pipeline](configuration.md#load-pipeline) |
| SYNTHAEA_* environment overrides with re-validation | built | apply_env_overrides in crates/config/src/load.rs; tests env_override_applies_and_revalidates, env_override_bad_type_is_specific_variant |  | [configuration.md#environment-overrides](configuration.md#environment-overrides) |
| offline_fallback: keep detecting locally when uploads cannot be set up | built | start_or_disable in apps/agent/src/upload.rs; tests a_missing_client_certificate_disables_the_upload_when_offline_fallback_is_on / _stops_the_agent_when_offline_fallback_is_off |  | [configuration.md#reference](configuration.md#reference) |
| Secret references (envvar:/file:) instead of cleartext | partial | SecretRef in crates/config/src/secret.rs, cleartext_secret_is_rejected_as_secret_invalid; server.mtls_passphrase is never resolved and transport refuses encrypted keys (crates/transport/src/client.rs) | [#93](https://github.com/synthaea-lab/agent/issues/93) | [configuration.md#secrets](configuration.md#secrets) |
| Committed default template and cli config init | partial | DEFAULT_TEMPLATE/write_default_template in crates/config/src/template.rs; tests/default_template.rs; Linux only (UnsupportedPlatform elsewhere) | [#92](https://github.com/synthaea-lab/agent/issues/92) | [configuration.md#template](configuration.md#template) |
| Resource and logging knobs (log.dir, log.max_mb, worker_threads, max_reconnect_backoff_ms) | partial | Parsed and validated in crates/config/src/schema.rs and load.rs, displayed by cli; not acted on by the agent | [#92](https://github.com/synthaea-lab/agent/issues/92) | [configuration.md#gaps-and-discrepancies](configuration.md#gaps-and-discrepancies) |
| Configuration hot reload | planned | Not supported; changes apply on restart (crates/config/src/lib.rs) | [#92](https://github.com/synthaea-lab/agent/issues/92) | [configuration.md#gaps-and-discrepancies](configuration.md#gaps-and-discrepancies) |

### Policy

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| Observe-only response policy by default, opted into per flag | built | ResponsePolicy in crates/policy/src/lib.rs (default_is_observe_only); apps/agent/src/commands/linux.rs enable_response |  | [configuration.md#compile-time-policy-helpers](configuration.md#compile-time-policy-helpers) |
| Evidence-gated name and parent exclusions (masquerade guard) and kill-gate provenance helpers | built | name_exclusion_applies, parent_exclusion_applies, service_main_path_is_trusted, is_login_session in crates/policy/src/lib.rs with unit tests (masquerade_locations_are_not, svchost_from_cmd_is_masquerade, a_login_session_pair_outside_a_system_path_does_not_qualify) |  | [configuration.md#compile-time-policy-helpers](configuration.md#compile-time-policy-helpers) |
| Windows event-log channel-group enablement | built | EventLogPolicy in crates/policy/src/lib.rs (default_enables_every_channel_group); eventlog_config in apps/agent/src/commands/windows.rs |  | [configuration.md#compile-time-policy-helpers](configuration.md#compile-time-policy-helpers) |
| Signed policy document: canonical JSON, Ed25519 verification, layered override merge with safety-critical completeness | partial | crates/policy/src/{document,canonical,signature,merge}.rs with tests sign_then_verify_succeeds, tamper_in_payload_breaks_verification, windows_eventlog_override_omitting_redaction_inherits_baseline_redaction; no loader/distribution, schema_version and policy_version monotonicity not enforced | [#92](https://github.com/synthaea-lab/agent/issues/92) | [configuration.md#the-signed-policy-document](configuration.md#the-signed-policy-document) |

### Redaction

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| URL credential redaction (userinfo, fragment, secret-named query values) | built | redact_url_secrets/is_secret_key in crates/redact/src/lib.rs; tests userinfo_and_fragment_are_always_redacted, a_sharepoint_tempauth_link_loses_its_bearer_token; apps/agent/src/redact.rs the_sink_redacts_both_quarantine_urls_before_forwarding |  | [redaction.md#urls-redact_url_secrets](redaction.md#urls-redact_url_secrets) |
| Command-line and argv credential redaction (best effort, documented limits) | built | redact_command_line/redact_argv in crates/redact/src/lib.rs; redacts_supported_command_line_shapes_and_keeps_near_misses, redaction_is_idempotent, never_panics_on_any_truncation_or_odd_input proptests |  | [redaction.md#command-lines-redact_command_line-and-redact_argv](redaction.md#command-lines-redact_command_line-and-redact_argv) |
| Free command-text redaction for shell lines, script blocks, AMSI buffers and WQL | built | redact_command_text/CommandDialect in crates/redact/src/text.rs; tests powershell_secret_parameters_and_securestring_literals_are_redacted, arbitrary_text_redaction_is_panic_free_and_idempotent |  | [redaction.md#free-command-text-redact_command_text](redaction.md#free-command-text-redact_command_text) |
| Output-boundary enforcement: raw events for detection, redacted copies for spool, events file, detections, baseline and capture | built | RedactingSink/redact_event in apps/agent/src/redact.rs; record_detection in apps/agent/src/sink/mod.rs; test the_real_output_wrapper_redacts_joined_linux_argv_and_raw_windows_lines |  | [redaction.md#where-redaction-happens](redaction.md#where-redaction-happens) |
| Policy-controlled sensor PII scrubbing (RedactionPolicy) | planned | RedactionPolicy type and merge tests exist in crates/policy, but no consumer reads it | [#92](https://github.com/synthaea-lab/agent/issues/92) | [redaction.md#known-limits](redaction.md#known-limits) |
| Published data-handling and privacy statement (what is collected, redacted, leaves the host) | planned | No user-facing statement in the repo | [#61](https://github.com/synthaea-lab/agent/issues/61) | [redaction.md#where-redaction-happens](redaction.md#where-redaction-happens) |

## Linux sensors

### eBPF probes

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| Process exec telemetry: kernel image path, parent comm, grandparent for subshells, uid/gid, cgroup id | built | crates/sensors/linux/ebpf/src/main.rs record_sched_process_exec + raw.rs raw_sched_process_exec; normalize::exec tests in crates/sensors/linux/userspace/src/normalize.rs |  | [sensors/linux/process-context.md#exec-events](sensors/linux/process-context.md#exec-events) |
| Exec argv captured in the probe (head 768 B + tail 256 B, omitted-byte count, /proc fallback) | built | ebpf main.rs read_exec_argv; wire parse_exec_record with crates/sensors/linux/wire/tests/exec_record.rs and tests/fuzz/fuzz_targets/exec_record_parse.rs; userspace proc.rs exec_argv/argv_from_windows tests |  | [sensors/linux/process-context.md#argv](sensors/linux/process-context.md#argv) |
| Process lineage and generations (ppid, pid-reuse-safe generation stamps, /proc priming) | built | raw.rs raw_sched_process_fork/exit, main.rs fill_lineage, userspace ebpf.rs prime_proc_lineage, proc.rs primed_generation/parse_stat_* tests |  | [sensors/linux/process-context.md#lineage](sensors/linux/process-context.md#lineage) |
| File open telemetry with in-kernel prefix/write-intent filter and masked flags | built | main.rs emit_file_open_event, wire path_filter.rs is_filtered_path (20 tests), normalize OPEN_FLAGS_MASK + apps/agent/tests/probe_open_synthetic_bits.rs; paths are not resolved against dfd |  | [sensors/linux/ebpf-probes.md#in-kernel-filters](sensors/linux/ebpf-probes.md#in-kernel-filters) |
| Kernel module load/unload, bpf() program/map lifecycle, prctl capability options, mount/umount | built | main.rs sys_enter_init_module/finit_module/delete_module/bpf/prctl/mount/umount; normalize kernel_module/bpf_operation/prctl/mount tests |  | [sensors/linux/ebpf-probes.md#what-each-syscall-route-captures](sensors/linux/ebpf-probes.md#what-each-syscall-route-captures) |
| Injection telemetry: ptrace, process_vm_readv/writev, memfd_create (with returned fd) | built | main.rs sys_enter_ptrace/process_vm_*/memfd_create + sys_exit_memfd_create; normalize tests |  | [sensors/linux/ebpf-probes.md#what-each-syscall-route-captures](sensors/linux/ebpf-probes.md#what-each-syscall-route-captures) |
| Privilege telemetry: setuid family, capset (both capability words), setns/unshare | built | main.rs sys_enter_set*id/capset/setns/unshare; normalize identity_change/cap_set/namespace tests |  | [sensors/linux/ebpf-probes.md#what-each-syscall-route-captures](sensors/linux/ebpf-probes.md#what-each-syscall-route-captures) |
| Raw-tracepoint attachment with BTF-derived offsets (works with perf_event_paranoid=3, no frozen kernel layouts) | built | raw.rs raw_sys_enter/raw_sys_exit, userspace btf.rs (9 tests incl. running kernel BTF), syscall.rs dispatch_actions_are_unique_and_in_range, agent status preflight |  | [sensors/linux/ebpf-probes.md#why-raw-tracepoints](sensors/linux/ebpf-probes.md#why-raw-tracepoints) |
| DNS queries over UDP/TCP port 53 from non-libc resolvers | built | raw.rs raw_dns_udp_enter, main.rs dns_udp_connect/write/sendto, userspace dns_udp.rs parse_query (19 tests), normalize::dns_udp_query; sendmsg/sendmmsg not hooked, no answers |  | [sensors/linux/uprobes.md#udp53-capture](sensors/linux/uprobes.md#udp53-capture) |
| File mutation telemetry: delete, rename (relative paths resolved), chmod, chown, setxattr/removexattr | partial | main.rs sys_enter_unlink*/rename*/chmod/fchmodat/chown*/setxattr/removexattr; normalize file_rename/resolve_dirfd_path tests; fd-only variants (fchmod, fchown, fsetxattr, lsetxattr) not hooked | [#88](https://github.com/synthaea-lab/agent/issues/88) | [sensors/linux/ebpf-probes.md#what-each-syscall-route-captures](sensors/linux/ebpf-probes.md#what-each-syscall-route-captures) |
| File write volume telemetry (burst-write signal, no path) | partial | main.rs sys_enter_write, normalize file_write tests; pwrite64/writev/pwritev are not in DISPATCH_ENTRIES | [#88](https://github.com/synthaea-lab/agent/issues/88) | [sensors/linux/ebpf-probes.md#what-is-not-hooked](sensors/linux/ebpf-probes.md#what-is-not-hooked) |
| Network telemetry: connect, bind, listen (bind-correlated address), accept, socket, sendto, recvfrom | partial | main.rs sys_enter_connect/bind/listen/sendto, enter/exit pairs for accept/recvfrom/socket via raw.rs PENDING_SYSCALL_EXIT; normalize tests; examples/accept_map_pressure.rs and pending_syscall_exit_pressure.rs; recvmsg/sendmsg/sendmmsg not hooked | [#88](https://github.com/synthaea-lab/agent/issues/88) | [sensors/linux/ebpf-probes.md#exit-pairing](sensors/linux/ebpf-probes.md#exit-pairing) |
| aarch64 support | partial | syscall.rs aarch64 DISPATCH_ENTRIES, btf.rs pt_regs.regs/syscallno, wire syscall_nr_from_i32; no arm64 build or lab validation in CI | [#62](https://github.com/synthaea-lab/agent/issues/62) | [sensors/linux/README.md#requirements-and-platform-differences](sensors/linux/README.md#requirements-and-platform-differences) |

### Userspace loader and process context

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| Parent image path on exec events, with subshell (fork-without-exec) inheritance and bounded cache with eviction accounting | built | crates/sensors/linux/userspace/src/parent_image.rs (29 unit tests), ParentImageEvictions read by agent health beacon |  | [sensors/linux/process-context.md#parent-image](sensors/linux/process-context.md#parent-image) |
| Security-relevant environment variables on exec (LD_PRELOAD, LD_AUDIT, GLIBC_TUNABLES, ...) | partial | proc.rs read_proc_environ_security + parse_proc_environ_security tests; read at drain time, so short-lived processes yield nothing | [#88](https://github.com/synthaea-lab/agent/issues/88) | [sensors/linux/process-context.md#environment](sensors/linux/process-context.md#environment) |
| Container attribution (id from probe-time cgroup id; image/name from Docker socket) | partial | sensor-linux-container extract_container_id/container_id_from_cgroupfs/CgroupIdCache tests, docker.rs tests; gaps: cgroup v2 only, no Kubernetes pod context, no rootless podman, uprobe events never attributed | [#88](https://github.com/synthaea-lab/agent/issues/88) | [sensors/linux/process-context.md#containers](sensors/linux/process-context.md#containers) |
| Ring-buffer loss accounting | partial | Only SIGNAL_TOOL_DROPS is counted and surfaced; other rings log an aya-log warn per drop; PENDING_*_DROPPED counters exist but are not read by the agent | [#89](https://github.com/synthaea-lab/agent/issues/89) | [sensors/linux/userspace-loader.md#back-pressure-and-loss](sensors/linux/userspace-loader.md#back-pressure-and-loss) |

### Signal tamper telemetry

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| Signals to the agent, including cross-restart SIGKILL attribution through a pinned map | built | main.rs emit_signal_event/SIGNAL_TAMPER_LAST, userspace ebpf.rs load_ebpf_for_run/reclaim_foreign_pin (4 tests), sensor.rs sweep_survived_sigkill |  | [sensors/linux/signals.md#the-pinned-sigkill-slot](sensors/linux/signals.md#the-pinned-sigkill-slot) |
| Signals to listed security tools (signal_generate, unit cgroup membership, reload filtering, drop counter) | partial | raw.rs raw_signal_generate, unit_procs.rs ToolWatch/UnitResolver (30 tests), SIGNAL_TOOL_DROPS + normalize::signals_lost; kernel-mediated stops are read from the command (`systemctl freeze|set-property`, `prlimit --pid`); direct cgroup file writes and the memory.max OOM kill are not reported | [#49](https://github.com/synthaea-lab/agent/issues/49) | [sensors/linux/signals.md#signals-to-security-tools](sensors/linux/signals.md#signals-to-security-tools) |

### BPF-LSM

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| Timestomp detection via BPF-LSM inode_setattr (caller-chosen atime/mtime) | built | main.rs inode_setattr, userspace ebpf.rs attach_inode_setattr, btf.rs parse_inode_setattr_offsets tests, normalize file_set_time tests; requires kernel 6.3+ hook signature and lsm=bpf |  | [sensors/linux/lsm.md#inode_setattr](sensors/linux/lsm.md#inode_setattr) |
| BPF-LSM file_open observation (fires for io_uring) | partial | main.rs file_open, crates/sensors/linux/lsm/src/attach.rs, apps/agent/tests/lsm_io_uring_evasion.rs; counter only, no event emitted | [#88](https://github.com/synthaea-lab/agent/issues/88) | [sensors/linux/lsm.md#file_open](sensors/linux/lsm.md#file_open) |
| Inline blocking (deny open/exec/connect on a verdict) via BPF-LSM | planned | Not built: file_open never denies on its own; no verdict source wired; bprm_check/socket_connect hooks absent | [#90](https://github.com/synthaea-lab/agent/issues/90) | [sensors/linux/lsm.md#not-built](sensors/linux/lsm.md#not-built) |

### Uprobes and DNS

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| DNS resolution via getaddrinfo uprobe (query, up to 24 answers, failures) | built | main.rs getaddrinfo_entry/exit, uprobes normalize::dns_query tests, redact_dns_query tests |  | [sensors/linux/uprobes.md#the-probes](sensors/linux/uprobes.md#the-probes) |
| TLS plaintext capture (OpenSSL/GnuTLS SSL_read/SSL_write) with redaction and per-process budgets | partial | main.rs ssl_* probes, uprobes sensor.rs attach_tls_uprobes, budget.rs SlidingBudget, redact.rs tests; dynamic libraries only, BoringSSL not detected, events carry no ppid/container, budgets not exposed by agent | [#88](https://github.com/synthaea-lab/agent/issues/88) | [sensors/linux/uprobes.md#limits](sensors/linux/uprobes.md#limits) |
| Shell readline capture with redaction | partial | main.rs readline_exit, symbol_resolver resolve_readline_symbols (libreadline/libedit only), normalize/redact tests; zsh not covered | [#88](https://github.com/synthaea-lab/agent/issues/88) | [sensors/linux/uprobes.md#the-probes](sensors/linux/uprobes.md#the-probes) |
| TLS ClientHello metadata (SNI, JA4) | planned | Parser and tests exist in crates/sensors/linux/userspace/src/tls_client_hello.rs; no kernel capture feeds it | [#22](https://github.com/synthaea-lab/agent/issues/22) | [sensors/linux/uprobes.md#limits](sensors/linux/uprobes.md#limits) |

### Audit fallback

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| SELinux AVC denials as PolicyDenial events (alongside eBPF or as part of the fallback) | built | audit classify.rs classify_avc/avc_action tests, avc.rs AvcReader (15 tests over socketpair), agent starts_avc_reader test |  | [sensors/linux/audit-fallback.md#the-avc-reader](sensors/linux/audit-fallback.md#the-avc-reader) |
| Audit-netlink fallback sensor (exec, connect) when eBPF is unavailable | partial | crates/sensors/linux/audit/src/sensor.rs, parse.rs, classify.rs tests, tests/robustness.rs, fuzz audit_parse; single-record classification (no SYSCALL join), no ppid, long arguments dropped | [#51](https://github.com/synthaea-lab/agent/issues/51) | [sensors/linux/audit-fallback.md#limits](sensors/linux/audit-fallback.md#limits) |

### Netlink

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| TCP listening-socket snapshots with PID attribution (ListenPort events) | built | netlink socket.rs/wire.rs DiagMsg::parse (real-capture tests), proc_join.rs, normalize::listen_port_event tests, tests/robustness.rs, fuzz netlink_parse; polled every 10 s by agent |  | [sensors/linux/netlink.md#listening-sockets](sensors/linux/netlink.md#listening-sockets) |
| Conntrack TCP flows with byte counters, attributed to a PID (NetworkFlow events) | built | conntrack_socket.rs dump, conntrack_attrs.rs ConntrackFlow::parse tests, normalize::conntrack_flow_events_for tests; counters need nf_conntrack_acct=1 |  | [sensors/linux/netlink.md#conntrack-flows](sensors/linux/netlink.md#conntrack-flows) |
| UDP bound-socket snapshots | partial | snapshot_udp/listen_port_events_udp exist in netlink lib.rs but are unfiltered and not called by the agent; ListenPortEvent lacks a protocol field | [#40](https://github.com/synthaea-lab/agent/issues/40) | [sensors/linux/netlink.md#listening-sockets](sensors/linux/netlink.md#listening-sockets) |
| Proc connector fork/exec/exit cross-check against the eBPF stream | partial | proc_socket.rs ProcEventSubscription, proc_events.rs ProcEvent::parse tests; nothing consumes it and no schema mapping | [#88](https://github.com/synthaea-lab/agent/issues/88) | [sensors/linux/netlink.md#proc-connector](sensors/linux/netlink.md#proc-connector) |

### Journal

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| Authentication events from journald (sshd accept/fail, sudo, su, PAM sessions and auth failures) | built | journal classify.rs (37 tests), auth.rs to_auth_event (14 tests), tail.rs ClassifiedJournal dedup tests; sshd accept and sudo lab-verified, failure paths unit-tested only |  | [sensors/linux/journal.md#mappings](sensors/linux/journal.md#mappings) |
| systemd unit lifecycle: first-start persistence flag and security-unit stop events | built | journal persistence.rs UnitPersistenceTracker tests, unitstop.rs to_unit_stop_event tests; system-manager stop record not captured on a real host; unit failures not mapped |  | [sensors/linux/journal.md#mappings](sensors/linux/journal.md#mappings) |
| Journal tail liveness canary and cursor resume | built | journal canary.rs send_canary tests, tail.rs with_line_hook, agent journal_cursor.rs |  | [sensors/linux/journal.md#liveness-and-resume](sensors/linux/journal.md#liveness-and-resume) |

### Service logs

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| Web access-log signatures (traversal, SQLi, scanners, webshell-like) and per-window summaries | built | logs access.rs/http.rs/summary.rs/budget.rs tests, fuzz logs_parse, agent log_sources.rs |  | [sensors/linux/service-logs.md#signatures-and-events](sensors/linux/service-logs.md#signatures-and-events) |
| MySQL/MariaDB failed-login events | built | logs mysql.rs parse_mysql_error_line/to_auth_event tests (real MySQL 8 and MariaDB lines) |  | [sensors/linux/service-logs.md#parsing](sensors/linux/service-logs.md#parsing) |
| Rotation-safe log tailing with persisted position and misparse health alert | built | logs tail.rs Tailer tests (rename, copy-truncate, overlong lines), health.rs MisparseWatch tests |  | [sensors/linux/service-logs.md#health](sensors/linux/service-logs.md#health) |

### Process memory

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| Process memory map and memory reads for YARA memory scanning | built | crates/sensors/linux/procmem/src/lib.rs (9 tests incl. non-UTF-8 memfd name and own-process read), agent memscan.rs ProcMemSource |  | [sensors/linux/procmem.md#api](sensors/linux/procmem.md#api) |

## Windows sensors

### ETW

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| Process start/exit with real PEB command line, token SID + integrity level, parent lineage and kernel incarnation stamps | built | crates/sensors/windows/etw/src/providers.rs process_provider/on_process_start; kernel_process.rs tests; winapi.rs read_process_cmdline/read_process_user/read_process_sequence_number; pid_cache.rs tests; tests/kernel_process_keyword_mask.rs (ignored, needs elevation) |  | [sensors/windows/etw-enrichment.md#event-metadata](sensors/windows/etw-enrichment.md#event-metadata) |
| Image/DLL load events (Kernel-Process EID 5) for tracked processes | built | providers.rs on_image_load; kernel_process.rs tests; providers.rs test kernel_process_reads_process_thread_image_and_silo_events (Windows) |  | [sensors/windows/etw.md#providers](sensors/windows/etw.md#providers) |
| File create/write events with drive-letter paths and 8.3 short-name expansion | built | providers.rs file_provider; normalize.rs normalize_nt_path/disposition_to_flags tests; long_path.rs tests; tests/kernel_file_keyword_mask.rs (ignored) |  | [sensors/windows/etw-enrichment.md#paths](sensors/windows/etw-enrichment.md#paths) |
| TCP connect (IPv4/IPv6) and UDP send events with per-flow dedup | built | providers.rs network_provider; normalize.rs ConnectDedup tests |  | [sensors/windows/etw.md#providers](sensors/windows/etw.md#providers) |
| AMSI de-obfuscated script content with hash dedup and per-process budget | built | providers.rs amsi_provider; amsi.rs decode_text/AmsiGate with 9 tests |  | [sensors/windows/etw.md#bounds-and-back-pressure](sensors/windows/etw.md#bounds-and-back-pressure) |
| BITS job events attributed to the client process, Microsoft update hosts filtered | built | bits.rs BitsJobs/is_microsoft_update_url (14 tests); tests/robustness.rs |  | [sensors/windows/etw-enrichment.md#bits-jobs](sensors/windows/etw-enrichment.md#bits-jobs) |
| Mark-of-the-web (Zone.Identifier) write as FileQuarantine and removal as FileDelete | built | zone_identifier.rs parse/QuarantineDedup/mark_removal (23 tests); tests/robustness.rs never-panic suite |  | [sensors/windows/etw-enrichment.md#mark-of-the-web](sensors/windows/etw-enrichment.md#mark-of-the-web) |
| Remote thread creation (Sysmon 8 equivalent) without a driver | built | cross_process.rs ThreadOrigins/admit_remote_thread (25 tests incl. LSASS); providers.rs forward_remote_thread |  | [sensors/windows/etw-enrichment.md#remote-threads](sensors/windows/etw-enrichment.md#remote-threads) |
| Memory-reaching opens of LSASS (Sysmon 10 equivalent) with spoof-resistant LSASS identification | built | cross_process.rs reaches_memory/lsass_open_is_reported/is_system_lsass/LsassTracker tests; providers.rs audit_api_provider |  | [sensors/windows/etw-enrichment.md#lsass-access](sensors/windows/etw-enrichment.md#lsass-access) |
| Randomized session name with orphan cleanup across unclean shutdowns | built | sensor.rs stop_all_orphaned_sessions; normalize.rs random_session_name/parse_orphaned_sessions/select_orphaned_sessions/start_or_stop_session tests |  | [sensors/windows/etw.md#session-names-and-orphan-cleanup](sensors/windows/etw.md#session-names-and-orphan-cleanup) |
| Deterministic liveness canary with blind-session diagnosis (own losses, foreign real-time sessions) | built | sensor.rs liveness_watch/silent_session_diagnosis; etw_sessions.rs; normalize.rs describe_silent_session/listing_is_conclusive/describe_foreign_sessions tests |  | [sensors/windows/etw.md#liveness-canary-and-blind-session-diagnosis](sensors/windows/etw.md#liveness-canary-and-blind-session-diagnosis) |
| DNS, registry-write, PowerShell 4104, WMI, dynamic .NET assembly load and SMB connect telemetry | partial | providers.rs dns_provider/registry_provider/powershell_provider/wmi_provider/dotnet_provider/smb_provider; payload.rs decoders unit- and property-tested; user-mode providers enabled with all keywords | [#91](https://github.com/synthaea-lab/agent/issues/91) | [sensors/windows/etw.md#providers](sensors/windows/etw.md#providers) |
| LDAP search and NTLM usage telemetry (budgeted / deduplicated) | built | providers.rs ldap_provider/ntlm_provider; budget.rs PidBudget/KeyDedup tests; payload.rs ldap/ntlm decoder tests |  | [sensors/windows/etw.md#providers](sensors/windows/etw.md#providers) |
| Container attribution for process-isolated (server silo) containers | partial | silo.rs (23 tests), hcs.rs, winapi.rs read_server_silo_id; lab Done-when unchecked; needs Windows 11 22H2 / Server 2025 | [#39](https://github.com/synthaea-lab/agent/issues/39) | [sensors/windows/etw-enrichment.md#containers](sensors/windows/etw-enrichment.md#containers) |
| Executed image file identity for the T1204.002 rename-and-replace gate | partial | lib.rs identity_token/image_identity_is_capturable tests; winapi.rs image_file_id; race window up to ETW delivery latency remains | [#46](https://github.com/synthaea-lab/agent/issues/46) | [sensors/windows/etw-enrichment.md#image-file-identity](sensors/windows/etw-enrichment.md#image-file-identity) |
| Handle duplication, threadless injection and kernel-mode activity visibility (TI-ETW / ObRegisterCallbacks) | planned | not built; requires PPL driver | [#32](https://github.com/synthaea-lab/agent/issues/32) | [sensors/windows/etw-enrichment.md#lsass-access](sensors/windows/etw-enrichment.md#lsass-access) |

### Event Log

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| Service install (7045), scheduled task create/update (4698/4702) and local account creation (4720) persistence artifacts | built | eventlog/src/sensor.rs SERVICE_INSTALLS/SCHEDULED_TASKS/SCHEDULED_TASK_UPDATES/ACCOUNT_CREATIONS; xml/records parser tests; tests/xml_parser_robustness.rs |  | [sensors/windows/eventlog.md#poll-targets](sensors/windows/eventlog.md#poll-targets) |
| Logon events 4624/4625/4648/4672 as Auth | built | sensor.rs LOGON_EVENTS/to_auth_event; xml/records/logon.rs parse_logon_block tests with capture-derived fixtures |  | [sensors/windows/eventlog.md#notes-per-source](sensors/windows/eventlog.md#notes-per-source) |
| AppLocker and WDAC policy decisions, Defender verdicts and tamper traces | built | sensor.rs APPLOCKER_*/WDAC_OP/DEFENDER_OP normalizers and tests; tests/applocker_robustness.rs |  | [sensors/windows/eventlog.md#poll-targets](sensors/windows/eventlog.md#poll-targets) |
| Task Scheduler Operational 106 with action read-back from the task definition | built | sensor.rs normalize_task_registered_from/read_task_definition tests; channel off by default (warned) |  | [sensors/windows/eventlog.md#notes-per-source](sensors/windows/eventlog.md#notes-per-source) |
| RDP/console session lifecycle (21/23/24/25) and RDP authentication (1149) | built | sensor.rs SESSION_LIFECYCLE/RDP_CONNECTIONS; targets/session.rs tests; tests/session_robustness.rs |  | [sensors/windows/eventlog.md#poll-targets](sensors/windows/eventlog.md#poll-targets) |
| Event log cleared (Security 1102, System 104) | built | sensor.rs SECURITY_LOG_CLEARS/LOG_FILE_CLEARS; targets/log_cleared.rs tests; tests/log_cleared_robustness.rs |  | [sensors/windows/eventlog.md#notes-per-source](sensors/windows/eventlog.md#notes-per-source) |
| Per-target liveness heartbeats and disabled-channel warning | built | sensor.rs EventLogSensor::liveness (config_tests liveness_*), warn_about_disabled_channels; channel.rs tests (Windows) |  | [sensors/windows/eventlog.md#liveness](sensors/windows/eventlog.md#liveness) |
| Kerberos delegation failures (201/202) | partial | sensor.rs KERBEROS_DELEGATION_FAILURES; targets/kerberos.rs tests; tests/kerberos_delegation_failure_robustness.rs; channel off by default and not enabled by the sensor | [#91](https://github.com/synthaea-lab/agent/issues/91) | [sensors/windows/eventlog.md#disabled-channels](sensors/windows/eventlog.md#disabled-channels) |
| Automatic audit subcategory enablement via auditpol | partial | sensor.rs enable_audit_subcategory; best-effort, no automated test | [#91](https://github.com/synthaea-lab/agent/issues/91) | [sensors/windows/eventlog.md#audit-policy-enablement](sensors/windows/eventlog.md#audit-policy-enablement) |
| Push transport via EvtSubscribe | partial | subscribe.rs subscribe/SubscriptionHandle; config_tests subscribe_transport_selectable; no liveness, no bookmark, agent hard-codes Polling | [#91](https://github.com/synthaea-lab/agent/issues/91) | [sensors/windows/eventlog.md#subscribe](sensors/windows/eventlog.md#subscribe) |
| Per-channel toggles and transport driven by policy | partial | apps/agent/src/commands/windows.rs eventlog_config: only 4 switches come from EventLogPolicy (default), others hard-coded | [#91](https://github.com/synthaea-lab/agent/issues/91) | [sensors/windows/eventlog.md#configuration](sensors/windows/eventlog.md#configuration) |

### Socket table

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| TCP listener and fixed-port UDP socket snapshots for LISTENER-DRIFT | built | sockets/src/snapshot.rs snapshot_for_drift; raw.rs is_drift_relevant tests; tests/live_snapshot.rs (Windows, default suite) |  | [sensors/windows/sockets.md](sensors/windows/sockets.md) |

### Minifilter

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| Kernel-reported file deletes, renames, timestamp-set requests and raw volume opens | built | driver/minifilter/SynthaeaFilter.c; minifilter/src/wire.rs decode + proptest, events.rs to_event tests; driver not built in CI, lab only |  | [sensors/windows/minifilter.md#what-is-reported](sensors/windows/minifilter.md#what-is-reported) |
| Two-sided loss accounting and silence heartbeat for the driver channel | built | minifilter/src/stats.rs ChannelStats (proptest); channel.rs LossReport; agent spawn_minifilter heartbeat |  | [sensors/windows/minifilter.md#loss-accounting](sensors/windows/minifilter.md#loss-accounting) |
| ADS, named pipes, process/image/registry kernel callbacks, ELAM/PPL launch and tamper resistance | planned | not built; driver allows unload, registers only CREATE/SET_INFORMATION | [#27](https://github.com/synthaea-lab/agent/issues/27) | [sensors/windows/minifilter.md#status-and-gaps](sensors/windows/minifilter.md#status-and-gaps) |
| Production (attestation) driver signing | planned | test-signing only | [#58](https://github.com/synthaea-lab/agent/issues/58) | [sensors/windows/minifilter.md#building-and-running](sensors/windows/minifilter.md#building-and-running) |

### Network (WFP)

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| WFP network telemetry and inline block | planned | not built | [#33](https://github.com/synthaea-lab/agent/issues/33) | [sensors/windows/README.md](sensors/windows/README.md) |

## macOS sensors

### EndpointSecurity

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| Exec with argv, parent image and kernel code-signing verdict; file open/create/rename/unlink and writable shared mmap | partial | endpoint-security/shim/es_shim.c, src/normalize.rs (unit tests on all OS), src/sensor.rs; never run with an entitled client | [#78](https://github.com/synthaea-lab/agent/issues/78) | [sensors/macos/endpoint-security.md#subscriptions](sensors/macos/endpoint-security.md#subscriptions) |
| BTM launch-item persistence, SSH/login/loginwindow sessions, quarantine provenance, mount, signals to ES clients, XPC connects | partial | es_shim.c groups PERSISTENCE..XPC; normalize.rs tests (quarantine_agent, wherefroms_urls, BtmItemType); lab validation pending | [#78](https://github.com/synthaea-lab/agent/issues/78) | [sensors/macos/endpoint-security.md#subscriptions](sensors/macos/endpoint-security.md#subscriptions) |
| Injection and tamper process events (task ports, ptrace, CS invalidation) | planned | not subscribed | [#37](https://github.com/synthaea-lab/agent/issues/37) | [sensors/macos/endpoint-security.md#gaps](sensors/macos/endpoint-security.md#gaps) |
| OS security-subsystem events (XProtect, Gatekeeper override, TCC modify, OD accounts, profiles) | planned | not subscribed | [#38](https://github.com/synthaea-lab/agent/issues/38) | [sensors/macos/endpoint-security.md#gaps](sensors/macos/endpoint-security.md#gaps) |
| Anti-forensics file operations (quarantine strip, timestomp, hidden flags, kext/IOKit) | planned | not subscribed | [#20](https://github.com/synthaea-lab/agent/issues/20) | [sensors/macos/endpoint-security.md#gaps](sensors/macos/endpoint-security.md#gaps) |
| AUTH-mode inline blocking | planned | NOTIFY-only subscriptions in es_shim.c | [#90](https://github.com/synthaea-lab/agent/issues/90) | [sensors/macos/endpoint-security.md#gaps](sensors/macos/endpoint-security.md#gaps) |

### Unified log

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| sudo outcomes, TCC decisions (joined) and Gatekeeper verdicts from the unified log, rate-bounded | built | unifiedlog/src/classify.rs, tcc.rs TccJoiner, stream.rs NormalizedLogStream; unit tests with verbatim macOS 26 captures |  | [sensors/macos/unified-log.md#pipeline](sensors/macos/unified-log.md#pipeline) |
| TCC requesting-client attribution | partial | TccDecisionEvent::client always None (redacted in public stream) | [#36](https://github.com/synthaea-lab/agent/issues/36) | [sensors/macos/unified-log.md#redaction-limits](sensors/macos/unified-log.md#redaction-limits) |

### Socket table

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| Entitlement-free TCP listener snapshots with direct pid/ppid/uid attribution for LISTENER-DRIFT | built | sockets/shim/sockets_shim.c, src/snapshot.rs; tests/live_snapshot.rs (macOS) |  | [sensors/macos/sockets.md](sensors/macos/sockets.md) |
| UDP bound-socket snapshots | planned | shim walks TCP only | [#40](https://github.com/synthaea-lab/agent/issues/40) | [sensors/macos/sockets.md#gaps](sensors/macos/sockets.md#gaps) |

### Network Extension

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| Flows (inbound/outbound, byte counts) and DNS query/response with process attribution | partial | network-extension/src/wire.rs, receiver.rs (socket round-trip test), normalize.rs tests; Swift providers are unbuilt scaffolds; accept_loop serves one connection at a time | [#21](https://github.com/synthaea-lab/agent/issues/21) | [sensors/macos/network-extension.md](sensors/macos/network-extension.md) |
| User attribution and macOS 15 endpoint APIs (wire v2) | planned | normalize emits User::Unknown; NWHostEndpoint APIs in Swift | [#35](https://github.com/synthaea-lab/agent/issues/35) | [sensors/macos/network-extension.md#known-gaps](sensors/macos/network-extension.md#known-gaps) |

### macOS agent wiring

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| Silence monitoring, log-stream restart and health counters for macOS sources | planned | apps/agent/src/commands/macos.rs registers no SensorHeartbeat; shed/skew counters unread | [#34](https://github.com/synthaea-lab/agent/issues/34) | [sensors/macos/README.md#differences-from-windows-and-linux](sensors/macos/README.md#differences-from-windows-and-linux) |

## Detection

### Rule engine

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| Stateless single-event ATT&CK rules (exec, file, connect, signal, log-clear, AMSI, Defender, LDAP, NTLM, package change) | built | crates/rules/src/stateless/mod.rs evaluate_* dispatchers (rules in one module per tactic) and the amsi/defender/ldap/ntlm/inventory modules; tests in crates/rules/src/tests/*.rs (over 800 tests) |  | [detection/rules.md#public-contract](detection/rules.md#public-contract) |
| Stateful correlation rules over a bounded, incarnation-aware history (RuleState: T1105, T1059 lineage, BEACON, SCAN-*, RECON-BURST, EGRESS-*, ARCHIVE-EXFIL, ransomware rename/unlink, auth bursts, LISTENER-DRIFT, POLICY-DENIAL-DRIFT, ...) | built | crates/rules/src/state.rs RuleState::on_*; crates/rules/src/sliding.rs; tests in crates/rules/src/tests/linux.rs, windows.rs, logon.rs, privesc.rs etc.; proptest in rdp.rs and sudo.rs |  | [detection/rules.md#rulestate-internals](detection/rules.md#rulestate-internals) |
| Signature-gated T1204.002 (downloaded file run) silenced only by a chain-verified signature on the image that ran | partial | crates/rules/src/signature_gate.rs SignatureGatedAlert::resolve; apps/agent/src/enrich_queue.rs image_confirmed and its test. Gaps: image identity is captured only on Windows and only from the ETW callback (window between process start and callback stays open); Linux has no signature scheme so the finding always raises | [#46](https://github.com/synthaea-lab/agent/issues/46) | [detection/rules.md#signature-gated-findings](detection/rules.md#signature-gated-findings) |
| ODD-HOUR-LOGON with operator-configured offset, work hours and exempt accounts | partial | crates/rules/src/logon.rs, RuleState::set_local_utc_offset_minutes/set_work_hours/set_odd_hour_exempt_accounts/set_local_zone; crates/config/src/schema.rs DetectionConfig; tests in crates/rules/src/tests/logon.rs. Platform time-zone verification per OS and window calibration are open | [#15](https://github.com/synthaea-lab/agent/issues/15) | [detection/rules.md#configuration](detection/rules.md#configuration) |
| LISTENER-DRIFT keyed on protocol, seeded from a startup snapshot | partial | RuleState::on_listen_port and seed_listen_ports in crates/rules/src/state.rs, rule in crates/rules/src/drift_state.rs; tests in crates/rules/src/tests/linux.rs. UDP bound-socket snapshots and the protocol field are not collected on every platform | [#40](https://github.com/synthaea-lab/agent/issues/40) | [detection/rules.md#first-seen-shapes](detection/rules.md#first-seen-shapes) |
| Impact/privilege-escalation joins on Windows and macOS (T1548 joins, T1486 write-volume) | partial | T1486 write-volume corroboration (RuleState::on_file_write, SlidingSum) is exercised on Linux; Windows/macOS remainder deferred | [#19](https://github.com/synthaea-lab/agent/issues/19) | [detection/rules.md#rulestate-internals](detection/rules.md#rulestate-internals) |

### Sigma

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| Sigma process_creation subset with strict load-time validation (fields, modifiers incl. \|all, keywords, list-of-maps selections, logsource, metadata) | built | crates/sigma/src/validate.rs, eval.rs, rule.rs; tests in crates/sigma/src/tests.rs and crates/sigma/tests/content.rs (shipped rules fire on their samples) |  | [detection/sigma.md#supported-subset](detection/sigma.md#supported-subset) |
| Bounded condition grammar (and/or/not, parentheses, 1 of / all of patterns and them) compiled once per rule | built | crates/sigma/src/condition.rs compile/Compiled::eval with MAX_* bounds; crates/sigma/src/condition_tests.rs |  | [detection/sigma.md#conditions](detection/sigma.md#conditions) |
| Per-platform rule loading (macOS also loads linux/), platform derived from the path under the rules root | built | crates/sigma/src/engine.rs Platform::rule_dirs, SigmaEngine::load_dir_for; crates/sigma/tests/platform.rs EXPECTED; sink tests the_agent_loads_only_the_sigma_rules_of_its_own_platform |  | [detection/sigma.md#which-rules-a-host-loads](detection/sigma.md#which-rules-a-host-loads) |
| Hardened YAML parsing (duplicate/merge keys and unknown tags refused, strict booleans, rule-sized budget) | built | crates/sigma/src/engine.rs parse_rule_yaml, describe_yaml_error; tests in crates/sigma/src/tests.rs |  | [detection/sigma.md#parsing-hardening](detection/sigma.md#parsing-hardening) |
| PE version-resource fields (OriginalFileName, Company, Description, Product) in windows/ rules | partial | Engine side built: crates/sigma/src/eval.rs Haystacks::get, validate.rs WINDOWS_ONLY_FIELDS, tests in src/tests.rs. Gap found in code: apps/agent/src/sink/mod.rs detect_exec runs eval_exec on the capture thread before apps/agent/src/enrich_queue.rs writes original_file_name/company_name/... and every sensor leaves them None, so in the running agent these rules never match. No public issue found | [#95](https://github.com/synthaea-lab/agent/issues/95) | [detection/sigma.md#fields](detection/sigma.md#fields) |
| Other logsource categories and services, extra fields (ParentCommandLine, Hashes, User, ...), windash/re/base64offset modifiers, aggregations and timeframe | planned | Refused at load by crates/sigma/src/validate.rs and condition.rs; nothing maps them | [#96](https://github.com/synthaea-lab/agent/issues/96) | [detection/sigma.md#log-source](detection/sigma.md#log-source) |

### YARA

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| Budgeted background YARA-X scan of files opened for write, attributed to the writing process and fused into its verdict | built | crates/yara/src/queue.rs ScanQueue (512 cap, 200 ms settle) and its tests; apps/agent/src/sink/mod.rs detect_file_open, start_yara, fuse_yara_match; crates/yara/tests/content.rs |  | [detection/yara.md#file-scanning](detection/yara.md#file-scanning) |
| Per-user read check so the agent's CAP_DAC_READ_SEARCH cannot be aimed at files the requester cannot read | built | crates/yara/src/access.rs Requester::open and its tests; RuleSet::scan_file_as |  | [detection/yara.md#reading-on-the-requesters-behalf](detection/yara.md#reading-on-the-requesters-behalf) |
| Triggered, budgeted process-memory scanning on Linux (memfd exec → scan executable file-less regions) | built | crates/yara/src/memory.rs scan_memory, MemoryScanQueue, MemoryBudget with tests; apps/agent/src/memscan.rs ProcMemSource; sink request_memory_scan on T1620 and its sink test. Reading other uids needs CAP_SYS_PTRACE, not granted by default |  | [detection/yara.md#process-memory-scanning](detection/yara.md#process-memory-scanning) |
| Quarantine of a YARA-matched file | partial | apps/agent/src/sink/mod.rs quarantine_matched_payload; sink tests a_yara_match_with_quarantine_enabled_moves_the_payload_and_audits_it. Only Linux calls enable_response; on Windows and macOS --enable-quarantine is ignored and no RESPONSE-QUARANTINE line is written | [#97](https://github.com/synthaea-lab/agent/issues/97) | [detection/yara.md#what-a-match-does](detection/yara.md#what-a-match-does) |
| Process-memory scanning on Windows and macOS | planned | start_memscan returns Load::Absent off Linux (apps/agent/src/sink/mod.rs); no MemorySource implementation for those platforms | [#32](https://github.com/synthaea-lab/agent/issues/32) | [detection/yara.md#platform-differences](detection/yara.md#platform-differences) |

### IOC matching

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| Memory-bounded IOC matching of SHA-256, IP and domain (label-boundary suffix) with a Bloom pre-filter and exact tier, hot-swappable | built | crates/intel/src/set.rs, filter.rs, engine.rs; crates/intel/tests/engine.rs, domains.rs, robustness.rs, feed_golden.rs, content.rs, draft_golden.rs |  | [detection/ioc.md#data-structure](detection/ioc.md#data-structure) |
| IOC findings in the agent on exec hash, connect/flow destination and DNS query, with per-indicator cooldown and own control-plane traffic skip | built | apps/agent/src/ioc.rs IocMatcher check_exec_image/check_connect/check_dns_query and its unit tests; apps/agent/src/own_traffic.rs; apps/agent/src/sink/mod.rs detect_connect/detect_dns_query/enrich worker callback |  | [detection/ioc.md#in-the-agent](detection/ioc.md#in-the-agent) |
| Signed production delivery of IOC feeds | partial | Feeds load from &lt;content_root&gt;/ioc/ delivered by the signed content manifest; production signing keys are not in place, so in production a feed is a locally placed file | [#43](https://github.com/synthaea-lab/agent/issues/43) | [detection/ioc.md#loading](detection/ioc.md#loading) |
| IOC hash match on written files | planned | FileWriteEvent carries no path or hash; nothing calls the matcher on writes | [#96](https://github.com/synthaea-lab/agent/issues/96) | [detection/ioc.md#where-it-matches](detection/ioc.md#where-it-matches) |

### Enrichment

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| SHA-256 of executed images off the capture thread, with an identity-checked cache and single-handle hashing | built | crates/enrich/src/lib.rs Enricher::enrich/enrich_uncached and unit tests; apps/agent/src/enrich_queue.rs EnrichQueue and tests |  | [detection/enrichment.md#the-cache](detection/enrichment.md#the-cache) |
| Code-signature verdict (Windows Authenticode + catalog, macOS codesign) | built | crates/enrich/src/sig.rs verify per platform; Linux always Signature::Unsupported (no standard scheme) |  | [detection/enrichment.md#signature-verification](detection/enrichment.md#signature-verification) |
| PE version-resource strings on Windows | partial | crates/enrich/src/pe_info.rs read and tests; reads by path through version.dll so it does not share the single-handle guarantee; not visible to Sigma at evaluation time (see sigma PE fields) | [#95](https://github.com/synthaea-lab/agent/issues/95) | [detection/enrichment.md#pe-version-strings](detection/enrichment.md#pe-version-strings) |

### On-device ML

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| Rust/Python feature parity for cmdline, correlation, T1, lineage and rarity extractors, and the common-set snapshot reader | built | crates/ml/src/features/*.rs; crates/ml/tests/features_golden.rs, capture_parity.rs, t1_golden.rs, lineage_golden.rs, rarity_golden.rs, common_set_snapshot_golden.rs, common_set_snapshot_robustness.rs (fixtures from the ml/server siblings) |  | [detection/ml.md#feature-extractors-and-parity](detection/ml.md#feature-extractors-and-parity) |
| ONNX Isolation Forest scoring with conformal threshold, out-of-distribution guard and arity check | built | crates/ml/src/scorer.rs, scorer/correlation.rs, scorer/behavior.rs, bounds.rs; tests crates/ml/tests/scorer.rs, correlation_scorer.rs, t1_scorer.rs, threshold_tests |  | [detection/ml.md#scoring](detection/ml.md#scoring) |
| T2 correlation scorer feeding the correlator's Bayesian belief in the agent | partial | apps/agent/src/sink/correlation.rs load_correlation_scorer and correlate; ml::score_to_llr. No model trained on real multi-event captures ships; GAIN = 20 is provisional; models are not reloaded on reload_content | [#94](https://github.com/synthaea-lab/agent/issues/94) | [detection/ml.md#t2-in-the-agent](detection/ml.md#t2-in-the-agent) |
| T0 command-line scorer on-device | partial | CmdlineScorer exists and is parity-tested (crates/ml/tests/scorer.rs) but nothing in apps/agent/src constructs or calls it | [#94](https://github.com/synthaea-lab/agent/issues/94) | [detection/ml.md#tiers](detection/ml.md#tiers) |
| T1 17-feature behaviour scorer on-device | partial | BehaviorScorer exists with strict metadata (crates/ml/tests/t1_scorer.rs); not wired into the agent; waits for a model trained on a real capture | [#94](https://github.com/synthaea-lab/agent/issues/94) | [detection/ml.md#tiers](detection/ml.md#tiers) |
| Per-feature attribution of a score from the ONNX tree structure | partial | crates/ml/src/forest/mod.rs, forest/onnx.rs, proto.rs; crates/ml/tests/attribution_golden.rs. score_explained is not called by the agent, so detections carry no attributions yet | [#94](https://github.com/synthaea-lab/agent/issues/94) | [detection/ml.md#attribution](detection/ml.md#attribution) |
| Fleet common-set rarity as capped correlator evidence | partial | apps/agent/src/sink/mod.rs load_common_set, note_image_rarity, rarity_evidence with sink tests; ml::features::rarity. K, minimum coverage (10), max age (3 days) and filter FP rate are provisional. Note: the doc comments in crates/ml/src/features/rarity.rs and apps/agent/src/sink/mod.rs field `common_set` still say nothing in the agent reads the snapshot, which the code contradicts | [#94](https://github.com/synthaea-lab/agent/issues/94) | [detection/ml.md#rarity-and-the-common-set](detection/ml.md#rarity-and-the-common-set) |
| Static onnxruntime release build; dev build portability | partial | crates/ml/Cargo.toml dynamic-onnx default feature; prebuilt runtime fails to link on Debian 12 / Ubuntu 22.04 | [#53](https://github.com/synthaea-lab/agent/issues/53) | [detection/ml.md#build](detection/ml.md#build) |

### Deception

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| Seed-derived canary files with inventory-first lifecycle (plant, refresh, verify, remove) and neighbour-matched mtime/owner/mode | built | crates/deception/src/plan.rs, lifecycle.rs with unit tests; apps/agent/src/deception.rs start_with_decoys, spawn_refresh, retire |  | [detection/deception.md#lifecycle](detection/deception.md#lifecycle) |
| Canary-touch detection with allow list, exec hold for out-of-order delivery, read-only cooldown and ransomware corroboration | built | crates/deception/src/tripwire.rs Tripwires::matches and tests; apps/agent/src/sink/canary.rs CanaryGate (detect, hold, judge_held, raise) with the sink canary test families; apps/agent/src/deception.rs CanaryAllow |  | [detection/deception.md#detection-path](detection/deception.md#detection-path) |
| Decoy credentials in canaries, hashes registered with the control plane | built | crates/deception/src/plan.rs decoy_token/decoy_tokens; apps/agent/src/deception.rs register_with_retry (schedule tested), register_decoys_in_background |  | [detection/deception.md#decoy-credentials](detection/deception.md#decoy-credentials) |
| Canary touches observed under open floods | partial | Detection reads sensor open events; ring-buffer overflow drops them and those drops are not reported in the health beacon | [#89](https://github.com/synthaea-lab/agent/issues/89) | [detection/deception.md#limits](detection/deception.md#limits) |
| Honeypot listeners | planned | Described as intent in crates/deception/src/lib.rs; not implemented | [#96](https://github.com/synthaea-lab/agent/issues/96) | [detection/deception.md#limits](detection/deception.md#limits) |

### Correlation

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| Co-occurrence rules over a 60 s window (dropper chain, spawn+connect, connect+payload write, respawn+beacon, DNS tunnelling, in-memory assembly + connect/SMB, exec+SMB), once per window per rule and pid | built | crates/correlator/src/engine.rs CorrelationEngine::evaluate, crates/correlator/src/rules.rs; tests in crates/correlator/src/tests/rules.rs |  | [correlation.md#co-occurrence-rules](correlation.md#co-occurrence-rules) |
| Web access-log request paired with a web-server child shell (T1505.003), bounded and shedding-counted | built | CorrelationEngine::queue_web_shell/flush_web_shells, rules::rule_web_request_shell; tests in crates/correlator/src/tests/web.rs |  | [correlation.md#web-request-plus-web-server-shell-t1505003](correlation.md#web-request-plus-web-server-shell-t1505003) |
| Masquerade-guarded name exclusions (IGNORED, BAYES_NAME_EXCLUSIONS) | built | engine.rs masquerading map + policy::name_exclusion_applies/parent_exclusion_applies; tests masqueraded_ignored_name_is_still_correlated, real_system_svchost_stays_ignored in tests/rules.rs |  | [correlation.md#excluded-processes-and-the-masquerade-check](correlation.md#excluded-processes-and-the-masquerade-check) |
| Per-entity (ppid, comm) Bayesian belief with decay and a once-per-crossing BAYES alert, parent-incarnation aware | built | crates/correlator/src/bayes.rs update_belief, engine.rs bayes_alert/belief_or_insert; tests in tests/behavior.rs and tests/parent_generation.rs |  | [correlation.md#the-bayesian-belief](correlation.md#the-bayesian-belief) |
| Fleet rarity (image not in the common-set snapshot) as weak, capped belief evidence | built | CorrelationEngine::apply_rarity_evidence, bayes::apply_rarity_llr, sink rarity_evidence; tests in crates/correlator/src/tests/rarity.rs and sink rarity_evidence_follows_the_snapshot_the_hash_and_the_coverage (weight provisional) |  | [correlation.md#update-rule](correlation.md#update-rule) |
| Kill shield for the process holding an SSH login session | built | policy::is_login_session, KillShield::LoginSession; tests in tests/behavior.rs and sink an_ssh_login_session_crossing_bayes_is_refused_not_killed, an_sshd_reexecd_for_a_login_crossing_bayes_is_refused_not_killed |  | [correlation.md#kill-shields-provenance-recorded-at-exec](correlation.md#kill-shields-provenance-recorded-at-exec) |
| ML correlation score as an extra LLR term on the belief | partial | Scorer wired (apps/agent/src/sink/correlation.rs correlate -&gt; ml::score_to_llr -&gt; CorrelationEngine::update_belief_with_ml); score_to_llr gain/clamps are placeholders and no trained model ships, so the term is absent on a default install | [#94](https://github.com/synthaea-lab/agent/issues/94) | [correlation.md#update-rule](correlation.md#update-rule) |
| Kill shield for a system service's main process | partial | CorrelationEngine::is_service_main_process/kill_shield + policy::service_main_path_is_trusted; tests in tests/behavior.rs and sink a_system_service_crossing_bayes_is_refused_not_killed. Only filled from execs seen after agent start, so pre-existing services are unshielded | [#52](https://github.com/synthaea-lab/agent/issues/52) | [correlation.md#kill-shields-provenance-recorded-at-exec](correlation.md#kill-shields-provenance-recorded-at-exec) |

### Verdict fusion

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| Cross-engine verdict fusion per entity: max severity/score, same-technique dedup window from first sighting, bounded evidence | built | crates/verdict/src/lib.rs VerdictEngine::record; unit tests in the same file; wired via apps/agent/src/sink/mod.rs record_detection and fuse_yara_match |  | [correlation.md#verdict-fusion](correlation.md#verdict-fusion) |
| Operator suppression of a technique on an entity (cli suppress/unsuppress, bounded) | built | VerdictEngine::suppress/unsuppress/suppressions, DetectionSink::suppress_verdict, apps/agent/src/ipc_handler.rs, apps/cli/src/main.rs; tests the_suppression_list_is_bounded etc. in verdict/src/lib.rs (runtime only, cleared on restart) |  | [correlation.md#verdict-fusion](correlation.md#verdict-fusion) |

## Response and self-protection

### Response

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| Escalation alert (RESPONSE-ESCALATE) when a fused verdict reaches High | built | response::should_escalate (crates/response/src/escalate.rs), sink escalate_if_warranted; tests a_critical_fused_verdict_raises_an_escalation_alert_without_killing, a_high_severity_yara_match_raises_an_escalation_alert in apps/agent/src/sink/tests.rs |  | [response.md#escalation](response.md#escalation) |
| Ransomware reflex: kill a process that both raised the burst rule and touched a canary within 60 s | built | apps/agent/src/ransomware_join.rs RansomwareJoin, sink ransomware_reflex; tests a_burst_then_a_canary_touch_by_the_same_process_kills_it, a_burst_and_a_canary_touch_from_two_processes_kill_neither in apps/agent/src/sink/tests.rs (Linux wiring only) |  | [response.md#what-can-trigger-a-kill](response.md#what-can-trigger-a-kill) |
| Quarantine list and restore (agent quarantine list\|restore), hash-checked, never overwrites, audited | built | response::list_quarantined/unquarantine/is_still_quarantined, apps/agent/src/quarantine_cmd.rs cmd_quarantine_restore; tests in quarantine.rs and quarantine_cmd.rs |  | [response.md#restore-and-list](response.md#restore-and-list) |
| Policy-gated automated kill on BAYES crossing, with kill shield and observe-only default | partial | apps/agent/src/sink/response.rs crosses_kill_gate, kill_for; Linux only (windows/macos cmd_run ignore response flags); service-main shield gap for services started before the agent | [#52](https://github.com/synthaea-lab/agent/issues/52) | [lifecycle.md#5-automated-response](lifecycle.md#5-automated-response) |
| Automated process kill on a correlator BAYES crossing, observe-only by default, with protected-pid refusal | partial | sink crosses_kill_gate/maybe_kill/kill_for, response::kill_process (tests in kill.rs), Linux terminate_process; sink tests bayes_crossing_with_kill_enabled_calls_terminate_on_the_verdict_pid. Only Linux calls enable_response; Windows/macOS accept --enable-kill and ignore it. No public issue tracks the other platforms | [#97](https://github.com/synthaea-lab/agent/issues/97) | [response.md#the-kill-gate](response.md#the-kill-gate) |
| Automated quarantine of a YARA-matched written file (digest-named, origin sidecar, 0400, symlink-safe, writer-safe snapshot) | partial | response::quarantine_file (crates/response/src/quarantine.rs, extensive unit tests), sink quarantine_matched_payload; sink tests a_yara_match_with_quarantine_enabled_moves_the_payload_and_audits_it. Linux only; under the packaged unit it cannot move files out of other users' directories; Windows ACL hardening absent | [#97](https://github.com/synthaea-lab/agent/issues/97) | [response.md#quarantine](response.md#quarantine) |
| Host isolation (block all but loopback, DHCP and control plane) with persisted intent and start-up reconciliation | partial | crates/response/src/isolation.rs isolate_host/lift_isolation/reconcile, unit-tested against a fake firewall; no HostFirewall implementation, no trigger, isolate_enabled always false in the binary | [#33](https://github.com/synthaea-lab/agent/issues/33) | [response.md#host-isolation-library-only](response.md#host-isolation-library-only) |
| Remediation: disable/remove attacker persistence, snapshot rollback, damage-manifest-scoped cleanup | planned | No code beyond quarantine restore | [#31](https://github.com/synthaea-lab/agent/issues/31) | [response.md#not-built-yet](response.md#not-built-yet) |
| Live response: analyst-driven, time-boxed, audited sessions | planned | crates/response/src/live.rs is a doc comment only | [#28](https://github.com/synthaea-lab/agent/issues/28) | [response.md#not-built-yet](response.md#not-built-yet) |

### Supervision

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| Watchdog respawn with crash-loop backoff | built | apps/watchdog/src/supervise.rs Backoff; tests fast_crashes_double_the_delay_up_to_the_cap, healthy_exit_resets_the_backoff_to_the_floor |  | [architecture.md#two-layers-of-kill-resistance](architecture.md#two-layers-of-kill-resistance) |
| Progress-backed hang detection (heartbeat file advanced only by completed on_event) | built | apps/agent/src/heartbeat.rs (writer_thread_advances_the_file), apps/agent/src/sink/mod.rs on_event progress counter, apps/watchdog/src/supervise.rs HeartbeatMonitor (a_hung_agent_is_flagged_after_miss_limit_stalled_checks) |  | [architecture.md#two-layers-of-kill-resistance](architecture.md#two-layers-of-kill-resistance) |
| Agent binary hash pinning before every spawn; Linux service-definition drift report | built | apps/watchdog/src/supervise.rs supervise_loop, apps/watchdog/src/tamper.rs BinaryPin |  | [architecture.md#two-layers-of-kill-resistance](architecture.md#two-layers-of-kill-resistance) |
| Post-update probation and rollback | partial | apps/watchdog/src/probation.rs Probation, decide; Linux only, Windows/macOS self-update not built | [#60](https://github.com/synthaea-lab/agent/issues/60) | [architecture.md#two-layers-of-kill-resistance](architecture.md#two-layers-of-kill-resistance) |

### Self-protection

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| Two-layer kill resistance: service manager restarts the watchdog, watchdog respawns the agent with crash-loop backoff | built | apps/watchdog/src/supervise.rs supervise_loop/Backoff, apps/watchdog/src/service/*; tests fast_crashes_double_the_delay_up_to_the_cap, healthy_exit_resets_the_backoff_to_the_floor |  | [self-protection.md#two-layers-of-kill-resistance](self-protection.md#two-layers-of-kill-resistance) |
| Agent dies with a killed watchdog (PR_SET_PDEATHSIG) | built | supervise.rs die_with_parent; test agent_dies_when_watchdog_is_sigkilled (Linux only) |  | [self-protection.md#two-layers-of-kill-resistance](self-protection.md#two-layers-of-kill-resistance) |
| Hang detection from a progress-backed heartbeat file | built | apps/agent/src/heartbeat.rs, supervise.rs HeartbeatMonitor; tests a_hung_agent_is_flagged_after_miss_limit_stalled_checks, a_missing_reading_is_never_itself_a_miss |  | [self-protection.md#liveness-and-hang-detection](self-protection.md#liveness-and-hang-detection) |
| Agent binary hash pin, re-checked before every spawn | built | apps/watchdog/src/tamper.rs BinaryPin; tests pin_detects_a_swapped_file, pin_detects_a_deleted_file |  | [self-protection.md#integrity-of-the-installed-artifacts](self-protection.md#integrity-of-the-installed-artifacts) |
| Service definition drift detection and install-surface hardening | partial | apps/watchdog/src/service/linux.rs snapshot_definition/drift_report (Linux only), tamper.rs refuse_world_writable_dir/harden_*; Windows SDDL hardening in service/windows.rs with tests; macOS has neither | [#42](https://github.com/synthaea-lab/agent/issues/42) | [self-protection.md#integrity-of-the-installed-artifacts](self-protection.md#integrity-of-the-installed-artifacts) |
| Sensor-silence detection (T1562) with per-sensor deadlines | partial | crates/tamper/src/heartbeat.rs SilenceMonitor (unit tests), apps/agent/src/silence.rs spawn_monitor (test a_sensor_confirmed_silent_is_a_tamper_alert_that_is_counted); wired on Linux and Windows, not macOS; eBPF has no canary | [#34](https://github.com/synthaea-lab/agent/issues/34) | [self-protection.md#sensor-silence-silence-is-a-detection](self-protection.md#sensor-silence-silence-is-a-detection) |
| Periodic self-integrity check against the signed release manifest (T1601) | partial | crates/tamper/src/integrity.rs Manifest::verify (unit tests), apps/agent/src/integrity.rs spawn_monitor; Linux only because versioned self-update is Linux only | [#60](https://github.com/synthaea-lab/agent/issues/60) | [self-protection.md#integrity-of-the-installed-artifacts](self-protection.md#integrity-of-the-installed-artifacts) |
| Protected-resource monitoring of the agent's own files (T1562) | partial | apps/agent/src/protected.rs ProtectedResourceGuard; tests a_foreign_write_to_a_protected_path_fires_an_alert, a_foreign_delete_of_a_protected_path_fires_an_alert. Linux only; watchdog binary and unit file not covered; not counted in the tamper counter. No public issue | [#97](https://github.com/synthaea-lab/agent/issues/97) | [self-protection.md#protected-resources](self-protection.md#protected-resources) |
| Kill loudness: record the sender of a termination signal before exit | partial | apps/agent/src/kill_loudness.rs (helpers unit-tested; flow validated manually). SIGKILL attribution relies on the eBPF probe; kernel-mediated stops are read from the command, direct cgroup writes and the OOM kill raise nothing | [#49](https://github.com/synthaea-lab/agent/issues/49) | [self-protection.md#kill-loudness](self-protection.md#kill-loudness) |
| Release probation with rollback and ban, and pre-start recovery of an unexecutable release | partial | apps/watchdog/src/probation.rs, recovery.rs, supervise.rs settle_probation; tests a_promoted_release_whose_agent_never_makes_progress_is_rolled_back_and_banned. Linux only | [#60](https://github.com/synthaea-lab/agent/issues/60) | [self-protection.md#release-probation-and-recovery](self-protection.md#release-probation-and-recovery) |
| Peer mesh: signed attestation heartbeats and heighten-only posture gossip | planned | crates/mesh/src/lib.rs is a doc comment only | [#29](https://github.com/synthaea-lab/agent/issues/29) | [self-protection.md#peer-mesh-planned](self-protection.md#peer-mesh-planned) |
| Kernel-level process protection (Windows PPL/ELAM driver) | planned | No driver in the workspace | [#27](https://github.com/synthaea-lab/agent/issues/27) | [self-protection.md#platform-coverage](self-protection.md#platform-coverage) |

### Health

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| Sensor-silence monitoring and health beacon | partial | apps/agent/src/silence.rs spawn_monitor, apps/agent/src/commands/common.rs health_collector; wired on Linux and Windows, not macOS | [#34](https://github.com/synthaea-lab/agent/issues/34) | [lifecycle.md#threads-in-agent-run](lifecycle.md#threads-in-agent-run) |

### Security model

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| Linux agent runs as unprivileged synthaea user with a minimal ambient capability set and systemd sandboxing | built | packaging/linux/systemd/synthaea-agent.service, synthaea.sysusers, alpine/synthaea-agent.initd; apps/agent/src/commands/linux.rs has_bpf_capabilities. The dev fallback unit from apps/watchdog/src/service/linux.rs cmd_install runs as root with no sandboxing. No automated test of the unit itself. |  | [security-model.md#privileges-per-os](security-model.md#privileges-per-os) |
| Windows service SID gates the minifilter port to the agent | built | apps/watchdog/src/service/windows.rs cmd_install (sc sidtype unrestricted); crates/sensors/windows/minifilter/src/lib.rs AGENT_SERVICE_SID; lab check crates/sensors/windows/driver/test/port-check.ps1 (not in CI) |  | [security-model.md#windows-minifilter-port](security-model.md#windows-minifilter-port) |
| Test-key guard: packaged builds cannot carry the public test key; test-keyed builds refuse to act on manifests without --allow-test-key | built | tools/check-no-test-key.sh and tools/assert-no-test-key.sh (CI, packaging scripts, static-agent workflows); apps/agent/src/trust.rs ensure_key_trusted plus tests; crates/updater/tests/test_key_build.rs |  | [security-model.md#keeping-the-test-key-out-of-packages](security-model.md#keeping-the-test-key-out-of-packages) |
| Offline release signing from a PKCS#11 token | built | tools/release/src/pkcs11.rs, signer.rs; tools/test-pkcs11.sh |  | [security-model.md#offline-signing](security-model.md#offline-signing) |
| Manifest path validation, anti-rollback and bounded artifact downloads | built | crates/updater/src/manifest.rs validate_entry_paths/check_release_version; content.rs is_safe_content_path; rotation.rs check_window; apps/agent/src/content.rs MAX_CONTENT_ARTIFACT_BYTES test; release.rs MAX_RELEASE_ARTIFACT_BYTES |  | [security-model.md#what-a-valid-signature-does-not-prove](security-model.md#what-a-valid-signature-does-not-prove) |
| Secrets in config are external references only (envvar:/file:), cleartext rejected | built | crates/config/src/secret.rs SecretRef plus tests; load.rs cleartext_secret_is_rejected_as_secret_invalid |  | [security-model.md#secret-handling](security-model.md#secret-handling) |
| mTLS transport with optional pinned private CA (no silent fallback to public roots) | built | crates/transport/src/client.rs build_tls_config/load_ca_roots; crates/transport/tests/private_ca.rs |  | [security-model.md#network](security-model.md#network) |
| Never-panic robustness suites for byte parsers | built | crates/sensors/linux/{audit,netlink}/tests/robustness.rs, wire/tests/exec_record.rs, windows/etw/tests/robustness.rs, windows/eventlog/tests/*robustness.rs, minifilter/src/wire.rs proptests, intel/tests/robustness.rs, userspace/src/tls_client_hello.rs tests. The linux logs parsers have no tests/ robustness suite (only the fuzz target) |  | [security-model.md#never-panic-parsers-and-fuzzing](security-model.md#never-panic-parsers-and-fuzzing) |
| Kill resistance: watchdog respawn plus service-manager restart, crash-loop backoff, hung-agent detection | built | apps/watchdog/src/supervise.rs (Backoff, HeartbeatMonitor, tests); apps/agent/src/heartbeat.rs; apps/watchdog/src/service/{linux,windows,macos}.rs |  | [security-model.md#self-protection](security-model.md#self-protection) |
| Binary pinning and periodic self-integrity check against the signed manifest | built | apps/watchdog/src/tamper.rs BinaryPin (used on every OS in supervise.rs, although tamper.rs's module doc says Linux-only); apps/agent/src/integrity.rs check_once plus tests |  | [security-model.md#self-protection](security-model.md#self-protection) |
| Windows hardened service DACL against non-SYSTEM sc stop/delete | built | apps/watchdog/src/service/windows.rs HARDENED_SERVICE_SDDL plus unit tests. This is friction only: admins keep WRITE_DAC |  | [security-model.md#self-protection](security-model.md#self-protection) |
| Credential redaction of telemetry at output boundaries | built | apps/agent/src/redact.rs RedactingSink; crates/redact/src/lib.rs and text.rs with proptests (proptest-regressions present) |  | [security-model.md#secret-handling](security-model.md#secret-handling) |
| Role-separated embedded Ed25519 keys (release, content, snapshot, recovery) with fail-closed unprovisioned state | partial | crates/updater/src/key.rs plus unit tests; crates/updater/tests/unprovisioned_build.rs. release, content and recovery hold TEMPORARY keys (2026-11-12) and snapshot is still 'unprovisioned' (its key turns the snapshot loop on; custody undecided) | [#43](https://github.com/synthaea-lab/agent/issues/43) | [security-model.md#signing-keys-and-the-test-key-guard](security-model.md#signing-keys-and-the-test-key-guard) |
| Local IPC restricted to root/elevated peers with bounded framing | partial | crates/ipc/src/stream.rs PeerCreds::check_authorized plus unit tests; frame.rs MAX_MESSAGE_BYTES plus test; server.rs RECENT_DETECTIONS_HARD_LIMIT. Gaps: no connection cap or idle timeout, and the client does not authenticate the server endpoint. Also, the stream.rs bind comment says the socket dir is root-permissioned, but packaging/linux/systemd/synthaea.tmpfiles makes /run/synthaea 0755 synthaea-owned | [#98](https://github.com/synthaea-lab/agent/issues/98) | [security-model.md#local-ipc-cli-and-ui-to-agent](security-model.md#local-ipc-cli-and-ui-to-agent) |
| Coverage-guided fuzzing of parsers on a schedule | partial | tests/fuzz/fuzz_targets/{audit_parse,netlink_parse,exec_record_parse,logs_parse}.rs. .github/workflows/fuzz.yml matrix runs only audit_parse and netlink_parse. tests/fuzz/README.md table omits logs_parse. No public issue found | [#98](https://github.com/synthaea-lab/agent/issues/98) | [security-model.md#never-panic-parsers-and-fuzzing](security-model.md#never-panic-parsers-and-fuzzing) |
| Protected-resource monitoring, sensor-silence alerts, kill-loudness | partial | apps/agent/src/protected.rs, silence.rs, kill_loudness.rs (Linux). SIGKILL attribution relies on the eBPF pinned map and is missing under the audit fallback. crates/tamper/src/lib.rs doc still lists protected-resource monitoring as not done, but it is implemented in apps/agent/src/protected.rs. macOS supplementary-sensor silence monitoring is a known gap | [#34](https://github.com/synthaea-lab/agent/issues/34) | [security-model.md#self-protection](security-model.md#self-protection) |
| Fail-closed kill guard for response actions | partial | crates/response/src/kill.rs protected_reason plus tests. The correlator's service-main refusal misses services started before the agent | [#52](https://github.com/synthaea-lab/agent/issues/52) | [security-model.md#response-actions-fail-closed-guards](security-model.md#response-actions-fail-closed-guards) |
| Passphrase-protected mTLS client key | planned | server.mtls_passphrase is parsed but not wired. crates/transport/src/client.rs build_tls_config refuses encrypted PEM keys. No public issue found | [#93](https://github.com/synthaea-lab/agent/issues/93) | [security-model.md#secret-handling](security-model.md#secret-handling) |
| Agent enrollment / client certificate issuance and renewal | planned | No enroll subcommand in apps/agent/src/main.rs. Certificates are placed by hand. Mentioned in the scope of operator-guide and acceptance-run issues only | [#79](https://github.com/synthaea-lab/agent/issues/79) | [security-model.md#network](security-model.md#network) |
| macOS network-extension socket peer authentication and line cap | planned | crates/sensors/macos/network-extension/src/receiver.rs: no peer check, and BufRead::lines without a length cap. Access relies on app-group container permissions | [#35](https://github.com/synthaea-lab/agent/issues/35) | [security-model.md#macos-network-extension-socket](security-model.md#macos-network-extension-socket) |
| Windows install-directory permission (DACL) audit | planned | KNOWN GAP comment in apps/watchdog/src/service/windows.rs cmd_install. Unix has refuse_world_writable_dir | [#98](https://github.com/synthaea-lab/agent/issues/98) | [security-model.md#what-is-not-defended](security-model.md#what-is-not-defended) |
| Kernel-level self-protection (Windows PPL/ELAM driver, macOS ES system extension for tamper resistance) | planned | Not built. A user-mode ceiling applies to every control on the page | [#27](https://github.com/synthaea-lab/agent/issues/27) | [security-model.md#what-is-not-defended](security-model.md#what-is-not-defended) |
| Detection of a security tool stopped through kernel resource limits (prlimit, memory.max, cgroup.freeze) | partial | Command-line rules in crates/rules/src/securitytool.rs (`systemctl freeze`/`set-property` with a memory, task or `CPUQuota` below 10 %, written in `%`, `‰` or `‱`; `prlimit --pid`, or any abbreviation of it, resolved to a listed tool by comm and by image name, cached and live). A write-intent open of a cgroup limit file leaves the open probe (crates/sensors/linux/wire/src/path_filter.rs `is_cgroup_limit_write`, then `check_security_tool_cgroup_write`, which reads the last two path segments after resolving `.` and `..`, so a non-normalized spelling or a cgroup2 mounted elsewhere is read too): unit-tested, and run on Fedora 43 (kernel 7.2.9), against a synthetic unit and the real `auditd.service`: an alert for each write to `memory.max`, `memory.high`, `cgroup.freeze`, `pids.max` and `cpu.max` of a listed unit, none for an unlisted unit; same result on Rocky 9.8 (kernel 5.14, synthetic unit). The non-normalized spellings were run by the reviewer on Debian 12 (6.1) before the fix and not rerun after it. The OOM kill itself raises no alert | [#49](https://github.com/synthaea-lab/agent/issues/49) | [security-model.md#what-is-not-defended](security-model.md#what-is-not-defended) |
| Signed self-update on Windows and macOS; Authenticode and notarization of packages | planned | apply-release is Linux-only (apps/agent/src/trust.rs Manifest::Release cfg note) | [#60](https://github.com/synthaea-lab/agent/issues/60) | [security-model.md#what-is-not-defended](security-model.md#what-is-not-defended) |
| Peer-to-peer mesh attestation | planned | crates/mesh/src/lib.rs is a 29-line doc-only stub | [#29](https://github.com/synthaea-lab/agent/issues/29) | [security-model.md#network](security-model.md#network) |

## Delivery, interfaces and build

### Transport

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| Store-and-forward upload of events and detections, at-least-once, byte-capped spools | built | apps/agent/src/upload.rs start, persist_detection; tests unacked_drain_redelivers_acked_drain_deletes, skipped_segment_is_discarded_and_newer_data_flows, detection_retry_key_survives_spool_reopen_until_ack |  | [lifecycle.md#6-enrichment-output-and-upload](lifecycle.md#6-enrichment-output-and-upload) |
| Offline fallback when upload cannot be set up | built | apps/agent/src/upload.rs start_or_disable; test a_missing_client_certificate_disables_the_upload_when_offline_fallback_is_on |  | [lifecycle.md#startup](lifecycle.md#startup) |
| mTLS client-certificate authentication to the control plane | built | crates/transport/src/client.rs build_tls_config; tests an_unreadable_client_certificate_or_key_names_the_file, apps/agent/src/upload.rs the_ca_and_the_client_certificate_reach_the_transport_config |  | [transport.md#tls-and-identity](transport.md#tls-and-identity) |
| Pinning the control plane to a private CA | built | client.rs load_ca_roots; crates/transport/tests/private_ca.rs |  | [transport.md#tls-and-identity](transport.md#tls-and-identity) |
| Store-and-forward event upload with at-least-once delivery | built | crates/transport/src/upload.rs EventUploader + apps/agent/src/upload.rs SpoolDrain; tests/http_path.rs success_uploads_every_batch_then_acks_once, transient_server_error_leaves_the_drain_untouched_for_redelivery |  | [transport.md#event-upload](transport.md#event-upload) |
| Poison-segment skipping with separate server and network attempt budgets | built | upload.rs upload_once; tests/http_path.rs connection_refused_repeated_is_skipped_only_at_the_larger_network_budget, poison_batch_not_in_the_first_slot_still_reaches_max_drain_attempts |  | [transport.md#failure-classification](transport.md#failure-classification) |
| Oversized events shortened to the server body limit instead of dropped | built | crates/transport/src/event_limit.rs fit_batches; unit tests an_event_padded_past_the_body_limit_is_shortened_and_keeps_who_ran_what, upload.rs a_segment_with_an_event_that_cannot_be_shortened_is_not_acknowledged |  | [transport.md#body-size-bounds](transport.md#body-size-bounds) |
| Structured detection upload with idempotency keys and per-record refusal | built | detection_upload.rs DetectionUploader, refuses_this_record; apps/agent/src/upload.rs persist_detection; tests/http_path.rs structured_detection_retry_sends_a_stable_idempotency_key, a_record_the_server_refuses_for_good_does_not_stop_the_others_of_its_segment |  | [transport.md#detection-upload](transport.md#detection-upload) |
| Oversized detections shortened to fit, keeping identity | built | detection_upload.rs fit_detection_to_limit; tests/http_path.rs a_record_over_the_server_body_limit_is_shortened_and_sent_not_dropped, a_single_event_that_stays_too_big_is_reduced_to_its_identity_and_still_fits |  | [transport.md#body-size-bounds](transport.md#body-size-bounds) |
| Bounded on-disk spool with shed-oldest and dropped counters in the health beacon | built | apps/agent/src/upload.rs spool_cap_bytes, SpoolHealth; crates/store/src/spool.rs |  | [transport.md#the-spool-contract](transport.md#the-spool-contract) |
| Offline fallback: keep detecting when upload cannot be set up | built | apps/agent/src/upload.rs start_or_disable; tests a_missing_client_certificate_disables_the_upload_when_offline_fallback_is_on, a_missing_client_certificate_stops_the_agent_when_offline_fallback_is_off |  | [transport.md#degraded-behavior](transport.md#degraded-behavior) |
| Decoy credential hash registration | built | client.rs register_decoy_tokens; tests decoy_registration_body_is_the_documented_wire_shape, the_decoy_endpoint_is_a_real_server_route |  | [transport.md#endpoints](transport.md#endpoints) |
| Passphrase-protected client keys | partial | Refused with an explicit error (client.rs is_encrypted_pem, test a_passphrase_protected_client_key_is_refused_with_a_clear_message); server.mtls_passphrase is parsed but never read | [#93](https://github.com/synthaea-lab/agent/issues/93) | [transport.md#tls-and-identity](transport.md#tls-and-identity) |
| Graceful shutdown with a bounded final spool drain | partial | upload.rs UploadLoop final_drain (tests final_drain_is_bounded_by_its_budget, stop_interrupts_a_long_backoff); registered with the shutdown plan on Linux only (TransportHandle::register_shutdown) | [#97](https://github.com/synthaea-lab/agent/issues/97) | [transport.md#upload-loop-and-shutdown](transport.md#upload-loop-and-shutdown) |
| Health beacon upload to the control plane | partial | client.rs send_heartbeat, test heartbeat_body_is_the_documented_wire_shape; wired on Linux and Windows, not on macOS | [#34](https://github.com/synthaea-lab/agent/issues/34) | [transport.md#platform-differences](transport.md#platform-differences) |
| Retry/backoff and batch tuning from agent.toml | planned | TransportConfig fields exist but agent.toml exposes none; resources.max_reconnect_backoff_ms and heartbeat_interval are parsed but not read | [#92](https://github.com/synthaea-lab/agent/issues/92) | [transport.md#configuration](transport.md#configuration) |

### Local outputs

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| JSON-Lines event and alert outputs with torn-tail repair | built | crates/sinks/src/lib.rs JsonlWriter, JsonlEventSink; crates/sinks/src/tests.rs torn_tail_is_repaired_on_reopen, hostile_comm_and_cmdline_stay_valid_json |  | [local-interfaces.md#jsonl-outputs](local-interfaces.md#jsonl-outputs) |
| Syslog/CEF and OCSF/ECS local outputs | planned | Named as follow-ups in crates/sinks/src/lib.rs; no code | [#96](https://github.com/synthaea-lab/agent/issues/96) | [local-interfaces.md#jsonl-outputs](local-interfaces.md#jsonl-outputs) |

### Local control channel

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| Local control channel with OS peer authentication (Unix socket / named pipe) | built | crates/ipc/src/server.rs, stream.rs check_authorized; crates/ipc/tests/e2e.rs run privileged in CI with SYNTHAEA_REQUIRE_PRIVILEGED_TESTS=1 |  | [local-interfaces.md#local-control-channel](local-interfaces.md#local-control-channel) |
| Hot content reload of a running agent after apply-content-manifest | built | protocol.rs Request::ReloadContent, apps/agent/src/ipc_handler.rs reload_content, apps/agent/src/content.rs notify_running_agent; e2e round_trip_every_endpoint |  | [local-interfaces.md#requests](local-interfaces.md#requests) |

### Admin CLI

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| Local admin CLI over IPC (status, health, detections, policy, suppress) | built | apps/cli/src/main.rs, apps/agent/src/ipc_handler.rs AgentHandler + tests |  | [architecture.md#binaries](architecture.md#binaries) |
| Admin CLI: status, health, detections, policy, suppress/unsuppress, config init/check/path | partial | apps/cli/src/main.rs; no tests of its own (IPC calls covered by crates/ipc tests) | [#98](https://github.com/synthaea-lab/agent/issues/98) | [local-interfaces.md#cli](local-interfaces.md#cli) |

### Content

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| Hot reload of Sigma/YARA/common-set content after apply-content-manifest | partial | apps/agent/src/content.rs cmd_apply_content_manifest notifies over IPC; apps/agent/src/ipc_handler.rs reload_content -&gt; apps/agent/src/sink/mod.rs reload_content; no periodic trigger | [#44](https://github.com/synthaea-lab/agent/issues/44) | [lifecycle.md#hot-content-reload](lifecycle.md#hot-content-reload) |

### Updates

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| Signed, staged binary self-update with atomic promotion (Linux) | built | apps/agent/src/release.rs apply_release, crates/updater/src/layout.rs; tests a_newer_signed_release_is_staged_verified_and_promoted, a_tampered_artifact_is_never_promoted_and_leaves_nothing_behind |  | [updates-and-releases.md#binary-self-update](updates-and-releases.md#binary-self-update) |
| Post-promotion probation, rollback to last proven release, ban list | built | apps/watchdog/src/probation.rs, crates/updater/src/lib.rs rollback, banlist.rs; tests two_bad_releases_in_a_row_both_roll_back_to_the_last_proven_release, sign_stage_verify_promote_then_rollback_and_ban |  | [updates-and-releases.md#probation-and-rollback](updates-and-releases.md#probation-and-rollback) |
| Pre-start recovery from a release whose watchdog cannot execute | built | apps/watchdog/src/recovery.rs; tests an_unexecutable_watchdog_rolls_back_and_is_banned; packaging/linux/systemd/synthaea-agent.service ExecStartPre |  | [updates-and-releases.md#probation-and-rollback](updates-and-releases.md#probation-and-rollback) |
| SELinux relabel of staged releases | built | apps/agent/src/release.rs restore_selinux_labels; tests a_failing_restorecon_under_enforcing_refuses_the_release, under_permissive_a_failed_relabel_is_reported_not_fatal |  | [updates-and-releases.md#binary-self-update](updates-and-releases.md#binary-self-update) |
| Signed content delivery per canary ring with anti-replay and path safety | built | crates/updater/src/content.rs, apps/agent/src/content.rs plan_with_key, download_and_apply; tests download_and_apply_rejects_a_hash_mismatch_before_writing_it, download_and_apply_preserves_progress_when_a_later_entry_fails |  | [updates-and-releases.md#content-delivery](updates-and-releases.md#content-delivery) |
| Halted-ring handling (423) with a distinct exit code | built | apps/agent/src/content.rs halted_reason, EXIT_RING_HALTED; tests a_halted_ring_is_reported_not_failed_and_changes_nothing, a_halt_on_the_second_artifact_preserves_the_first_applied_entry |  | [updates-and-releases.md#content-delivery](updates-and-releases.md#content-delivery) |
| Content withdrawal by corrective roll-forward release | built | tools/release/src/roll_forward.rs (8 tests); apps/agent/src/content.rs a_roll_forward_that_stops_listing_a_rule_removes_it_from_disk_and_state |  | [updates-and-releases.md#content-delivery](updates-and-releases.md#content-delivery) |
| Over-the-air key rotation signed by the offline recovery key | built | crates/updater/src/rotation.rs, trust_state.rs, apps/agent/src/rotation.rs; tests an_applied_rotation_survives_a_restart_and_moves_the_release_key, a_replayed_or_older_rotation_changes_nothing, a_corrupt_record_is_refused_and_a_deleted_one_is_a_fresh_install |  | [updates-and-releases.md#key-rotation](updates-and-releases.md#key-rotation) |
| Fleet common-set snapshot fetch | partial | apps/agent/src/snapshot_fetch.rs (16 tests), crates/updater/src/snapshot.rs (13 tests); loop stays off in production builds because no snapshot key is provisioned | [#43](https://github.com/synthaea-lab/agent/issues/43) | [updates-and-releases.md#common-set-snapshot](updates-and-releases.md#common-set-snapshot) |
| Windows and macOS binary self-update | planned | apps/agent/src/release.rs returns an error off Linux; updater::layout is Linux-only | [#60](https://github.com/synthaea-lab/agent/issues/60) | [updates-and-releases.md#platform-differences](updates-and-releases.md#platform-differences) |
| Periodic update trigger (timer for apply-release and apply-content-manifest) | planned | Both are one-shot commands; no timer or loop exists | [#44](https://github.com/synthaea-lab/agent/issues/44) | [updates-and-releases.md#what-is-delivered-and-how](updates-and-releases.md#what-is-delivered-and-how) |
| Production signing keys embedded in packaged builds | partial | crates/updater/keys/*.pub hold TEMPORARY keys (2026-11-12, no ceremony, no custody, to be replaced); tests/unprovisioned_build.rs proves a build embeds exactly the committed keys and refuses the public test seed | [#43](https://github.com/synthaea-lab/agent/issues/43) | [updates-and-releases.md#the-trust-set](updates-and-releases.md#the-trust-set) |
| Agent upgrade and version-skew policy | planned | No skew policy in code; a newer agent field refused by an older server is dropped per record (detection_upload.rs refuses_this_record) | [#59](https://github.com/synthaea-lab/agent/issues/59) | [transport.md#detection-upload](transport.md#detection-upload) |

### Release signing

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| Offline manifest build and signing (key file, test key, PKCS#11) | partial | tools/release/src/main.rs, sign.rs, pkcs11.rs (tools/test-pkcs11.sh); production keys not yet in place | [#43](https://github.com/synthaea-lab/agent/issues/43) | [architecture.md#binaries](architecture.md#binaries) |

### release-tool

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| Offline manifest building and signing, including PKCS#11 tokens | built | tools/release/src/sign.rs, pkcs11.rs; tools/release/tests/pkcs11_softhsm.rs run by tools/test-pkcs11.sh in CI |  | [updates-and-releases.md#building-and-signing-releases-release-tool](updates-and-releases.md#building-and-signing-releases-release-tool) |

### Packaging

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| Public test key kept out of packaged builds | built | tools/check-no-test-key.sh, tools/assert-no-test-key.sh; CI lint job and release test-key-guard/publish steps |  | [packaging.md#test-key-exclusion](packaging.md#test-key-exclusion) |
| Static musl .deb for Debian/Ubuntu | built | packaging/linux/build-deb.sh; .github/workflows/linux-deb-portability.yml installs and starts it |  | [packaging.md#static-deb](packaging.md#static-deb) |
| Static musl .apk for Alpine | partial | packaging/linux/alpine/APKBUILD; linux-apk-portability.yml builds, installs, upgrades, removes; signed only by a throwaway abuild key | [#54](https://github.com/synthaea-lab/agent/issues/54) | [packaging.md#apk](packaging.md#apk) |
| .rpm for RHEL/Fedora | partial | packaging/linux/build-rpm.sh and spec template exist; no CI job builds or tests it; not published | [#54](https://github.com/synthaea-lab/agent/issues/54) | [packaging.md#rpm](packaging.md#rpm) |
| Windows MSI | partial | packaging/windows/Product.wxs, build.ps1; not built in CI, release publishes only agent.exe; unsigned | [#55](https://github.com/synthaea-lab/agent/issues/55) | [packaging.md#windows](packaging.md#windows) |
| Notarized macOS package | planned | packaging/macos/README.md design only; CI builds the bare agent binary | [#26](https://github.com/synthaea-lab/agent/issues/26) | [packaging.md#macos](packaging.md#macos) |
| arm64 builds | planned | All packaging and CI targets are x86_64 (macOS arm64 binary only) | [#62](https://github.com/synthaea-lab/agent/issues/62) | [packaging.md#status-by-platform](packaging.md#status-by-platform) |

### CI and development

| Capability | Status | Evidence | Tracking issue | Docs |
| --- | --- | --- | --- | --- |
| Three-OS CI gates with sibling contract tests, cargo-deny, eBPF embedding check and DCO | built | .github/workflows/ci.yml jobs lint/deny/test/content/linux-ebpf, dco.yml; crates/siblings |  | [development.md#ci-gates](development.md#ci-gates) |
| Tag-driven release workflow publishing per-OS artifacts with SHA256SUMS | partial | .github/workflows/release-please.yml, release.yml, distribute.yml; SBOM and provenance attestations for every file; Authenticode, Developer ID + notarization and GPG run only when their secrets are set (unsigned 0.0.x alpha otherwise); no rpm/MSI/pkg | [#54](https://github.com/synthaea-lab/agent/issues/54) | [packaging.md#release-workflow](packaging.md#release-workflow) |
| Default development build links on older glibc distributions | partial | Default dynamic-onnx build needs libstdc++ from GCC 13+; fails on Debian 12 / Ubuntu 22.04 | [#53](https://github.com/synthaea-lab/agent/issues/53) | [development.md#building](development.md#building) |
