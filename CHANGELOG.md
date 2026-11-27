# Changelog

## [0.0.2](https://github.com/synthaea-lab/agent/compare/v0.0.1...v0.0.2) (2026-11-27)


### Features

* **agent:** replay a recorded events.jsonl into one case per entity (ml[#3](https://github.com/synthaea-lab/agent/issues/3)) ([20a850d](https://github.com/synthaea-lab/agent/commit/20a850d24c5b52d16b18a2234b679439b11e9d69))
* **agent:** replay a recorded events.jsonl into one case per entity (Refs ml[#3](https://github.com/synthaea-lab/agent/issues/3)) ([aec0792](https://github.com/synthaea-lab/agent/commit/aec0792757abe901b53911d3df7f5fc5e5ce971f))
* **agent:** report eBPF ring drop totals in the health beacon (Closes [#335](https://github.com/synthaea-lab/agent/issues/335)) ([#336](https://github.com/synthaea-lab/agent/issues/336)) ([2ce1d45](https://github.com/synthaea-lab/agent/commit/2ce1d45b67536b9ba4089815f200fcd1892a6de9))
* **rules:** alert on a write to cpu.max of a listed unit ([9360ee9](https://github.com/synthaea-lab/agent/commit/9360ee9169392a586b196d185fc86368414be58c)), closes [#49](https://github.com/synthaea-lab/agent/issues/49)
* **rules:** mark a Debian firefox-esr download ([42c9adc](https://github.com/synthaea-lab/agent/commit/42c9adc62e0824583c659261bf6c86f446c4de08)), closes [#221](https://github.com/synthaea-lab/agent/issues/221)
* **rules:** mark a Linux browser download from its partial-file rename ([259c46c](https://github.com/synthaea-lab/agent/commit/259c46c2d9bf75e9f9acb031a073497ba332ac7e)), closes [#221](https://github.com/synthaea-lab/agent/issues/221)
* **rules:** mark a Linux browser download from its partial-file rename ([#221](https://github.com/synthaea-lab/agent/issues/221)) ([a2bfcd7](https://github.com/synthaea-lab/agent/commit/a2bfcd7c5be5e43da9d5af2fa57ff050439a19e0))
* **rules:** match the Chromium Snap's download image and its real Downloads path ([#267](https://github.com/synthaea-lab/agent/issues/267)) ([#283](https://github.com/synthaea-lab/agent/issues/283)) ([6090a44](https://github.com/synthaea-lab/agent/commit/6090a44f2121f7a3d45f170289ce8c26291953ce))
* **rules:** match the Firefox family's browser image by shape ([#221](https://github.com/synthaea-lab/agent/issues/221)) ([8e08ae3](https://github.com/synthaea-lab/agent/commit/8e08ae3c156fc0a931d56edf9474a30fa271c4d9))
* **rules:** match the Firefox family's browser image by shape (Refs [#221](https://github.com/synthaea-lab/agent/issues/221)) ([6fe204e](https://github.com/synthaea-lab/agent/commit/6fe204ea09865c41a84c098a3ee3d9673bf46728))
* **rules:** read the renaming browser's image from the process lineage when the sensor lost it (Refs [#17](https://github.com/synthaea-lab/agent/issues/17), [#221](https://github.com/synthaea-lab/agent/issues/221)) ([#302](https://github.com/synthaea-lab/agent/issues/302)) ([a142f0d](https://github.com/synthaea-lab/agent/commit/a142f0df47cf1764e80a8a17e5d4d105798f4431))
* **rules:** the captured Chrome, Edge, Brave, Opera and Vivaldi images mark a browser download (Refs [#221](https://github.com/synthaea-lab/agent/issues/221)) ([84b5ae7](https://github.com/synthaea-lab/agent/commit/84b5ae7fdaab18da7b023ed677cc1f9ebdbab745))
* **sensor-linux-audit:** report a SIGKILL of the previous agent from auditd's log (Refs [#275](https://github.com/synthaea-lab/agent/issues/275)) ([#287](https://github.com/synthaea-lab/agent/issues/287)) ([a24313a](https://github.com/synthaea-lab/agent/commit/a24313abd6dfe7be3ca242d386daebcf2a8a8402))
* **sensor-linux-wire:** pass a write to a cgroup limit file through the path filter ([4587bc4](https://github.com/synthaea-lab/agent/commit/4587bc44cd8bfd6686b9f01ddb4c31f2ef3236cc)), closes [#49](https://github.com/synthaea-lab/agent/issues/49)
* **sensor-linux-wire:** pass a write to a cgroup limit file through the path filter ([#49](https://github.com/synthaea-lab/agent/issues/49)) ([a440507](https://github.com/synthaea-lab/agent/commit/a4405075b7354269ceb4b6d4fda2b7a779e8aa80))
* **sensor-linux:** count ring buffer drops per ring instead of logging each one (Closes [#304](https://github.com/synthaea-lab/agent/issues/304)) ([#333](https://github.com/synthaea-lab/agent/issues/333)) ([e268865](https://github.com/synthaea-lab/agent/commit/e268865e31e1176ef05809386586b6b8cf0d06d6))
* **sensor-linux:** verify_probes fails a program over a verified-instruction ceiling (Refs [#226](https://github.com/synthaea-lab/agent/issues/226)) ([#318](https://github.com/synthaea-lab/agent/issues/318)) ([7b9dcd8](https://github.com/synthaea-lab/agent/commit/7b9dcd851458b0a2d3e388534004493339e4cdbc))
* **signal:** a SIGKILL from the agent's watchdog on a stalled heartbeat is Low, not tampering (Refs [#322](https://github.com/synthaea-lab/agent/issues/322)) ([#323](https://github.com/synthaea-lab/agent/issues/323)) ([385a58f](https://github.com/synthaea-lab/agent/commit/385a58f827094290669d2347259bc4aeb194d979))
* **updater:** provision temporary release, content and recovery keys ([#43](https://github.com/synthaea-lab/agent/issues/43)) ([a125888](https://github.com/synthaea-lab/agent/commit/a1258885bf74d18e82a3578a51fff8f16253c004))
* **updater:** provision temporary release, content and recovery keys ([#43](https://github.com/synthaea-lab/agent/issues/43)) ([f97058c](https://github.com/synthaea-lab/agent/commit/f97058cde3b0b4f81d00e3332a48da384f9f3051))
* **uprobes:** capture DNS lookups through gethostbyname* ([#240](https://github.com/synthaea-lab/agent/issues/240)) ([a60b5f7](https://github.com/synthaea-lab/agent/commit/a60b5f723ee3fc921882666bb1e3515d63c4c09c))
* **uprobes:** capture DNS lookups through gethostbyname* ([#240](https://github.com/synthaea-lab/agent/issues/240)) ([bee3215](https://github.com/synthaea-lab/agent/commit/bee3215eb889fcc3beae9394d736c75fea285e2e))


### Bug Fixes

* **agent:** a Sigma detection carries its ATT&CK ids, not its raw tags ([#324](https://github.com/synthaea-lab/agent/issues/324)) ([3b9fe0d](https://github.com/synthaea-lab/agent/commit/3b9fe0de637c310bcf8914ad08c06b784a65e568))
* **agent:** canary cooldown and YARA trigger use has_write_intent (Refs [#233](https://github.com/synthaea-lab/agent/issues/233)) ([30f60d6](https://github.com/synthaea-lab/agent/commit/30f60d619f644383db6e428c259fff9b93db5485))
* **agent:** infer time_t in localzone so clippy passes on musl ([#332](https://github.com/synthaea-lab/agent/issues/332)) ([d6fe97f](https://github.com/synthaea-lab/agent/commit/d6fe97fdd20a2c653a386252763c45084a6de29f))
* **agent:** keep every case a replay sees, not only the last state per entity ([f2d73bd](https://github.com/synthaea-lab/agent/commit/f2d73bdda7f1382e427b6b8b13164a5301edf968))
* **agent:** replay drains the worker before a newer incarnation (Refs ml[#3](https://github.com/synthaea-lab/agent/issues/3)) ([ac576c5](https://github.com/synthaea-lab/agent/commit/ac576c536d7f1639edee040a4fb6322068c43bd6))
* **agent:** the uprobes heartbeat is watched while a capture is wanted, not while a thread runs ([43d9912](https://github.com/synthaea-lab/agent/commit/43d9912fad92f09c3658ab507c2e913d68fc147e))
* **agent:** Windows and macOS cmd_run flush the enrich queue and shut workers down ([92cd39a](https://github.com/synthaea-lab/agent/commit/92cd39a315234c3e64439f7c144808d642c33378))
* **agent:** Windows and macOS cmd_run flush the enrich queue and shut workers down (Closes [#147](https://github.com/synthaea-lab/agent/issues/147)) ([3d879c1](https://github.com/synthaea-lab/agent/commit/3d879c112c9bef43a394cba95e119386e6afb7c8))
* **audit:** attribute a SIGKILL of the watchdog under the audit fallback (Closes [#342](https://github.com/synthaea-lab/agent/issues/342)) ([#343](https://github.com/synthaea-lab/agent/issues/343)) ([804f470](https://github.com/synthaea-lab/agent/commit/804f4706ddeda594e8155e06035e92544934b054))
* **audit:** key in-progress execs by serial, records of other execs interleave ([31582a5](https://github.com/synthaea-lab/agent/commit/31582a539de069bdc5401d0da2e088c684fc1a31)), closes [#51](https://github.com/synthaea-lab/agent/issues/51)
* **audit:** rebuild an exec whose argv the kernel split over EXECVE records ([d77657b](https://github.com/synthaea-lab/agent/commit/d77657bc33ed601f75a6d3072c34d80c3146d091))
* **audit:** rebuild an exec whose argv the kernel split over EXECVE records ([e2c664b](https://github.com/synthaea-lab/agent/commit/e2c664b47fd82c8303899ce797506645ca4d5073)), closes [#51](https://github.com/synthaea-lab/agent/issues/51)
* **audit:** size the netlink socket for bursts and report cut records ([156812f](https://github.com/synthaea-lab/agent/commit/156812ff265a062af5c035ff6d942eb96f59a497))
* **audit:** size the netlink socket for bursts and report cut records ([d16c090](https://github.com/synthaea-lab/agent/commit/d16c0906ade6f2016d273a6fc74ea4d84553e759)), closes [#237](https://github.com/synthaea-lab/agent/issues/237)
* **correlator:** classify an IPv4-mapped destination as its IPv4 address ([8258a95](https://github.com/synthaea-lab/agent/commit/8258a9521f62baeb68a34ad810816f88caaf4ef2)), closes [#203](https://github.com/synthaea-lab/agent/issues/203)
* **enrich:** build the RAII contexts only on success, honour hash_len ([#163](https://github.com/synthaea-lab/agent/issues/163)) ([f7c36c9](https://github.com/synthaea-lab/agent/commit/f7c36c92149aa0aaf337b8ac0fca989a6099eaee))
* **etw:** deduplicate NTLM records before the process lookup; close review test gaps ([9dabf9b](https://github.com/synthaea-lab/agent/commit/9dabf9b7e3cc5d7520531a7cb8241403a381f489))
* **etw:** normalizing a path or registry key never slices inside a character ([5695929](https://github.com/synthaea-lab/agent/commit/5695929eb136f602cff8e472eab2e3944ea1e77f))
* **etw:** normalizing a path or registry key never slices inside a character ([91437fd](https://github.com/synthaea-lab/agent/commit/91437fd4d038e31571878f42fef68cb62c137712))
* **etw:** read registry value writes from SetValueKey (EID 5), not QueryKey (EID 4) ([#252](https://github.com/synthaea-lab/agent/issues/252)) ([d49e2c7](https://github.com/synthaea-lab/agent/commit/d49e2c707710bfef3ae496c86b37483bd6904208))
* **rules:** a shell reached through /usr/sbin on a merged-/usr system is not a masquerade (Closes [#305](https://github.com/synthaea-lab/agent/issues/305)) ([#306](https://github.com/synthaea-lab/agent/issues/306)) ([49a6e98](https://github.com/synthaea-lab/agent/commit/49a6e9871308ff371132ee8c08e10febc2389830))
* **rules:** a systemctl -M/-H target is not the verb ([#246](https://github.com/synthaea-lab/agent/issues/246)) ([bac3704](https://github.com/synthaea-lab/agent/commit/bac370418bc154d549fd037309acd29d0e74356c))
* **rules:** a systemctl -M/-H target is not the verb (Refs [#246](https://github.com/synthaea-lab/agent/issues/246)) ([7d75de9](https://github.com/synthaea-lab/agent/commit/7d75de9fe71a301a451c1346151d0dbc8276d4f4))
* **rules:** alert on a starving CPUQuota and resolve the prlimit target to a tool ([#49](https://github.com/synthaea-lab/agent/issues/49)) ([a22fc4f](https://github.com/synthaea-lab/agent/commit/a22fc4f08b8611a9caf47da64e9378da961907a1))
* **rules:** alert on a starving CPUQuota and resolve the prlimit target to a tool (Refs [#49](https://github.com/synthaea-lab/agent/issues/49)) ([e2f4fff](https://github.com/synthaea-lab/agent/commit/e2f4fffa4fe1a5ca16c9ca766c56c9750308a04f))
* **rules:** drop the exact firefox-esr line, the shape match covers it ([#221](https://github.com/synthaea-lab/agent/issues/221)) ([a09e2d1](https://github.com/synthaea-lab/agent/commit/a09e2d145b95325e817a8fdcbb83717cb613501a))
* **rules:** Opera's .opdownload partial suffix finishes a browser download ([#221](https://github.com/synthaea-lab/agent/issues/221)) ([79eee9d](https://github.com/synthaea-lab/agent/commit/79eee9d551efaac557e2c30afda34193a13ec49c))
* **rules:** read abbreviated --pid and per-mille CPUQuota, union the names of a pid ([3d64009](https://github.com/synthaea-lab/agent/commit/3d640090177b9deb47a6ff1b2cd7924254b8f8aa)), closes [#49](https://github.com/synthaea-lab/agent/issues/49)
* **rules:** systemctl options that take a value do not hide the verb ([#246](https://github.com/synthaea-lab/agent/issues/246)) ([7befcac](https://github.com/synthaea-lab/agent/commit/7befcac0eff34fbb8b632e26b202c451b1ef582a))
* **rules:** systemd stamping a persistent timer is not a timestomp (Closes [#353](https://github.com/synthaea-lab/agent/issues/353)) ([#360](https://github.com/synthaea-lab/agent/issues/360)) ([253509f](https://github.com/synthaea-lab/agent/commit/253509f41b24918d8c2ccc1aec59dc32790dc672))
* **schema:** has_write_intent counts O_TRUNC, which empties the file ([b461150](https://github.com/synthaea-lab/agent/commit/b46115058ea4b6fd54275e743c97c894852b8dbf))
* **schema:** has_write_intent counts O_TRUNC, which empties the file ([5a99c5d](https://github.com/synthaea-lab/agent/commit/5a99c5deb2364d8f33c6f81fe71bd1142bba999d))
* **sensor-linux-ebpf:** a fork records the parent's tgid as ppid, and a new thread no entry ([#375](https://github.com/synthaea-lab/agent/issues/375)) ([15a5ca3](https://github.com/synthaea-lab/agent/commit/15a5ca3c1cfe86d3fa8ffa8678ba743fed305713)), closes [#372](https://github.com/synthaea-lab/agent/issues/372)
* **sensor-linux-ebpf:** i686 ptrace and process_vm offsets start at 12, not 16 ([aa9d2ee](https://github.com/synthaea-lab/agent/commit/aa9d2ee5757c1f6b7112006f5c0539940d96385f))
* **sensor-linux-ebpf:** i686 ptrace and process_vm offsets start at 12, not 16 ([7077312](https://github.com/synthaea-lab/agent/commit/7077312af5b7af964e40059ffc814b63f70515b5)), closes [#218](https://github.com/synthaea-lab/agent/issues/218)
* **sensor-linux-ebpf:** SSL_READ_ARGS holds three u64s, so the 5.15 and 6.1 verifiers accept the entry probes ([2d064ea](https://github.com/synthaea-lab/agent/commit/2d064ea4c4972dc0515fc5db7cccbb97fc40d10e))
* **sensor-linux-ebpf:** SSL_READ_ARGS holds three u64s, so the 5.15 and 6.1 verifiers accept the entry probes ([3d880c2](https://github.com/synthaea-lab/agent/commit/3d880c2aa1d6ade9dab9deded754a7dc2ee9c7be))
* **sensor-linux-journal:** cap the length of a journal line, count what it drops ([#189](https://github.com/synthaea-lab/agent/issues/189)) ([40f5d2e](https://github.com/synthaea-lab/agent/commit/40f5d2e83826f8bbce8060a21bc110980aca0513))
* **sensor-linux-wire,rules:** a non-normalized cgroup limit path is not dropped, and cgroup2 mounted elsewhere is read (Refs [#49](https://github.com/synthaea-lab/agent/issues/49)) ([04015e5](https://github.com/synthaea-lab/agent/commit/04015e5ec296495abbd48115d76e64a57c0d33b5))
* **sensor-linux-wire:** a path that can leave its filtered prefix is never filtered (Closes [#350](https://github.com/synthaea-lab/agent/issues/350)) ([#352](https://github.com/synthaea-lab/agent/issues/352)) ([7706a86](https://github.com/synthaea-lab/agent/commit/7706a868621f2bebe9b7fc6b0fb983ce3df8dbe6))
* **sensor-linux:** always inline emit_kernel_module_event; verify probes on 7.2 in CI ([#319](https://github.com/synthaea-lab/agent/issues/319)) ([f1ededb](https://github.com/synthaea-lab/agent/commit/f1ededba8d1103d183cfda58a55657b6cd12844d))
* **sensor-linux:** bpffs mutations and AppArmor profile removal leave the /sys filter, and alert ([#359](https://github.com/synthaea-lab/agent/issues/359)) ([ed572f7](https://github.com/synthaea-lab/agent/commit/ed572f76bc49fd16173ff5f53fb360c8d4e7b999)), closes [#356](https://github.com/synthaea-lab/agent/issues/356)
* **sensor-linux:** fill cgroup_id on uprobe events through fill_event_meta ([#337](https://github.com/synthaea-lab/agent/issues/337)) ([d3e324f](https://github.com/synthaea-lab/agent/commit/d3e324f03fad8f032c1b6313395b0bb95106c02b))
* **sensor-linux:** raw-tracepoint try_into maps to the typed loader error ([42cb2e7](https://github.com/synthaea-lab/agent/commit/42cb2e721c5b4a88b0460f596ee2da6bb7049cac))
* **sensor-linux:** raw-tracepoint try_into maps to the typed loader error (Fixes [#185](https://github.com/synthaea-lab/agent/issues/185)) ([e67c737](https://github.com/synthaea-lab/agent/commit/e67c7371a83bd291f3bc31f2f8e2c2d37f940eb3))
* **sensor-linux:** size FILE_OPEN_EVENTS at 1 MiB for device-enumeration bursts ([#340](https://github.com/synthaea-lab/agent/issues/340)) ([01cefd1](https://github.com/synthaea-lab/agent/commit/01cefd12eca63115a313ed19dc91ade9ca121482))
* **sensor-linux:** verify_probes loads the optional paths enabled (Closes [#310](https://github.com/synthaea-lab/agent/issues/310)) ([#311](https://github.com/synthaea-lab/agent/issues/311)) ([26350b7](https://github.com/synthaea-lab/agent/commit/26350b7367f4310f571bc30abac22f30fd267189))
* **sensor-macos:** cap the length of a unified-log and NetworkExtension line, count what is dropped (Refs [#189](https://github.com/synthaea-lab/agent/issues/189)) ([#377](https://github.com/synthaea-lab/agent/issues/377)) ([d7c958c](https://github.com/synthaea-lab/agent/commit/d7c958cc1ccfcabb22f8b78349ee8f2acbbe03c6))
* **sensor-windows:** NT path prefix must end at a path component ([6201816](https://github.com/synthaea-lab/agent/commit/620181634fedde6e8da6cde86f9ed3d625b6ef97))
* **sensor-windows:** NT path prefix must end at a path component (Fixes [#257](https://github.com/synthaea-lab/agent/issues/257)) ([e2582df](https://github.com/synthaea-lab/agent/commit/e2582df825a925cb74566f7fe0ce80d0a946d0d7))
* **sigma:** restore the Windows-only refusal message's line continuation ([a776cc9](https://github.com/synthaea-lab/agent/commit/a776cc9400521e11d0b9d27da6991aa7d668eca6))
* **sinks:** count the alerts alerts.ndjson refuses and report them in the health beacon ([ab7060f](https://github.com/synthaea-lab/agent/commit/ab7060f9af924d6f324b49de54d9308b808408a9))
* **sinks:** count the alerts alerts.ndjson refuses and report them in the health beacon ([f1156ee](https://github.com/synthaea-lab/agent/commit/f1156ee3be655fb86fbb53af1a0477c83d44f1be)), closes [#167](https://github.com/synthaea-lab/agent/issues/167)
* **toolchain:** fetch the onnxruntime source from a release asset, upstream answers 404 ([#298](https://github.com/synthaea-lab/agent/issues/298)) ([1135518](https://github.com/synthaea-lab/agent/commit/1135518a254758d1c2a88c3f8ce561081a882612))
* **uprobes:** find musl's libc without the musl-dev symlink ([129f24c](https://github.com/synthaea-lab/agent/commit/129f24c7503e6f25cb95cebc9feffc63d5db832d))
* **uprobes:** find musl's libc without the musl-dev symlink ([812be1a](https://github.com/synthaea-lab/agent/commit/812be1abe4aa7a4c95a051b58361fff8b7ce532e))


### Performance

* **etw:** enable each provider for the event ids it handles, with keyword masks where the manifest has them ([#253](https://github.com/synthaea-lab/agent/issues/253)) ([72be82a](https://github.com/synthaea-lab/agent/commit/72be82af2a63a00846e15a88b328c0f5f4854bcd)), closes [#91](https://github.com/synthaea-lab/agent/issues/91)
* **sensor-linux-ebpf:** filter file paths in tail-called programs ([#351](https://github.com/synthaea-lab/agent/issues/351)) ([#380](https://github.com/synthaea-lab/agent/issues/380)) ([3e826b8](https://github.com/synthaea-lab/agent/commit/3e826b830317c058e2c722256e47288ed555a8e9))


### Packaging and release

* accept "statically linked" too in the verify_probes static check ([7a2f4bf](https://github.com/synthaea-lab/agent/commit/7a2f4bf102f87c1101cd1ecf3c121890eebd6902))
* also boot 5.15 and 6.1 builds from late 2023 in linux-ebpf-verify ([294afe4](https://github.com/synthaea-lab/agent/commit/294afe48cffab26a77b25975089e2cc5d969e1c9))
* build verify_probes as a static musl binary, fail a probe-less build ([3677822](https://github.com/synthaea-lab/agent/commit/3677822b31b776f29726282c751403a9922f1c4c))
* build verify_probes as a static musl binary, fail a probe-less build ([28b7de6](https://github.com/synthaea-lab/agent/commit/28b7de6fa1b18795934b825151372aa9094b7baf))
* **deny:** keep unmaintained crates in scope across the whole graph (Refs [#326](https://github.com/synthaea-lab/agent/issues/326)) ([#341](https://github.com/synthaea-lab/agent/issues/341)) ([5c22b1e](https://github.com/synthaea-lab/agent/commit/5c22b1e085e52bd0a9bd2716826935dbfa7d6306))
* **deps:** bump actions/create-github-app-token from 3.3.0 to 3.4.0 ([#325](https://github.com/synthaea-lab/agent/issues/325)) ([494c063](https://github.com/synthaea-lab/agent/commit/494c063941377a15558554529e5ee5df0f4f9e1a))
* **deps:** bump cc from 1.11.0 to 1.11.1 ([#273](https://github.com/synthaea-lab/agent/issues/273)) ([b2648c1](https://github.com/synthaea-lab/agent/commit/b2648c1088569af12460559214f7cfdba172e5c1))
* **deps:** bump cc from 1.11.1 to 1.11.2 ([#331](https://github.com/synthaea-lab/agent/issues/331)) ([9f587f0](https://github.com/synthaea-lab/agent/commit/9f587f01da9f67c7bb1542b6a327e2fb00901998))
* **deps:** bump clap from 4.6.7 to 4.6.8 ([#329](https://github.com/synthaea-lab/agent/issues/329)) ([e8b36a4](https://github.com/synthaea-lab/agent/commit/e8b36a40dcaf1a8b0934f9f2dc7ff8a3e9addb9d))
* **deps:** bump ctrlc from 3.5.2 to 3.5.3 ([#328](https://github.com/synthaea-lab/agent/issues/328)) ([1501ab1](https://github.com/synthaea-lab/agent/commit/1501ab1113fae32e30f11e579eac782161040985))
* **deps:** bump EmbarkStudios/cargo-deny-action from 2.1.1 to 2.1.3 ([#326](https://github.com/synthaea-lab/agent/issues/326)) ([b33c09c](https://github.com/synthaea-lab/agent/commit/b33c09c7525e45e01667ea98118eb92a24576d06))
* **deps:** bump regex from 1.13.1 to 1.13.2 ([#330](https://github.com/synthaea-lab/agent/issues/330)) ([3104060](https://github.com/synthaea-lab/agent/commit/31040609bb09fde20807a17bf6fb23de9808608c))
* **deps:** bump serde-saphyr from 2.1.1 to 2.2.0 ([#327](https://github.com/synthaea-lab/agent/issues/327)) ([f41cd79](https://github.com/synthaea-lab/agent/commit/f41cd79cae187cfe93d7c10e3531649a8f7887be))
* **deps:** bump ureq from 3.5.1 to 3.5.2 ([#274](https://github.com/synthaea-lab/agent/issues/274)) ([70ad30d](https://github.com/synthaea-lab/agent/commit/70ad30daff4f608c4bb02019058af92160fb5ca5))
* **lint:** enforce CLAUDE.md's platform-code rule with check-platform-cfg.py (Closes [#150](https://github.com/synthaea-lab/agent/issues/150)) ([#346](https://github.com/synthaea-lab/agent/issues/346)) ([be5a0ad](https://github.com/synthaea-lab/agent/commit/be5a0adadc5b21457d0371660bb9d127b2d22e1e))
* linux-ebpf-verify on 7.2 no longer allows inode_setattr to be refused ([#320](https://github.com/synthaea-lab/agent/issues/320)) ([e098a30](https://github.com/synthaea-lab/agent/commit/e098a308715c0b22a688649e8d08b5c89b1493db))
* **linux-ebpf:** add the musl target to the pinned toolchain ([67c8f24](https://github.com/synthaea-lab/agent/commit/67c8f2428d7098b410a42254c89dc0565e5d4ab0))
* load every eBPF program on 5.15 and 6.1 in a VM ([5911ccc](https://github.com/synthaea-lab/agent/commit/5911ccc335dd3976b1ad7fc2c7cce3f6e59a9405))
* load every eBPF program on 5.15 and 6.1 kernels in a VM ([7ada3d7](https://github.com/synthaea-lab/agent/commit/7ada3d7779879838f75f098d919b3ff2d9a47a23))
* **release:** refuse a release that embeds the temporary updater keys ([#43](https://github.com/synthaea-lab/agent/issues/43)) ([8965805](https://github.com/synthaea-lab/agent/commit/8965805f1e339d2e1398e4b8db32bc92e69795ef))
* **release:** refuse a release that embeds the temporary updater keys (Refs [#43](https://github.com/synthaea-lab/agent/issues/43)) ([473e499](https://github.com/synthaea-lab/agent/commit/473e4998e788cd867f7ae66ed9b565795c857da4))
* **release:** the temporary-key guard reads the key, waits for signing, never publishes (Refs [#43](https://github.com/synthaea-lab/agent/issues/43)) ([9a312c0](https://github.com/synthaea-lab/agent/commit/9a312c0070198e3893382d3e02194babc14e7a93))

## 0.0.1 (2026-11-09)


### Bug Fixes

* **packaging:** point the deb/apk builders at packaging/toolchain/ ([#201](https://github.com/synthaea-lab/agent/issues/201)) ([dca211d](https://github.com/synthaea-lab/agent/commit/dca211d5150205b059a0a9762716a4cf7af2b55d))


### Packaging and release

* release pipeline with release-please, per-OS signing, SBOM and attestations ([#193](https://github.com/synthaea-lab/agent/issues/193)) ([7ed64ac](https://github.com/synthaea-lab/agent/commit/7ed64ac94d65aa314ba16872c63b068f35b853ff))
