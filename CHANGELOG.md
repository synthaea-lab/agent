# Changelog

## [0.0.2](https://github.com/synthaea-lab/agent/compare/v0.0.1...v0.0.2) (2026-11-13)


### Features

* **agent:** replay a recorded events.jsonl into one case per entity (ml[#3](https://github.com/synthaea-lab/agent/issues/3)) ([20a850d](https://github.com/synthaea-lab/agent/commit/20a850d24c5b52d16b18a2234b679439b11e9d69))
* **agent:** replay a recorded events.jsonl into one case per entity (Refs ml[#3](https://github.com/synthaea-lab/agent/issues/3)) ([aec0792](https://github.com/synthaea-lab/agent/commit/aec0792757abe901b53911d3df7f5fc5e5ce971f))
* **rules:** alert on a write to cpu.max of a listed unit ([9360ee9](https://github.com/synthaea-lab/agent/commit/9360ee9169392a586b196d185fc86368414be58c)), closes [#49](https://github.com/synthaea-lab/agent/issues/49)
* **rules:** mark a Linux browser download from its partial-file rename ([259c46c](https://github.com/synthaea-lab/agent/commit/259c46c2d9bf75e9f9acb031a073497ba332ac7e)), closes [#221](https://github.com/synthaea-lab/agent/issues/221)
* **rules:** mark a Linux browser download from its partial-file rename ([#221](https://github.com/synthaea-lab/agent/issues/221)) ([a2bfcd7](https://github.com/synthaea-lab/agent/commit/a2bfcd7c5be5e43da9d5af2fa57ff050439a19e0))
* **rules:** match the Firefox family's browser image by shape ([#221](https://github.com/synthaea-lab/agent/issues/221)) ([8e08ae3](https://github.com/synthaea-lab/agent/commit/8e08ae3c156fc0a931d56edf9474a30fa271c4d9))
* **rules:** match the Firefox family's browser image by shape (Refs [#221](https://github.com/synthaea-lab/agent/issues/221)) ([6fe204e](https://github.com/synthaea-lab/agent/commit/6fe204ea09865c41a84c098a3ee3d9673bf46728))
* **rules:** the captured Chrome, Edge, Brave, Opera and Vivaldi images mark a browser download (Refs [#221](https://github.com/synthaea-lab/agent/issues/221)) ([84b5ae7](https://github.com/synthaea-lab/agent/commit/84b5ae7fdaab18da7b023ed677cc1f9ebdbab745))
* **sensor-linux-wire:** pass a write to a cgroup limit file through the path filter ([4587bc4](https://github.com/synthaea-lab/agent/commit/4587bc44cd8bfd6686b9f01ddb4c31f2ef3236cc)), closes [#49](https://github.com/synthaea-lab/agent/issues/49)
* **sensor-linux-wire:** pass a write to a cgroup limit file through the path filter ([#49](https://github.com/synthaea-lab/agent/issues/49)) ([a440507](https://github.com/synthaea-lab/agent/commit/a4405075b7354269ceb4b6d4fda2b7a779e8aa80))
* **updater:** provision temporary release, content and recovery keys ([#43](https://github.com/synthaea-lab/agent/issues/43)) ([a125888](https://github.com/synthaea-lab/agent/commit/a1258885bf74d18e82a3578a51fff8f16253c004))
* **updater:** provision temporary release, content and recovery keys ([#43](https://github.com/synthaea-lab/agent/issues/43)) ([f97058c](https://github.com/synthaea-lab/agent/commit/f97058cde3b0b4f81d00e3332a48da384f9f3051))
* **uprobes:** capture DNS lookups through gethostbyname* ([#240](https://github.com/synthaea-lab/agent/issues/240)) ([a60b5f7](https://github.com/synthaea-lab/agent/commit/a60b5f723ee3fc921882666bb1e3515d63c4c09c))
* **uprobes:** capture DNS lookups through gethostbyname* ([#240](https://github.com/synthaea-lab/agent/issues/240)) ([bee3215](https://github.com/synthaea-lab/agent/commit/bee3215eb889fcc3beae9394d736c75fea285e2e))


### Bug Fixes

* **agent:** canary cooldown and YARA trigger use has_write_intent (Refs [#233](https://github.com/synthaea-lab/agent/issues/233)) ([30f60d6](https://github.com/synthaea-lab/agent/commit/30f60d619f644383db6e428c259fff9b93db5485))
* **agent:** keep every case a replay sees, not only the last state per entity ([f2d73bd](https://github.com/synthaea-lab/agent/commit/f2d73bdda7f1382e427b6b8b13164a5301edf968))
* **agent:** replay drains the worker before a newer incarnation (Refs ml[#3](https://github.com/synthaea-lab/agent/issues/3)) ([ac576c5](https://github.com/synthaea-lab/agent/commit/ac576c536d7f1639edee040a4fb6322068c43bd6))
* **audit:** key in-progress execs by serial, records of other execs interleave ([31582a5](https://github.com/synthaea-lab/agent/commit/31582a539de069bdc5401d0da2e088c684fc1a31)), closes [#51](https://github.com/synthaea-lab/agent/issues/51)
* **audit:** rebuild an exec whose argv the kernel split over EXECVE records ([d77657b](https://github.com/synthaea-lab/agent/commit/d77657bc33ed601f75a6d3072c34d80c3146d091))
* **audit:** rebuild an exec whose argv the kernel split over EXECVE records ([e2c664b](https://github.com/synthaea-lab/agent/commit/e2c664b47fd82c8303899ce797506645ca4d5073)), closes [#51](https://github.com/synthaea-lab/agent/issues/51)
* **audit:** size the netlink socket for bursts and report cut records ([156812f](https://github.com/synthaea-lab/agent/commit/156812ff265a062af5c035ff6d942eb96f59a497))
* **audit:** size the netlink socket for bursts and report cut records ([d16c090](https://github.com/synthaea-lab/agent/commit/d16c0906ade6f2016d273a6fc74ea4d84553e759)), closes [#237](https://github.com/synthaea-lab/agent/issues/237)
* **correlator:** classify an IPv4-mapped destination as its IPv4 address ([8258a95](https://github.com/synthaea-lab/agent/commit/8258a9521f62baeb68a34ad810816f88caaf4ef2)), closes [#203](https://github.com/synthaea-lab/agent/issues/203)
* **etw:** deduplicate NTLM records before the process lookup; close review test gaps ([9dabf9b](https://github.com/synthaea-lab/agent/commit/9dabf9b7e3cc5d7520531a7cb8241403a381f489))
* **etw:** normalizing a path or registry key never slices inside a character ([5695929](https://github.com/synthaea-lab/agent/commit/5695929eb136f602cff8e472eab2e3944ea1e77f))
* **etw:** normalizing a path or registry key never slices inside a character ([91437fd](https://github.com/synthaea-lab/agent/commit/91437fd4d038e31571878f42fef68cb62c137712))
* **rules:** a systemctl -M/-H target is not the verb ([#246](https://github.com/synthaea-lab/agent/issues/246)) ([bac3704](https://github.com/synthaea-lab/agent/commit/bac370418bc154d549fd037309acd29d0e74356c))
* **rules:** a systemctl -M/-H target is not the verb (Refs [#246](https://github.com/synthaea-lab/agent/issues/246)) ([7d75de9](https://github.com/synthaea-lab/agent/commit/7d75de9fe71a301a451c1346151d0dbc8276d4f4))
* **rules:** alert on a starving CPUQuota and resolve the prlimit target to a tool ([#49](https://github.com/synthaea-lab/agent/issues/49)) ([a22fc4f](https://github.com/synthaea-lab/agent/commit/a22fc4f08b8611a9caf47da64e9378da961907a1))
* **rules:** alert on a starving CPUQuota and resolve the prlimit target to a tool (Refs [#49](https://github.com/synthaea-lab/agent/issues/49)) ([e2f4fff](https://github.com/synthaea-lab/agent/commit/e2f4fffa4fe1a5ca16c9ca766c56c9750308a04f))
* **rules:** Opera's .opdownload partial suffix finishes a browser download ([#221](https://github.com/synthaea-lab/agent/issues/221)) ([79eee9d](https://github.com/synthaea-lab/agent/commit/79eee9d551efaac557e2c30afda34193a13ec49c))
* **rules:** read abbreviated --pid and per-mille CPUQuota, union the names of a pid ([3d64009](https://github.com/synthaea-lab/agent/commit/3d640090177b9deb47a6ff1b2cd7924254b8f8aa)), closes [#49](https://github.com/synthaea-lab/agent/issues/49)
* **rules:** systemctl options that take a value do not hide the verb ([#246](https://github.com/synthaea-lab/agent/issues/246)) ([7befcac](https://github.com/synthaea-lab/agent/commit/7befcac0eff34fbb8b632e26b202c451b1ef582a))
* **schema:** has_write_intent counts O_TRUNC, which empties the file ([b461150](https://github.com/synthaea-lab/agent/commit/b46115058ea4b6fd54275e743c97c894852b8dbf))
* **schema:** has_write_intent counts O_TRUNC, which empties the file ([5a99c5d](https://github.com/synthaea-lab/agent/commit/5a99c5deb2364d8f33c6f81fe71bd1142bba999d))
* **sensor-linux-ebpf:** i686 ptrace and process_vm offsets start at 12, not 16 ([aa9d2ee](https://github.com/synthaea-lab/agent/commit/aa9d2ee5757c1f6b7112006f5c0539940d96385f))
* **sensor-linux-ebpf:** i686 ptrace and process_vm offsets start at 12, not 16 ([7077312](https://github.com/synthaea-lab/agent/commit/7077312af5b7af964e40059ffc814b63f70515b5)), closes [#218](https://github.com/synthaea-lab/agent/issues/218)
* **sensor-linux-ebpf:** SSL_READ_ARGS holds three u64s, so the 5.15 and 6.1 verifiers accept the entry probes ([2d064ea](https://github.com/synthaea-lab/agent/commit/2d064ea4c4972dc0515fc5db7cccbb97fc40d10e))
* **sensor-linux-ebpf:** SSL_READ_ARGS holds three u64s, so the 5.15 and 6.1 verifiers accept the entry probes ([3d880c2](https://github.com/synthaea-lab/agent/commit/3d880c2aa1d6ade9dab9deded754a7dc2ee9c7be))
* **sensor-linux-journal:** cap the length of a journal line, count what it drops ([#189](https://github.com/synthaea-lab/agent/issues/189)) ([40f5d2e](https://github.com/synthaea-lab/agent/commit/40f5d2e83826f8bbce8060a21bc110980aca0513))
* **sensor-linux-wire,rules:** a non-normalized cgroup limit path is not dropped, and cgroup2 mounted elsewhere is read (Refs [#49](https://github.com/synthaea-lab/agent/issues/49)) ([04015e5](https://github.com/synthaea-lab/agent/commit/04015e5ec296495abbd48115d76e64a57c0d33b5))
* **sensor-linux:** raw-tracepoint try_into maps to the typed loader error ([42cb2e7](https://github.com/synthaea-lab/agent/commit/42cb2e721c5b4a88b0460f596ee2da6bb7049cac))
* **sensor-linux:** raw-tracepoint try_into maps to the typed loader error (Fixes [#185](https://github.com/synthaea-lab/agent/issues/185)) ([e67c737](https://github.com/synthaea-lab/agent/commit/e67c7371a83bd291f3bc31f2f8e2c2d37f940eb3))
* **uprobes:** find musl's libc without the musl-dev symlink ([129f24c](https://github.com/synthaea-lab/agent/commit/129f24c7503e6f25cb95cebc9feffc63d5db832d))
* **uprobes:** find musl's libc without the musl-dev symlink ([812be1a](https://github.com/synthaea-lab/agent/commit/812be1abe4aa7a4c95a051b58361fff8b7ce532e))


### Packaging and release

* accept "statically linked" too in the verify_probes static check ([7a2f4bf](https://github.com/synthaea-lab/agent/commit/7a2f4bf102f87c1101cd1ecf3c121890eebd6902))
* also boot 5.15 and 6.1 builds from late 2023 in linux-ebpf-verify ([294afe4](https://github.com/synthaea-lab/agent/commit/294afe48cffab26a77b25975089e2cc5d969e1c9))
* build verify_probes as a static musl binary, fail a probe-less build ([3677822](https://github.com/synthaea-lab/agent/commit/3677822b31b776f29726282c751403a9922f1c4c))
* build verify_probes as a static musl binary, fail a probe-less build ([28b7de6](https://github.com/synthaea-lab/agent/commit/28b7de6fa1b18795934b825151372aa9094b7baf))
* **linux-ebpf:** add the musl target to the pinned toolchain ([67c8f24](https://github.com/synthaea-lab/agent/commit/67c8f2428d7098b410a42254c89dc0565e5d4ab0))
* load every eBPF program on 5.15 and 6.1 in a VM ([5911ccc](https://github.com/synthaea-lab/agent/commit/5911ccc335dd3976b1ad7fc2c7cce3f6e59a9405))
* load every eBPF program on 5.15 and 6.1 kernels in a VM ([7ada3d7](https://github.com/synthaea-lab/agent/commit/7ada3d7779879838f75f098d919b3ff2d9a47a23))

## 0.0.1 (2026-11-09)


### Bug Fixes

* **packaging:** point the deb/apk builders at packaging/toolchain/ ([#201](https://github.com/synthaea-lab/agent/issues/201)) ([dca211d](https://github.com/synthaea-lab/agent/commit/dca211d5150205b059a0a9762716a4cf7af2b55d))


### Packaging and release

* release pipeline with release-please, per-OS signing, SBOM and attestations ([#193](https://github.com/synthaea-lab/agent/issues/193)) ([7ed64ac](https://github.com/synthaea-lab/agent/commit/7ed64ac94d65aa314ba16872c63b068f35b853ff))
