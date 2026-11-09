# Contributing to Synthaea

Synthaea is alpha software. The Linux agent runs end to end, while much of the wider system is
still being designed, so the foundations are still cheap to argue about.

**One of the most valuable contributions is still a well-argued objection to a design
decision.** If you think the schema design is wrong, the metamorphism claims are
overstated, the ML tiering won't hold its latency budget, or the roadmap's dependency order is
broken — say so. Those arguments are cheap today and ruinously expensive in eighteen months.

---

## Ground rules specific to this project

Synthaea is security software. Two rules follow from that and are not negotiable.

### 1. We do not accept offensive tooling

"Metamorphism" in Synthaea means **the agent diversifies itself** — moving-target defense for our
own binary, so an attacker can't fingerprint or reliably disable a known-layout agent.

We will not accept contributions that:

- mutate arbitrary third-party binaries to evade other security products,
- implement or package exploitation primitives beyond what a detection test requires,
- add evasion capability whose only use is against defenders.

Adversary-emulation content for **testing our own detections** is welcome and necessary — see
[Detection content](#detection-content) for how to submit it safely.

### 2. Vulnerabilities are never public issues

If you found a way to blind, crash, bypass, or subvert the agent, that is a security report, not a
bug report. Read **[SECURITY.md](SECURITY.md)** and use the private channel.

This includes techniques that defeat the agent's self-defense layers (tamper, mesh, per-install
variation). We would much rather hear it from you first.

---

## Developer Certificate of Origin

Synthaea has **no CLA and no rights assignment**. You keep your copyright.

We do require a [Developer Certificate of Origin](https://developercertificate.org/) sign-off, so
the provenance of every contribution is clean and auditable. Add a `Signed-off-by` line to each
commit:

```bash
git commit -s -m "docs: correct the BPF LSM kernel requirement"
```

This produces:

```
Signed-off-by: Your Name <your.email@example.com>
```

By signing off, you certify that you wrote the contribution or otherwise have the right to submit
it under the project's license. Use your real name — pseudonymous sign-offs don't serve the
purpose.

### Licensing of your contribution

Contributions are accepted under **Apache-2.0**, except contributions to the Linux eBPF probes,
which are dual-licensed **GPL-2.0-only OR MIT** because the kernel verifier requires a GPL-compatible license. See [`NOTICE`](NOTICE) and [`LICENSE`](LICENSE) — a
deliberate, recorded decision carried over from the project's start.

Because there is no CLA, **the project cannot relicense your contribution without your consent.**
That's a deliberate, recorded trade-off, and it means the license boundaries above are effectively
permanent. Please make sure you're comfortable with them before submitting.

---

## How to contribute

### Challenging a design decision

Locked decisions are recorded as Architecture Decision Records (cited as `ADR-00xx` in code
comments and PRs). Each ADR states its context, the decision, the alternatives rejected, and the
consequences accepted; where a comment's reasoning matters to the code, it is stated in the
comment itself.

To challenge one, **open an issue that engages with the recorded consequences.** An ADR is not
sacred — several will be superseded — but reopening one costs the team real time, so the bar is:

- What in the ADR's *context* has changed, or was wrong at the time?
- Which recorded *consequence* is worse than we estimated?
- What does your alternative cost, including migration for anything already built on it?

"I'd prefer Go" is not an argument. "Here is the measured p99 in the kernel callback path, and
here's why the current choice can't hit the §2.4 budget" is.

Superseding an ADR means writing a new one that references the old — we don't edit history.

### Improving the specification

Documentation PRs are welcome immediately. Particularly wanted:

- **Correctness of platform claims.** The sensor guides for
  [Linux](docs/sensors/linux/README.md), [Windows](docs/sensors/windows/README.md) and
  [macOS](docs/sensors/macos/README.md) make specific assertions about kernel facilities, ETW
  providers, BPF-LSM availability and EndpointSecurity events. If one is wrong or out of date,
  that's a high-value fix.
- **Prior art we've mischaracterized.** If the documentation is unfair to osquery, Velociraptor,
  Wazuh, Falco or any other project, correct us. We'd rather be accurate than flattering to
  ourselves.
- **Threat-model gaps.** Especially where the honest limitations matter more than the
  capability lists.

### Detection content

Accepted — content is code here; the content itself lives in
[synthaea-lab/rules](https://github.com/synthaea-lab/rules).
Every shipped rule must compile/validate in its engine AND fire on a crafted matching sample
(CI-enforced by the content suites — add your sample with your rule). Coming requirements as the
pipeline hardens: a MITRE ATT&CK technique mapping, negative (must-NOT-fire) samples, and a
false-positive assessment — an alert that fires on benign activity costs every operator's trust,
so FP governance is strict.

---

## Quality gates

[docs/development.md](docs/development.md#ci-gates) lists every check a pull request must
pass: formatting with nightly `rustfmt`, the dependency-direction check, `cargo-deny`, clippy
with `-D warnings`, and the tests on Linux, Windows and macOS, plus the detection-content
suites. Run the same checks on one machine before pushing:

```sh
tools/gauntlet.sh          # everything
tools/gauntlet.sh --fast   # skip the cross-target and documentation passes
```

One contract deserves a special mention: **feature parity between Python and Rust.**
Feature extraction exists twice, for training in
[synthaea-lab/ml](https://github.com/synthaea-lab/ml) and for inference in `crates/ml`, and
any divergence silently invalidates the shipped models. Both sides test against the same
golden fixtures. If you change a feature on one side, change the other in the same step,
regenerate the fixtures and retrain; see [crates/ml](crates/ml/README.md#feature-parity).

## Clean code

Rules the codebase already follows; PRs are reviewed against them. Most are ordinary software
engineering — the first two exist because this is a *detection* codebase, where quiet drift
between two copies of the same logic silently produces wrong verdicts.

- **One definition per predicate.** A security-relevant test (write-intent flags, suspicious
  path, private IP…) is defined in exactly one place per language and called everywhere else —
  e.g. `is_file_write` in `correlator`, `has_write_intent` in `rules`. If you find yourself re-typing a bitmask or a path list, you're creating the
  next parity bug.
- **Cross-language mirrors are contracts.** Anything implemented in both Python (training) and
  Rust (inference) must say so in a comment on *both* sides, and be locked by a shared test
  (golden file or mirrored test suites). See "Quality gates" above.
- **One module, one responsibility.** A file that accumulates a second engine, a second layer,
  or a second platform gets split (`apps/agent/src/{commands,sink}.rs`,
  `crates/correlator/src/{event,bus,rules,behavior,bayes,engine}.rs`). Platform `cfg`s live in
  one designated module per crate, not scattered.
- **Comments say *why*, and carry their evidence.** The best comments in this repo cite the lab
  session or the false positive that motivated a threshold, an exclusion, or a fallback
  ("FP observed 2026-08-28, NjRAT capture"). Keep doing that. Comments that restate the code get
  deleted in review.
- **Every fixed bug gets a regression test** named after the scenario, with the date and the
  real-world condition in a comment (see `download_then_shebang_script_exec_matches`).
- **Magic numbers are named constants with a calibration note** — a threshold without the story
  of how it was chosen can't be safely re-tuned later.
- **Untrusted input is escaped/validated at one choke point.** Event fields (`comm`, `cmdline`,
  paths) are attacker-controlled; serialization goes through serde on the canonical schema types
  (locked by golden fixtures), never ad-hoc string building.
- **Public API stays stable through refactors**: split modules, then `pub use` re-exports at the
  crate root so consumers don't churn.
- Naming and language: **English only** — identifiers, comments, docs, commits (a project rule;
  the old iteration's mixed-language files were translated during migration). ATT&CK technique
  IDs stay verbatim.

## Code standards

Recorded early so they're not invented under deadline pressure.

- **Rust** throughout the agent — including the eBPF probes (aya); **C only where the Windows
  kernel driver requires it**. The control plane is TypeScript/Next.js
  (ADR-0001).
- **`unsafe` is confined to per-platform FFI shims** behind safe interfaces, and every `unsafe`
  block carries a `// SAFETY:` comment justifying it.
- **No allocation on the hot path.** The probe path and on-device inference carry documented
  budgets (see each crate's docs — enrich, yara, ml); budget regressions are review blockers.
- **Fail open.** Any code path that can deny an operation must have a bounded timeout that
  degrades to *allow*. An EDR that bricks the machine is worse than no EDR. (To be re-adopted as
  an ADR when the first blocking path — BPF-LSM `response` — lands.)
- **Content is code.** Rules and models ship through the same canary rings as binaries. No
  exceptions, ever.

## Commit and PR conventions

- Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`).
- Every commit signed off (`git commit -s`).
- PRs describe *why*, not just *what*. The diff already says what.
- PRs that touch a documented decision must say which ADR they're operating under, or propose a
  new one.

## Code of conduct

Be straightforward and be kind. Argue with the design, not the person holding it. Security work
attracts strong opinions; strong opinions are welcome, contempt is not.

Conduct concerns go to the same private contact as security reports in
[SECURITY.md](SECURITY.md).
