# Security Policy

Synthaea is security software. A vulnerability here is not an inconvenience — it is a foothold on
every endpoint running the agent, at the highest privilege level on the machine. We treat reports
accordingly.

> [!IMPORTANT]
> **Placeholders to fill before the repository goes public.** The contact address and PGP key
> below are not yet provisioned. A security policy that points nowhere is worse than none, because
> it convinces a reporter they've disclosed responsibly when nobody received it.
>
> - [ ] Provision `security@<domain>` and route it to a monitored, access-controlled inbox
> - [ ] Publish a PGP key and record its fingerprint here
> - [ ] Enable GitHub Private Vulnerability Reporting on the repository
> - [ ] Register for CVE assignment (GitHub is a CNA and can issue CVEs for this repo)

---

## Reporting a vulnerability

**Do not open a public issue.**

Preferred: **GitHub Private Vulnerability Reporting** — the *Security* tab → *Report a
vulnerability*. It's private, threaded, and gives us a path to a CVE.

Alternative: email **security@\<domain\>**, encrypted with our PGP key (fingerprint: *TBD*) if the
report contains exploit detail.

Please include, to whatever extent you have it:

- Component and version (agent, driver, control plane, morph pipeline)
- Platform and OS build
- Impact — what an attacker gains
- Reproduction steps or a proof of concept
- Whether the finding is already public or shared with third parties

### What to expect

| Stage | Target |
| --- | --- |
| Acknowledgement of receipt | 48 hours |
| Initial assessment and severity | 5 business days |
| Fix or documented mitigation | 90 days, or sooner by severity |
| Public disclosure | Coordinated with you, after a fix ships |

We follow coordinated disclosure and will credit you by name unless you'd rather we didn't. If we
disagree with your severity assessment, we'll tell you why rather than quietly downgrading it.

---

## Scope

### In scope — and specifically wanted

Because of what this project is, these categories matter more here than in ordinary software:

- **Agent bypass.** Executing malicious behavior the agent should have detected or blocked.
- **Agent blinding or disablement.** Killing, crashing, silencing, unhooking, or starving the
  sensor. **Including techniques that defeat the morph layer** — see below.
- **Privilege escalation via the agent.** The agent runs at SYSTEM/root with a kernel component.
  Any path from unprivileged code to agent-level privilege is critical.
- **Kernel instability.** A reproducible BSOD, panic, or deadlock caused by the driver or probes.
  We treat these as security issues, not merely stability bugs — a crash loop is a denial of
  protection.
- **Control-plane compromise.** Tenant isolation failures, enrollment/PKI weaknesses, policy or
  content injection.
- **Supply chain.** Anything that lets an attacker influence the variant factory, the content
  distribution pipeline, or the signing path. This is the highest-severity class in the project:
  it converts one compromise into fleet-wide code execution.
- **Model attacks.** Adversarial evasion of the ML tiers, training-data poisoning, or model
  extraction — see the research note below.

### Out of scope

- Findings against the design documents. Those are design disagreements — open an issue and see
  [CONTRIBUTING.md](CONTRIBUTING.md#challenging-a-design-decision).
- Attacks requiring physical access, or an already-kernel-level adversary (see the honesty note
  below).
- Missing hardening flags with no demonstrated exploit path. Report them as ordinary issues.
- Automated scanner output submitted without analysis.

---

## An honest boundary on agent self-protection

We claim that Synthaea's metamorphic layer makes the agent hard to fingerprint and hard to
reliably disable. We explicitly **do not** claim it stops an adversary who already has kernel
execution — via a vulnerable signed driver or otherwise. Against that adversary, no user-mode
technique wins, and our documented defense is kernel-level protection plus server-side heartbeat,
because agent silence is itself a detection.

This matters for triage: *"I was already SYSTEM with a loaded malicious driver and I killed the
agent"* is a known and documented limitation
([docs/architecture/threat-model.md](docs/architecture/threat-model.md)), not a vulnerability.

*"I disabled the agent from a normal user account,"* or *"I derived a reliable kill primitive
against one tenant's variant and it worked against another tenant's,"* **is** a vulnerability, and
a serious one — the second breaks the central claim of the morph design. Please report it.

---

## Research on the ML models

Adversarial ML research against our shipped models is welcome and in scope. Two requests:

1. **Evasion techniques generalize.** If you've found a way to evade our behavioral models that
   likely evades other vendors' too, tell us privately first and let us coordinate more broadly.
   The responsible-disclosure norms here are less settled than for memory-safety bugs; we'd rather
   over-coordinate.
2. **Don't poison the live corpus.** If your research involves submitting crafted telemetry,
   contact us first and we'll set up an isolated tenant. Poisoning a shared training corpus harms
   every user of the project, and cleaning it is expensive.

## Supported versions

The project is pre-release; there are no supported versions yet. Once we ship, this table will
list supported branches and their support windows.

| Version | Supported |
| --- | --- |
| pre-release (design phase) | n/a — no released code |

## Safe harbor

We will not pursue or support legal action against researchers who act in good faith: who report
promptly and privately, who avoid privacy violations and service degradation, who don't exfiltrate
data beyond what's needed to demonstrate impact, and who give us reasonable time to fix before
disclosing. If you're unsure whether something crosses a line, ask us first — we'd rather have the
conversation.
