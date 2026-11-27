# Designed, not built

Three parts of the agent have a written design and no code. Each was an empty crate in the
workspace until 2026-11-27, holding only this text as its doc comment; an empty crate reads as
something built, so the text lives here until the work starts. Starting one means creating the
crate and adding it to `tools/check-deps.py` in the same change.

## Peer mesh

Tracked in [#29](https://github.com/synthaea-lab/agent/issues/29).

Peer-to-peer communication between agents on the same network segment — reviving
the old iteration's mesh design (peer attestation: "making an agent kill loud,
fast, and recoverable") and extending it with fleet posture. Two jobs:

- **Peer attestation**: agents exchange signed heartbeats with their neighbors.
  A killed or silenced agent cannot report its own death — its peers can, and
  do, both to the server and locally. Combined with `tamper`'s self-detection,
  every kill path is loud from at least one vantage point.
- **Posture gossip**: adaptive posture changes (`server/fleet`) propagate
  peer-to-peer in addition to the server channel — faster inside a segment, and
  resilient when the control plane is unreachable (an offline pool can still
  raise its collective alertness from a local detection).

## Security guardrails (designed in, not bolted on)

P2P inside an EDR is a gift to an attacker if done casually, so the protocol is
deliberately minimal:
- Peers authenticate mutually with their enrollment identities (same PKI as
  `transport`); unenrolled peers are noise.
- Messages are **signed, typed, and read-only**: attestation facts and posture
  hints. There is NO command channel — nothing an agent receives over the mesh
  makes it execute anything, and posture hints can only ever HEIGHTEN (the same
  never-disables rule as server posture, verified against the signed policy).
- A posture hint is advisory until corroborated: it carries the originating
  case/policy signature; unsigned or replayed hints are dropped and reported.
- Bounded chatter: fixed fan-out, rate limits, jittered intervals — the mesh
  must never become a scanning signature or a `DoS` amplifier.

## Device control

Tracked in [#30](https://github.com/synthaea-lab/agent/issues/30).

Peripheral telemetry and control, USB storage first:

- **Telemetry**: device attach/detach events (vendor/product/serial, class),
  file transfers to removable media (joining existing file events to the mount),
  `BadUSB` heuristics (HID appearing on a storage-class device, keystroke-speed
  anomalies) as detections.
- **Control**: policy-gated modes per device class — allow / read-only / block /
  notify — enforced platform-natively (Windows: device installation policies;
  macOS: `DiskArbitration` + ES auth events; Linux: udev rules + mount options),
  with per-device allowlists by serial.
- Every enforcement action is a detection-grade event: audited, case-attachable,
  and visible to the user via the `ui` tray (why was my stick blocked).

## Sensor conformance suite

Tracked in [#25](https://github.com/synthaea-lab/agent/issues/25).

The sensor conformance suite. Runs one battery of scenario-driven checks against
any `Sensor` implementation (event completeness, field fidelity, ordering, delivery
under load) and emits the per-platform capability matrix published in the docs —
generated from results, never maintained by hand.
