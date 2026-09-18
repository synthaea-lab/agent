# Data Flow - sensor-linux-uprobes

Complete documentation of how captured TLS plaintext and shell commands flow through
the system, from eBPF capture to server storage.

**Security Note:** This sensor captures highly sensitive data (credentials, tokens,
session cookies). Understanding the complete data flow is critical for:
- Security reviews and threat modeling
- Compliance assessments (GDPR, HIPAA, PCI-DSS)
- Access control and audit trail design
- Data retention and deletion policies

---

## Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ eBPF (Kernel Space)                                                         │
│  ┌─────────────┐                                                            │
│  │ ssl_write() │ ──┐                                                        │
│  │ uprobe      │   │   Ring Buffer                                          │
│  └─────────────┘   ├─► TLS_CAPTURE_EVENTS ─┐                               │
│  ┌─────────────┐   │   (256 KB, per-CPU)    │                               │
│  │ ssl_read()  │ ──┘                        │                               │
│  │ uretprobe   │                            │                               │
│  └─────────────┘                            │                               │
│                                             │                               │
│  ┌─────────────┐   Ring Buffer              │                               │
│  │ readline()  │ ─► READLINE_EVENTS ────────┤                               │
│  │ uretprobe   │   (256 KB, per-CPU)        │                               │
│  └─────────────┘                            │                               │
└─────────────────────────────────────────────┼───────────────────────────────┘
                                              │
                                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Userspace (sensor-linux-uprobes)                                            │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │ Ring Buffer Draining (sensor.rs)                                      │  │
│  │  - Read wire::TlsCaptureEvent / wire::ReadlineInputEvent             │  │
│  │  - Budget enforcement (sliding 1-sec window per-PID)                 │  │
│  │  - Allowlist filtering (process names)                               │  │
│  │  - Container attribution from /proc/<pid>/cgroup (issue #80)         │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                              │                                              │
│                              ▼                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │ Normalization (normalize.rs)                                          │  │
│  │  - Wire format → schema::Event                                        │  │
│  │  - CLOCK_MONOTONIC → epoch nanoseconds                                │  │
│  │  ✅ REDACTION HAPPENS HERE (redact.rs) - Phase 9                      │  │
│  │    - HTTP: Authorization, Cookie, credentials in URLs, API keys       │  │
│  │    - Shell: export FOO=, --password=, -p, AWS_*, curl -u              │  │
│  │  - Event::TlsCapture / Event::ReadlineInput emitted                   │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                              │                                              │
│                              ▼                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │ EventSink::on_event()                                                 │  │
│  │  - Trait boundary: sensor → detection pipeline                        │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
                                              │
                                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Detection Pipeline (agent)                                                  │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │ DetectionSink (agent/src/sink.rs)                                     │  │
│  │  - Rules evaluation (crates/rules)                                    │  │
│  │  - Sigma matching (crates/sigma)                                      │  │
│  │  - Correlation (crates/correlator)                                    │  │
│  │  - ML features extraction (crates/ml)                                 │  │
│  │  - Enrichment queue (process lineage, network context)                │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                              │                                              │
│                              ▼                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │ Enrichment (crates/enrich)                                            │  │
│  │  - Reverse DNS lookups                                                │  │
│  │  - GeoIP resolution                                                   │  │
│  │  - Process tree walking                                               │  │
│  │  - Container metadata (Docker API)                                    │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                              │                                              │
│                              ▼                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │ Spool (crates/store)                                                  │  │
│  │  - JSON-Lines format on disk                                          │  │
│  │  - Path: /var/lib/synthea/spool/*.jsonl                              │  │
│  │  - Bounded size (rotates when full)                                   │  │
│  │  - Permissions: 0600 (root only)                                      │  │
│  │  ⚠️ SENSITIVE DATA IN PLAINTEXT (even with redaction, not all        │  │
│  │     patterns caught)                                                  │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                              │                                              │
│                              ▼                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │ Transport (crates/transport)                                          │  │
│  │  - HTTPS POST to server API                                           │  │
│  │  - TLS 1.2+ encryption in transit                                     │  │
│  │  - Client certificate auth (mTLS)                                     │  │
│  │  - Compression: gzip                                                  │  │
│  │  - Retry with exponential backoff                                     │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
                                              │
                                              ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ Server (server/)                                                            │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │ Ingestion API (Next.js)                                               │  │
│  │  - POST /api/events                                                   │  │
│  │  - mTLS verification (client cert)                                    │  │
│  │  - Rate limiting                                                      │  │
│  │  - Schema validation (reject malformed events)                        │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                              │                                              │
│                              ▼                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │ PostgreSQL Database                                                   │  │
│  │  - Table: events                                                      │  │
│  │  - Columns: id, agent_id, event_type, timestamp, payload (jsonb)      │  │
│  │  - Indexes: timestamp, event_type, agent_id                           │  │
│  │  - Encryption at rest: TBD (depends on deployment)                    │  │
│  │  ⚠️ SENSITIVE DATA PERSISTED (redacted, but not all patterns caught)  │  │
│  │  - Retention: Configurable per customer (default: 90 days)            │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                              │                                              │
│                              ▼                                              │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │ Query API / Web UI                                                    │  │
│  │  - Search: Elasticsearch / PostgreSQL full-text                       │  │
│  │  - Access control: RBAC (users, roles, permissions)                   │  │
│  │  - Audit logging: WHO accessed WHAT event WHEN                        │  │
│  │  - Export: JSON, CSV (with access control)                            │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Detailed Stage Breakdown

### Stage 1: eBPF Capture (Kernel Space)

**Where:** `crates/sensors/linux/ebpf/src/main.rs`

**What happens:**
- Uprobes fire when instrumented functions execute (SSL_write, SSL_read, readline)
- Probe reads function arguments from registers/stack
- Probe reads buffer memory using `bpf_probe_read_user_buf()` (up to 256 bytes for TLS, 512 for readline)
- Probe assembles `wire::TlsCaptureEvent` or `wire::ReadlineInputEvent` in per-CPU scratch buffer
- Event emitted to ring buffer via `RingBuf::output()`

**Security properties:**
- ✅ Data captured before encryption (TLS write) or after decryption (TLS read)
- ✅ No userspace visibility into this stage (kernel-only)
- ⚠️ **NO REDACTION YET** - full plaintext in ring buffer
- ⚠️ Ring buffer readable by root/CAP_BPF only

**Performance:**
- Budget: MAX_TLS_CAPTURE = 256 bytes, MAX_READLINE_INPUT = 512 bytes
- Ring buffer: 256 KB per-CPU (drops events when full)
- Overhead: ~2-10x vs tracepoints (uprobe cost)

---

### Stage 2: Ring Buffer Draining (Userspace)

**Where:** `crates/sensors/linux/uprobes/src/sensor.rs`

**What happens:**
- Tokio task polls ring buffers (TLS_CAPTURE_EVENTS, READLINE_EVENTS)
- Reads `wire::TlsCaptureEvent` / `wire::ReadlineInputEvent` structs
- **Budget enforcement:** Checks per-PID sliding 1-sec window
  - TLS: default 4096 bytes/sec per process
  - Readline: default 10 commands/sec per process
  - Exceeded → event dropped, counter incremented
- **Allowlist filtering:** Checks process `comm` against configured allowlist
  - Empty allowlist = all processes allowed
  - Non-empty = only listed processes captured
- **Container attribution:** Reads `/proc/<pid>/cgroup` for container ID (issue #80)
- Passes event to normalization

**Security properties:**
- ⚠️ **NO REDACTION YET** - still plaintext
- ✅ Budget prevents runaway capture from single process
- ✅ Allowlist reduces attack surface (only capture from known processes)
- ⚠️ Ring buffer data briefly in userspace memory (process memory)

**Dropped events:**
- Logged at debug level during capture
- Counted and reported at shutdown:
  ```
  sensor-linux-uprobes: TLS captures dropped (budget/allowlist): 142
  ```

---

### Stage 3: Normalization + Redaction (Userspace)

**Where:** `crates/sensors/linux/uprobes/src/normalize.rs`

**What happens:**
1. Convert wire format (fixed-size repr(C)) → schema Event (unbounded Rust types)
2. Convert CLOCK_MONOTONIC timestamp → epoch nanoseconds
3. **✅ REDACTION HAPPENS HERE** (`crate::redact`)
   - `redact_tls_data()`: Masks HTTP headers, credentials in URLs, API keys
   - `redact_readline_input()`: Masks passwords, export statements, AWS credentials
4. Create `Event::TlsCapture` or `Event::ReadlineInput`
5. Pass to `EventSink::on_event()`

**Security properties:**
- ✅ **REDACTION APPLIED** before leaving sensor boundary
- ✅ Patterns matched: Authorization, Cookie, --password=, export FOO=, curl -u, etc.
- ⚠️ Best-effort pattern matching (attackers may evade)
- ⚠️ Non-redacted data briefly in memory before redaction

**Redaction patterns:**
- **TLS:** `Authorization:`, `Cookie:`, `https://user:pass@host`, `?api_key=`
- **Readline:** `export FOO=`, `--password=`, `-p`, `AWS_SECRET_ACCESS_KEY=`, `curl -u`
- See `crates/sensors/linux/uprobes/src/redact.rs` for full list

---

### Stage 4: Detection Pipeline (Agent)

**Where:** `agent/src/sink.rs`, `crates/rules`, `crates/sigma`, `crates/correlator`, `crates/ml`

**What happens:**
- `DetectionSink` receives `Event::TlsCapture` / `Event::ReadlineInput`
- Rules engine evaluates YARA/Sigma rules
- Correlator looks for multi-event patterns
- ML features extracted (if ML enabled)
- Enrichment queued (reverse DNS, GeoIP, process tree)

**Security properties:**
- ✅ Data already redacted (from Stage 3)
- ⚠️ Rules/ML may extract features from redacted data
- ⚠️ Detection logic has full access to event payload

**Performance:**
- Asynchronous: events queued, processed in background
- Bounded queues: back-pressure if detection too slow

---

### Stage 5: Enrichment (Agent)

**Where:** `crates/enrich`

**What happens:**
- Reverse DNS lookups for IP addresses
- GeoIP resolution (MaxMind DB)
- Process tree walking (/proc/<pid>/...)
- Container metadata (Docker/containerd API)
- Results merged into event

**Security properties:**
- ✅ Data already redacted
- ⚠️ External lookups (DNS, GeoIP) may leak metadata
- ⚠️ Process tree may contain sensitive info (cmdline args)

---

### Stage 6: Spool (Agent Local Storage)

**Where:** `crates/store`, `/var/lib/synthea/spool/*.jsonl`

**What happens:**
- Events serialized to JSON-Lines format
- Written to local disk spool
- Rotation when file size exceeds limit
- Bounded total spool size (oldest files deleted)

**Security properties:**
- ✅ Data redacted (from Stage 3)
- ⚠️ **PLAINTEXT JSON ON DISK** - even with redaction, not all patterns caught
- ✅ File permissions: 0600 (root only)
- ⚠️ No encryption at rest by default
- ⚠️ Filesystem snapshots/backups may contain spool

**Retention:**
- Default: Until uploaded to server + local retention window
- Configurable: Max spool size, max file age
- Deletion: Oldest files deleted when spool full

**Compliance considerations:**
- GDPR: Spool is "personal data processing" if contains PII
- HIPAA: PHI on disk requires encryption at rest + access audit
- PCI-DSS: Cardholder data requires encryption at rest

---

### Stage 7: Transport (Agent → Server)

**Where:** `crates/transport`

**What happens:**
- HTTPS POST to server API (`/api/events`)
- TLS 1.2+ encryption in transit
- mTLS (client certificate authentication)
- Compression: gzip
- Retry with exponential backoff on failure

**Security properties:**
- ✅ Encrypted in transit (TLS)
- ✅ Client authentication (mTLS)
- ⚠️ Server CA must be trusted (cert pinning recommended)
- ⚠️ Network metadata visible (source IP, timing, size)

**Failure handling:**
- Network error → retry with backoff
- Server error (4xx, 5xx) → log + retry
- Events remain in spool until successful upload

---

### Stage 8: Server Ingestion (Server)

**Where:** `server/` (Next.js API)

**What happens:**
- POST /api/events endpoint receives batch
- mTLS verification (client cert)
- Schema validation (reject malformed events)
- Rate limiting (per agent)
- Insert into PostgreSQL `events` table

**Security properties:**
- ✅ Data already redacted (from Stage 3)
- ✅ mTLS prevents unauthorized agents
- ✅ Schema validation prevents injection
- ⚠️ API has full access to event payloads

**Access control:**
- mTLS: Only agents with valid certs can ingest
- Rate limiting: Prevent abuse/DoS
- Audit logging: Which agent sent which events

---

### Stage 9: PostgreSQL Storage (Server)

**Where:** PostgreSQL database, `events` table

**Schema:**
```sql
CREATE TABLE events (
    id BIGSERIAL PRIMARY KEY,
    agent_id UUID NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_events_timestamp ON events (timestamp);
CREATE INDEX idx_events_type ON events (event_type);
CREATE INDEX idx_events_agent ON events (agent_id);
```

**Security properties:**
- ✅ Data already redacted (from Stage 3)
- ⚠️ **PLAINTEXT JSON IN DATABASE** - even with redaction
- ⚠️ Encryption at rest: Depends on deployment (PostgreSQL TDE, disk encryption)
- ⚠️ Backups contain sensitive data (same retention as primary)
- ⚠️ Database admin has full access to all events

**Retention:**
- Default: 90 days (configurable per customer)
- Deletion: Automated job deletes events older than retention period
- VACUUM: Reclaim disk space after deletion

**Compliance considerations:**
- GDPR: Right to erasure requires event deletion by subject_id
- HIPAA: Audit trail required (who accessed which events when)
- PCI-DSS: Cardholder data max retention 90 days

---

### Stage 10: Query API / Web UI (Server)

**Where:** `server/` (Next.js pages + API routes)

**What happens:**
- Users query events via web UI
- Search: Elasticsearch or PostgreSQL full-text
- Access control: RBAC (users, roles, permissions)
- Audit logging: WHO accessed WHAT event WHEN
- Export: JSON, CSV (with access control)

**Security properties:**
- ✅ Data already redacted (from Stage 3)
- ✅ RBAC prevents unauthorized access
- ✅ Audit trail for accountability
- ⚠️ Exported files may contain sensitive data (redacted, but not all patterns caught)
- ⚠️ Search queries may leak metadata

**Access control:**
- User authentication (SSO, local accounts)
- Role-based permissions (admin, analyst, viewer)
- Agent isolation (users see only their agents' events)
- Field-level permissions (future: hide specific fields per role)

**Audit trail:**
- Every query logged (user, timestamp, query, result count)
- Every export logged (user, timestamp, event IDs)
- Every event view logged (user, timestamp, event ID)

---

## Security Summary

### Data States

| Stage | Location | Format | Redacted | Encrypted | Access Control |
|-------|----------|--------|----------|-----------|----------------|
| eBPF capture | Kernel ring buffer | Binary (wire) | ❌ | ❌ | root/CAP_BPF |
| Ring buffer drain | Agent memory | Binary (wire) | ❌ | ❌ | root |
| **Normalization** | Agent memory | Schema Event | ✅ | ❌ | root |
| Detection pipeline | Agent memory | Schema Event | ✅ | ❌ | root |
| Spool | Disk (/var/lib/synthea) | JSON-Lines | ✅ | ❌ (⚠️) | 0600 (root) |
| Transport | Network | JSON (gzip) | ✅ | ✅ TLS | mTLS |
| Server API | Server memory | JSON | ✅ | ❌ | mTLS |
| PostgreSQL | Database | JSONB | ✅ | ⚠️ (depends) | DB auth |
| Web UI | Browser | JSON | ✅ | ✅ HTTPS | RBAC |

### Attack Surface

**Threats:**
1. **Kernel compromise:** Attacker with root can read ring buffers before redaction
2. **Agent compromise:** Attacker with root can read spool files (redacted, but not all patterns caught)
3. **Network MITM:** Attacker intercepts transport (mitigated by TLS/mTLS)
4. **Server compromise:** Attacker accesses PostgreSQL (redacted data, but still sensitive)
5. **Backup exposure:** Backups contain spool/DB dumps (same sensitivity as primary)
6. **Insider threat:** DB admin or web UI user with elevated permissions

**Mitigations:**
- ✅ Redaction at sensor boundary (Stage 3)
- ✅ TLS encryption in transit (Stage 7)
- ✅ mTLS authentication (Stage 7-8)
- ✅ RBAC in web UI (Stage 10)
- ✅ Audit logging (Stage 10)
- ⚠️ No encryption at rest for spool (Stage 6) - **TODO**
- ⚠️ No encryption at rest for DB (Stage 9) - deployment-dependent

---

## Compliance Implications

### GDPR (General Data Protection Regulation)

**Personal Data:**
- TLS captures: May contain PII (names, emails, IDs in HTTP requests)
- Readline inputs: May contain PII (usernames, email addresses in commands)

**Requirements:**
- ✅ Data minimization: Redaction reduces PII exposure
- ✅ Purpose limitation: Captured for security monitoring only
- ⚠️ Right to erasure: Requires deletion by `agent_id` or `user_id` (not yet implemented)
- ⚠️ Data breach notification: 72 hours if plaintext data exposed

**Recommendations:**
- Implement deletion by subject ID (future work)
- Document legal basis (legitimate interest: security monitoring)
- DPO review before production deployment

### HIPAA (Health Insurance Portability and Accountability Act)

**PHI (Protected Health Information):**
- TLS captures: May contain PHI (patient IDs, medical records in API requests)
- Readline inputs: May contain PHI (patient names in SQL queries)

**Requirements:**
- ⚠️ Encryption at rest: Spool and DB require encryption (not default)
- ⚠️ Access audit: Comprehensive logging required (partially implemented)
- ⚠️ Business Associate Agreement: Vendor must sign BAA
- ⚠️ Minimum necessary: Only capture what's needed (use allowlist)

**Recommendations:**
- Enable disk encryption (LUKS, dm-crypt, PostgreSQL TDE)
- Implement comprehensive audit trail (all access logged)
- Limit retention to minimum necessary (30 days for HIPAA)

### PCI-DSS (Payment Card Industry Data Security Standard)

**Cardholder Data:**
- TLS captures: May contain credit card numbers (PAN) in HTTP requests
- Readline inputs: Less likely, but possible (curl commands with card numbers)

**Requirements:**
- ❌ **CRITICAL:** PCI-DSS prohibits storing full PAN after authorization
- ❌ Redaction patterns do NOT currently mask credit card numbers
- ⚠️ If PAN captured, must encrypt at rest + strict access control + max 90-day retention

**Recommendations:**
- **DO NOT use in PCI-DSS environments** until PAN redaction implemented
- Add regex for credit card numbers (Luhn algorithm validation)
- Consider disabling TLS capture entirely for payment processing systems

---

## Redaction Effectiveness

### What IS redacted:

**TLS captures:**
- ✅ HTTP `Authorization: Bearer ...` headers
- ✅ HTTP `Cookie: session_id=...` headers
- ✅ Credentials in URLs: `https://user:pass@host`
- ✅ API keys in query strings: `?api_key=secret`

**Readline inputs:**
- ✅ Export statements: `export PASSWORD=secret`
- ✅ Password flags: `--password=secret`, `-psecret`
- ✅ AWS credentials: `AWS_SECRET_ACCESS_KEY=...`
- ✅ Basic auth: `curl -u user:pass`

### What is NOT redacted:

**TLS captures:**
- ❌ Base64-encoded credentials (Authorization: Basic base64...)
- ❌ Cookies with non-standard names (e.g., `X-Auth-Token`)
- ❌ Custom headers (e.g., `X-API-Key`, `X-Session-ID`)
- ❌ Credentials in POST body (JSON, form data)
- ❌ Binary protocols (gRPC, protobuf) - kept as-is

**Readline inputs:**
- ❌ Passwords in positional arguments: `mysql -u root password123`
- ❌ Secrets in environment variables set inline: `PASSWORD=foo command`
- ❌ Heredocs with secrets: `cat <<EOF\nsecret\nEOF`
- ❌ Obfuscated commands: `eval $(base64 -d <<<...)`

**Mitigation:**
- Redaction is **best-effort**, not a security boundary
- Use allowlist to limit capture to known-safe processes
- Disable TLS capture in high-risk environments (payment, healthcare)
- Regular security audits to identify new credential patterns

---

## Recommendations

### For Operators:

1. **Use allowlist by default:** Only capture from known processes
   ```rust
   let config = UprobesConfig::new()
       .with_tls_enabled()
       .tls_allow_processes(&["curl", "wget"]);
   ```

2. **Enable spool encryption:** Use LUKS/dm-crypt for `/var/lib/synthea`

3. **Limit retention:** Set shortest acceptable retention period
   ```yaml
   retention:
     tls_capture: 7d
     readline_input: 30d
   ```

4. **Monitor dropped events:** High drop rate = noisy process or attack
   ```
   sensor-linux-uprobes: TLS captures dropped (budget/allowlist): 142
   ```

5. **Audit access:** Review who queries TLS/readline events

### For Developers:

1. **Extend redaction patterns:** Add patterns for new credential types
2. **Implement compliance modes:** GDPR/HIPAA/PCI-DSS presets
3. **Add spool encryption:** Encrypt JSON files before writing
4. **Add retention enforcement:** Auto-delete events by age
5. **Add PAN detection:** Redact credit card numbers (Luhn validation)

### For Compliance:

1. **Document legal basis:** Why capturing TLS/readline is necessary
2. **DPO review:** Before production deployment
3. **BAA for HIPAA:** If capturing PHI
4. **PCI-DSS assessment:** If handling payment data (high risk)
5. **Data breach plan:** What to do if spool/DB exposed

---

## Future Work (Phase 9 remaining)

- [ ] Implement ComplianceMode enum (GDPR/HIPAA/PCI-DSS)
- [ ] Add retention policies per event type
- [ ] Spool encryption at rest
- [ ] PostgreSQL TDE deployment guide
- [ ] PAN (credit card) redaction
- [ ] Right to erasure (deletion by subject ID)
- [ ] Comprehensive audit trail (all event access logged)

---

**Last Updated:** 2026-09-15 (Phase 9 - Data flow documentation)
**Maintainers:** Security team, compliance team
**Review Cycle:** Quarterly, or when adding new capture types
