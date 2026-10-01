//! BITS jobs (#284, T1197): the `Microsoft-Windows-Bits-Client` records that
//! tie a BITS download, whose network I/O the BITS service does itself, back
//! to the process that asked for it, reported as `schema::BitsJobEvent`.
//!
//! Platform-independent on purpose: the URL is attacker-controlled (any client
//! picks it), so the host check is unit-tested on every CI leg and has a
//! never-panic suite in `tests/robustness.rs`. Only the ETW hook lives in the
//! Windows-gated `providers`.
//!
//! The provider's job-level records don't all carry what the event needs.
//! Field layout read off the local Windows 11 `Bits-Client/Operational` log
//! (2026-10-01):
//!
//! | EID | Meaning | Client pid | URL / local path |
//! |---|---|---|---|
//! | 16403 | file added to a job | `processId` | `RemoteName` / `LocalName` |
//! | 4 | job completed | none (service) | none |
//! | 5 | job cancelled | `processId` | none |
//! | 61 | transfer error | none (service) | `url` / none |
//!
//! So [`BitsJobs`] remembers each job from its file-added record and fills the
//! later ones in from it. That is also where the filter applies: a job whose
//! file comes from a Microsoft update host is never remembered, so none of its
//! records are forwarded.

use std::collections::HashMap;

use schema::{BitsJobEvent, BitsJobState, EventMeta};

/// Hosts whose BITS jobs are dropped at the sensor, matched on the URL's host
/// and every subdomain. BITS is the transport of Windows Update, WSUS,
/// Defender signatures, the Store, Delivery Optimization and Edge's component
/// updater: on the 2026-10-01 Windows 11 host every one of those fetched from
/// one of these. Attackers can't host content under them, which is what makes
/// a host (not a client name) safe to quiet on.
///
/// The job's owner is deliberately not a filter: a `SYSTEM`-owned job to a
/// host outside this list is what a SYSTEM-level implant using BITS looks like,
/// and the benign ones (OEM and browser system-wide updaters) are a handful a
/// day.
pub const MICROSOFT_UPDATE_HOSTS: &[&str] = &[
    "microsoft.com",
    "windows.com",
    "windowsupdate.com",
    "msftconnecttest.com",
];

/// Jobs remembered between their file-added record and their last one. A job
/// lives seconds to hours; this many concurrently in flight means a client is
/// creating jobs in a loop, and the oldest go first (counted).
pub const MAX_TRACKED_JOBS: usize = 1024;

/// The host of an `http(s)` URL, port, userinfo and trailing dot stripped.
/// `None` for any other scheme (BITS also takes SMB paths) or an empty host.
/// The authority ends at the first `/`, `?`, `#` or `\`, the way `WinHTTP`
/// cracks it, so `https://evil.test\.microsoft.com` is `evil.test`.
#[must_use]
pub fn url_host(url: &str) -> Option<&str> {
    let (scheme, rest) = url.split_once("://")?;
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return None;
    }
    let authority = &rest[..rest.find(['/', '?', '#', '\\']).unwrap_or(rest.len())];
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = match host_port.strip_prefix('[') {
        Some(literal) => literal.split_once(']')?.0,
        None => host_port
            .split_once(':')
            .map_or(host_port, |(host, _)| host),
    };
    let host = host.strip_suffix('.').unwrap_or(host);
    (!host.is_empty()).then_some(host)
}

/// Whether `url` fetches from a [`MICROSOFT_UPDATE_HOSTS`] host. A host with
/// any character outside `[A-Za-z0-9.-]` never matches: percent-encoding or a
/// non-ASCII lookalike must not buy a URL its way out of the telemetry.
#[must_use]
pub fn is_microsoft_update_url(url: &str) -> bool {
    let Some(host) = url_host(url) else {
        return false;
    };
    if !host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return false;
    }
    MICROSOFT_UPDATE_HOSTS.iter().any(|domain| {
        host.len() >= domain.len()
            && host[host.len() - domain.len()..].eq_ignore_ascii_case(domain)
            && (host.len() == domain.len()
                || host.as_bytes()[host.len() - domain.len() - 1] == b'.')
    })
}

/// A job as its file-added record described it.
struct TrackedJob {
    /// The client that added the file.
    meta: EventMeta,
    job_title: String,
    url: String,
    local_path: String,
    /// Insertion order, for eviction.
    seq: u64,
}

/// The jobs in flight, keyed by job GUID. Turns each forwarded record into a
/// [`BitsJobEvent`], or `None` when the record is filtered or belongs to a job
/// that never passed the filter.
#[derive(Default)]
pub struct BitsJobs {
    jobs: HashMap<String, TrackedJob>,
    seq: u64,
    /// File-added records dropped as Microsoft update jobs.
    filtered: u64,
    /// Jobs forgotten at [`MAX_TRACKED_JOBS`] before their last record.
    evicted: u64,
}

impl BitsJobs {
    /// EID 16403: `client` added `url` → `local_path` to the job. Forwarded
    /// and remembered, unless the URL is a Microsoft update host.
    pub fn file_added(
        &mut self,
        client: EventMeta,
        job_id: String,
        job_title: String,
        url: String,
        local_path: String,
    ) -> Option<BitsJobEvent> {
        if is_microsoft_update_url(&url) {
            self.filtered += 1;
            self.jobs.remove(&job_id);
            return None;
        }
        if self.jobs.len() >= MAX_TRACKED_JOBS && !self.jobs.contains_key(&job_id) {
            self.evict_oldest();
        }
        self.seq += 1;
        let event = BitsJobEvent {
            meta: client.clone(),
            job_id: job_id.clone(),
            job_title: job_title.clone(),
            state: BitsJobState::FileAdded,
            url: url.clone(),
            local_path: local_path.clone(),
            bytes_transferred: None,
            hresult: None,
        };
        self.jobs.insert(
            job_id,
            TrackedJob {
                meta: client,
                job_title,
                url,
                local_path,
                seq: self.seq,
            },
        );
        Some(event)
    }

    /// EID 4: the job completed, reported by the service at `timestamp_ns`.
    /// The job's last record: it is forgotten.
    pub fn completed(
        &mut self,
        job_id: &str,
        timestamp_ns: u64,
        bytes_transferred: Option<u64>,
    ) -> Option<BitsJobEvent> {
        let job = self.jobs.remove(job_id)?;
        Some(job.event(
            job_id,
            timestamp_ns,
            BitsJobState::Completed,
            bytes_transferred,
            None,
        ))
    }

    /// EID 5: `canceller` cancelled the job. The job's last record: it is
    /// forgotten.
    pub fn cancelled(&mut self, job_id: &str, canceller: EventMeta) -> Option<BitsJobEvent> {
        let mut job = self.jobs.remove(job_id)?;
        let timestamp_ns = canceller.timestamp_ns;
        job.meta = canceller;
        Some(job.event(job_id, timestamp_ns, BitsJobState::Cancelled, None, None))
    }

    /// EID 61: a transfer of the job failed with `hresult`. BITS retries on
    /// its own, so the job stays remembered.
    pub fn transfer_error(
        &mut self,
        job_id: &str,
        timestamp_ns: u64,
        bytes_transferred: Option<u64>,
        hresult: u32,
    ) -> Option<BitsJobEvent> {
        let job = self.jobs.get(job_id)?;
        Some(job.event(
            job_id,
            timestamp_ns,
            BitsJobState::TransferError,
            bytes_transferred,
            Some(hresult),
        ))
    }

    /// File-added records dropped as Microsoft update jobs, since start.
    #[must_use]
    pub fn filtered(&self) -> u64 {
        self.filtered
    }

    /// Jobs forgotten at [`MAX_TRACKED_JOBS`] before their last record, since
    /// start.
    #[must_use]
    pub fn evicted(&self) -> u64 {
        self.evicted
    }

    fn evict_oldest(&mut self) {
        let oldest = self
            .jobs
            .iter()
            .min_by_key(|(_, job)| job.seq)
            .map(|(id, _)| id.clone());
        if let Some(id) = oldest {
            self.jobs.remove(&id);
            self.evicted += 1;
        }
    }
}

impl TrackedJob {
    fn event(
        &self,
        job_id: &str,
        timestamp_ns: u64,
        state: BitsJobState,
        bytes_transferred: Option<u64>,
        hresult: Option<u32>,
    ) -> BitsJobEvent {
        BitsJobEvent {
            meta: EventMeta {
                timestamp_ns,
                ..self.meta.clone()
            },
            job_id: job_id.to_string(),
            job_title: self.job_title.clone(),
            state,
            url: self.url.clone(),
            local_path: self.local_path.clone(),
            bytes_transferred,
            hresult,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const JOB: &str = "{c40080ab-6fe4-418a-8ba6-c271c5298f18}";
    const PAYLOAD_URL: &str = "https://example.test/payload.exe";
    const PAYLOAD: &str = r"C:\Users\u\AppData\Local\Temp\p.exe";
    const UPDATE_URL: &str =
        "http://msedge.b.tlu.dl.delivery.mp.microsoft.com/filestreamingservice/files/0a26aa65";

    fn client(pid: u32, timestamp_ns: u64) -> EventMeta {
        EventMeta {
            pid,
            timestamp_ns,
            comm: "bitsadmin.exe".into(),
            ..schema::fixtures::meta()
        }
    }

    fn add(jobs: &mut BitsJobs, job_id: &str, url: &str) -> Option<BitsJobEvent> {
        jobs.file_added(
            client(6412, 1),
            job_id.into(),
            "update".into(),
            url.into(),
            PAYLOAD.into(),
        )
    }

    #[test]
    fn url_host_strips_port_userinfo_and_path() {
        for (url, host) in [
            ("https://example.test/a.exe", "example.test"),
            ("http://example.test:8080/a", "example.test"),
            ("https://user:pw@example.test/a", "example.test"),
            ("https://microsoft.com@evil.test/a", "evil.test"),
            ("https://evil.test#@microsoft.com", "evil.test"),
            ("https://evil.test?.microsoft.com", "evil.test"),
            (r"https://evil.test\.microsoft.com", "evil.test"),
            ("HTTPS://Example.Test./a", "Example.Test"),
            ("http://[2001:db8::1]:80/a", "2001:db8::1"),
        ] {
            assert_eq!(url_host(url), Some(host), "{url}");
        }
        for url in [
            r"\\server\share\a.exe",
            "file:///C:/a.exe",
            "ftp://example.test/a",
            "https://",
            "https:///a",
            "http://[2001:db8::1/a",
            "",
        ] {
            assert_eq!(url_host(url), None, "{url}");
        }
    }

    #[test]
    fn microsoft_update_hosts_and_their_subdomains_match() {
        for url in [
            UPDATE_URL,
            "http://download.windowsupdate.com/c/msdownload/update/a.cab",
            "https://definitionupdates.microsoft.com/download/x",
            "https://Microsoft.COM/x",
            "http://www.msftconnecttest.com/connecttest.txt",
        ] {
            assert!(is_microsoft_update_url(url), "{url}");
        }
    }

    #[test]
    fn lookalike_hosts_do_not_match() {
        for url in [
            PAYLOAD_URL,
            "https://microsoft.com.evil.test/a.exe",
            "https://evilmicrosoft.com/a.exe",
            "https://microsoft.com@evil.test/a.exe",
            "https://evil.test%2f.microsoft.com/a.exe",
            "https://evil.test%2Emicrosoft.com/a.exe",
            "https://xn--mcrosoft-wza.com/a.exe",
            "https://micrоsoft.com/a.exe", // Cyrillic 'о'
            r"\\microsoft.com\share\a.exe",
        ] {
            assert!(!is_microsoft_update_url(url), "{url}");
        }
    }

    #[test]
    fn a_job_is_forwarded_from_its_file_added_record() {
        let mut jobs = BitsJobs::default();
        let event = add(&mut jobs, JOB, PAYLOAD_URL).expect("forwarded");
        assert_eq!(event.state, BitsJobState::FileAdded);
        assert_eq!(event.meta.pid, 6412);
        assert_eq!(event.url, PAYLOAD_URL);
        assert_eq!(event.local_path, PAYLOAD);
    }

    #[test]
    fn a_completion_is_attributed_to_the_client_that_added_the_file() {
        let mut jobs = BitsJobs::default();
        add(&mut jobs, JOB, PAYLOAD_URL);
        let done = jobs.completed(JOB, 99, Some(4096)).expect("forwarded");
        assert_eq!(done.state, BitsJobState::Completed);
        assert_eq!((done.meta.pid, done.meta.timestamp_ns), (6412, 99));
        assert_eq!(done.meta.comm, "bitsadmin.exe");
        assert_eq!(
            (done.url.as_str(), done.local_path.as_str()),
            (PAYLOAD_URL, PAYLOAD)
        );
        assert_eq!(done.bytes_transferred, Some(4096));
        assert!(
            jobs.completed(JOB, 100, None).is_none(),
            "a completed job is forgotten"
        );
    }

    #[test]
    fn a_microsoft_update_job_is_filtered_with_all_its_records() {
        let mut jobs = BitsJobs::default();
        assert!(add(&mut jobs, JOB, UPDATE_URL).is_none());
        assert!(jobs.transfer_error(JOB, 2, None, 0x8019_0194).is_none());
        assert!(jobs.completed(JOB, 3, None).is_none());
        assert_eq!(jobs.filtered(), 1);
    }

    #[test]
    fn a_job_that_adds_a_microsoft_file_after_another_is_filtered_from_then_on() {
        let mut jobs = BitsJobs::default();
        assert!(add(&mut jobs, JOB, PAYLOAD_URL).is_some());
        assert!(add(&mut jobs, JOB, UPDATE_URL).is_none());
        assert!(jobs.completed(JOB, 3, None).is_none());
    }

    #[test]
    fn records_of_an_unseen_job_are_dropped() {
        // A job created before the agent started: its file-added record was
        // never seen, so nothing says whose it is or where it fetches from.
        let mut jobs = BitsJobs::default();
        assert!(jobs.completed(JOB, 1, None).is_none());
        assert!(jobs.cancelled(JOB, client(1, 1)).is_none());
        assert!(jobs.transfer_error(JOB, 1, None, 1).is_none());
    }

    #[test]
    fn a_cancellation_names_the_canceller() {
        let mut jobs = BitsJobs::default();
        add(&mut jobs, JOB, PAYLOAD_URL);
        let cancelled = jobs.cancelled(JOB, client(7000, 50)).expect("forwarded");
        assert_eq!(cancelled.state, BitsJobState::Cancelled);
        assert_eq!(
            (cancelled.meta.pid, cancelled.meta.timestamp_ns),
            (7000, 50)
        );
        assert!(jobs.completed(JOB, 51, None).is_none());
    }

    #[test]
    fn a_transfer_error_keeps_the_job() {
        let mut jobs = BitsJobs::default();
        add(&mut jobs, JOB, PAYLOAD_URL);
        let failed = jobs
            .transfer_error(JOB, 5, Some(1917), 0x8019_0194)
            .expect("forwarded");
        assert_eq!(failed.state, BitsJobState::TransferError);
        assert_eq!(failed.hresult, Some(0x8019_0194));
        assert_eq!(failed.bytes_transferred, Some(1917));
        assert!(jobs.completed(JOB, 6, None).is_some());
    }

    #[test]
    fn the_job_table_is_bounded_and_counts_what_it_forgets() {
        let mut jobs = BitsJobs::default();
        for i in 0..=MAX_TRACKED_JOBS {
            add(&mut jobs, &format!("{{job-{i}}}"), PAYLOAD_URL);
        }
        assert_eq!(jobs.jobs.len(), MAX_TRACKED_JOBS);
        assert_eq!(jobs.evicted(), 1);
        assert!(
            jobs.completed("{job-0}", 1, None).is_none(),
            "the oldest job goes first"
        );
        assert!(
            jobs.completed(&format!("{{job-{MAX_TRACKED_JOBS}}}"), 1, None)
                .is_some()
        );
    }
}
