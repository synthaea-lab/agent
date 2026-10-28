//! Domain classes for EGRESS-DOMAIN (T1567, #380): which names are storage and paste
//! services, and which addresses a DNS answer names. The join with the volume a process
//! sends lives in `RuleState::check_egress_volume`; this module is the part that needs no
//! state.
//!
//! The class comes from the **name the process asked for**, never from the address it
//! connected to: a storage or paste service shares its addresses with every other site behind
//! the same CDN, so an address says nothing by itself. The join key is therefore the pid and
//! the address its own lookup returned.
//!
//! Not classified, on purpose: a webhook (`discord.com/api/webhooks`, T1567.004). Its name is
//! the host of the whole chat service, and only the URL path tells a webhook from a user, which
//! DNS never carries. The Sigma rule over command lines sees it.

use std::net::IpAddr;

/// A class of exfiltration destination, which decides the technique.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DomainClass {
    /// A cloud storage or file-sharing service: T1567.002.
    CloudStorage,
    /// A paste or text-sharing service: T1567.003.
    PasteService,
}

/// Named constants, not literals inside a `match`: `tools/attack-coverage.py` reads a
/// technique from a `technique` field or from a string constant of this shape.
const CLOUD_STORAGE_TECHNIQUE: &str = "T1567.002";
const PASTE_SERVICE_TECHNIQUE: &str = "T1567.003";

impl DomainClass {
    pub(crate) fn technique(self) -> &'static str {
        match self {
            Self::CloudStorage => CLOUD_STORAGE_TECHNIQUE,
            Self::PasteService => PASTE_SERVICE_TECHNIQUE,
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::CloudStorage => "cloud storage or file sharing",
            Self::PasteService => "paste or text sharing",
        }
    }
}

/// Registered names of storage and file-sharing services. A name matches itself and every
/// subdomain of it, on a label boundary (`notdropbox.com` is not `dropbox.com`).
///
/// Chosen for services whose purpose is to hold what a user hands them, so that sending
/// them tens of megabytes from a process that is not their client is the signal. Not
/// complete, and not meant to be: a name missing here is a miss, never a false alarm.
const CLOUD_STORAGE_DOMAINS: &[&str] = &[
    "drive.google.com",
    "storage.googleapis.com",
    "dropbox.com",
    "dropboxapi.com",
    "dropboxusercontent.com",
    "onedrive.live.com",
    "1drv.ms",
    "sharepoint.com",
    "blob.core.windows.net",
    "box.com",
    "mega.nz",
    "mega.io",
    "wetransfer.com",
    "transfer.sh",
    "file.io",
    "gofile.io",
    "anonfiles.com",
    "catbox.moe",
    "0x0.st",
    "temp.sh",
];

/// Registered names of paste and text-sharing services, matched like
/// [`CLOUD_STORAGE_DOMAINS`]. `gist.github.com` is left out: developers share gists all day, and
/// the rule has no way to tell one from an upload.
const PASTE_DOMAINS: &[&str] = &[
    "pastebin.com",
    "paste.ee",
    "hastebin.com",
    "rentry.co",
    "controlc.com",
    "dpaste.com",
    "dpaste.org",
    "ix.io",
    "termbin.com",
    "justpaste.it",
    "privatebin.net",
];

/// Whether `name` is `domain` or a subdomain of it.
fn is_under(name: &str, domain: &str) -> bool {
    name == domain
        || name
            .strip_suffix(domain)
            .is_some_and(|rest| rest.ends_with('.'))
}

/// Amazon S3 under any of its address shapes: `bucket.s3.amazonaws.com`,
/// `s3.<region>.amazonaws.com`, `s3-<region>.amazonaws.com`, `bucket.s3-accelerate.amazonaws.com`.
/// The label has to be exactly `s3` or start with `s3-`: `evil-s3.amazonaws.com` and
/// `ec2.amazonaws.com` are not storage.
fn is_s3(name: &str) -> bool {
    name.strip_suffix(".amazonaws.com")
        .is_some_and(|rest| rest.split('.').any(|l| l == "s3" || l.starts_with("s3-")))
}

/// The class of the name a process looked up, when it is one of the listed services.
pub(crate) fn classify_domain(name: &str) -> Option<DomainClass> {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    if PASTE_DOMAINS.iter().any(|d| is_under(&name, d)) {
        Some(DomainClass::PasteService)
    } else if is_s3(&name) || CLOUD_STORAGE_DOMAINS.iter().any(|d| is_under(&name, d)) {
        Some(DomainClass::CloudStorage)
    } else {
        None
    }
}

/// The addresses a DNS answer carries, in either shape the producers emit: a bare address
/// (the Linux `getaddrinfo` probe) or the Windows DNS-Client provider's `type:1 1.2.3.4;`
/// list, which also holds CNAME targets (`type:5 name;`) that are not addresses and are
/// skipped.
pub(crate) fn resolved_addresses(result: &str) -> Vec<IpAddr> {
    result
        .split(|c: char| c.is_whitespace() || c == ';' || c == ',')
        .filter_map(|token| token.parse().ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_listed_service_and_its_subdomains_are_classified() {
        for (name, class) in [
            ("pastebin.com", DomainClass::PasteService),
            ("www.pastebin.com", DomainClass::PasteService),
            ("PasteBin.COM.", DomainClass::PasteService),
            ("dropbox.com", DomainClass::CloudStorage),
            ("content.dropboxapi.com", DomainClass::CloudStorage),
            ("acme.sharepoint.com", DomainClass::CloudStorage),
            ("acct.blob.core.windows.net", DomainClass::CloudStorage),
            ("mega.nz", DomainClass::CloudStorage),
            ("transfer.sh", DomainClass::CloudStorage),
            ("bucket.s3.amazonaws.com", DomainClass::CloudStorage),
            ("s3.eu-west-1.amazonaws.com", DomainClass::CloudStorage),
            ("s3-us-west-2.amazonaws.com", DomainClass::CloudStorage),
            (
                "bucket.s3-accelerate.amazonaws.com",
                DomainClass::CloudStorage,
            ),
        ] {
            assert_eq!(classify_domain(name), Some(class), "{name}");
        }
    }

    #[test]
    fn a_lookalike_or_an_unrelated_name_is_not_classified() {
        for name in [
            "notdropbox.com",
            "pastebin.com.evil.test",
            "evilpastebin.com",
            "dropbox.com.cn.example",
            "evil-s3.amazonaws.com",
            "ec2.amazonaws.com",
            "amazonaws.com",
            "example.com",
            "github.com",
            "gist.github.com",
            "discord.com",
            "",
            ".",
        ] {
            assert_eq!(classify_domain(name), None, "{name}");
        }
    }

    #[test]
    fn a_bare_address_and_the_windows_answer_list_both_parse() {
        let v4: IpAddr = "104.20.67.143".parse().unwrap();
        let v6: IpAddr = "2606:4700::6814:438f".parse().unwrap();
        assert_eq!(resolved_addresses("104.20.67.143"), [v4]);
        assert_eq!(
            resolved_addresses(
                "type:5 cdn.example.net;type:1 104.20.67.143;type:28 2606:4700::6814:438f;"
            ),
            [v4, v6]
        );
    }

    #[test]
    fn text_that_is_not_an_address_yields_none() {
        for text in ["", ";", "type:5 cdn.example.net;", "not-an-ip", "999.1.1.1"] {
            assert!(resolved_addresses(text).is_empty(), "{text}");
        }
    }
}
