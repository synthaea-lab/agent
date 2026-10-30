//! Findings that wait for the executed image's code signature (#441).
//!
//! The rules run on the capture thread, and the signature does not exist there
//! yet: hashing and Authenticode verification run afterwards, on the agent's
//! enrichment worker, because a verification on the capture thread can stall it
//! long enough for the kernel to drop events (#126). A rule whose verdict depends
//! on the signature therefore returns a [`SignatureGatedAlert`] instead of an
//! [`Alert`], the agent hands it to that worker with the event, and the worker
//! calls [`SignatureGatedAlert::resolve`] once the verdict is known.
//!
//! The verdict describes the file at the image's path when the worker opens it,
//! not necessarily the image that ran. The worker verifies a gated exec without
//! its cache (a cached `Valid` could belong to a file the path used to hold), but
//! a running image can be renamed on Windows: a dropper that moves itself aside
//! and puts a signed copy at its old path before the worker gets there would pass
//! the gate. So the sensor records the image file's identity at exec time
//! (`ExecEvent::image_file_id`, #688) and the worker compares it with the file it
//! verified: when they are not the same file, or either is unknown, the alert is
//! marked [`SignatureGatedAlert::unconfirmed_image`] and resolves as not verified
//! whatever the verdict. A backlog on the worker still widens the window between
//! exec and the sensor's capture, but no longer between capture and verification.

use schema::Signature;

use crate::Alert;

const NOT_VERIFIED: &str = "signature not verified";
const IMAGE_NOT_CONFIRMED: &str = "signature not verified: file differs from the image that ran";

/// What the enrichment knows about the executed image's signature, and how far
/// its `Valid` can be trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageSignature {
    /// The verdict; `None` when enrichment did not run for this event (its
    /// queue was full, or the image could not be read).
    pub verdict: Option<Signature>,
    /// `Valid` means a certificate chain to a trusted root: Authenticode
    /// (Windows). Not macOS: there `Valid` also covers ad-hoc signatures, which
    /// the linker puts on every arm64 binary, attacker-built ones included.
    pub chain_verified: bool,
}

/// An [`Alert`] whose fate depends on the executed image's signature.
#[derive(Debug, Clone)]
pub struct SignatureGatedAlert {
    alert: Alert,
    /// The verified file is the image that ran (see the module doc). Starts true:
    /// platforms with no identity capture never downgrade.
    image_confirmed: bool,
}

impl SignatureGatedAlert {
    pub(crate) fn new(alert: Alert) -> Self {
        Self {
            alert,
            image_confirmed: true,
        }
    }

    /// Marks the verified file as not provably the image that ran: the verdict
    /// then cannot silence the alert.
    #[must_use]
    pub fn unconfirmed_image(mut self) -> Self {
        self.image_confirmed = false;
        self
    }

    /// The alert to raise once the signature is known: none for a valid,
    /// chain-verified signature; otherwise the alert, its message saying what
    /// the signature was. An image that could not be verified alerts: losing
    /// the verdict must not lose the finding.
    #[must_use]
    pub fn resolve(self, signature: ImageSignature) -> Option<Alert> {
        if !self.image_confirmed {
            return Some(self.tagged(IMAGE_NOT_CONFIRMED));
        }
        let state = match signature.verdict {
            Some(Signature::Valid) if signature.chain_verified => return None,
            Some(Signature::Valid) => "signed, chain not verified on this platform",
            Some(Signature::Invalid) => "signature invalid",
            Some(Signature::Unsigned) => "unsigned",
            Some(Signature::Unsupported) | None => NOT_VERIFIED,
        };
        Some(self.tagged(state))
    }

    /// The alert as if the signature were unknown, for a caller that cannot
    /// wait for it (the enrichment queue is full).
    #[must_use]
    pub fn unverified(self) -> Alert {
        self.tagged(NOT_VERIFIED)
    }

    fn tagged(self, state: &str) -> Alert {
        let mut alert = self.alert;
        alert.message = format!("{} [{state}]", alert.message);
        alert
    }
}
