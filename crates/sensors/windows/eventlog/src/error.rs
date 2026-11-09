//! Why the polling transport could not read a channel.

/// A failed `EvtQuery` or `EvtNext`, with the Win32 error code it left.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum EventQueryError {
    /// The query was refused (Security without admin rights), named no channel, or was not
    /// valid `XPath`.
    #[error("EvtQuery on {channel} failed with Win32 error {code}")]
    Query { channel: String, code: u32 },
    /// Fetching the next batch of results failed for a reason other than the end of the set.
    #[error("EvtNext on {channel} failed with Win32 error {code}")]
    Next { channel: String, code: u32 },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The poll loop logs these as its `error` field: the wording is what operators grep for.
    #[test]
    fn messages_name_the_call_the_channel_and_the_code() {
        let query = EventQueryError::Query {
            channel: "Security".to_string(),
            code: 5,
        };
        assert_eq!(
            query.to_string(),
            "EvtQuery on Security failed with Win32 error 5"
        );
        let next = EventQueryError::Next {
            channel: "System".to_string(),
            code: 1460,
        };
        assert_eq!(
            next.to_string(),
            "EvtNext on System failed with Win32 error 1460"
        );
    }
}
