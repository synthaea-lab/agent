//! Substring scanning over one rendered `<Event>` block: the primitives every record parser
//! reads its fields with.

/// Splits a `wevtutil /f:xml` output into individual `<Event>...</Event>` blocks.
#[must_use]
pub fn split_event_blocks(xml: &str) -> Vec<&str> {
    let mut blocks = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find("<Event ") {
        let after_start = &rest[start..];
        match after_start.find("</Event>") {
            Some(end) => {
                let end_full = end + "</Event>".len();
                blocks.push(&after_start[..end_full]);
                rest = &after_start[end_full..];
            }
            None => break,
        }
    }
    blocks
}

/// Extracts the text strictly between the first occurrence of `start` and the next
/// occurrence of `end` after it.
#[must_use]
pub fn extract_between<'a>(block: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let from = block.find(start)? + start.len();
    let rest = &block[from..];
    let to = rest.find(end)?;
    Some(&rest[..to])
}

/// Unescapes the 5 standard XML entities. Needed for `TaskContent` (event 4698),
/// which is itself XML nested inside the enclosing `wevtutil` XML document, hence
/// escaped (`&lt;`/`&gt;`) there. Order is deliberate: `&amp;` last, so as not to
/// wrongly re-interpret a double-escaped `&amp;lt;` as `<` (not observed in
/// practice, but more correct to guard against).
#[must_use]
pub fn unescape_xml_entities(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// Text of a `<Data Name='{name}'>...</Data>` element, or `None` if the field is
/// absent, empty, or the literal `"-"` sentinel Windows uses for "not
/// applicable" (observed on `IpAddress` for local logons; guarded against here
/// so a missing field never round-trips as the literal string `"-"`).
pub(super) fn opt_data(block: &str, name: &str) -> Option<String> {
    extract_between(block, &format!("<Data Name='{name}'>"), "</Data>")
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "-")
        .map(str::to_string)
}

/// Reads an element's text without depending on whether the serializer added
/// attributes to its opening tag (for example, `EventID Qualifiers='16384'`).
/// Namespaces are ignored because Event Log's XML uses a default namespace.
pub(super) fn element_text<'a>(block: &'a str, name: &str) -> Option<&'a str> {
    let mut search_from = 0;
    while let Some(relative) = block.get(search_from..)?.find('<') {
        let start = search_from + relative + 1;
        let rest = block.get(start..)?;
        if rest.starts_with('/') || rest.starts_with('!') || rest.starts_with('?') {
            search_from = start + 1;
            continue;
        }
        let name_end = rest.find([' ', '\t', '\r', '\n', '/', '>'])?;
        if rest[..name_end]
            .rsplit(':')
            .next()?
            .eq_ignore_ascii_case(name)
        {
            let open_end = rest.find('>')?;
            let value_start = start + open_end + 1;
            let close = format!("</{}", &rest[..name_end]);
            let value_end = block.get(value_start..)?.find(&close)? + value_start;
            if block.get(value_end..)?.starts_with(&close) {
                return block.get(value_start..value_end);
            }
        }
        search_from = start + name_end + 1;
    }
    None
}

/// Reads a named event field in either `AppLocker`'s `<UserData>` shape or the
/// `EventData` `<Data Name='...'>value</Data>` shape. Field-name matching is
/// case-insensitive; the channel name is deliberately not consulted because
/// localized Event Viewer labels are not stable identifiers.
pub(super) fn event_field<'a>(block: &'a str, name: &str) -> Option<&'a str> {
    let mut search_from = 0;
    while let Some(relative) = block.get(search_from..)?.find('<') {
        let start = search_from + relative + 1;
        let rest = block.get(start..)?;
        if rest.starts_with('/') || rest.starts_with('!') || rest.starts_with('?') {
            search_from = start + 1;
            continue;
        }
        let name_end = rest.find([' ', '\t', '\r', '\n', '/', '>'])?;
        let element_name = rest[..name_end].rsplit(':').next()?;
        let open_end = rest.find('>')?;
        if element_name.eq_ignore_ascii_case("Data") {
            let open = &rest[..open_end];
            if attribute_value(open, "Name").is_some_and(|field| field.eq_ignore_ascii_case(name)) {
                let value_start = start + open_end + 1;
                let value_end = block.get(value_start..)?.find("</Data>")? + value_start;
                return block.get(value_start..value_end);
            }
        } else if element_name.eq_ignore_ascii_case(name) {
            let value_start = start + open_end + 1;
            let close = format!("</{}", &rest[..name_end]);
            let value_end = block.get(value_start..)?.find(&close)? + value_start;
            return block.get(value_start..value_end);
        }
        search_from = start + name_end + 1;
    }
    None
}

/// Finds an XML attribute by name without requiring a particular quote style.
pub(super) fn attribute_value<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    let bytes = text.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        while at < bytes.len() && !bytes[at].is_ascii_alphabetic() {
            at += 1;
        }
        let key_start = at;
        while at < bytes.len() && (bytes[at].is_ascii_alphanumeric() || bytes[at] == b'_') {
            at += 1;
        }
        if key_start == at {
            continue;
        }
        let key = text.get(key_start..at)?;
        while at < bytes.len() && bytes[at].is_ascii_whitespace() {
            at += 1;
        }
        if at >= bytes.len() || bytes[at] != b'=' {
            continue;
        }
        at += 1;
        while at < bytes.len() && bytes[at].is_ascii_whitespace() {
            at += 1;
        }
        if at >= bytes.len() || (bytes[at] != b'\'' && bytes[at] != b'"') {
            continue;
        }
        let quote = bytes[at];
        at += 1;
        let value_start = at;
        while at < bytes.len() && bytes[at] != quote {
            at += 1;
        }
        if key.eq_ignore_ascii_case(name) {
            return text.get(value_start..at);
        }
        at += usize::from(at < bytes.len());
    }
    None
}

/// `<Data Name='name'>value</Data>` of an `<EventData>` block: trimmed, XML
/// entities unescaped, `None` when absent or empty. The Defender and
/// `CodeIntegrity` field names contain spaces (`Threat Name`, `File Name`).
pub(super) fn data_field(block: &str, name: &str) -> Option<String> {
    let marker = format!("<Data Name='{name}'>");
    extract_between(block, &marker, "</Data>")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(unescape_xml_entities)
}

pub(super) fn data_u32(block: &str, name: &str) -> Option<u32> {
    data_field(block, name)?.parse().ok()
}

/// `<tag>value</tag>` inside the event's `<UserData>`: trimmed, entities
/// unescaped, `None` when absent or empty.
pub(super) fn user_data_field(block: &str, tag: &str) -> Option<String> {
    let user_data = extract_between(block, "<UserData>", "</UserData>")?;
    extract_between(user_data, &format!("<{tag}>"), &format!("</{tag}>"))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(unescape_xml_entities)
}

/// `EventRecordID`, `EventID` and `<Execution ProcessID>` of a block. `None`
/// without a record id; a missing event id or pid reads as 0.
pub(super) fn system_header(block: &str) -> Option<(u64, u32, u32)> {
    let record_id = extract_between(block, "<EventRecordID>", "</EventRecordID>")?
        .parse()
        .ok()?;
    let event_id = extract_between(block, "<EventID>", "</EventID>")
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0);
    let pid = extract_between(block, "ProcessID='", "'")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    Some((record_id, event_id, pid))
}

/// The header's `<Security UserID='...'/>`, in either quote style.
pub(super) fn security_user_id(block: &str) -> Option<String> {
    let header = extract_between(block, "<System>", "</System>")?;
    extract_between(header, "<Security UserID='", "'")
        .or_else(|| extract_between(header, "<Security UserID=\"", "\""))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(unescape_xml_entities)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xml::fixtures::{SCHEDULED_TASK_XML, SERVICE_INSTALL_XML};

    #[test]
    fn splits_a_single_event_block() {
        let blocks = split_event_blocks(SERVICE_INSTALL_XML);
        assert_eq!(blocks.len(), 1);
        assert!(blocks[0].starts_with("<Event "));
        assert!(blocks[0].ends_with("</Event>"));
    }

    #[test]
    fn splits_multiple_concatenated_event_blocks() {
        let doc = format!("{SERVICE_INSTALL_XML}{SCHEDULED_TASK_XML}");
        let blocks = split_event_blocks(&doc);
        assert_eq!(blocks.len(), 2);
    }

    #[test]
    fn no_event_blocks_in_empty_or_unrelated_input() {
        assert!(split_event_blocks("").is_empty());
        assert!(split_event_blocks("<NoEventsHere/>").is_empty());
    }

    #[test]
    fn extracts_between_markers() {
        assert_eq!(
            extract_between("<a>value</a>", "<a>", "</a>"),
            Some("value")
        );
        assert_eq!(extract_between("<a>value</a>", "<b>", "</b>"), None);
    }

    #[test]
    fn unescapes_the_five_standard_entities() {
        assert_eq!(unescape_xml_entities("a &lt;b&gt; c"), "a <b> c");
        assert_eq!(
            unescape_xml_entities("&quot;q&quot; &apos;a&apos;"),
            "\"q\" 'a'"
        );
        assert_eq!(unescape_xml_entities("R&amp;D"), "R&D");
        // &amp; last: a literal "&amp;lt;" in the source must not become "<".
        assert_eq!(unescape_xml_entities("&amp;lt;"), "&lt;");
    }

    #[test]
    fn element_text_ignores_attributes_namespace_prefix_and_case() {
        let block = "<e:EventID Qualifiers='16384'>7045</e:EventID>";
        assert_eq!(element_text(block, "EventID"), Some("7045"));
        assert_eq!(element_text(block, "eventid"), Some("7045"));
    }

    #[test]
    fn element_text_skips_closing_tags_and_longer_names() {
        let block = "</System><EventIDX>1</EventIDX><EventID>2</EventID>";
        assert_eq!(element_text(block, "EventID"), Some("2"));
    }

    #[test]
    fn element_text_is_none_for_an_unclosed_or_absent_element() {
        assert_eq!(element_text("<EventID>5", "EventID"), None);
        assert_eq!(element_text("<Other>5</Other>", "EventID"), None);
    }

    #[test]
    fn event_field_reads_both_the_data_name_and_the_plain_element_shapes() {
        let data = "<EventData><Data Name=\"FilePath\">a</Data></EventData>";
        let plain = "<UserData><R><FilePath>b</FilePath></R></UserData>";
        assert_eq!(event_field(data, "filepath"), Some("a"));
        assert_eq!(event_field(plain, "FILEPATH"), Some("b"));
    }

    #[test]
    fn event_field_does_not_mistake_a_longer_element_name() {
        let block = "<FullFilePath>x</FullFilePath><FilePath>y</FilePath>";
        assert_eq!(event_field(block, "FilePath"), Some("y"));
        assert_eq!(event_field(block, "Missing"), None);
    }

    #[test]
    fn attribute_value_accepts_both_quote_styles_and_spaces_around_equals() {
        let tag = "Execution ProcessID='4' ThreadID=\"8\" Name = 'x'";
        assert_eq!(attribute_value(tag, "ProcessID"), Some("4"));
        assert_eq!(attribute_value(tag, "threadid"), Some("8"));
        assert_eq!(attribute_value(tag, "Name"), Some("x"));
        assert_eq!(attribute_value(tag, "Missing"), None);
    }

    #[test]
    fn attribute_value_skips_an_unquoted_value() {
        let tag = "a=1 b='2'";
        assert_eq!(attribute_value(tag, "a"), None);
        assert_eq!(attribute_value(tag, "b"), Some("2"));
    }

    #[test]
    fn data_field_trims_unescapes_and_drops_empty_values() {
        let block = "<Data Name='Threat Name'> A&amp;B </Data><Data Name='Path'>  </Data>";
        assert_eq!(data_field(block, "Threat Name").as_deref(), Some("A&B"));
        assert_eq!(data_field(block, "Path"), None);
        assert_eq!(data_u32("<Data Name='N'>x</Data>", "N"), None);
        assert_eq!(data_u32("<Data Name='N'> 7 </Data>", "N"), Some(7));
    }

    #[test]
    fn opt_data_drops_the_dash_sentinel_and_keeps_entities_escaped() {
        let block = "<Data Name='IpAddress'>-</Data><Data Name='User'> a&amp;b </Data>";
        assert_eq!(opt_data(block, "IpAddress"), None);
        assert_eq!(opt_data(block, "User").as_deref(), Some("a&amp;b"));
    }

    #[test]
    fn user_data_field_unescapes_and_reads_only_inside_user_data() {
        let block = "<System><User>outside</User></System><UserData><X><User> a&lt;b </User></X></UserData>";
        assert_eq!(user_data_field(block, "User").as_deref(), Some("a<b"));
        assert_eq!(user_data_field("<User>x</User>", "User"), None);
    }

    #[test]
    fn system_header_defaults_a_missing_event_id_and_pid_to_zero() {
        let full =
            "<EventID> 21 </EventID><EventRecordID>9</EventRecordID><Execution ProcessID='5'/>";
        assert_eq!(system_header(full), Some((9, 21, 5)));
        assert_eq!(
            system_header("<EventRecordID>9</EventRecordID>"),
            Some((9, 0, 0))
        );
        assert_eq!(system_header("<EventID>21</EventID>"), None);
    }

    #[test]
    fn security_user_id_reads_the_header_in_either_quote_style() {
        let single = "<System><Security UserID='S-1-5-18'/></System>";
        let double = "<System><Security UserID=\"S-1-5-20\"/></System>";
        let outside = "<System></System><Security UserID='S-1-5-18'/>";
        assert_eq!(security_user_id(single).as_deref(), Some("S-1-5-18"));
        assert_eq!(security_user_id(double).as_deref(), Some("S-1-5-20"));
        assert_eq!(security_user_id(outside), None);
    }
}
