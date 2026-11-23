// SPDX-License-Identifier: Apache-2.0
// Copyright (c) SuperiorSoft LLC
//! The host-key rule (SVC-6). The fingerprint the hosting API reported for the server wins; with none reported, the
//! first key the server shows is pinned in plugin storage and every later connection must show the same one. Any
//! mismatch is `host_key_mismatch`, and the connection ends before the certificate or the command is sent.

/// The fingerprint without its `SHA256:` label and base64 padding, so `SHA256:abc=` and `abc` compare equal.
pub fn norm(fp: &str) -> String {
    let t = fp.trim();
    let t = if t.len() >= 7 && t[..7].eq_ignore_ascii_case("sha256:") { &t[7..] } else { t };
    t.trim_end_matches('=').to_string()
}

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The key is the expected one.
    Accept,
    /// First use: accept and remember this (normalised) fingerprint.
    Pin(String),
    /// The key is not the expected one: end the connection.
    Mismatch,
}

/// `reported`: what the hosting API said. `pinned`: what plugin storage holds for this server. `presented`: the key the
/// server showed now.
pub fn judge(reported: Option<&str>, pinned: Option<&str>, presented: &str) -> Verdict {
    let presented = norm(presented);
    let reported = reported.map(norm).filter(|r| !r.is_empty());
    if let Some(r) = reported {
        return if r == presented { Verdict::Accept } else { Verdict::Mismatch };
    }
    match pinned.map(norm).filter(|p| !p.is_empty()) {
        Some(p) if p == presented => Verdict::Accept,
        Some(_) => Verdict::Mismatch,
        None => Verdict::Pin(presented),
    }
}

/// The plugin-storage key of a server's pinned fingerprint.
pub fn pin_key(server_id: &str) -> String {
    format!("sites.hostkey.{server_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reported_fingerprint_that_matches_is_accepted_even_with_a_stale_pin() {
        assert_eq!(judge(Some("SHA256:abc="), Some("old"), "abc"), Verdict::Accept);
    }
    #[test]
    fn a_reported_fingerprint_that_differs_is_a_mismatch_and_beats_a_matching_pin() {
        assert_eq!(judge(Some("SHA256:abc"), Some("zzz"), "zzz"), Verdict::Mismatch);
    }
    #[test]
    fn with_nothing_reported_the_first_key_is_pinned() {
        assert_eq!(judge(None, None, "SHA256:key1"), Verdict::Pin("key1".into()));
        assert_eq!(judge(Some("  "), None, "key1"), Verdict::Pin("key1".into()));
    }
    #[test]
    fn a_pinned_key_must_match_afterwards() {
        assert_eq!(judge(None, Some("key1"), "SHA256:key1"), Verdict::Accept);
        assert_eq!(judge(None, Some("key1"), "SHA256:key2"), Verdict::Mismatch);
    }
}
