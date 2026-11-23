// SPDX-License-Identifier: Apache-2.0
// Copyright (c) SuperiorSoft LLC
//! The short-lived SSH certificates the hosting API signs for the device key (SVC-6), cached per account and server.
use serde_json::Value;
use std::collections::HashMap;

/// One issued certificate and the connection facts that came with it. Never `Debug`: the certificate stays out of logs.
#[derive(Clone)]
pub struct Issued {
    pub certificate: String,
    /// Epoch milliseconds.
    pub valid_before: u64,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub host_key_fingerprint: Option<String>,
}

/// Reads `{certificate, validBefore, connection{host, port, user, hostKeyFingerprint}}`.
pub fn parse_issued(body: &Value) -> Result<Issued, String> {
    let s = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).map(str::trim).filter(|x| !x.is_empty()).map(String::from);
    let c = body.get("connection").cloned().unwrap_or(Value::Null);
    let missing = |what: &str| format!("unavailable: the hosting API answered no {what}");
    Ok(Issued {
        certificate: s(body, "certificate").ok_or_else(|| missing("certificate"))?,
        valid_before: body.get("validBefore").and_then(Value::as_u64).ok_or_else(|| missing("validBefore"))?,
        host: s(&c, "host").ok_or_else(|| missing("connection host"))?,
        port: c.get("port").and_then(Value::as_u64).and_then(|p| u16::try_from(p).ok()).filter(|p| *p > 0).ok_or_else(|| missing("connection port"))?,
        user: s(&c, "user").ok_or_else(|| missing("connection user"))?,
        host_key_fingerprint: s(&c, "hostKeyFingerprint"),
    })
}

/// Certificates by (account, server). A different account empties it; so does a sign-out.
#[derive(Default)]
pub struct CertCache {
    account: Option<String>,
    by_server: HashMap<String, Issued>,
}

impl CertCache {
    /// Tells the cache who is signed in; a different account drops every entry.
    pub fn set_account(&mut self, account: &str) {
        if self.account.as_deref() != Some(account) {
            self.by_server.clear();
            self.account = Some(account.to_string());
        }
    }
    /// Sign-out: drop everything.
    pub fn clear(&mut self) {
        self.by_server.clear();
        self.account = None;
    }
    /// The cached certificate while it stays valid for more than `margin_ms` after `now_ms`.
    pub fn get(&self, server: &str, now_ms: u64, margin_ms: u64) -> Option<Issued> {
        self.by_server.get(server).filter(|i| now_ms.saturating_add(margin_ms) < i.valid_before).cloned()
    }
    pub fn put(&mut self, server: &str, issued: Issued) {
        self.by_server.insert(server.to_string(), issued);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn issued(valid_before: u64) -> Issued {
        Issued { certificate: "cert".into(), valid_before, host: "h".into(), port: 22, user: "u".into(), host_key_fingerprint: None }
    }

    #[test]
    fn a_fresh_certificate_is_a_hit() {
        let mut c = CertCache::default();
        c.set_account("a@x");
        c.put("s1", issued(1_000_000));
        assert!(c.get("s1", 100, 60_000).is_some());
        assert!(c.get("s2", 100, 60_000).is_none());
    }
    #[test]
    fn it_expires_a_margin_before_valid_before() {
        let mut c = CertCache::default();
        c.set_account("a@x");
        c.put("s1", issued(1_000_000));
        assert!(c.get("s1", 939_999, 60_000).is_some());
        assert!(c.get("s1", 940_000, 60_000).is_none(), "exactly valid_before - margin is already too late");
        assert!(c.get("s1", 2_000_000, 60_000).is_none());
    }
    #[test]
    fn another_account_or_a_sign_out_drops_the_cache() {
        let mut c = CertCache::default();
        c.set_account("a@x");
        c.put("s1", issued(1_000_000));
        c.set_account("a@x");
        assert!(c.get("s1", 0, 0).is_some(), "the same account keeps it");
        c.set_account("b@x");
        assert!(c.get("s1", 0, 0).is_none());
        c.put("s1", issued(1_000_000));
        c.clear();
        assert!(c.get("s1", 0, 0).is_none());
    }
    #[test]
    fn the_answer_is_parsed_and_a_short_one_is_refused() {
        let ok = json!({"certificate": "ssh-ed25519-cert-v01@openssh.com AAAA", "validBefore": 5000, "connection": {"host": "1.2.3.4", "port": 2222, "user": "agent", "hostKeyFingerprint": "SHA256:x"}});
        let i = parse_issued(&ok).unwrap();
        assert_eq!((i.host.as_str(), i.port, i.user.as_str(), i.valid_before), ("1.2.3.4", 2222, "agent", 5000));
        assert_eq!(i.host_key_fingerprint.as_deref(), Some("SHA256:x"));
        assert!(parse_issued(&json!({"certificate": "c", "validBefore": 1})).err().unwrap().starts_with("unavailable:"));
    }
}
