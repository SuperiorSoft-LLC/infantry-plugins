// SPDX-License-Identifier: Apache-2.0
//! SITES-URL-1: the shipped module.json keeps the account URLs as {api}/{site} templates, and stage.sh renders them
//! for the build environment (a release sets INFANTRY_BUILD_ENV=prod). This proves the prod render, what a release
//! ships, carries no loopback URL, and that the template holds no hard-coded host.

use serde_json::Value;

fn manifest() -> (String, Value) {
    let text = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/module.json")).unwrap();
    let json: Value = serde_json::from_str(&text).unwrap();
    (text, json)
}

fn is_local(s: &str) -> bool {
    s.contains("localhost") || s.contains("127.0.0.1") || s.contains("0.0.0.0")
}

#[test]
fn account_urls_are_templates_not_hosts() {
    let (_, m) = manifest();
    let p = &m["account"]["providers"][0];
    for key in ["billingUrl", "signUpUrl", "accountUrl"] {
        let v = p[key].as_str().unwrap();
        assert!(v.starts_with("{site}") || v.starts_with("{api}"), "{key} = {v} must be a template");
    }
}

#[test]
fn prod_render_has_no_local_url() {
    let (text, m) = manifest();
    let ep = &m["daemon"]["endpoints"];
    let api = ep["api"]["prod"].as_str().unwrap().trim_end_matches('/');
    let site = ep["site"]["prod"].as_str().unwrap().trim_end_matches('/');
    assert!(api.starts_with("https://") && site.starts_with("https://"), "prod endpoints must be https");
    // Same render as stage.sh: replace the templates, then drop the dev/staging endpoint table, which a prod build
    // never reads.
    let rendered = text.replace("{api}", api).replace("{site}", site);
    let mut r: Value = serde_json::from_str(&rendered).unwrap();
    for k in ["api", "site"] {
        let t = r["daemon"]["endpoints"][k].as_object_mut().unwrap();
        t.retain(|env, _| env == "prod");
    }
    let out = r.to_string();
    assert!(!is_local(&out), "prod render carries a local URL");
    let p = &r["account"]["providers"][0];
    assert_eq!(p["signUpUrl"], format!("{site}/plans"));
    assert_eq!(p["billingUrl"], format!("{site}/account/billing"));
}
