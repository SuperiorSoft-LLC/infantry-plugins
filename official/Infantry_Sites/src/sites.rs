// SPDX-License-Identifier: Apache-2.0
// Copyright (c) SuperiorSoft LLC
//! The server list and its state map (a port of the legacy SitesService/SitesDaemonPlugin answer). The network is
//! behind [`Net`] so every state is unit-tested with a fake.
use serde_json::{json, Value};

/// The account provider this plugin consumes (module.json `account.providers[infantry]`).
pub const PROVIDER: &str = "infantry";

/// What the plugin needs from the host: endpoints, frames into the daemon, one authorised GET.
pub trait Net {
    /// The environment's endpoint (`api` or `site`), no trailing slash; None when the manifest names none.
    fn endpoint(&self, name: &str) -> Option<String>;
    /// A frame into the daemon (`account_token`, `account_status`): its JSON answer, or the refusal text.
    fn frame(&self, kind: &str, data: Value) -> Result<Value, String>;
    /// GET with a bearer token: (status, JSON body; Null when the body is not JSON).
    fn get(&self, url: &str, bearer: &str) -> Result<(u16, Value), String>;
    /// POST a JSON body with a bearer token: (status, JSON body; Null when the body is not JSON).
    fn post(&self, url: &str, bearer: &str, body: &Value) -> Result<(u16, Value), String>;
    /// GET that also reports a `Retry-After` header in seconds. Hosts that can read headers override it.
    fn get_ra(&self, url: &str, bearer: &str) -> Result<(u16, Value, Option<u64>), String> {
        self.get(url, bearer).map(|(s, b)| (s, b, None))
    }
    /// POST that also reports a `Retry-After` header in seconds.
    fn post_ra(&self, url: &str, bearer: &str, body: &Value) -> Result<(u16, Value, Option<u64>), String> {
        self.post(url, bearer, body).map(|(s, b)| (s, b, None))
    }
}

pub struct Sites<N: Net> {
    net: N,
}

pub(crate) fn state(s: &str, message: &str) -> Value {
    json!({ "state": s, "message": message })
}

pub(crate) fn text<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get(k).and_then(Value::as_str).filter(|s| !s.is_empty())
}

/// The error code a WebServices error body carries (`{error: "code"}`, `{error: {code}}` or `{code}`).
pub(crate) fn code_of(v: &Value) -> String {
    let e = v.get("error");
    e.and_then(Value::as_str).or_else(|| e.and_then(|e| e.get("code")).and_then(Value::as_str)).or_else(|| text(v, "code")).unwrap_or("").to_ascii_lowercase()
}

pub(crate) fn message_of(v: &Value, fallback: &str) -> String {
    let e = v.get("error");
    text(v, "message").or_else(|| e.and_then(|e| e.get("message")).and_then(Value::as_str)).unwrap_or(fallback).to_string()
}

/// Copies the plan fields a body carries onto an answer.
fn plan_fields(from: &Value, to: &mut Value, keys: &[&str]) {
    for k in keys {
        if let Some(x) = from.get(*k).filter(|x| !x.is_null()) {
            to[*k] = x.clone();
        }
    }
}

enum Got {
    Answer(Value),
    /// A 401: the token was refused.
    Refused,
}

impl<N: Net> Sites<N> {
    pub fn new(net: N) -> Self {
        Sites { net }
    }

    /// The `sites_list` frame answer: always a state, never an error.
    pub fn list(&self) -> Value {
        let Some(api) = self.net.endpoint("api") else {
            return state("not_configured", "This build names no hosting API endpoint.");
        };
        let mut out = self.fetch(&api).unwrap_or_else(|v| v);
        if let Some(site) = self.net.endpoint("site") {
            out["siteUrl"] = json!(format!("{site}/account/servers"));
            out["signUpUrl"] = json!(format!("{site}/plans"));
        }
        out
    }

    /// The `infantry_sites_list` tool: the server array, or `"<kind>: <message>"`.
    pub fn servers(&self) -> Result<Value, String> {
        let v = self.list();
        match v.get("state").and_then(Value::as_str) {
            Some("ready") => Ok(v.get("servers").cloned().unwrap_or(json!([]))),
            Some(k) => Err(format!("{k}: {}", text(&v, "message").unwrap_or("hosting is not available"))),
            None => Err("unavailable: no answer".into()),
        }
    }

    /// Ok / Err are both answers; Err is a failure state.
    fn fetch(&self, api: &str) -> Result<Value, Value> {
        let url = format!("{api}/hosting/v1/servers");
        if let Got::Answer(v) = self.try_get(&url)? {
            return Ok(v);
        }
        // A 401: the token may have been revoked or rotated. Ask the hub to refresh once, then try once more.
        let _ = self.net.frame("account_status", json!({ "provider": PROVIDER, "refresh": true }));
        match self.try_get(&url)? {
            Got::Answer(v) => Ok(v),
            Got::Refused => Err(state("signed_out", "Your Infantry AI account session ended. Sign in again.")),
        }
    }

    /// The network, for the SSH flow that shares this plugin's token and error mapping.
    pub(crate) fn net(&self) -> &N {
        &self.net
    }

    /// The account token from the hub, or the failure state to answer with.
    pub(crate) fn token(&self) -> Result<String, Value> {
        match self.net.frame("account_token", json!({ "provider": PROVIDER })) {
            Ok(v) => text(&v, "accessToken").map(String::from).ok_or_else(|| state("signed_out", "Sign in to Infantry AI Hosting.")),
            Err(e) => {
                let l = e.to_ascii_lowercase();
                Err(if l.contains("not signed in") {
                    state("signed_out", "Sign in to Infantry AI Hosting.")
                } else if l.contains("no account provider") || l.contains("consumer") {
                    state("not_configured", "Infantry AI Hosting is not set up on this install.")
                } else if l.contains("could not be reached") {
                    // The daemon's own reason ("Infantry AI Hosting could not be reached: ..."): the page shows it with Retry.
                    state("unavailable", e.trim())
                } else {
                    state("unavailable", "The account service did not answer. Try again in a moment.")
                })
            }
        }
    }

    fn try_get(&self, url: &str) -> Result<Got, Value> {
        let token = self.token()?;
        let (status, body, retry_after) = self.net.get_ra(url, &token).map_err(|_| state("unavailable", "Hosting could not be reached. Try again in a moment."))?;
        let code = code_of(&body);
        Ok(Got::Answer(match status {
            200 => {
                let list = if body.is_array() { body.clone() } else { body.get("servers").or_else(|| body.get("items")).cloned().unwrap_or(json!([])) };
                let servers: Vec<Value> = list.as_array().into_iter().flatten().map(server).collect();
                let mut v = json!({ "state": "ready", "servers": servers });
                plan_fields(&body, &mut v, &["limit", "planStatus", "reclaimableUntil"]);
                v
            }
            401 => return Ok(Got::Refused),
            403 if code.contains("email") => state("email_unverified", &message_of(&body, "Verify your email to use hosting.")),
            403 => {
                let mut v = state("not_entitled", &message_of(&body, "Your plan does not include hosting."));
                plan_fields(&body, &mut v, &["planStatus", "reclaimableUntil"]);
                v
            }
            409 if code == "scheduled_for_destroy" => state("bad_request", &message_of(&body, "this server is scheduled to be destroyed")),
            409 => {
                let mut v = state("limit", &message_of(&body, "You reached your server limit."));
                plan_fields(&body, &mut v, &["limit"]);
                v
            }
            404 => state("not_found", "no such server"),
            501 => state("not_configured", "This hosting service is not set up."),
            400 | 422 => state("bad_request", &message_of(&body, "the request was refused")),
            429 => state("unavailable", &match retry_after {
                Some(s) => format!("slow down: too many requests, try again in {s} s"),
                None => "slow down: too many requests, try again later".to_string(),
            }),
            502 => state("unavailable", "The hosting provider had a problem. Try again in a minute."),
            503 if code == "not_configured" => state("not_configured", &message_of(&body, "This hosting service is not set up.")),
            _ => state("unavailable", &message_of(&body, "Hosting is not available right now.")),
        }))
    }
}

/// The public fields of one server, absent ones as null (the panel and the tool read the same shape).
fn server(s: &Value) -> Value {
    let g = |k: &str| s.get(k).cloned().unwrap_or(Value::Null);
    json!({
        "id": g("id"), "name": g("name"), "status": g("status"), "sshReady": s.get("sshReady").and_then(Value::as_bool).unwrap_or(true),
        "ip": g("ip"), "region": g("region"), "size": g("size"), "createdAt": g("createdAt"), "destroyAt": g("destroyAt"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    #[derive(Default)]
    struct Fake {
        api: Option<&'static str>,
        token: Option<Result<Value, String>>,
        replies: RefCell<VecDeque<Result<(u16, Value), String>>>,
        calls: RefCell<Vec<String>>,
        retry_after: std::cell::Cell<Option<u64>>,
    }
    impl Net for &Fake {
        fn endpoint(&self, n: &str) -> Option<String> {
            match n {
                "api" => self.api.map(String::from),
                "site" => Some("https://site.test".into()),
                _ => None,
            }
        }
        fn frame(&self, kind: &str, _d: Value) -> Result<Value, String> {
            self.calls.borrow_mut().push(kind.into());
            if kind == "account_token" {
                self.token.clone().unwrap_or(Ok(json!({"accessToken": "tok"})))
            } else {
                Ok(json!({}))
            }
        }
        fn get(&self, url: &str, bearer: &str) -> Result<(u16, Value), String> {
            assert_eq!(url, "https://api.test/hosting/v1/servers");
            assert_eq!(bearer, "tok");
            self.replies.borrow_mut().pop_front().expect("a reply")
        }
        fn get_ra(&self, url: &str, bearer: &str) -> Result<(u16, Value, Option<u64>), String> {
            self.get(url, bearer).map(|(s, b)| (s, b, self.retry_after.get()))
        }
        fn post(&self, _url: &str, _bearer: &str, _body: &Value) -> Result<(u16, Value), String> {
            unreachable!("the list tests never post")
        }
    }
    fn fake(replies: Vec<Result<(u16, Value), String>>) -> Fake {
        Fake { api: Some("https://api.test"), replies: RefCell::new(replies.into()), ..Default::default() }
    }
    fn answer(f: &Fake) -> Value {
        Sites::new(f).list()
    }

    #[test]
    fn ready_lists_servers_with_links() {
        let f = fake(vec![Ok((200, json!({"servers": [{"id": "s1", "name": "a", "status": "active", "sshReady": true, "ip": "1.2.3.4", "region": "nyc", "size": "s", "createdAt": 1, "destroyAt": null, "secret": "x"}], "limit": 3, "planStatus": "active"})))]);
        let v = answer(&f);
        assert_eq!(v["state"], "ready");
        assert_eq!(v["servers"][0]["ip"], "1.2.3.4");
        assert_eq!(v["servers"][0]["sshReady"], true);
        assert!(v["servers"][0].get("secret").is_none());
        assert_eq!((v["limit"].clone(), v["planStatus"].clone()), (json!(3), json!("active")));
        assert_eq!(v["siteUrl"], "https://site.test/account/servers");
        assert_eq!(v["signUpUrl"], "https://site.test/plans");
    }
    #[test]
    fn a_bare_array_is_accepted_and_the_tool_returns_the_array() {
        let f = fake(vec![Ok((200, json!([{"id": "s1"}])))]);
        assert_eq!(Sites::new(&f).servers().unwrap()[0]["id"], "s1");
    }
    #[test]
    fn signed_out_without_a_token() {
        let mut f = fake(vec![]);
        f.token = Some(Err("not signed in to Infantry AI Hosting".into()));
        assert_eq!(answer(&f)["state"], "signed_out");
        assert!(Sites::new(&f).servers().unwrap_err().starts_with("signed_out:"));
    }
    #[test]
    fn a_401_retries_once_then_signed_out() {
        let f = fake(vec![Ok((401, Value::Null)), Ok((401, Value::Null))]);
        assert_eq!(answer(&f)["state"], "signed_out");
        assert_eq!(f.calls.borrow().iter().filter(|c| *c == "account_status").count(), 1);
    }
    #[test]
    fn a_401_then_a_good_answer_is_ready() {
        let f = fake(vec![Ok((401, Value::Null)), Ok((200, json!({"servers": []})))]);
        assert_eq!(answer(&f)["state"], "ready");
    }
    #[test]
    fn not_entitled_keeps_plan_fields() {
        let f = fake(vec![Ok((403, json!({"error": "not_entitled", "planStatus": "lapsed", "reclaimableUntil": 99})))]);
        let v = answer(&f);
        assert_eq!((v["state"].clone(), v["planStatus"].clone(), v["reclaimableUntil"].clone()), (json!("not_entitled"), json!("lapsed"), json!(99)));
    }
    #[test]
    fn email_unverified() {
        let f = fake(vec![Ok((403, json!({"error": {"code": "email_unverified", "message": "Verify first"}})))]);
        let v = answer(&f);
        assert_eq!((v["state"].clone(), v["message"].clone()), (json!("email_unverified"), json!("Verify first")));
    }
    #[test]
    fn limit_carries_the_limit() {
        let f = fake(vec![Ok((409, json!({"limit": 2})))]);
        let v = answer(&f);
        assert_eq!((v["state"].clone(), v["limit"].clone()), (json!("limit"), json!(2)));
    }
    #[test]
    fn not_configured_without_an_api_endpoint_and_on_503() {
        let mut f = fake(vec![]);
        f.api = None;
        assert_eq!(answer(&f)["state"], "not_configured");
        assert_eq!(answer(&fake(vec![Ok((503, json!({"error": "not_configured"})))]))["state"], "not_configured");
    }
    #[test]
    fn not_configured_when_the_hub_has_no_provider() {
        let mut f = fake(vec![]);
        f.token = Some(Err("no account provider 'infantry'".into()));
        assert_eq!(answer(&f)["state"], "not_configured");
    }
    #[test]
    fn an_unreachable_account_service_keeps_the_daemons_reason_not_signed_out() {
        let mut f = fake(vec![]);
        f.token = Some(Err("Infantry AI Hosting could not be reached: timed out".into()));
        let v = answer(&f);
        assert_eq!((v["state"].as_str(), v["message"].as_str()), (Some("unavailable"), Some("Infantry AI Hosting could not be reached: timed out")));
    }

    #[test]
    fn unavailable_on_a_network_error_and_on_500() {
        assert_eq!(answer(&fake(vec![Err("connection refused".into())]))["state"], "unavailable");
        assert_eq!(answer(&fake(vec![Ok((500, Value::Null))]))["state"], "unavailable");
    }
    #[test]
    fn b22_a_server_without_sshready_is_ready() {
        let f = fake(vec![Ok((200, json!({"servers": [{"id": "s1", "name": "a"}, {"id": "s2", "sshReady": false}]})))]);
        let v = answer(&f);
        assert_eq!((v["servers"][0]["sshReady"].clone(), v["servers"][1]["sshReady"].clone()), (json!(true), json!(false)));
    }
    #[test]
    fn b23_the_list_error_map_follows_the_kotlin_plugin() {
        let state_of = |status, body: Value, ra: Option<u64>| {
            let f = fake(vec![Ok((status, body))]);
            f.retry_after.set(ra);
            answer(&f)
        };
        assert_eq!(state_of(404, json!({}), None)["state"], "not_found");
        assert_eq!(state_of(400, json!({"message": "bad filter"}), None)["message"], "bad filter");
        assert_eq!(state_of(422, json!({}), None)["state"], "bad_request");
        assert_eq!(state_of(409, json!({"error": "scheduled_for_destroy", "message": "going away"}), None)["state"], "bad_request");
        assert_eq!(state_of(409, json!({"limit": 2}), None)["state"], "limit");
        assert_eq!(state_of(429, json!({}), Some(12))["message"], "slow down: too many requests, try again in 12 s");
        assert_eq!(state_of(429, json!({}), None)["message"], "slow down: too many requests, try again later");
        assert_eq!(state_of(502, json!({"message": "do not show"}), None)["message"], "The hosting provider had a problem. Try again in a minute.");
        assert_eq!(state_of(501, json!({}), None)["state"], "not_configured");
    }
    #[test]
    fn no_token_ever_appears_in_an_answer() {
        let f = fake(vec![Ok((500, json!({"message": "boom"})))]);
        assert!(!answer(&f).to_string().contains("tok"));
    }
}
