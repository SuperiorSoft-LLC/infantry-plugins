// SPDX-License-Identifier: Apache-2.0
// Copyright (c) SuperiorSoft LLC
//! Infantry_Sites: a client of the WebServices hosting API, served as a plugin sidecar. No secret lives here: the
//! access token is asked from the daemon's account hub (`account_token`) for every call and never stored or logged.
pub mod cert;
pub mod hostkey;
pub mod sites;
pub mod ssh;

use infantry_plugin_sdk::{export_plugin, host, types::{CallContext, Caller, Frame}, Plugin};
use serde_json::Value;
use sites::{Net, Sites};
use ssh::{SharedCache, SshExec, Store};
use std::sync::{Arc, Mutex, OnceLock};

/// The real network: the daemon's frames and HTTP imports.
struct HostNet;

impl Net for HostNet {
    fn endpoint(&self, name: &str) -> Option<String> {
        host::config::endpoint(name).map(|u| u.trim_end_matches('/').to_string()).filter(|u| !u.is_empty())
    }
    fn frame(&self, kind: &str, data: Value) -> Result<Value, String> {
        let r = host::frames::request(kind, &data.to_string(), None, 15_000)?;
        serde_json::from_str(&r.data).map_err(|e| format!("{kind}: the daemon answered a non-JSON frame: {e}"))
    }
    fn get(&self, url: &str, bearer: &str) -> Result<(u16, Value), String> {
        let req = host::http::HttpRequest {
            method: "GET".into(),
            url: url.into(),
            headers: vec![("authorization".into(), format!("Bearer {bearer}")), ("accept".into(), "application/json".into())],
            body: None,
            timeout_ms: Some(15_000),
        };
        let r = host::http::send(&req)?;
        let v = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
        Ok((r.status, v))
    }
    fn post(&self, url: &str, bearer: &str, body: &Value) -> Result<(u16, Value), String> {
        let req = host::http::HttpRequest {
            method: "POST".into(),
            url: url.into(),
            headers: vec![
                ("authorization".into(), format!("Bearer {bearer}")),
                ("accept".into(), "application/json".into()),
                ("content-type".into(), "application/json".into()),
            ],
            body: Some(body.to_string().into_bytes()),
            timeout_ms: Some(15_000),
        };
        let r = host::http::send(&req)?;
        let v = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
        Ok((r.status, v))
    }
}

/// The plugin secret, plugin storage, settings and clock of the real host.
struct HostStore;

impl HostStore {
    /// The keystore name of this plugin's secret (`plugin.<module id, lowercase>`; the daemon pins reads to it).
    fn secret_name() -> String {
        format!("plugin.{}", host::config::module_id().to_lowercase())
    }
}

impl Store for HostStore {
    fn secret_get(&self, field: &str) -> Result<Option<String>, String> {
        let r = host::frames::request("plugin_secret_get", &serde_json::json!({ "field": field }).to_string(), None, 10_000)?;
        let v: Value = serde_json::from_str(&r.data).map_err(|_| "plugin_secret_get: the daemon answered a non-JSON frame".to_string())?;
        Ok(v.get("value").and_then(Value::as_str).map(String::from))
    }
    fn secret_set(&self, field: &str, value: &str) -> Result<(), String> {
        host::frames::request("secret_field_set", &serde_json::json!({ "name": Self::secret_name(), "field": field, "value": value }).to_string(), None, 10_000).map(|_| ())
    }
    fn kv_get(&self, key: &str) -> Option<String> {
        host::storage::kv_get(key).ok().flatten()
    }
    fn kv_set(&self, key: &str, value: &str) -> Result<(), String> {
        host::storage::kv_set(key, value)
    }
    fn setting(&self, key: &str) -> Option<String> {
        host::settings::get(key)
    }
    fn now_ms(&self) -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
    }
}

/// Certificates live for the life of the sidecar and are dropped on sign-out or an account change.
fn certs() -> SharedCache {
    static CACHE: OnceLock<SharedCache> = OnceLock::new();
    CACHE.get_or_init(|| Arc::new(Mutex::new(cert::CertCache::default()))).clone()
}

fn ssh_exec(args: &str) -> Result<String, String> {
    let req = ssh::parse_request(args)?;
    SshExec::new(HostNet, HostStore, certs()).exec(req).map(|v| v.to_string())
}

pub struct SitesPlugin;

impl Plugin for SitesPlugin {
    fn call_tool(name: String, args: String, ctx: CallContext) -> Result<String, String> {
        match name.as_str() {
            "infantry_sites_list" => Sites::new(HostNet).servers().map(|v| v.to_string()),
            // The owner and an agent session may run commands on the owner's servers; nobody else.
            "infantry_sites_ssh_exec" if !(ctx.caller.owner || ctx.caller.agent) => Err("not_allowed: only the owner or an agent session may run commands on a hosting server".into()),
            "infantry_sites_ssh_exec" => ssh_exec(&args),
            "infantry_sites_ssh_upload" => Err("unavailable: uploading a file over SSH is not in this build yet (SVC-7)".into()),
            other => Err(format!("unknown tool {other}")),
        }
    }

    fn handle_frame(frame: Frame, caller: Caller) -> Result<Option<Frame>, String> {
        match frame.type_.as_str() {
            "sites_list" => Ok(Some(Frame { type_: "sites_list".into(), data: Sites::new(HostNet).list().to_string(), session_id: frame.session_id, request_id: frame.request_id })),
            "sites_ssh_exec" if !caller.owner => Err("not_allowed: only the owner may run commands on a hosting server from the app".into()),
            "sites_ssh_exec" => ssh_exec(&frame.data).map(|data| Some(Frame { type_: "sites_ssh_exec".into(), data, session_id: frame.session_id, request_id: frame.request_id })),
            "sites_ssh_upload" => Err("unavailable: uploading a file over SSH is not in this build yet (SVC-7)".into()),
            other => Err(format!("this plugin does not answer {other}")),
        }
    }
}

export_plugin!(SitesPlugin);
