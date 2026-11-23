// SPDX-License-Identifier: Apache-2.0
// Copyright (c) SuperiorSoft LLC
//! Infantry_Sites: a client of the WebServices hosting API, served as a plugin sidecar. No secret lives here: the
//! access token is asked from the daemon's account hub (`account_token`) for every call and never stored or logged.
pub mod sites;

use infantry_plugin_sdk::{export_plugin, host, types::{CallContext, Caller, Frame}, Plugin};
use serde_json::Value;
use sites::{Net, Sites};

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
}

pub struct SitesPlugin;

impl Plugin for SitesPlugin {
    fn call_tool(name: String, _args: String, _ctx: CallContext) -> Result<String, String> {
        match name.as_str() {
            "infantry_sites_list" => Sites::new(HostNet).servers().map(|v| v.to_string()),
            "infantry_sites_ssh_exec" | "infantry_sites_ssh_upload" => Err("unavailable: SSH is not in this build yet (SVC-5)".into()),
            other => Err(format!("unknown tool {other}")),
        }
    }

    fn handle_frame(frame: Frame, _caller: Caller) -> Result<Option<Frame>, String> {
        match frame.type_.as_str() {
            "sites_list" => Ok(Some(Frame { type_: "sites_list".into(), data: Sites::new(HostNet).list().to_string(), session_id: frame.session_id, request_id: frame.request_id })),
            "sites_ssh_exec" | "sites_ssh_upload" => Err("unavailable: SSH is not in this build yet (SVC-5)".into()),
            other => Err(format!("this plugin does not answer {other}")),
        }
    }
}

export_plugin!(SitesPlugin);
