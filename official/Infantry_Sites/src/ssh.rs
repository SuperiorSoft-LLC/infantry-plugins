// SPDX-License-Identifier: Apache-2.0
// Copyright (c) SuperiorSoft LLC
//! `sites_ssh_exec` / `infantry_sites_ssh_exec` (SVC-6): run one command on the signed-in user's server.
//!
//! The device key is an ED25519 key made once and kept as the plugin secret `ssh_device_ed25519`; it never leaves the
//! plugin. The hosting API signs a short-lived certificate for its public half; russh (pure Rust, no OpenSSH on the
//! machine) logs in with it. The key, the certificate and the account token never reach an answer, an error or a log.
use crate::cert::{parse_issued, CertCache, Issued};
use crate::hostkey::{self, Verdict};
use crate::sites::{code_of, message_of, text, Net, Sites, PROVIDER};
use russh::client;
use russh::keys::{ssh_key::LineEnding, Algorithm, Certificate, HashAlg, PrivateKey, PublicKeyOrCertificate};
use russh::ChannelMsg;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// The plugin secret that holds the device key (OpenSSH format).
pub const SECRET_FIELD: &str = "ssh_device_ed25519";

/// Settings (module.json `daemon.config`); the defaults here repeat the manifest's.
pub const K_OUTPUT_BYTES: &str = "limits.sites.ssh.outputBytes";
pub const K_CONNECT_SEC: &str = "limits.sites.ssh.connectTimeoutSec";
pub const K_COMMAND_SEC: &str = "limits.sites.ssh.commandTimeoutSec";
pub const K_COMMAND_MAX_SEC: &str = "limits.sites.ssh.maxCommandTimeoutSec";
pub const K_CERT_MARGIN_SEC: &str = "limits.sites.ssh.certMarginSec";
pub const K_RETRY_SEC: &str = "limits.sites.ssh.retryAfterSec";
const DEFAULT_OUTPUT_BYTES: u64 = 65_536;
const DEFAULT_CONNECT_SEC: u64 = 15;
const DEFAULT_COMMAND_SEC: u64 = 60;
const DEFAULT_COMMAND_MAX_SEC: u64 = 600;
const DEFAULT_CERT_MARGIN_SEC: u64 = 60;
const DEFAULT_RETRY_SEC: u64 = 15;

/// What the SSH flow needs from the host besides the network: the plugin secret, plugin storage, settings, the clock.
pub trait Store {
    fn secret_get(&self, field: &str) -> Result<Option<String>, String>;
    fn secret_set(&self, field: &str, value: &str) -> Result<(), String>;
    fn kv_get(&self, key: &str) -> Option<String>;
    fn kv_set(&self, key: &str, value: &str) -> Result<(), String>;
    fn setting(&self, key: &str) -> Option<String>;
    fn now_ms(&self) -> u64;
}

#[derive(Clone, Copy)]
struct Limits {
    output_bytes: usize,
    connect: Duration,
    command: Duration,
    command_max: Duration,
    cert_margin_ms: u64,
    retry_sec: u64,
}

impl Limits {
    fn load<S: Store>(s: &S) -> Limits {
        let n = |k: &str, d: u64| s.setting(k).and_then(|v| v.trim().parse::<u64>().ok()).unwrap_or(d);
        Limits {
            output_bytes: n(K_OUTPUT_BYTES, DEFAULT_OUTPUT_BYTES).max(1) as usize,
            connect: Duration::from_secs(n(K_CONNECT_SEC, DEFAULT_CONNECT_SEC).max(1)),
            command: Duration::from_secs(n(K_COMMAND_SEC, DEFAULT_COMMAND_SEC).max(1)),
            command_max: Duration::from_secs(n(K_COMMAND_MAX_SEC, DEFAULT_COMMAND_MAX_SEC).max(1)),
            cert_margin_ms: n(K_CERT_MARGIN_SEC, DEFAULT_CERT_MARGIN_SEC) * 1000,
            retry_sec: n(K_RETRY_SEC, DEFAULT_RETRY_SEC),
        }
    }
}

#[derive(Debug)]
pub struct Request {
    pub server: Option<String>,
    pub command: String,
    pub timeout_sec: Option<u64>,
}

/// `{server?, command, timeoutSec?}`.
pub fn parse_request(args: &str) -> Result<Request, String> {
    let v: Value = if args.trim().is_empty() { json!({}) } else { serde_json::from_str(args).map_err(|_| "bad_request: the arguments are not JSON".to_string())? };
    let command = v.get("command").and_then(Value::as_str).map(str::to_string).filter(|c| !c.trim().is_empty()).ok_or("bad_request: command is required")?;
    Ok(Request {
        server: v.get("server").and_then(Value::as_str).map(str::trim).filter(|s| !s.is_empty()).map(String::from),
        command,
        timeout_sec: v.get("timeoutSec").and_then(Value::as_u64),
    })
}

/// A flow ends in an answer (also the non-error `setting_up`) or in a `"<kind>: <message>"` failure.
enum Out {
    Done(Value),
    Fail(String),
}
fn fail<T>(kind: &str, msg: &str) -> Result<T, Out> {
    Err(Out::Fail(format!("{kind}: {msg}")))
}
fn state_fail<T>(v: &Value) -> Result<T, Out> {
    fail(text(v, "state").unwrap_or("unavailable"), text(v, "message").unwrap_or("hosting is not available"))
}

/// The certificates, shared by every call of the plugin (the lock also serialises first-time key generation).
pub type SharedCache = Arc<Mutex<CertCache>>;

pub struct SshExec<N: Net, S: Store> {
    sites: Sites<N>,
    store: S,
    cache: SharedCache,
}

impl<N: Net, S: Store> SshExec<N, S> {
    pub fn new(net: N, store: S, cache: SharedCache) -> Self {
        SshExec { sites: Sites::new(net), store, cache }
    }

    /// The tool and frame answer: a JSON answer, or `"<kind>: <message>"`. Nothing secret survives into either.
    pub fn exec(&self, req: Request) -> Result<Value, String> {
        let mut secrets: Vec<String> = Vec::new();
        let r = self.run(&req, &mut secrets);
        let scrub = |s: String| secrets.iter().filter(|x| x.len() >= 8).fold(s, |s, x| s.replace(x.as_str(), "[removed]"));
        match r {
            Ok(v) | Err(Out::Done(v)) => serde_json::from_str(&scrub(v.to_string())).map_err(|_| "unavailable: the answer could not be read".to_string()),
            Err(Out::Fail(e)) => {
                if e.starts_with("signed_out:") {
                    self.cache.lock().unwrap().clear();
                }
                Err(scrub(e))
            }
        }
    }

    fn run(&self, req: &Request, secrets: &mut Vec<String>) -> Result<Value, Out> {
        let lim = Limits::load(&self.store);
        let Some(api) = self.sites.net().endpoint("api") else { return fail("not_configured", "This build names no hosting API endpoint.") };
        let listed = self.sites.list();
        if text(&listed, "state") != Some("ready") {
            return state_fail(&listed);
        }
        let servers: Vec<Value> = listed.get("servers").and_then(Value::as_array).cloned().unwrap_or_default();
        let server = pick_server(&servers, req.server.as_deref())?;
        let (id, name) = (text(&server, "id").unwrap_or_default().to_string(), text(&server, "name").unwrap_or("server").to_string());
        if id.is_empty() {
            return fail("unavailable", "the server list carried a server without an id");
        }
        let account = self.account_identity();

        // One lock for the cache and the device key: two first calls cannot make two keys.
        let (key, issued) = {
            let mut cache = self.cache.lock().unwrap();
            cache.set_account(&account);
            let key = self.device_key(secrets)?;
            match cache.get(&id, self.store.now_ms(), lim.cert_margin_ms) {
                Some(i) => (key, i),
                None => {
                    let pubkey = key.public_key().to_openssh().map_err(|_| Out::Fail("unavailable: the device key could not be encoded".into()))?;
                    let issued = self.issue(&api, &id, &pubkey, &lim, secrets)?;
                    cache.put(&id, issued.clone());
                    (key, issued)
                }
            }
        };
        secrets.push(issued.certificate.clone());

        let cert = Certificate::from_openssh(&issued.certificate).map_err(|_| Out::Fail("unavailable: the hosting API sent a certificate that could not be read".into()))?;
        let command_timeout = req.timeout_sec.map(|t| Duration::from_secs(t.max(1))).unwrap_or(lim.command).min(lim.command_max);
        let pin_key = hostkey::pin_key(&id);
        let target = Target { host: issued.host.clone(), port: issued.port, user: issued.user.clone(), reported: issued.host_key_fingerprint.clone(), pinned: self.store.kv_get(&pin_key) };
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|_| Out::Fail("unavailable: the SSH client could not start".into()))?;
        let (out, new_pin) = rt.block_on(connect_and_run(&target, Arc::new(key), cert, &req.command, command_timeout, &lim))?;
        if let Some(fp) = new_pin {
            // First use: the pin is kept for this server from now on (a failed save only means we pin again next time).
            let _ = self.store.kv_set(&pin_key, &fp);
        }
        Ok(json!({
            "server": name, "exitCode": out.exit_code, "stdout": out.stdout, "stderr": out.stderr,
            "truncated": out.truncated, "timedOut": out.timed_out,
        }))
    }

    /// Who is signed in (the account's email); a stable word when the hub does not say.
    fn account_identity(&self) -> String {
        match self.sites.net().frame("account_status", json!({ "provider": PROVIDER })) {
            Ok(v) => text(&v, "email").map(str::to_ascii_lowercase).unwrap_or_else(|| "account".into()),
            Err(_) => "account".into(),
        }
    }

    /// The device key: read from the plugin secret, or made now and saved.
    fn device_key(&self, secrets: &mut Vec<String>) -> Result<PrivateKey, Out> {
        let unreadable = || Out::Fail("unavailable: the stored SSH device key could not be read".into());
        match self.store.secret_get(SECRET_FIELD).map_err(|_| Out::Fail("unavailable: the plugin secret store did not answer".into()))? {
            Some(pem) if !pem.trim().is_empty() => {
                secrets.push(pem.trim().to_string());
                PrivateKey::from_openssh(pem.trim()).map_err(|_| unreadable())
            }
            _ => {
                let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).map_err(|_| Out::Fail("unavailable: an SSH device key could not be made".into()))?;
                let pem = key.to_openssh(LineEnding::LF).map_err(|_| unreadable())?;
                secrets.push(pem.trim().to_string());
                self.store.secret_set(SECRET_FIELD, &pem).map_err(|_| Out::Fail("unavailable: the SSH device key could not be saved in the plugin secret store".into()))?;
                Ok(key)
            }
        }
    }

    /// `POST /hosting/v1/servers/{id}/ssh/certificate`: the certificate, or the state to answer with.
    fn issue(&self, api: &str, id: &str, pubkey: &str, lim: &Limits, secrets: &mut Vec<String>) -> Result<Issued, Out> {
        let url = format!("{api}/hosting/v1/servers/{id}/ssh/certificate");
        let body = json!({ "publicKey": pubkey });
        let mut refreshed = false;
        loop {
            let token = self.sites.token().map_err(|v| state_fail::<()>(&v).unwrap_err())?;
            secrets.push(token.clone());
            let (status, reply) = self.sites.net().post(&url, &token, &body).map_err(|_| Out::Fail("unavailable: Hosting could not be reached. Try again in a moment.".into()))?;
            let code = code_of(&reply);
            return match status {
                200 => parse_issued(&reply).map_err(Out::Fail),
                401 if !refreshed => {
                    refreshed = true;
                    let _ = self.sites.net().frame("account_status", json!({ "provider": PROVIDER, "refresh": true }));
                    continue;
                }
                401 => fail("signed_out", "Your Infantry AI account session ended. Sign in again."),
                403 if code.contains("email") => fail("email_unverified", &message_of(&reply, "Verify your email to use hosting.")),
                403 => fail("not_entitled", &message_of(&reply, "Your plan does not include hosting.")),
                404 => fail("not_found", &message_of(&reply, "That server no longer exists.")),
                409 if code == "server_setting_up" => Err(Out::Done(json!({
                    "status": "setting_up",
                    "retryAfterSec": reply.get("retryAfterSec").and_then(Value::as_u64).unwrap_or(lim.retry_sec),
                    "message": message_of(&reply, "The server is still being set up. Try again shortly."),
                }))),
                409 if code == "not_running" => fail("not_running", &message_of(&reply, "The server is not running. Start it first.")),
                501 => fail("not_configured", "This hosting service is not set up."),
                503 if code == "not_configured" => fail("not_configured", &message_of(&reply, "This hosting service is not set up.")),
                _ => fail("unavailable", &message_of(&reply, "Hosting is not available right now.")),
            };
        }
    }
}

/// The server the call means: by id or name, or the only one.
fn pick_server(servers: &[Value], wanted: Option<&str>) -> Result<Value, Out> {
    let names = || if servers.is_empty() { "none".to_string() } else { servers.iter().filter_map(|s| text(s, "name")).collect::<Vec<_>>().join(", ") };
    match wanted {
        Some(w) => match servers.iter().find(|s| text(s, "id") == Some(w)).or_else(|| servers.iter().find(|s| text(s, "name").is_some_and(|n| n.eq_ignore_ascii_case(w)))) {
            Some(s) => Ok(s.clone()),
            None => fail("not_found", &format!("no server is named '{w}'. Your servers: {}", names())),
        },
        None => match servers {
            [] => fail("not_found", "you have no hosting servers yet"),
            [one] => Ok(one.clone()),
            _ => fail("bad_request", &format!("you have {} servers; name one in 'server'. Your servers: {}", servers.len(), names())),
        },
    }
}

struct Target {
    host: String,
    port: u16,
    user: String,
    reported: Option<String>,
    pinned: Option<String>,
}

struct Output {
    exit_code: Option<u32>,
    stdout: String,
    stderr: String,
    truncated: bool,
    timed_out: bool,
}

/// Applies the host-key rule while the key exchange runs; a refusal stops it before any authentication is sent.
struct Client {
    reported: Option<String>,
    pinned: Option<String>,
    seen: Arc<Mutex<Option<Verdict>>>,
}

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let PublicKeyOrCertificate::PublicKey { key, .. } = key else { return Ok(false) };
        let v = hostkey::judge(self.reported.as_deref(), self.pinned.as_deref(), &key.fingerprint(HashAlg::Sha256).to_string());
        let ok = !matches!(v, Verdict::Mismatch);
        *self.seen.lock().unwrap() = Some(v);
        Ok(ok)
    }
}

fn push_capped(buf: &mut Vec<u8>, data: &[u8], cap: usize, truncated: &mut bool) {
    let room = cap.saturating_sub(buf.len());
    if data.len() > room {
        *truncated = true;
    }
    buf.extend_from_slice(&data[..data.len().min(room)]);
}

async fn connect_and_run(t: &Target, key: Arc<PrivateKey>, cert: Certificate, command: &str, command_timeout: Duration, lim: &Limits) -> Result<(Output, Option<String>), Out> {
    let seen = Arc::new(Mutex::new(None));
    let handler = Client { reported: t.reported.clone(), pinned: t.pinned.clone(), seen: seen.clone() };
    // ED25519 host keys first.
    let mut keys = russh::Preferred::default().key.to_vec();
    keys.sort_by_key(|a| *a != Algorithm::Ed25519);
    let config = Arc::new(client::Config { preferred: russh::Preferred { key: keys.into(), ..Default::default() }, ..Default::default() });

    let login = async {
        let mut h = client::connect(config, (t.host.as_str(), t.port), handler).await?;
        let r = h.authenticate_openssh_cert(t.user.as_str(), key, cert).await?;
        Ok::<_, russh::Error>((h, r))
    };
    let mismatch = || matches!(*seen.lock().unwrap(), Some(Verdict::Mismatch));
    let (handle, auth) = match tokio::time::timeout(lim.connect, login).await {
        Err(_) => return fail("unavailable", "the server did not answer in time"),
        Ok(Err(_)) if mismatch() => {
            return fail("host_key_mismatch", "the server's SSH host key is not the one expected for it; nothing was sent. If the server was rebuilt, this is expected: remove it and create it again.")
        }
        Ok(Err(e)) => return fail("unavailable", &format!("the SSH connection failed ({})", short(&e))),
        Ok(Ok(x)) => x,
    };
    if !matches!(auth, russh::client::AuthResult::Success) {
        return fail("auth_failed", "the server refused the certificate");
    }
    let new_pin = match seen.lock().unwrap().take() {
        Some(Verdict::Pin(fp)) => Some(fp),
        _ => None,
    };

    let mut out = Output { exit_code: None, stdout: String::new(), stderr: String::new(), truncated: false, timed_out: false };
    let (mut so, mut se) = (Vec::new(), Vec::new());
    let mut ch = handle.channel_open_session().await.map_err(|e| Out::Fail(format!("unavailable: the SSH session could not open ({})", short(&e))))?;
    ch.exec(true, command.as_bytes().to_vec()).await.map_err(|e| Out::Fail(format!("unavailable: the command could not be sent ({})", short(&e))))?;
    let deadline = tokio::time::Instant::now() + command_timeout;
    loop {
        match tokio::time::timeout_at(deadline, ch.wait()).await {
            Err(_) => {
                out.timed_out = true;
                let _ = ch.close().await;
                break;
            }
            Ok(None) => break,
            Ok(Some(ChannelMsg::Data { data })) => push_capped(&mut so, &data, lim.output_bytes, &mut out.truncated),
            Ok(Some(ChannelMsg::ExtendedData { data, ext: 1 })) => push_capped(&mut se, &data, lim.output_bytes, &mut out.truncated),
            Ok(Some(ChannelMsg::ExitStatus { exit_status })) => out.exit_code = Some(exit_status),
            Ok(Some(ChannelMsg::Close)) => break,
            Ok(Some(_)) => {}
        }
    }
    out.stdout = String::from_utf8_lossy(&so).into_owned();
    out.stderr = String::from_utf8_lossy(&se).into_owned();
    let _ = handle.disconnect(russh::Disconnect::ByApplication, "", "en").await;
    Ok((out, new_pin))
}

/// A short, secret-free description of a russh error.
fn short(e: &russh::Error) -> String {
    e.to_string().chars().take(120).collect()
}

#[cfg(test)]
#[path = "ssh_tests.rs"]
mod tests;
