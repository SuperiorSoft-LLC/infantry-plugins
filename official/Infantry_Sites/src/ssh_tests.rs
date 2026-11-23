// SPDX-License-Identifier: Apache-2.0
// Copyright (c) SuperiorSoft LLC
//! Tests of the SSH exec flow against an in-process russh server that trusts a test CA (port 0, no real server).
use super::*;
use russh::keys::ssh_key::certificate::{Builder, CertType};
use russh::keys::ssh_key::Fingerprint;
use russh::keys::PublicKey;
use russh::server::{self, Auth, Msg, Session};
use russh::{Channel, ChannelId};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

const TOKEN: &str = "tok-secret-0123456789";
const USER: &str = "agent";

fn real_now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64
}

// ---- an in-process SSH server that trusts one CA --------------------------------------------------------------

struct Seen {
    commands: Mutex<Vec<String>>,
    auth_attempts: AtomicUsize,
}

#[derive(Clone)]
struct Handler {
    ca: Fingerprint,
    seen: Arc<Seen>,
}

impl server::Server for Handler {
    type Handler = Handler;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Handler {
        self.clone()
    }
}

impl server::Handler for Handler {
    type Error = russh::Error;

    async fn channel_open_session(&mut self, _c: Channel<Msg>, reply: server::ChannelOpenHandle, _s: &mut Session) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }
    async fn auth_openssh_certificate(&mut self, user: &str, cert: &Certificate) -> Result<Auth, Self::Error> {
        self.seen.auth_attempts.fetch_add(1, Ordering::SeqCst);
        let now = real_now_ms() / 1000;
        let ok = cert.validate_at(now, &[self.ca]).is_ok() && cert.valid_principals().iter().any(|p| p == user);
        Ok(if ok { Auth::Accept } else { Auth::reject() })
    }
    async fn exec_request(&mut self, ch: ChannelId, data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        let cmd = String::from_utf8_lossy(data).to_string();
        self.seen.commands.lock().unwrap().push(cmd.clone());
        session.channel_success(ch)?;
        match cmd.as_str() {
            "hello" => {
                session.data(ch, b"out\n".to_vec())?;
                session.extended_data(ch, 1, b"err\n".to_vec())?;
                session.exit_status_request(ch, 7)?;
            }
            "flood" => {
                session.data(ch, vec![b'x'; 5000])?;
                session.exit_status_request(ch, 0)?;
            }
            "hang" => return Ok(()),
            _ => session.exit_status_request(ch, 127)?,
        }
        session.eof(ch)?;
        session.close(ch)?;
        Ok(())
    }
}

struct TestServer {
    port: u16,
    host_fp: String,
    seen: Arc<Seen>,
}

/// Starts the server on port 0 in its own thread; it trusts `ca` and shows `host_key`.
fn start_server(ca: &PrivateKey, host_key: PrivateKey) -> TestServer {
    let seen = Arc::new(Seen { commands: Mutex::new(vec![]), auth_attempts: AtomicUsize::new(0) });
    let host_fp = host_key.public_key().fingerprint(HashAlg::Sha256).to_string();
    let handler = Handler { ca: ca.public_key().fingerprint(HashAlg::Sha256), seen: seen.clone() };
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            tx.send(listener.local_addr().unwrap().port()).unwrap();
            let config = Arc::new(server::Config {
                keys: vec![host_key],
                auth_rejection_time: Duration::from_millis(1),
                auth_rejection_time_initial: Some(Duration::from_millis(1)),
                ..Default::default()
            });
            loop {
                let Ok((sock, _)) = listener.accept().await else { return };
                let (cfg, h) = (config.clone(), handler.clone());
                tokio::spawn(async move {
                    if let Ok(s) = server::run_stream(cfg, sock, h).await {
                        let _ = s.await;
                    }
                });
            }
        });
    });
    TestServer { port: rx.recv().unwrap(), host_fp, seen }
}

fn new_key() -> PrivateKey {
    PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap()
}

// ---- the fake host: network, store ----------------------------------------------------------------------------

struct FakeNet {
    port: u16,
    /// Signs the certificates (the API's CA).
    signer: PrivateKey,
    /// The fingerprint the API reports (None: reports none).
    reported: RefCell<Option<String>>,
    valid_after_off: i64,
    valid_before_off: i64,
    servers: RefCell<Vec<Value>>,
    email: RefCell<String>,
    /// When set, the certificate endpoint answers this instead.
    cert_reply: RefCell<Option<(u16, Value)>>,
    signed_out: Cell<bool>,
    posts: Cell<usize>,
    posted_keys: RefCell<Vec<String>>,
    issued_certs: RefCell<Vec<String>>,
}

impl FakeNet {
    fn new(port: u16, signer: PrivateKey) -> FakeNet {
        FakeNet {
            port,
            signer,
            reported: RefCell::new(None),
            valid_after_off: -60,
            valid_before_off: 3600,
            servers: RefCell::new(vec![json!({"id": "s1", "name": "web", "status": "active", "sshReady": true})]),
            email: RefCell::new("owner@example.test".into()),
            cert_reply: RefCell::new(None),
            signed_out: Cell::new(false),
            posts: Cell::new(0),
            posted_keys: RefCell::new(vec![]),
            issued_certs: RefCell::new(vec![]),
        }
    }
}

impl Net for &FakeNet {
    fn endpoint(&self, n: &str) -> Option<String> {
        (n == "api").then(|| "https://api.test".to_string())
    }
    fn frame(&self, kind: &str, _d: Value) -> Result<Value, String> {
        match kind {
            "account_token" if self.signed_out.get() => Err("not signed in to Infantry AI Hosting".into()),
            "account_token" => Ok(json!({ "accessToken": TOKEN })),
            "account_status" => Ok(json!({ "email": *self.email.borrow() })),
            _ => Ok(json!({})),
        }
    }
    fn get(&self, _url: &str, _b: &str) -> Result<(u16, Value), String> {
        Ok((200, json!({ "servers": *self.servers.borrow() })))
    }
    fn post(&self, url: &str, bearer: &str, body: &Value) -> Result<(u16, Value), String> {
        assert_eq!(bearer, TOKEN);
        assert!(url.starts_with("https://api.test/hosting/v1/servers/") && url.ends_with("/ssh/certificate"), "{url}");
        self.posts.set(self.posts.get() + 1);
        if let Some(r) = self.cert_reply.borrow().clone() {
            return Ok(r);
        }
        let pk = body["publicKey"].as_str().unwrap();
        self.posted_keys.borrow_mut().push(pk.to_string());
        let subject = PublicKey::from_openssh(pk).unwrap();
        let now = (real_now_ms() / 1000) as i64;
        let (after, before) = ((now + self.valid_after_off) as u64, (now + self.valid_before_off) as u64);
        let mut b = Builder::new_with_random_nonce(&mut rand::rng(), subject.key_data().clone(), after, before).unwrap();
        b.key_id("test").unwrap();
        b.cert_type(CertType::User).unwrap();
        b.valid_principal(USER).unwrap();
        let cert = b.sign(&self.signer).unwrap().to_openssh().unwrap();
        self.issued_certs.borrow_mut().push(cert.clone());
        let mut conn = json!({"host": "127.0.0.1", "port": self.port, "user": USER});
        if let Some(fp) = self.reported.borrow().clone() {
            conn["hostKeyFingerprint"] = json!(fp);
        }
        Ok((200, json!({"certificate": cert, "validBefore": before * 1000, "connection": conn})))
    }
}

#[derive(Default)]
struct FakeStore {
    secrets: RefCell<HashMap<String, String>>,
    kv: RefCell<HashMap<String, String>>,
    settings: RefCell<HashMap<String, String>>,
    now_offset_ms: Cell<u64>,
    secret_writes: Cell<usize>,
}

impl Store for &FakeStore {
    fn secret_get(&self, f: &str) -> Result<Option<String>, String> {
        Ok(self.secrets.borrow().get(f).cloned())
    }
    fn secret_set(&self, f: &str, v: &str) -> Result<(), String> {
        self.secret_writes.set(self.secret_writes.get() + 1);
        self.secrets.borrow_mut().insert(f.into(), v.into());
        Ok(())
    }
    fn kv_get(&self, k: &str) -> Option<String> {
        self.kv.borrow().get(k).cloned()
    }
    fn kv_set(&self, k: &str, v: &str) -> Result<(), String> {
        self.kv.borrow_mut().insert(k.into(), v.into());
        Ok(())
    }
    fn setting(&self, k: &str) -> Option<String> {
        self.settings.borrow().get(k).cloned()
    }
    fn now_ms(&self) -> u64 {
        real_now_ms() + self.now_offset_ms.get()
    }
}

fn req(cmd: &str) -> Request {
    Request { server: None, command: cmd.into(), timeout_sec: None }
}
fn named(server: &str, cmd: &str) -> Request {
    Request { server: Some(server.into()), command: cmd.into(), timeout_sec: None }
}
fn exec(net: &FakeNet, store: &FakeStore, cache: &SharedCache, r: Request) -> Result<Value, String> {
    SshExec::new(net, store, cache.clone()).exec(r)
}
fn cache() -> SharedCache {
    Arc::new(Mutex::new(CertCache::default()))
}
/// A world: a server trusting CA `ca`, an API that signs with the CA (or with a stranger when `signer_is_ca` is false).
fn world(signer_is_ca: bool) -> (TestServer, FakeNet) {
    let ca = new_key();
    let srv = start_server(&ca, new_key());
    let net = FakeNet::new(srv.port, if signer_is_ca { ca } else { new_key() });
    (srv, net)
}

// ---- behaviour ------------------------------------------------------------------------------------------------

#[test]
fn a_valid_certificate_runs_a_command_and_returns_stdout_stderr_and_exit_code() {
    let (srv, net) = world(true);
    let v = exec(&net, &FakeStore::default(), &cache(), req("hello")).unwrap();
    assert_eq!((v["stdout"].as_str(), v["stderr"].as_str(), v["exitCode"].as_u64()), (Some("out\n"), Some("err\n"), Some(7)));
    assert_eq!((v["server"].as_str(), v["truncated"].as_bool(), v["timedOut"].as_bool()), (Some("web"), Some(false), Some(false)));
    assert_eq!(*srv.seen.commands.lock().unwrap(), vec!["hello".to_string()]);
}

#[test]
fn the_device_key_is_made_once_and_the_same_public_key_is_sent_each_time() {
    let (_srv, net) = world(true);
    let store = FakeStore::default();
    let c = cache();
    exec(&net, &store, &c, req("hello")).unwrap();
    *net.email.borrow_mut() = "other@example.test".into(); // forces a second certificate
    exec(&net, &store, &c, req("hello")).unwrap();
    assert_eq!(store.secret_writes.get(), 1, "one key was made");
    let keys = net.posted_keys.borrow();
    assert_eq!(keys.len(), 2);
    assert_eq!(keys[0], keys[1]);
    assert!(keys[0].starts_with("ssh-ed25519 "));
}

#[test]
fn a_cached_certificate_is_reused_until_the_margin_before_it_ends() {
    let (_srv, net) = world(true);
    let store = FakeStore::default();
    let c = cache();
    exec(&net, &store, &c, req("hello")).unwrap();
    exec(&net, &store, &c, req("hello")).unwrap();
    assert_eq!(net.posts.get(), 1, "second call is a cache hit");
    // The certificate lives 3600 s and the margin is 60 s: at +3530 s it is still used, at +3545 s it is not.
    store.now_offset_ms.set(3_530_000);
    exec(&net, &store, &c, req("hello")).unwrap();
    assert_eq!(net.posts.get(), 1, "still before the margin");
    store.now_offset_ms.set(3_545_000);
    exec(&net, &store, &c, req("hello")).unwrap();
    assert_eq!(net.posts.get(), 2, "inside the margin: a new certificate");
}

#[test]
fn another_account_drops_the_cache_and_a_sign_out_too() {
    let (_srv, net) = world(true);
    let store = FakeStore::default();
    let c = cache();
    exec(&net, &store, &c, req("hello")).unwrap();
    *net.email.borrow_mut() = "someone-else@example.test".into();
    exec(&net, &store, &c, req("hello")).unwrap();
    assert_eq!(net.posts.get(), 2, "a different account asks again");
    // A sign-out empties the cache: signing back in as the same account still needs a new certificate.
    net.signed_out.set(true);
    assert!(exec(&net, &store, &c, req("hello")).unwrap_err().starts_with("signed_out:"));
    net.signed_out.set(false);
    let before = net.posts.get();
    exec(&net, &store, &c, req("hello")).unwrap();
    assert_eq!(net.posts.get(), before + 1, "nothing was kept");
}

#[test]
fn an_expired_certificate_is_refused() {
    let (srv, mut net) = world(true);
    net.valid_after_off = -7200;
    net.valid_before_off = -3600;
    let e = exec(&net, &FakeStore::default(), &cache(), req("hello")).unwrap_err();
    assert!(e.starts_with("auth_failed:"), "{e}");
    assert!(srv.seen.commands.lock().unwrap().is_empty());
}

#[test]
fn a_certificate_from_the_wrong_ca_is_refused() {
    let (srv, net) = world(false);
    let e = exec(&net, &FakeStore::default(), &cache(), req("hello")).unwrap_err();
    assert!(e.starts_with("auth_failed:"), "{e}");
    assert!(srv.seen.commands.lock().unwrap().is_empty());
}

#[test]
fn output_is_capped_by_the_setting_and_flagged() {
    let (_srv, net) = world(true);
    let store = FakeStore::default();
    store.settings.borrow_mut().insert(K_OUTPUT_BYTES.into(), "100".into());
    let v = exec(&net, &store, &cache(), req("flood")).unwrap();
    assert_eq!(v["stdout"].as_str().unwrap().len(), 100);
    assert_eq!(v["truncated"], true);
}

#[test]
fn a_command_that_runs_too_long_times_out_and_says_so() {
    let (_srv, net) = world(true);
    let t = std::time::Instant::now();
    let v = exec(&net, &FakeStore::default(), &cache(), Request { server: None, command: "hang".into(), timeout_sec: Some(1) }).unwrap();
    assert_eq!(v["timedOut"], true);
    assert!(v["exitCode"].is_null());
    assert!(t.elapsed() < Duration::from_secs(10));
}

#[test]
fn the_command_timeout_comes_from_the_setting_and_a_call_cannot_exceed_the_maximum() {
    let (_srv, net) = world(true);
    let store = FakeStore::default();
    store.settings.borrow_mut().insert(K_COMMAND_SEC.into(), "1".into());
    let v = exec(&net, &store, &cache(), req("hang")).unwrap();
    assert_eq!(v["timedOut"], true, "the setting's value applied");
    store.settings.borrow_mut().insert(K_COMMAND_MAX_SEC.into(), "1".into());
    let v = exec(&net, &store, &cache(), Request { server: None, command: "hang".into(), timeout_sec: Some(3600) }).unwrap();
    assert_eq!(v["timedOut"], true, "an hour was cut to the 1 s maximum");
}

// ---- the host-key rule, end to end ----------------------------------------------------------------------------

#[test]
fn a_reported_fingerprint_that_matches_lets_the_command_run_and_pins_nothing() {
    let (srv, net) = world(true);
    *net.reported.borrow_mut() = Some(srv.host_fp.clone());
    let store = FakeStore::default();
    exec(&net, &store, &cache(), req("hello")).unwrap();
    assert!(store.kv.borrow().is_empty());
}

#[test]
fn a_reported_fingerprint_that_differs_is_a_mismatch_and_nothing_is_sent() {
    let (srv, net) = world(true);
    *net.reported.borrow_mut() = Some("SHA256:notTheRealHostKeyFingerprintAAAAAAAAAAAAAAAAA".into());
    let e = exec(&net, &FakeStore::default(), &cache(), req("hello")).unwrap_err();
    assert!(e.starts_with("host_key_mismatch:"), "{e}");
    assert_eq!(srv.seen.auth_attempts.load(Ordering::SeqCst), 0, "not even the certificate was offered");
    assert!(srv.seen.commands.lock().unwrap().is_empty());
}

#[test]
fn with_none_reported_the_first_key_is_pinned_and_a_changed_key_is_a_mismatch() {
    let (srv, net) = world(true);
    let store = FakeStore::default();
    exec(&net, &store, &cache(), req("hello")).unwrap();
    let pin = store.kv.borrow().get(&hostkey::pin_key("s1")).cloned().expect("pinned on first use");
    assert_eq!(pin, hostkey::norm(&srv.host_fp));
    // Same server id, now a different host key behind it.
    let (srv2, net2) = world(true);
    let e = exec(&net2, &store, &cache(), req("hello")).unwrap_err();
    assert!(e.starts_with("host_key_mismatch:"), "{e}");
    assert!(srv2.seen.commands.lock().unwrap().is_empty());
}

// ---- states and server choice ---------------------------------------------------------------------------------

#[test]
fn setting_up_is_an_answer_not_an_error_and_not_running_is_an_error() {
    let (_srv, net) = world(true);
    let store = FakeStore::default();
    *net.cert_reply.borrow_mut() = Some((409, json!({"error": "server_setting_up", "retryAfterSec": 20, "message": "Almost there"})));
    let v = exec(&net, &store, &cache(), req("hello")).unwrap();
    assert_eq!((v["status"].as_str(), v["retryAfterSec"].as_u64(), v["message"].as_str()), (Some("setting_up"), Some(20), Some("Almost there")));
    *net.cert_reply.borrow_mut() = Some((409, json!({"error": {"code": "not_running"}})));
    assert!(exec(&net, &store, &cache(), req("hello")).unwrap_err().starts_with("not_running:"));
    *net.cert_reply.borrow_mut() = Some((409, json!({"error": "server_setting_up"})));
    store.settings.borrow_mut().insert(K_RETRY_SEC.into(), "42".into());
    assert_eq!(exec(&net, &store, &cache(), req("hello")).unwrap()["retryAfterSec"], 42);
}

#[test]
fn the_other_states_map_like_the_server_list() {
    let (_srv, net) = world(true);
    let store = FakeStore::default();
    for (reply, kind) in [
        ((403, json!({"error": "not_entitled"})), "not_entitled:"),
        ((403, json!({"error": "email_unverified"})), "email_unverified:"),
        ((503, json!({"error": "not_configured"})), "not_configured:"),
        ((503, json!({})), "unavailable:"),
        ((404, json!({})), "not_found:"),
    ] {
        *net.cert_reply.borrow_mut() = Some(reply);
        let e = exec(&net, &store, &cache(), req("hello")).unwrap_err();
        assert!(e.starts_with(kind) && e.len() > kind.len() + 3, "{e}");
    }
}

#[test]
fn the_server_is_optional_with_one_server_and_a_readable_error_otherwise() {
    let (_srv, net) = world(true);
    let store = FakeStore::default();
    net.servers.borrow_mut().push(json!({"id": "s2", "name": "db", "status": "active", "sshReady": true}));
    let e = exec(&net, &store, &cache(), req("hello")).unwrap_err();
    assert!(e.starts_with("bad_request:") && e.contains("web") && e.contains("db"), "{e}");
    let e = exec(&net, &store, &cache(), named("nope", "hello")).unwrap_err();
    assert!(e.starts_with("not_found:") && e.contains("web, db"), "{e}");
    assert_eq!(exec(&net, &store, &cache(), named("WEB", "hello")).unwrap()["server"], "web");
    assert_eq!(exec(&net, &store, &cache(), named("s1", "hello")).unwrap()["server"], "web");
    net.servers.borrow_mut().clear();
    assert!(exec(&net, &store, &cache(), req("hello")).unwrap_err().starts_with("not_found:"));
}

#[test]
fn a_command_is_required() {
    assert!(parse_request("{}").unwrap_err().starts_with("bad_request:"));
    assert!(parse_request(r#"{"command": "  "}"#).is_err());
    let r = parse_request(r#"{"server":"web","command":"ls","timeoutSec":5}"#).unwrap();
    assert_eq!((r.server.as_deref(), r.command.as_str(), r.timeout_sec), (Some("web"), "ls", Some(5)));
}

// ---- secrets stay out -----------------------------------------------------------------------------------------

#[test]
fn no_key_certificate_or_token_text_reaches_an_answer_or_an_error() {
    let (_srv, net) = world(true);
    let store = FakeStore::default();
    let c = cache();
    let mut shown = vec![format!("{:?}", exec(&net, &store, &c, req("hello"))), format!("{:?}", exec(&net, &store, &c, req("nope")))];
    *net.reported.borrow_mut() = Some("SHA256:wrong".into());
    shown.push(format!("{:?}", exec(&net, &store, &cache(), req("hello"))));
    *net.cert_reply.borrow_mut() = Some((500, json!({"message": format!("boom {TOKEN}")})));
    shown.push(format!("{:?}", exec(&net, &store, &cache(), req("hello"))));
    let all = shown.join("\n");
    let pem = store.secrets.borrow().get(SECRET_FIELD).cloned().unwrap();
    let pem_body: Vec<&str> = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    assert!(pem_body.len() >= 2);
    for needle in pem_body.iter().copied().chain([TOKEN]) {
        assert!(!all.contains(needle), "a secret leaked: {}", &needle[..6]);
    }
    assert!(!net.issued_certs.borrow().is_empty());
    for cert in net.issued_certs.borrow().iter() {
        let blob = cert.split_whitespace().nth(1).unwrap();
        assert!(!all.contains(blob), "a certificate leaked");
    }
    assert!(all.contains("[removed]"), "the token echoed by the API was scrubbed");
}
