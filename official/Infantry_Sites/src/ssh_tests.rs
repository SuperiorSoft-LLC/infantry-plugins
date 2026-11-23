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
    /// The server's disk: path -> bytes (written by the upload command, read by `cat 'p'`).
    files: Mutex<HashMap<String, Vec<u8>>>,
}

#[derive(Clone)]
struct Handler {
    ca: Fingerprint,
    seen: Arc<Seen>,
    /// Uploads waiting for end-of-input: channel -> (path, bytes so far).
    pending: HashMap<ChannelId, (String, Vec<u8>)>,
}

/// The path of `mkdir -p "$(dirname -- 'p')" && cat > 'p'`, un-quoted the way a POSIX shell would.
fn upload_path(cmd: &str) -> Option<String> {
    let q = cmd.strip_prefix("mkdir -p \"$(dirname -- ")?;
    let (a, b) = q.split_once(")\" && cat > ")?;
    if a != b {
        return None;
    }
    let inner = b.strip_prefix('\'')?.strip_suffix('\'')?;
    Some(inner.replace("'\\''", "'"))
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
    async fn data(&mut self, ch: ChannelId, data: &[u8], _s: &mut Session) -> Result<(), Self::Error> {
        if let Some((_, buf)) = self.pending.get_mut(&ch) {
            buf.extend_from_slice(data);
        }
        Ok(())
    }
    async fn channel_eof(&mut self, ch: ChannelId, session: &mut Session) -> Result<(), Self::Error> {
        if let Some((path, buf)) = self.pending.remove(&ch) {
            self.seen.files.lock().unwrap().insert(path, buf);
            session.exit_status_request(ch, 0)?;
            session.eof(ch)?;
            session.close(ch)?;
        }
        Ok(())
    }
    async fn exec_request(&mut self, ch: ChannelId, data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        let cmd = String::from_utf8_lossy(data).to_string();
        self.seen.commands.lock().unwrap().push(cmd.clone());
        session.channel_success(ch)?;
        if let Some(path) = upload_path(&cmd) {
            self.pending.insert(ch, (path, Vec::new()));
            return Ok(());
        }
        if let Some(q) = cmd.strip_prefix("cat '") {
            let path = q.strip_suffix('\'').unwrap_or(q).replace("'\\''", "'");
            let found = self.seen.files.lock().unwrap().get(&path).cloned();
            match found {
                Some(b) => {
                    session.data(ch, b)?;
                    session.exit_status_request(ch, 0)?;
                }
                None => session.exit_status_request(ch, 1)?,
            }
            session.eof(ch)?;
            session.close(ch)?;
            return Ok(());
        }
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
            "slow" => {
                tokio::time::sleep(Duration::from_millis(1500)).await;
                session.data(ch, b"slow done\n".to_vec())?;
                session.exit_status_request(ch, 0)?;
            }
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
    let seen = Arc::new(Seen { commands: Mutex::new(vec![]), auth_attempts: AtomicUsize::new(0), files: Mutex::new(HashMap::new()) });
    let host_fp = host_key.public_key().fingerprint(HashAlg::Sha256).to_string();
    let handler = Handler { ca: ca.public_key().fingerprint(HashAlg::Sha256), seen: seen.clone(), pending: HashMap::new() };
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
    /// How many of the next certificates are signed by a stranger (the server will refuse them).
    bad_first: Cell<usize>,
    retry_after: Cell<Option<u64>>,
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
            bad_first: Cell::new(0),
            retry_after: Cell::new(None),
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
        let cert = if self.bad_first.get() > 0 {
            self.bad_first.set(self.bad_first.get() - 1);
            b.sign(&new_key()).unwrap().to_openssh().unwrap()
        } else {
            b.sign(&self.signer).unwrap().to_openssh().unwrap()
        };
        self.issued_certs.borrow_mut().push(cert.clone());
        let mut conn = json!({"host": "127.0.0.1", "port": self.port, "user": USER});
        if let Some(fp) = self.reported.borrow().clone() {
            conn["hostKeyFingerprint"] = json!(fp);
        }
        Ok((200, json!({"certificate": cert, "validBefore": before * 1000, "connection": conn})))
    }
    fn post_ra(&self, url: &str, bearer: &str, body: &Value) -> Result<(u16, Value, Option<u64>), String> {
        self.post(url, bearer, body).map(|(s, b)| (s, b, self.retry_after.get()))
    }
}

#[derive(Default)]
struct FakeStore {
    secrets: RefCell<HashMap<String, String>>,
    kv: RefCell<HashMap<String, String>>,
    settings: RefCell<HashMap<String, String>>,
    now_offset_ms: Cell<u64>,
    secret_writes: Cell<usize>,
    logs: RefCell<Vec<String>>,
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
    fn log(&self, line: &str) {
        self.logs.borrow_mut().push(line.to_string());
    }
}

fn req(cmd: &str) -> Request {
    Request { server: None, command: cmd.into(), timeout_sec: None, stdin: None }
}
fn named(server: &str, cmd: &str) -> Request {
    Request { server: Some(server.into()), command: cmd.into(), timeout_sec: None, stdin: None }
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
    // The certificate lives 3600 s and the default margin is 300 s: at +3250 s it is still used, at +3350 s it is not.
    store.now_offset_ms.set(3_250_000);
    exec(&net, &store, &c, req("hello")).unwrap();
    assert_eq!(net.posts.get(), 1, "still before the margin");
    store.now_offset_ms.set(3_350_000);
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
    let v = exec(&net, &FakeStore::default(), &cache(), Request { server: None, command: "hang".into(), timeout_sec: Some(1), stdin: None }).unwrap();
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
    let v = exec(&net, &store, &cache(), Request { server: None, command: "hang".into(), timeout_sec: Some(3600), stdin: None }).unwrap();
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
    shown.extend(store.logs.borrow().iter().cloned());
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

// ---- SSH parity with the Kotlin plugin (SVC-G1/G2) ------------------------------------------------------------

fn b64(bytes: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[test]
fn b4_b5_b6_the_live_defaults_are_120_1800_and_300_seconds_in_code_and_in_the_manifest() {
    let lim = Limits::load(&&FakeStore::default());
    assert_eq!((lim.command, lim.command_max, lim.cert_margin_ms), (Duration::from_secs(120), Duration::from_secs(1800), 300_000));
    let manifest: Value = serde_json::from_str(include_str!("../module.json")).unwrap();
    let fields = manifest["daemon"]["config"][0]["fields"].as_array().unwrap();
    let default_of = |key: &str| fields.iter().find(|f| f["key"] == key).unwrap()["default"].as_u64().unwrap();
    assert_eq!((default_of(K_COMMAND_SEC), default_of(K_COMMAND_MAX_SEC), default_of(K_CERT_MARGIN_SEC)), (120, 1800, 300));
    // The setting keys are the ones that were already there.
    assert_eq!((K_COMMAND_SEC, K_COMMAND_MAX_SEC, K_CERT_MARGIN_SEC), ("limits.sites.ssh.commandTimeoutSec", "limits.sites.ssh.maxCommandTimeoutSec", "limits.sites.ssh.certMarginSec"));
}

#[test]
fn b5_a_call_may_ask_up_to_the_maximum_and_no_more() {
    let lim = Limits::load(&&FakeStore::default());
    assert_eq!(command_timeout(Some(1800), &lim), Duration::from_secs(1800));
    assert_eq!(command_timeout(Some(99_999), &lim), Duration::from_secs(1800));
}

#[test]
fn b10_a_timeout_of_zero_or_none_is_the_default() {
    let lim = Limits::load(&&FakeStore::default());
    assert_eq!(command_timeout(Some(0), &lim), Duration::from_secs(120));
    assert_eq!(command_timeout(None, &lim), Duration::from_secs(120));
    assert_eq!(command_timeout(Some(5), &lim), Duration::from_secs(5));
    // A negative number is not a u64: the request carries none.
    assert_eq!(parse_request(r#"{"command":"ls","timeoutSec":-3}"#).unwrap().timeout_sec, None);
}

#[test]
fn b11_two_servers_of_one_name_are_refused_and_an_id_is_matched_in_any_case() {
    let (_srv, net) = world(true);
    let store = FakeStore::default();
    net.servers.borrow_mut().push(json!({"id": "S2", "name": "Web", "status": "active", "sshReady": true}));
    let e = exec(&net, &store, &cache(), named("web", "hello")).unwrap_err();
    assert_eq!(e, "bad_request: 2 servers are named 'web'; pass its id");
    assert!(exec(&net, &store, &cache(), named("s1", "hello")).is_ok(), "the id picks the first");
    // The second one has a certificate asked for under its own id.
    assert_eq!(exec(&net, &store, &cache(), named("s2", "hello")).unwrap()["server"], "Web");
}

#[test]
fn b12_a_legacy_base64_seed_is_rebuilt_into_the_same_key_and_left_in_place() {
    let (_srv, net) = world(true);
    let store = FakeStore::default();
    let seed = [7u8; 32];
    let legacy = b64(&seed);
    store.secrets.borrow_mut().insert(SECRET_FIELD.into(), legacy.clone());
    let v = exec(&net, &store, &cache(), req("hello")).unwrap();
    assert_eq!(v["exitCode"], 7);
    let want = PrivateKey::from(Ed25519Keypair::from_seed(&seed)).public_key().to_openssh().unwrap();
    assert_eq!(net.posted_keys.borrow()[0], want, "the certificate is for the key the Kotlin app made");
    assert_eq!(store.secret_writes.get(), 0, "the stored seed is untouched");
    assert!(!format!("{v:?}").contains(&legacy));
    // Anything that is neither a PEM nor a 32-byte seed is still a clear error, never a new key.
    store.secrets.borrow_mut().insert(SECRET_FIELD.into(), b64(&[1u8; 20]));
    assert!(exec(&net, &store, &cache(), req("hello")).unwrap_err().starts_with("unavailable: the stored SSH device key"));
    assert_eq!(store.secret_writes.get(), 0);
}

#[test]
fn b14_the_certificate_errors_400_429_and_502_are_mapped_like_the_kotlin_plugin() {
    let (_srv, net) = world(true);
    let store = FakeStore::default();
    *net.cert_reply.borrow_mut() = Some((400, json!({"error": "bad_public_key"})));
    assert_eq!(exec(&net, &store, &cache(), req("hello")).unwrap_err(), "bad_request: the hosting service refused this PC's SSH key");
    *net.cert_reply.borrow_mut() = Some((429, json!({})));
    net.retry_after.set(Some(30));
    assert_eq!(exec(&net, &store, &cache(), req("hello")).unwrap_err(), "unavailable: slow down: too many requests, try again in 30 s");
    net.retry_after.set(None);
    assert_eq!(exec(&net, &store, &cache(), req("hello")).unwrap_err(), "unavailable: slow down: too many requests, try again later");
    *net.cert_reply.borrow_mut() = Some((502, json!({"message": "droplet api said no"})));
    assert_eq!(exec(&net, &store, &cache(), req("hello")).unwrap_err(), "unavailable: The hosting provider had a problem. Try again in a minute.");
    // 403 without a server text names the permission; 409 setting-up takes the Retry-After header when the body has no seconds.
    *net.cert_reply.borrow_mut() = Some((403, json!({})));
    assert!(exec(&net, &store, &cache(), req("hello")).unwrap_err().contains("hosting.servers.ssh"));
    *net.cert_reply.borrow_mut() = Some((409, json!({"error": "server_setting_up"})));
    net.retry_after.set(Some(45));
    assert_eq!(exec(&net, &store, &cache(), req("hello")).unwrap()["retryAfterSec"], 45);
}

#[test]
fn b16_after_auth_failed_the_cached_certificate_is_forgotten_and_one_fresh_one_is_tried() {
    let (srv, net) = world(true);
    let store = FakeStore::default();
    let c = cache();
    net.bad_first.set(1); // the first certificate is refused by the server, the next one is good
    let v = exec(&net, &store, &c, req("hello")).unwrap();
    assert_eq!(v["exitCode"], 7);
    assert_eq!(net.posts.get(), 2, "one stale certificate, one fresh one");
    assert_eq!(srv.seen.auth_attempts.load(Ordering::SeqCst), 2);
    // A good certificate is cached again: the next call asks for nothing.
    exec(&net, &store, &c, req("hello")).unwrap();
    assert_eq!(net.posts.get(), 2);
    // Two refusals in a row: it stops after the one retry.
    net.bad_first.set(2);
    let c2 = cache();
    let e = exec(&net, &store, &c2, req("hello")).unwrap_err();
    assert!(e.starts_with("auth_failed:"), "{e}");
    assert_eq!(net.posts.get(), 4);
}

#[test]
fn b18_a_host_key_refusal_names_both_fingerprints() {
    let (srv, net) = world(true);
    let wrong = "SHA256:notTheRealHostKeyFingerprintAAAAAAAAAAAAAAAAA";
    *net.reported.borrow_mut() = Some(wrong.into());
    let e = exec(&net, &FakeStore::default(), &cache(), req("hello")).unwrap_err();
    assert!(e.starts_with("host_key_mismatch:") && e.contains(wrong) && e.contains(&srv.host_fp), "{e}");
    // A pinned key that changed names both too.
    let store = FakeStore::default();
    *net.reported.borrow_mut() = None;
    exec(&net, &store, &cache(), req("hello")).unwrap();
    let (srv2, net2) = world(true);
    let e = exec(&net2, &store, &cache(), req("hello")).unwrap_err();
    assert!(e.contains(&srv2.host_fp) && e.contains(&hostkey::norm(&srv.host_fp)), "{e}");
}

#[test]
fn b20_a_connect_or_auth_failure_writes_one_log_line_with_host_port_and_no_secret() {
    let (srv, net) = world(false); // the server refuses the certificate
    let store = FakeStore::default();
    let e = exec(&net, &store, &cache(), req("hello")).unwrap_err();
    assert!(e.starts_with("auth_failed:"));
    let logs = store.logs.borrow().clone();
    assert_eq!(logs.len(), 2, "the failure and its one retry: {logs:?}");
    let place = format!("127.0.0.1:{}", srv.port);
    for l in &logs {
        assert!(l.contains(&place) && l.contains("auth_failed"), "{l}");
        assert!(!l.contains(TOKEN) && !l.contains("ssh-ed25519") && !l.contains("BEGIN"), "{l}");
    }
    // Nothing listens: a connect failure is logged with its host and port too.
    let (_srv, mut net) = world(true);
    let dead = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    net.port = dead.local_addr().unwrap().port();
    drop(dead);
    let store = FakeStore::default();
    assert!(exec(&net, &store, &cache(), req("hello")).unwrap_err().starts_with("unavailable:"));
    let logs = store.logs.borrow().clone();
    assert_eq!(logs.len(), 1);
    assert!(logs[0].contains(&format!("127.0.0.1:{}", net.port)), "{logs:?}");
}


// ---- upload (SVC-7) -------------------------------------------------------------------------------------------

fn up(path: &str, content: &str) -> Request {
    parse_upload(&json!({"path": path, "content": content}).to_string()).unwrap()
}
fn disk(srv: &TestServer, path: &str) -> Option<Vec<u8>> {
    srv.seen.files.lock().unwrap().get(path).cloned()
}

#[test]
fn an_upload_writes_reads_back_and_replaces_the_file() {
    let (srv, net) = world(true);
    let (store, c) = (FakeStore::default(), cache());
    let v = exec(&net, &store, &c, up("/srv/app/a.txt", "one
line é")).unwrap();
    assert_eq!(v["exitCode"].as_u64(), Some(0));
    assert_eq!(disk(&srv, "/srv/app/a.txt").unwrap(), "one
line é".as_bytes());
    let back = exec(&net, &store, &c, req("cat '/srv/app/a.txt'")).unwrap();
    assert_eq!(back["stdout"].as_str(), Some("one
line é"));
    exec(&net, &store, &c, up("/srv/app/a.txt", "two")).unwrap();
    assert_eq!(disk(&srv, "/srv/app/a.txt").unwrap(), b"two");
    assert_eq!(srv.seen.commands.lock().unwrap()[0], "mkdir -p \"$(dirname -- '/srv/app/a.txt')\" && cat > '/srv/app/a.txt'");
}

#[test]
fn an_empty_file_is_written() {
    let (srv, net) = world(true);
    exec(&net, &FakeStore::default(), &cache(), up("/e", "")).unwrap();
    assert_eq!(disk(&srv, "/e").unwrap(), Vec::<u8>::new());
}

#[test]
fn an_oversized_upload_is_refused_naming_the_setting_and_nothing_is_sent() {
    let (srv, net) = world(true);
    let store = FakeStore::default();
    store.settings.borrow_mut().insert(K_MAX_UPLOAD_BYTES.into(), "10".into());
    let e = exec(&net, &store, &cache(), up("/big", "01234567890")).unwrap_err();
    assert!(e.starts_with("bad_request:") && e.contains("limits.sites.ssh.maxUploadBytes") && e.contains("11 bytes"), "{e}");
    assert!(srv.seen.commands.lock().unwrap().is_empty());
    exec(&net, &store, &cache(), up("/ok", "0123456789")).unwrap();
    // The default is 1 MiB.
    let e = exec(&net, &FakeStore::default(), &cache(), up("/big", &"x".repeat(1_048_577))).unwrap_err();
    assert!(e.contains("1048576"), "{e}");
}

#[test]
fn a_path_with_a_quote_and_a_space_is_quoted_so_the_shell_sees_one_word() {
    assert_eq!(shell_quote("a'b"), r"'a'\''b'");
    let (srv, net) = world(true);
    let path = "/srv/my dir/it's $HOME;rm -rf x.txt";
    exec(&net, &FakeStore::default(), &cache(), up(path, "ok")).unwrap();
    assert_eq!(disk(&srv, path).unwrap(), b"ok");
}

#[test]
fn an_upload_needs_a_path_and_content() {
    assert!(parse_upload("{\"content\":\"x\"}").unwrap_err().starts_with("bad_request:"));
    assert!(parse_upload("{\"path\":\"  \",\"content\":\"x\"}").unwrap_err().starts_with("bad_request:"));
    assert!(parse_upload("{\"path\":\"/a\"}").unwrap_err().starts_with("bad_request:"));
}

#[test]
fn an_upload_answer_and_log_hold_no_key_certificate_or_token() {
    let (_srv, net) = world(true);
    let store = FakeStore::default();
    let v = exec(&net, &store, &cache(), up("/s", "data")).unwrap();
    let all = format!("{v} {:?}", store.logs.borrow());
    assert!(!all.contains(TOKEN) && !all.contains("PRIVATE KEY") && !all.contains("-cert-v01"), "{all}");
}

// ---- concurrency (SVC-FIX-4): calls at the same time -------------------------------------------------------------

/// A thread-safe fake of the host: the API signs for every server it lists, each at its own port.
struct SyncNet {
    signer: PrivateKey,
    /// (id, name, port)
    servers: Vec<(String, String, u16)>,
    posts: AtomicUsize,
    /// Held a moment inside the certificate request, so two calls that ask together overlap.
    post_delay: Duration,
}

impl SyncNet {
    fn new(signer: PrivateKey, servers: Vec<(&str, &str, u16)>) -> SyncNet {
        SyncNet {
            signer,
            servers: servers.into_iter().map(|(i, n, p)| (i.to_string(), n.to_string(), p)).collect(),
            posts: AtomicUsize::new(0),
            post_delay: Duration::from_millis(200),
        }
    }
}

impl Net for &SyncNet {
    fn endpoint(&self, n: &str) -> Option<String> {
        (n == "api").then(|| "https://api.test".to_string())
    }
    fn frame(&self, kind: &str, _d: Value) -> Result<Value, String> {
        match kind {
            "account_token" => Ok(json!({ "accessToken": TOKEN })),
            "account_status" => Ok(json!({ "email": "owner@example.test" })),
            _ => Ok(json!({})),
        }
    }
    fn get(&self, _url: &str, _b: &str) -> Result<(u16, Value), String> {
        let list: Vec<Value> = self.servers.iter().map(|(i, n, _)| json!({"id": i, "name": n, "status": "active", "sshReady": true})).collect();
        Ok((200, json!({ "servers": list })))
    }
    fn post(&self, url: &str, _bearer: &str, body: &Value) -> Result<(u16, Value), String> {
        self.posts.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(self.post_delay);
        let id = url.trim_start_matches("https://api.test/hosting/v1/servers/").trim_end_matches("/ssh/certificate");
        let port = self.servers.iter().find(|s| s.0 == id).map(|s| s.2).ok_or("no such server")?;
        let subject = PublicKey::from_openssh(body["publicKey"].as_str().unwrap()).unwrap();
        let now = real_now_ms() / 1000;
        let mut b = Builder::new_with_random_nonce(&mut rand::rng(), subject.key_data().clone(), now - 60, now + 3600).unwrap();
        b.key_id("test").unwrap();
        b.cert_type(CertType::User).unwrap();
        b.valid_principal(USER).unwrap();
        let cert = b.sign(&self.signer).unwrap().to_openssh().unwrap();
        Ok((200, json!({"certificate": cert, "validBefore": (now + 3600) * 1000, "connection": {"host": "127.0.0.1", "port": port, "user": USER}})))
    }
}

#[derive(Default)]
struct SyncStore {
    secrets: Mutex<HashMap<String, String>>,
    kv: Mutex<HashMap<String, String>>,
    settings: Mutex<HashMap<String, String>>,
    secret_writes: AtomicUsize,
    kv_writes: AtomicUsize,
}

impl Store for &SyncStore {
    fn secret_get(&self, f: &str) -> Result<Option<String>, String> {
        let v = self.secrets.lock().unwrap().get(f).cloned();
        // A slow secret store: two first calls that read together both see nothing unless the key lock holds.
        std::thread::sleep(Duration::from_millis(100));
        Ok(v)
    }
    fn secret_set(&self, f: &str, v: &str) -> Result<(), String> {
        self.secret_writes.fetch_add(1, Ordering::SeqCst);
        self.secrets.lock().unwrap().insert(f.into(), v.into());
        Ok(())
    }
    fn kv_get(&self, k: &str) -> Option<String> {
        self.kv.lock().unwrap().get(k).cloned()
    }
    fn kv_set(&self, k: &str, v: &str) -> Result<(), String> {
        self.kv_writes.fetch_add(1, Ordering::SeqCst);
        self.kv.lock().unwrap().insert(k.into(), v.into());
        Ok(())
    }
    fn setting(&self, k: &str) -> Option<String> {
        self.settings.lock().unwrap().get(k).cloned()
    }
    fn now_ms(&self) -> u64 {
        real_now_ms()
    }
    fn log(&self, _line: &str) {}
}

/// Two servers of one account (both trust the same CA), and the host fakes that serve them.
fn two_servers() -> (TestServer, TestServer, SyncNet, SyncStore) {
    let ca = new_key();
    let (a, b) = (start_server(&ca, new_key()), start_server(&ca, new_key()));
    let net = SyncNet::new(ca, vec![("s1", "web", a.port), ("s2", "db", b.port)]);
    (a, b, net, SyncStore::default())
}

fn run_on(net: &SyncNet, store: &SyncStore, cache: &SharedCache, server: &str, cmd: &str) -> Result<Value, String> {
    SshExec::new(net, store, cache.clone()).exec(named(server, cmd))
}

#[test]
fn a_list_is_answered_while_a_long_command_runs() {
    let (_a, _b, net, store) = two_servers();
    let c = cache();
    std::thread::scope(|s| {
        let slow = s.spawn(|| run_on(&net, &store, &c, "s1", "slow"));
        std::thread::sleep(Duration::from_millis(900)); // the command is on the wire by now
        let t = std::time::Instant::now();
        let listed = Sites::new(&net).list();
        assert_eq!(listed["state"], "ready");
        assert!(t.elapsed() < Duration::from_millis(500), "the list waited {:?} behind the command", t.elapsed());
        assert_eq!(c.lock().unwrap().running(), 1, "the command is still running");
        assert_eq!(slow.join().unwrap().unwrap()["stdout"], "slow done\n");
    });
}

#[test]
fn two_commands_on_different_servers_run_at_the_same_time() {
    let (a, b, net, store) = two_servers();
    let c = cache();
    run_on(&net, &store, &c, "s1", "hello").unwrap(); // device key, certificates and pins are ready: only the commands race
    run_on(&net, &store, &c, "s2", "hello").unwrap();
    let t = std::time::Instant::now();
    std::thread::scope(|s| {
        let (x, y) = (s.spawn(|| run_on(&net, &store, &c, "s1", "slow")), s.spawn(|| run_on(&net, &store, &c, "s2", "slow")));
        assert_eq!(x.join().unwrap().unwrap()["exitCode"], 0);
        assert_eq!(y.join().unwrap().unwrap()["exitCode"], 0);
    });
    // Two 1.5 s commands one after the other would take 3 s.
    assert!(t.elapsed() < Duration::from_millis(2600), "they ran one after the other: {:?}", t.elapsed());
    assert!(a.seen.commands.lock().unwrap().contains(&"slow".to_string()) && b.seen.commands.lock().unwrap().contains(&"slow".to_string()));
}

#[test]
fn two_commands_on_one_server_run_at_the_same_time_too() {
    let (_a, _b, net, store) = two_servers();
    let c = cache();
    run_on(&net, &store, &c, "s1", "hello").unwrap();
    let t = std::time::Instant::now();
    std::thread::scope(|s| {
        let (x, y) = (s.spawn(|| run_on(&net, &store, &c, "s1", "slow")), s.spawn(|| run_on(&net, &store, &c, "s1", "slow")));
        x.join().unwrap().unwrap();
        y.join().unwrap().unwrap();
    });
    assert!(t.elapsed() < Duration::from_millis(2600), "{:?}", t.elapsed());
}

#[test]
fn first_use_from_two_calls_makes_one_key_asks_one_certificate_and_pins_once() {
    let (a, _b, net, store) = two_servers();
    let c = cache();
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|s| {
        let go = || {
            barrier.wait();
            run_on(&net, &store, &c, "s1", "hello")
        };
        let (x, y) = (s.spawn(go), s.spawn(go));
        assert_eq!(x.join().unwrap().unwrap()["exitCode"], 7);
        assert_eq!(y.join().unwrap().unwrap()["exitCode"], 7);
    });
    assert_eq!(store.secret_writes.load(Ordering::SeqCst), 1, "one device key was made");
    assert_eq!(net.posts.load(Ordering::SeqCst), 1, "one certificate was asked for");
    assert_eq!(store.kv_writes.load(Ordering::SeqCst), 1, "the host key was pinned once");
    assert_eq!(store.kv.lock().unwrap().get(&hostkey::pin_key("s1")).map(|p| hostkey::norm(p)), Some(hostkey::norm(&a.host_fp)));
    assert_eq!(a.seen.auth_attempts.load(Ordering::SeqCst), 2, "both calls signed in");
}

#[test]
fn first_use_on_two_servers_at_once_still_makes_one_device_key_and_one_pin_each() {
    let (a, b, net, store) = two_servers();
    let c = cache();
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|s| {
        let (x, y) = (
            s.spawn(|| {
                barrier.wait();
                run_on(&net, &store, &c, "s1", "hello")
            }),
            s.spawn(|| {
                barrier.wait();
                run_on(&net, &store, &c, "s2", "hello")
            }),
        );
        x.join().unwrap().unwrap();
        y.join().unwrap().unwrap();
    });
    assert_eq!(store.secret_writes.load(Ordering::SeqCst), 1, "one device key for both servers");
    assert_eq!(net.posts.load(Ordering::SeqCst), 2, "a certificate for each server");
    let kv = store.kv.lock().unwrap();
    assert_eq!(kv.get(&hostkey::pin_key("s1")).map(|p| hostkey::norm(p)), Some(hostkey::norm(&a.host_fp)));
    assert_eq!(kv.get(&hostkey::pin_key("s2")).map(|p| hostkey::norm(p)), Some(hostkey::norm(&b.host_fp)));
}

#[test]
fn past_the_limit_a_call_is_refused_in_words_and_nothing_is_sent_and_a_freed_slot_works_again() {
    let (a, _b, net, store) = two_servers();
    store.settings.lock().unwrap().insert(K_MAX_CONCURRENT.into(), "1".into());
    let c = cache();
    run_on(&net, &store, &c, "s1", "hello").unwrap();
    std::thread::scope(|s| {
        let slow = s.spawn(|| run_on(&net, &store, &c, "s1", "slow"));
        std::thread::sleep(Duration::from_millis(900));
        let e = run_on(&net, &store, &c, "s1", "hello").unwrap_err();
        assert!(e.starts_with("limit: 1 SSH calls are already running"), "{e}");
        assert!(e.contains(K_MAX_CONCURRENT) && e.contains("try again"), "{e}");
        assert_eq!(a.seen.commands.lock().unwrap().iter().filter(|c| c.as_str() == "hello").count(), 1, "the refused call ran nothing");
        slow.join().unwrap().unwrap();
    });
    assert_eq!(c.lock().unwrap().running(), 0, "every slot came back");
    assert_eq!(run_on(&net, &store, &c, "s1", "hello").unwrap()["exitCode"], 7);
}

#[test]
fn the_default_limit_lets_four_calls_run_together_and_refuses_the_fifth() {
    let (_a, _b, net, store) = two_servers();
    let c = cache();
    run_on(&net, &store, &c, "s1", "hello").unwrap();
    std::thread::scope(|s| {
        let running: Vec<_> = (0..4).map(|_| s.spawn(|| run_on(&net, &store, &c, "s1", "slow"))).collect();
        std::thread::sleep(Duration::from_millis(900));
        assert!(run_on(&net, &store, &c, "s1", "hello").unwrap_err().starts_with("limit: 4 SSH calls are already running"));
        for r in running {
            r.join().unwrap().unwrap();
        }
    });
}

#[test]
fn a_command_that_timed_out_says_so_in_words_as_well_as_the_flag() {
    let (_srv, net) = world(true);
    let v = exec(&net, &FakeStore::default(), &cache(), Request { server: None, command: "hang".into(), timeout_sec: Some(1), stdin: None }).unwrap();
    assert_eq!(v["timedOut"], true);
    let m = v["message"].as_str().expect("a message");
    assert!(m.starts_with("timed out: the command did not finish within 1 s"), "{m}");
    assert!(m.contains("timeoutSec") && m.contains(K_COMMAND_MAX_SEC), "{m}");
    let ok = exec(&net, &FakeStore::default(), &cache(), req("hello")).unwrap();
    assert!(ok.get("message").is_none(), "a command that finished has no message");
}
