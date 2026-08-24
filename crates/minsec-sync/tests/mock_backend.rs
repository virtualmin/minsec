//! End-to-end test of the real `minsec-sync` binary against a scripted
//! in-process mock of the minsec.io API: enroll (with proof-of-work),
//! signed report submission (signature verified here, like the server
//! does), and feed pulls exercising full, 304, and delta responses.
//! nftables is exercised via `--dry-run` script output.
//!
//! True cross-implementation conformance against the Go backend lives in
//! tests/e2e-multiplayer.sh (needs the minsec.io repo and a database).

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};

const DIFFICULTY: u32 = 8;
const CHALLENGE: &str = "test-challenge-abc";
const HOST_ID: &str = "018f3c00-0000-7000-8000-00000000e2e1";

#[derive(Default)]
struct Backend {
    pubkey: Option<[u8; 32]>,
    report_bodies: Vec<Vec<u8>>,
    report_seqs: Vec<u64>,
    /// Current v4 feed: (snapshot, etag, body). Swapped by the test between
    /// binary invocations.
    v4: (i64, String, String),
    requests: Vec<String>,
}

struct Req {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

fn read_request(stream: &mut TcpStream) -> Option<Req> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end = loop {
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break pos;
        }
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.lines();
    let mut first = lines.next()?.split_whitespace();
    let method = first.next()?.to_string();
    let path = first.next()?.to_string();
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    let len: usize = headers.get("content-length").and_then(|v| v.parse().ok()).unwrap_or(0);
    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < len {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    Some(Req {
        method,
        path,
        headers,
        body,
    })
}

fn respond(stream: &mut TcpStream, status: &str, headers: &[(&str, &str)], body: &str) {
    let mut out = format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (k, v) in headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str("\r\n");
    out.push_str(body);
    let _ = stream.write_all(out.as_bytes());
}

fn handle(state: &Arc<Mutex<Backend>>, stream: &mut TcpStream) {
    let Some(req) = read_request(stream) else { return };
    let mut st = state.lock().unwrap();
    st.requests.push(format!("{} {}", req.method, req.path));
    match (req.method.as_str(), req.path.split('?').next().unwrap()) {
        ("POST", "/v1/enroll/challenge") => {
            let body = format!(
                r#"{{"challenge":"{CHALLENGE}","difficulty":{DIFFICULTY},"expires_in":300,"algo":"sha256-pow-v1"}}"#
            );
            respond(stream, "200 OK", &[("Content-Type", "application/json")], &body);
        }
        ("POST", "/v1/enroll") => {
            let v: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
            let nonce = v["pow_nonce"].as_str().unwrap_or_default();
            if !minsec_proto::pow::check(v["challenge"].as_str().unwrap_or_default(), nonce, DIFFICULTY) {
                respond(stream, "403 Forbidden", &[], r#"{"error":"pow_rejected"}"#);
                return;
            }
            let pk: [u8; 32] = B64
                .decode(v["pubkey"].as_str().unwrap_or_default())
                .unwrap()
                .try_into()
                .unwrap();
            if st.pubkey == Some(pk) {
                respond(stream, "409 Conflict", &[], r#"{"error":"already_enrolled"}"#);
                return;
            }
            st.pubkey = Some(pk);
            let body = format!(
                r#"{{"host_id":"{HOST_ID}","report_url":"/v1/reports","feed_url":"/v1/feed","min_report_interval":300}}"#
            );
            respond(stream, "201 Created", &[("Content-Type", "application/json")], &body);
        }
        ("POST", "/v1/reports") => {
            let host = req.headers.get("x-minsec-host").cloned().unwrap_or_default();
            let ts: i64 = req
                .headers
                .get("x-minsec-timestamp")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let sig: [u8; 64] = B64
                .decode(req.headers.get("x-minsec-signature").cloned().unwrap_or_default())
                .unwrap_or_default()
                .try_into()
                .unwrap_or([0; 64]);
            let key = ed25519_dalek::VerifyingKey::from_bytes(&st.pubkey.expect("enrolled")).unwrap();
            if host != HOST_ID || !minsec_proto::sign::verify(&key, &host, ts, &req.body, &sig) {
                respond(stream, "401 Unauthorized", &[], r#"{"error":"unauthorized"}"#);
                return;
            }
            let v: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
            let seq = v["seq"].as_u64().unwrap_or(0);
            if st.report_seqs.last().is_some_and(|last| seq <= *last) {
                respond(stream, "200 OK", &[], r#"{"accepted":0,"rejected":0,"duplicate":true}"#);
                return;
            }
            let n = v["reports"].as_array().map(|a| a.len()).unwrap_or(0);
            st.report_seqs.push(seq);
            st.report_bodies.push(req.body.clone());
            respond(stream, "200 OK", &[], &format!(r#"{{"accepted":{n},"rejected":0}}"#));
        }
        ("GET", "/v1/feed/basic/v4") => {
            let (snapshot, etag, body) = st.v4.clone();
            if req.headers.get("if-none-match") == Some(&etag) {
                respond(stream, "304 Not Modified", &[("ETag", &etag)], "");
                return;
            }
            // Serve a delta when the client is exactly one snapshot behind.
            let since: i64 = req
                .path
                .split_once("?since=")
                .and_then(|(_, s)| s.parse().ok())
                .unwrap_or(0);
            if since == snapshot - 1 && snapshot == 2 {
                let delta =
                    "# minsec-feed v1 delta tier=basic family=4 from=1 to=2 count=2\n+198.18.0.1\n-203.0.113.7\n"
                        .to_string();
                respond(
                    stream,
                    "200 OK",
                    &[("ETag", &etag), ("Content-Type", "text/plain")],
                    &delta,
                );
                return;
            }
            respond(
                stream,
                "200 OK",
                &[("ETag", &etag), ("Content-Type", "text/plain")],
                &body,
            );
        }
        _ => respond(stream, "404 Not Found", &[], r#"{"error":"not_found"}"#),
    }
}

fn start_server() -> (Arc<Mutex<Backend>>, String) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let state = Arc::new(Mutex::new(Backend {
        v4: (
            1,
            "\"s1\"".into(),
            "# minsec-feed v1 full tier=basic family=4 snapshot=1 generated=2026-08-23T12:00:00Z count=2\n\
             198.51.100.0/24\n203.0.113.7\n"
                .into(),
        ),
        ..Default::default()
    }));
    let st = state.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            handle(&st, &mut stream);
        }
    });
    (state, format!("http://{addr}"))
}

fn sync(args: &[&str], config: &Path) -> (bool, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_minsec-sync"))
        .arg("--config")
        .arg(config)
        .args(args)
        .output()
        .expect("run minsec-sync");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn full_cycle_against_mock_backend() {
    let (state, url) = start_server();
    let dir = std::env::temp_dir().join(format!("minsec-sync-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let events = dir.join("events.jsonl");
    let config = dir.join("sync.toml");
    std::fs::write(
        &config,
        format!(
            "server = \"{url}\"\nstate_dir = \"{}\"\nevents = \"{}\"\nipv6 = false\n",
            dir.join("state").display(),
            events.display()
        ),
    )
    .unwrap();

    // Events: two automatic bans (one v6 to aggregate), a manual ban and a
    // stale event that must be skipped.
    let t = now();
    std::fs::write(
        &events,
        format!(
            "{{\"kind\":\"start\",\"ts\":{t},\"version\":\"0.1.4\"}}\n\
             {{\"kind\":\"ban\",\"ts\":{t},\"net\":\"203.0.113.7/32\",\"filter\":\"sshd\",\"ttl\":600,\"hits\":5,\"escalation\":0,\"manual\":false}}\n\
             {{\"kind\":\"ban\",\"ts\":{t},\"net\":\"2001:db8:1:2:3::4/128\",\"filter\":\"postfix-sasl\",\"ttl\":600,\"hits\":2,\"escalation\":0,\"manual\":false}}\n\
             {{\"kind\":\"ban\",\"ts\":{t},\"net\":\"198.51.100.9/32\",\"filter\":\"sshd\",\"ttl\":600,\"hits\":1,\"escalation\":0,\"manual\":true}}\n\
             {{\"kind\":\"ban\",\"ts\":{},\"net\":\"198.51.100.10/32\",\"filter\":\"sshd\",\"ttl\":600,\"hits\":1,\"escalation\":0,\"manual\":false}}\n",
            t - 90_000
        ),
    )
    .unwrap();

    // Enroll.
    let (ok, stdout, stderr) = sync(&["enroll"], &config);
    assert!(ok, "enroll failed: {stderr}");
    assert!(stdout.contains(&format!("enrolled as {HOST_ID}")), "{stdout}");

    // Report: 2 reportable events; the manual ban is dropped by the events
    // reader, the stale one counts as skipped.
    let (ok, stdout, stderr) = sync(&["report"], &config);
    assert!(ok, "report failed: {stderr}");
    assert!(
        stdout.contains("reported 2 events (2 accepted, 0 rejected, 1 skipped)"),
        "{stdout}"
    );
    {
        let st = state.lock().unwrap();
        assert_eq!(st.report_bodies.len(), 1);
        let batch: serde_json::Value = serde_json::from_slice(&st.report_bodies[0]).unwrap();
        let ips: Vec<&str> = batch["reports"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["ip"].as_str().unwrap())
            .collect();
        assert_eq!(ips, vec!["203.0.113.7/32", "2001:db8:1:2::/64"]);
        assert!(batch["agent_version"].as_str().unwrap().starts_with("minsec-sync/"));
    }

    // Nothing new: no request is made beyond cursor bookkeeping.
    let (ok, stdout, _) = sync(&["report"], &config);
    assert!(ok);
    assert!(stdout.contains("reported 0 events"), "{stdout}");
    assert_eq!(state.lock().unwrap().report_bodies.len(), 1);

    // Pull #1: full feed into crowd4 (dry-run prints the nft script).
    let (ok, stdout, stderr) = sync(&["pull", "--dry-run"], &config);
    assert!(ok, "pull failed: {stderr}");
    assert!(stdout.contains("flush set inet minsec crowd4"), "{stdout}");
    assert!(stdout.contains("203.0.113.7"), "{stdout}");
    assert!(stdout.contains("198.51.100.0/24"), "{stdout}");
    assert!(stdout.contains("feed v4: full update, 2 entries"), "{stdout}");

    // Pull #2: unchanged (ETag hit).
    let (ok, stdout, _) = sync(&["pull", "--dry-run"], &config);
    assert!(ok);
    assert!(stdout.contains("feed v4: unchanged"), "{stdout}");
    assert!(!stdout.contains("flush set"), "{stdout}");

    // Server advances one snapshot: the client gets a delta.
    state.lock().unwrap().v4 = (
        2,
        "\"s2\"".into(),
        "# minsec-feed v1 full tier=basic family=4 snapshot=2 generated=2026-08-23T13:00:00Z count=2\n\
         198.18.0.1\n198.51.100.0/24\n"
            .into(),
    );
    let (ok, stdout, stderr) = sync(&["pull", "--dry-run"], &config);
    assert!(ok, "delta pull failed: {stderr}");
    assert!(stdout.contains("feed v4: delta update"), "{stdout}");
    assert!(
        stdout.contains("delete element inet minsec crowd4 { 203.0.113.7 }"),
        "{stdout}"
    );
    assert!(
        stdout.contains("add element inet minsec crowd4 { 198.18.0.1 }"),
        "{stdout}"
    );
    assert!(!stdout.contains("flush set"), "{stdout}");

    // State survived it all.
    let (ok, stdout, _) = sync(&["status"], &config);
    assert!(ok);
    assert!(stdout.contains(&format!("host_id: {HOST_ID}")), "{stdout}");
    assert!(stdout.contains("feed basic/v4: snapshot 2"), "{stdout}");

    let _ = std::fs::remove_dir_all(&dir);
}
