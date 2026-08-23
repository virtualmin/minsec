//! Daemon event loop: sources → engine, control socket, housekeeping.

use minsec_core::backend;
use minsec_core::config::Config;
use minsec_core::control::{Request, Response};
use minsec_core::engine::Engine;
use minsec_core::events::{now, EventLog};
use minsec_core::source::{file::FileTailer, journal, Line};
use std::cell::RefCell;
use std::rc::Rc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::mpsc;

pub fn run(cfg: Config, replay: bool) -> anyhow::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async_main(cfg, replay))
}

async fn async_main(cfg: Config, replay: bool) -> anyhow::Result<()> {
    let backend = backend::open(&cfg.defaults)?;
    let events = EventLog::open(&cfg.paths.state_dir.join("events.jsonl")).unwrap_or_else(|e| {
        tracing::warn!("event log unavailable ({e}); continuing without persistence");
        EventLog::sink()
    });
    let mut engine = Engine::new(cfg, backend, events)?;
    engine.start(now() as u32)?;

    let (tx, mut rx) = mpsc::channel::<Line>(4096);

    // File sources.
    let patterns = engine.file_patterns();
    if !patterns.is_empty() {
        let tailer = FileTailer::new(patterns, tx.clone(), !replay)?;
        tokio::task::spawn_local(async move {
            if let Err(e) = tailer.run().await {
                tracing::error!("file tailer stopped: {e}");
            }
        });
    }
    // journald.
    let matches = engine.journal_matches();
    if !matches.is_empty() {
        let jtx = tx.clone();
        tokio::task::spawn_local(async move {
            if let Err(e) = journal::run(matches, jtx).await {
                tracing::error!("journal follower stopped: {e}");
            }
        });
    }
    drop(tx);

    // Control socket.
    let sock = engine.cfg.paths.socket.clone();
    if let Some(dir) = sock.parent() {
        std::fs::create_dir_all(dir).ok();
    }
    let _ = std::fs::remove_file(&sock);
    let listener = UnixListener::bind(&sock).map_err(|e| anyhow::anyhow!("bind {}: {e}", sock.display()))?;
    // Owner-only by default; the package can relax this via the unit file/group.
    let _ = std::fs::set_permissions(&sock, std::os::unix::fs::PermissionsExt::from_mode(0o660));
    let (ctl_tx, mut ctl_rx) = mpsc::channel::<(Request, tokio::sync::oneshot::Sender<Response>)>(64);
    tokio::task::spawn_local(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let ctl_tx = ctl_tx.clone();
            tokio::task::spawn_local(async move {
                let (r, mut w) = stream.into_split();
                let mut lines = BufReader::new(r).lines();
                while let Ok(Some(l)) = lines.next_line().await {
                    let resp = match serde_json::from_str::<Request>(&l) {
                        Ok(req) => {
                            let (otx, orx) = tokio::sync::oneshot::channel();
                            if ctl_tx.send((req, otx)).await.is_err() {
                                break;
                            }
                            orx.await.unwrap_or_else(|_| Response::err("engine gone"))
                        }
                        Err(e) => Response::err(format!("bad request: {e}")),
                    };
                    let mut out = serde_json::to_string(&resp).unwrap_or_default();
                    out.push('\n');
                    if w.write_all(out.as_bytes()).await.is_err() {
                        break;
                    }
                }
            });
        }
    });

    let engine = Rc::new(RefCell::new(engine));
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    tracing::info!(socket = %sock.display(), "minsec ready");

    loop {
        tokio::select! {
            biased;
            _ = sigterm.recv() => break,
            _ = sigint.recv() => break,
            Some((req, reply)) = ctl_rx.recv() => {
                let resp = handle(&mut engine.borrow_mut(), req);
                let _ = reply.send(resp);
            }
            line = rx.recv() => {
                let Some(line) = line else { break };
                let t = now() as u32;
                let mut e = engine.borrow_mut();
                e.handle_line(&line, t);
                // Drain whatever else is queued before yielding.
                while let Ok(l) = rx.try_recv() {
                    e.handle_line(&l, t);
                }
            }
            _ = tick.tick() => engine.borrow_mut().tick(now() as u32),
        }
    }
    engine.borrow_mut().stop(now() as u32);
    let _ = std::fs::remove_file(&sock);
    tracing::info!("minsec stopped");
    Ok(())
}

fn handle(e: &mut Engine, req: Request) -> Response {
    let t = now() as u32;
    match req {
        Request::Ping => Response::message("pong"),
        Request::Status => Response {
            status: Some(e.status(t)),
            ..Response::ok()
        },
        Request::List => match e.list(t) {
            Ok(b) => Response {
                bans: Some(b),
                ..Response::ok()
            },
            Err(err) => Response::err(err),
        },
        Request::Ban { net, ttl, .. } => match e.manual_ban(net, ttl.map(std::time::Duration::from_secs), t) {
            Ok(()) => Response::message(format!("banned {}", minsec_core::ip::key_to_nft(&net))),
            Err(err) => Response::err(err),
        },
        Request::Unban { net } => match e.unban(net, t) {
            Ok(()) => Response::message(format!("unbanned {}", minsec_core::ip::key_to_nft(&net))),
            Err(err) => Response::err(err),
        },
        Request::Filters => Response {
            filters: Some(e.filter_names()),
            ..Response::ok()
        },
    }
}
