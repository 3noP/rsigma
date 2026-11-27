//! A NATS server that requires a user and a password: it answers a client
//! that signs in with them and refuses one that does not, as nats-server does
//! (`Authorization Violation`), and counts the clients it let in. For the
//! tests that a dynamic NATS source signs in with the daemon's credentials.

#![allow(dead_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

pub const USER: &str = "rsigma";
pub const PASSWORD: &str = "s3cret";

/// The server's URL, and how many clients it let in so far.
pub async fn auth_required_server() -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let signed_in = Arc::new(AtomicUsize::new(0));
    let count = signed_in.clone();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let count = count.clone();
            tokio::spawn(async move {
                let info = format!(
                    "INFO {{\"server_id\":\"test\",\"version\":\"2.10.0\",\"host\":\"127.0.0.1\",\
                     \"port\":{port},\"max_payload\":1048576,\"proto\":1,\"auth_required\":true}}\r\n"
                );
                if socket.write_all(info.as_bytes()).await.is_err() {
                    return;
                }
                let mut seen = String::new();
                let mut buf = [0u8; 4096];
                let mut allowed: Option<bool> = None;
                loop {
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => seen.push_str(&String::from_utf8_lossy(&buf[..n])),
                    }
                    if allowed.is_none()
                        && let Some(line) = seen.lines().find(|l| l.starts_with("CONNECT "))
                    {
                        let connect: serde_json::Value =
                            serde_json::from_str(&line["CONNECT ".len()..]).unwrap_or_default();
                        let ok = connect["user"] == USER && connect["pass"] == PASSWORD;
                        if ok {
                            count.fetch_add(1, Ordering::SeqCst);
                        }
                        allowed = Some(ok);
                    }
                    if seen.contains("PING\r\n") {
                        if allowed != Some(true) {
                            let _ = socket
                                .write_all(b"-ERR 'Authorization Violation'\r\n")
                                .await;
                            return;
                        }
                        if socket.write_all(b"PONG\r\n").await.is_err() {
                            return;
                        }
                        seen.clear();
                    }
                }
            });
        }
    });
    (format!("nats://127.0.0.1:{port}"), signed_in)
}
