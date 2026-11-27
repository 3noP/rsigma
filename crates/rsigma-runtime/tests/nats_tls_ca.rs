//! `NatsConnectConfig::tls_ca` (`--nats-tls-ca`): a NATS server whose
//! certificate a private CA issued is reached by naming that CA, and refused
//! without it; naming a CA requires TLS, so a server without TLS is refused
//! too. The servers are stand-ins that speak just enough of the protocol: an
//! INFO, the handshake where there is TLS, a PONG to each PING.

#![cfg(all(feature = "nats", feature = "otlp"))]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};
use rsigma_runtime::NatsConnectConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

/// A CA's certificate (PEM), and a server certificate it issued for
/// `localhost` and 127.0.0.1 with its key.
fn mint() -> (String, CertificateDer<'static>, PrivateKeyDer<'static>) {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "rsigma-nats-test-ca");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_key = KeyPair::generate().unwrap();
    let ca_pem = ca_params.self_signed(&ca_key).unwrap().pem();
    let issuer = Issuer::new(ca_params, ca_key);

    let mut server = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    server
        .subject_alt_names
        .push(SanType::IpAddress(std::net::IpAddr::from([127, 0, 0, 1])));
    server.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let key = KeyPair::generate().unwrap();
    let cert = server.signed_by(&key, &issuer).unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    (ca_pem, cert.der().clone(), key)
}

/// Serve NATS over TLS on 127.0.0.1 with this certificate; its port.
fn serve(cert: CertificateDer<'static>, key: PrivateKeyDer<'static>) -> u16 {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = Arc::new(
        rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut tcp in listener.incoming().flatten() {
            let config = config.clone();
            std::thread::spawn(move || {
                let info = format!(
                    "INFO {{\"server_id\":\"test\",\"version\":\"2.10.0\",\"host\":\"127.0.0.1\",\
                     \"port\":{port},\"max_payload\":1048576,\"proto\":1,\"tls_required\":true}}\r\n"
                );
                if tcp.write_all(info.as_bytes()).is_err() {
                    return;
                }
                let Ok(server) = rustls::ServerConnection::new(config) else {
                    return;
                };
                // Reading drives the handshake; a client that refuses the
                // certificate ends it there.
                let mut tls = rustls::StreamOwned::new(server, tcp);
                let mut seen = Vec::new();
                let mut buf = [0u8; 1024];
                loop {
                    match tls.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => seen.extend_from_slice(&buf[..n]),
                    }
                    if seen.windows(6).any(|w| w == b"PING\r\n") {
                        if tls.write_all(b"PONG\r\n").is_err() {
                            return;
                        }
                        seen.clear();
                    }
                }
            });
        }
    });
    port
}

/// Serve NATS in plaintext on 127.0.0.1: an INFO that asks for no TLS, a
/// PONG to each PING; its port.
fn serve_plaintext() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut tcp in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let info = format!(
                    "INFO {{\"server_id\":\"test\",\"version\":\"2.10.0\",\"host\":\"127.0.0.1\",\
                     \"port\":{port},\"max_payload\":1048576,\"proto\":1}}\r\n"
                );
                if tcp.write_all(info.as_bytes()).is_err() {
                    return;
                }
                let mut seen = Vec::new();
                let mut buf = [0u8; 1024];
                loop {
                    match tcp.read(&mut buf) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => seen.extend_from_slice(&buf[..n]),
                    }
                    if seen.windows(6).any(|w| w == b"PING\r\n") {
                        if tcp.write_all(b"PONG\r\n").is_err() {
                            return;
                        }
                        seen.clear();
                    }
                }
            });
        }
    });
    port
}

/// Connect to a stand-in server, naming its CA or not.
async fn connect(name_the_ca: bool) -> Result<async_nats::Client, async_nats::Error> {
    // async-nats builds its client config from the process-default provider.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let (ca_pem, cert, key) = mint();
    let mut ca = tempfile::NamedTempFile::new().unwrap();
    ca.write_all(ca_pem.as_bytes()).unwrap();
    let port = serve(cert, key);
    let config = NatsConnectConfig {
        url: format!("nats://localhost:{port}"),
        tls_ca: name_the_ca.then(|| ca.path().to_path_buf()),
        require_tls: true,
        ..Default::default()
    };
    tokio::time::timeout(Duration::from_secs(10), config.connect())
        .await
        .expect("connect did not return")
}

#[tokio::test]
async fn the_named_ca_lets_the_client_reach_the_server() {
    connect(true).await.expect("connected over TLS");
}

#[tokio::test]
async fn without_the_ca_the_server_is_refused() {
    let err = connect(false)
        .await
        .expect_err("a server certificate from an unknown CA must be refused");
    assert!(format!("{err:?}").contains("UnknownIssuer"), "{err:?}");
}

#[tokio::test]
async fn a_named_ca_refuses_a_server_without_tls() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let (ca_pem, _, _) = mint();
    let mut ca = tempfile::NamedTempFile::new().unwrap();
    ca.write_all(ca_pem.as_bytes()).unwrap();
    let url = format!("nats://127.0.0.1:{}", serve_plaintext());
    // The same server takes a client that names no CA.
    let plain = NatsConnectConfig::new(url.clone());
    tokio::time::timeout(Duration::from_secs(10), plain.connect())
        .await
        .expect("connect did not return")
        .expect("connected in plaintext");
    let config = NatsConnectConfig {
        url,
        tls_ca: Some(ca.path().to_path_buf()),
        ..Default::default()
    };
    let result = tokio::time::timeout(Duration::from_secs(20), config.connect())
        .await
        .expect("connect did not return");
    assert!(
        result.is_err(),
        "a client that names a CA must refuse a server without TLS"
    );
}
