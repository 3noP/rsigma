//! Dynamic NATS sources sign in with the connection settings the daemon gives
//! them (its `--nats-*` flags): the resolver's initial read, the scheduler's
//! push subscription and the control subject, against a server that requires
//! a user and a password. Without those settings each is refused, as before.

#![cfg(feature = "nats")]

mod common;

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use common::nats_auth::{PASSWORD, USER, auth_required_server};
use rsigma_eval::pipeline::sources::{
    DataFormat, DynamicSource, ErrorPolicy, RefreshPolicy, SourceType,
};
use rsigma_runtime::NatsConnectConfig;
use rsigma_runtime::sources::refresh::{RefreshScheduler, nats_control_loop};
use rsigma_runtime::sources::{DefaultSourceResolver, SourceResolver};

fn credentials() -> NatsConnectConfig {
    NatsConnectConfig {
        username: Some(USER.into()),
        password: Some(PASSWORD.into()),
        ..Default::default()
    }
}

fn source(url: &str, refresh: RefreshPolicy) -> DynamicSource {
    DynamicSource {
        id: "live_iocs".into(),
        source_type: SourceType::Nats {
            url: url.into(),
            subject: "rsigma.iocs.current".into(),
            format: DataFormat::Json,
            extract: None,
        },
        refresh,
        timeout: None,
        on_error: ErrorPolicy::Fail,
        required: false,
        default: None,
    }
}

#[tokio::test]
async fn the_resolver_signs_a_nats_source_in_with_its_settings() {
    let (url, signed_in) = auth_required_server().await;
    let with = DefaultSourceResolver::new().with_nats(credentials());
    with.resolve(&source(&url, RefreshPolicy::Once))
        .await
        .expect("signed in with the daemon's credentials");
    assert_eq!(signed_in.load(Ordering::SeqCst), 1);

    let without = DefaultSourceResolver::new();
    assert!(
        without
            .resolve(&source(&url, RefreshPolicy::Once))
            .await
            .is_err()
    );
    assert_eq!(signed_in.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn the_push_subscription_signs_in_with_the_schedulers_settings() {
    let (url, signed_in) = auth_required_server().await;
    // The resolver has no credentials: only the push subscription can sign in.
    let handle = RefreshScheduler::new().with_nats(credentials()).run(
        vec![source(&url, RefreshPolicy::Push)],
        Arc::new(DefaultSourceResolver::new()),
    );
    let mut waited = Duration::ZERO;
    while signed_in.load(Ordering::SeqCst) == 0 && waited < Duration::from_secs(10) {
        tokio::time::sleep(Duration::from_millis(50)).await;
        waited += Duration::from_millis(50);
    }
    handle.abort();
    assert_eq!(signed_in.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn the_control_subject_signs_in_with_its_settings() {
    let (url, signed_in) = auth_required_server().await;
    let (trigger_tx, _trigger_rx) = tokio::sync::mpsc::channel(1);
    let refused = tokio::time::timeout(
        Duration::from_secs(5),
        nats_control_loop(
            &NatsConnectConfig::new(url.clone()),
            "rsigma.control.resolve",
            trigger_tx.clone(),
        ),
    )
    .await
    .expect("refused at once");
    assert!(refused.is_err());

    let config = NatsConnectConfig {
        url,
        ..credentials()
    };
    // Signed in, it listens until stopped: still running when the wait ends.
    let listening = tokio::time::timeout(
        Duration::from_secs(1),
        nats_control_loop(&config, "rsigma.control.resolve", trigger_tx),
    )
    .await;
    assert!(listening.is_err());
    assert_eq!(signed_in.load(Ordering::SeqCst), 1);
}
