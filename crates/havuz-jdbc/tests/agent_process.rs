//! The agent client against a real JVM.
//!
//! Everything else about the bridge can be unit tested; process supervision
//! cannot. A mock that always answers proves nothing about the two failures
//! that actually happen in production — a JVM that is not installed, and a JVM
//! that dies mid-request.
//!
//! Skipped unless the agent has been built and a Java runtime is on PATH, so
//! `cargo test` stays runnable without either.

use std::path::PathBuf;
use std::time::Duration;

use havuz_jdbc::{Agent, AgentCommand, AgentError};
use serde_json::json;

fn agent_jar() -> Option<PathBuf> {
    let jar = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../agent/build/havuz-agent.jar");
    jar.exists().then(|| jar.canonicalize().expect("a path that exists resolves"))
}

fn java_available() -> bool {
    std::process::Command::new("java")
        .arg("-version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// `None` when the environment cannot run the agent, so the test skips rather
/// than fails on a machine with no JDK.
async fn start() -> Option<std::sync::Arc<Agent>> {
    let jar = agent_jar()?;
    if !java_available() {
        return None;
    }
    Some(Agent::start(&AgentCommand::new("java", jar)).await.expect("the agent must start"))
}

#[tokio::test]
async fn a_missing_java_is_reported_as_a_missing_java() {
    // The error an operator sees first, and the one worth getting right: a
    // bare "No such file or directory" sends them looking in the wrong place.
    let command = AgentCommand::new("definitely-not-java", "/nonexistent.jar");
    let error = Agent::start(&command).await.expect_err("there is no such runtime");
    let message = error.to_string();
    assert!(message.contains("Java runtime"), "got: {message}");
    assert!(message.contains("definitely-not-java"), "got: {message}");
}

#[tokio::test]
async fn the_handshake_reports_the_runtime_it_found() {
    let Some(agent) = start().await else { return };
    let info = agent.info();
    assert!(!info.java.is_empty());
    assert!(agent.is_alive());
    agent.shutdown().await;
}

#[tokio::test]
async fn an_unknown_method_fails_the_request_and_not_the_process() {
    // One bad request must not take the agent down with it; every other
    // session on that JVM is still using it.
    let Some(agent) = start().await else { return };

    let error = agent.call("no_such_method", json!({})).await.expect_err("unknown methods are refused");
    assert!(error.to_string().contains("no_such_method"), "got: {error}");

    assert!(agent.is_alive(), "a rejected request must not kill the agent");
    agent.call("handshake", json!({})).await.expect("the agent still answers");
    agent.shutdown().await;
}

#[tokio::test]
async fn opening_a_session_without_a_url_is_a_request_error() {
    let Some(agent) = start().await else { return };
    let error = agent.call("open_session", json!({})).await.expect_err("url is required");
    assert!(error.to_string().contains("url"), "got: {error}");
    agent.shutdown().await;
}

#[tokio::test]
async fn requests_after_a_shutdown_fail_fast_rather_than_timing_out() {
    // The failure mode this guards against is a pool that hangs for the full
    // request timeout on every checkout after the JVM has gone.
    let Some(agent) = start().await else { return };
    agent.shutdown().await;

    // The reader task needs a moment to notice stdout closed.
    for _ in 0..50 {
        if !agent.is_alive() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(!agent.is_alive(), "shutdown must be observed");

    let started = std::time::Instant::now();
    let error = agent.call("handshake", json!({})).await.expect_err("the agent is gone");
    assert!(matches!(error, AgentError::Gone(_)), "got: {error:?}");
    assert!(started.elapsed() < Duration::from_secs(5), "it must not wait out the request timeout");
}

#[tokio::test]
async fn many_requests_share_one_jvm() {
    // The whole reason the agent is multi-session: a JVM per backend
    // connection would cost more than pooling saves.
    let Some(agent) = start().await else { return };

    let mut handles = Vec::new();
    for _ in 0..16 {
        let agent = agent.clone();
        handles.push(tokio::spawn(async move { agent.call("handshake", json!({})).await }));
    }
    for handle in handles {
        handle.await.expect("no task panicked").expect("every request is answered");
    }
    agent.shutdown().await;
}
