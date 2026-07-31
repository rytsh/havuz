//! Prometheus exposition.
//!
//! Rendered on demand from the same lock-free snapshots the dashboard uses, so
//! scraping costs one atomic load per counter and never touches the data path.

use std::fmt::Write;

use havuz_pg::GroupSnapshot;
use havuz_pool::PoolSnapshot;
use havuz_proto::PinReport;

pub fn render(pools: &[PoolSnapshot], groups: &[GroupSnapshot], pins: &PinReport, uptime_seconds: u64) -> String {
    let mut out = String::with_capacity(2048);

    metric(
        &mut out,
        "havuz_uptime_seconds",
        "gauge",
        "Seconds since the process started",
        &[(String::new(), uptime_seconds as f64)],
    );

    // The headline gauge. `havuz_pool_backend_connections` over
    // `havuz_pool_client_connections` is the fan-in an operator actually got.
    series(&mut out, "havuz_pool_backend_connections", "gauge", "Open backend connections", pools, |p| p.open as f64);
    series(&mut out, "havuz_pool_active_connections", "gauge", "Backends currently checked out", pools, |p| {
        p.active as f64
    });
    series(&mut out, "havuz_pool_idle_connections", "gauge", "Backends available for reuse", pools, |p| p.idle as f64);
    series(&mut out, "havuz_pool_waiting_clients", "gauge", "Clients queued for a backend", pools, |p| {
        p.waiting as f64
    });
    series(&mut out, "havuz_pool_max_size", "gauge", "Configured backend ceiling", pools, |p| p.max_size as f64);

    series(&mut out, "havuz_pool_checkouts_total", "counter", "Backend checkouts served", pools, |p| {
        p.checkout_total as f64
    });
    series(&mut out, "havuz_pool_connections_created_total", "counter", "Backend connections opened", pools, |p| {
        p.created_total as f64
    });
    series(&mut out, "havuz_pool_connections_closed_total", "counter", "Backend connections closed", pools, |p| {
        p.closed_total as f64
    });
    series(
        &mut out,
        "havuz_pool_checkout_timeouts_total",
        "counter",
        "Clients rejected after waiting out queue_timeout",
        pools,
        |p| p.timeout_total as f64,
    );
    series(&mut out, "havuz_pool_connect_errors_total", "counter", "Failed backend connection attempts", pools, |p| {
        p.connect_error_total as f64
    });
    series(
        &mut out,
        "havuz_pool_connections_discarded_total",
        "counter",
        "Backends retired instead of recycled",
        pools,
        |p| p.discarded_total as f64,
    );

    series(&mut out, "havuz_pool_wait_seconds_max", "gauge", "Longest observed checkout wait", pools, |p| {
        p.wait.max_micros as f64 / 1_000_000.0
    });
    series(&mut out, "havuz_pool_wait_seconds_mean", "gauge", "Mean checkout wait", pools, |p| {
        p.wait.mean_micros as f64 / 1_000_000.0
    });

    // Pin telemetry. `havuz_sessions_pinned_total` rising while
    // `havuz_pool_backend_connections` refuses to fall is the signature of a
    // transaction-mode pool that is not actually multiplexing.
    metric(
        &mut out,
        "havuz_sessions_pinned_total",
        "counter",
        "Transaction-mode sessions that lost the ability to share a backend",
        &pins
            .by_reason
            .iter()
            .map(|r| (format!("{{reason=\"{}\"}}", r.reason.as_str()), r.count as f64))
            .collect::<Vec<_>>(),
    );
    metric(
        &mut out,
        "havuz_sessions_clean_total",
        "counter",
        "Transaction-mode sessions that stayed shareable",
        &[(String::new(), pins.clean_sessions as f64)],
    );
    // Read/write split. `havuz_routing_statements_total{target="replica"}`
    // staying at zero while split is enabled means the replicas are not being
    // used, and the primary_reason counters say why.
    let mut routing_samples = Vec::new();
    let mut reason_samples = Vec::new();
    let mut lag_samples = Vec::new();
    let mut breaker_samples = Vec::new();

    for group in groups {
        let pool = escape(&group.name);
        routing_samples.push((format!("{{pool=\"{pool}\",target=\"primary\"}}"), group.routing.to_primary as f64));
        routing_samples.push((format!("{{pool=\"{pool}\",target=\"replica\"}}"), group.routing.to_replica as f64));

        for reason in &group.routing.primary_reasons {
            reason_samples
                .push((format!("{{pool=\"{pool}\",reason=\"{}\"}}", reason.reason.as_str()), reason.count as f64));
        }

        for replica in &group.replicas {
            let label = escape(&replica.routing.label);
            // An unmeasured replica is reported as -1 rather than 0: zero means
            // caught up, and a scrape must not confuse the two.
            lag_samples.push((
                format!("{{pool=\"{pool}\",replica=\"{label}\"}}"),
                replica.routing.lag_millis.map(|d| d.as_secs_f64()).unwrap_or(-1.0),
            ));
            breaker_samples.push((
                format!("{{pool=\"{pool}\",replica=\"{label}\",state=\"{}\"}}", replica.routing.breaker.state.as_str()),
                1.0,
            ));
        }
    }

    metric(
        &mut out,
        "havuz_routing_statements_total",
        "counter",
        "Statements routed to each target kind",
        &routing_samples,
    );
    metric(
        &mut out,
        "havuz_routing_primary_total",
        "counter",
        "Why a statement went to the primary instead of a replica",
        &reason_samples,
    );
    metric(
        &mut out,
        "havuz_replica_lag_seconds",
        "gauge",
        "Replication delay; -1 means not yet measured",
        &lag_samples,
    );
    metric(&mut out, "havuz_replica_breaker", "gauge", "Circuit breaker state per replica", &breaker_samples);

    metric(
        &mut out,
        "havuz_session_pin_rate",
        "gauge",
        "Share of transaction-mode sessions that were pinned",
        &[(String::new(), pins.pin_rate.unwrap_or(0.0) as f64)],
    );

    out
}

fn series<F>(out: &mut String, name: &str, kind: &str, help: &str, pools: &[PoolSnapshot], value: F)
where
    F: Fn(&PoolSnapshot) -> f64,
{
    let samples: Vec<(String, f64)> = pools
        .iter()
        .map(|p| (format!("{{pool=\"{}\",status=\"{}\"}}", escape(&p.name), escape(&p.status)), value(p)))
        .collect();
    metric(out, name, kind, help, &samples);
}

fn metric(out: &mut String, name: &str, kind: &str, help: &str, samples: &[(String, f64)]) {
    let _ = writeln!(out, "# HELP {name} {help}");
    let _ = writeln!(out, "# TYPE {name} {kind}");
    for (labels, value) in samples {
        let _ = writeln!(out, "{name}{labels} {value}");
    }
}

/// Label values are operator-supplied names; a stray quote would produce a
/// corrupt exposition that breaks the whole scrape, not just one series.
fn escape(value: &str) -> String {
    value.replace('\\', r"\\").replace('"', "\\\"").replace('\n', r"\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use havuz_pool::WaitStats;

    fn pins() -> PinReport {
        PinReport {
            pinned_sessions: 3,
            clean_sessions: 97,
            pin_rate: Some(0.03),
            by_reason: havuz_proto::PinReason::ALL
                .iter()
                .map(|r| havuz_proto::ReasonCount {
                    reason: *r,
                    count: if *r == havuz_proto::PinReason::SessionParameter { 3 } else { 0 },
                })
                .collect(),
            offenders: Vec::new(),
            truncated: false,
        }
    }

    fn snapshot(name: &str) -> PoolSnapshot {
        PoolSnapshot {
            name: name.into(),
            status: "active".into(),
            active: 3,
            idle: 1,
            open: 4,
            waiting: 96,
            max_size: 3,
            max_client_connections: 100,
            created_total: 4,
            closed_total: 0,
            checkout_total: 1234,
            timeout_total: 2,
            connect_error_total: 0,
            discarded_total: 1,
            wait: WaitStats { samples: 1234, mean_micros: 1500, max_micros: 250_000 },
        }
    }

    #[test]
    fn exposition_has_help_and_type_for_every_metric() {
        let out = render(&[snapshot("app_main")], &[], &pins(), 42);
        for line in out.lines().filter(|l| !l.starts_with('#') && !l.is_empty()) {
            let name = line.split(['{', ' ']).next().unwrap();
            assert!(out.contains(&format!("# HELP {name} ")), "{name} has no HELP");
            assert!(out.contains(&format!("# TYPE {name} ")), "{name} has no TYPE");
        }
    }

    #[test]
    fn pool_labels_are_present_and_values_are_correct() {
        let out = render(&[snapshot("app_main")], &[], &pins(), 42);
        assert!(out.contains("havuz_pool_backend_connections{pool=\"app_main\",status=\"active\"} 4"));
        assert!(out.contains("havuz_pool_waiting_clients{pool=\"app_main\",status=\"active\"} 96"));
        assert!(out.contains("havuz_pool_checkout_timeouts_total{pool=\"app_main\",status=\"active\"} 2"));
        assert!(out.contains("havuz_uptime_seconds 42"));
    }

    #[test]
    fn wait_times_are_reported_in_seconds() {
        let out = render(&[snapshot("app_main")], &[], &pins(), 1);
        assert!(out.contains("havuz_pool_wait_seconds_max{pool=\"app_main\",status=\"active\"} 0.25"));
    }

    #[test]
    fn label_values_are_escaped() {
        let mut s = snapshot(r#"we"ird\name"#);
        s.status = "active".into();
        let out = render(&[s], &[], &pins(), 1);
        assert!(out.contains(r#"pool="we\"ird\\name""#), "got:\n{out}");
        // The exposition must stay parseable: one series per line.
        assert!(!out.lines().any(|l| l.matches('\n').count() > 0));
    }

    #[test]
    fn no_pools_still_produces_valid_exposition() {
        let out = render(&[], &[], &pins(), 7);
        assert!(out.contains("havuz_uptime_seconds 7"));
        assert!(out.contains("# TYPE havuz_pool_backend_connections gauge"));
    }
}
