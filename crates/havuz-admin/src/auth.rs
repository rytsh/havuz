//! Bearer token middleware.

use axum::extract::{Request, State};
use axum::http::Method;
use axum::middleware::Next;
use axum::response::Response;

use crate::error::ApiError;
use crate::state::AdminState;

/// Paths that stay reachable without a token.
///
/// Health endpoints are probed by orchestrators that have no credentials, and
/// they expose nothing beyond liveness.
///
/// The dashboard's own files are public for a duller reason: a browser cannot
/// attach an `Authorization` header to the navigation that loads them, so a
/// dashboard behind the token is a dashboard nobody can ever enter a token
/// into. What is served there is a static bundle; every byte of data it
/// displays comes from `/api`, which stays shut. Only reads: a `POST` to a path
/// the router does not know is not something to wave through.
fn is_public(method: &Method, path: &str) -> bool {
    if matches!(path, "/healthz" | "/readyz") {
        return true;
    }
    if !matches!(*method, Method::GET | Method::HEAD) {
        return false;
    }
    !(path == "/api" || path.starts_with("/api/") || path == "/metrics")
}

pub async fn require_token(
    State(state): State<AdminState>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let Some(expected) = state.token.clone() else {
        // No token configured. The bootstrap validator has already refused to
        // start in this mode unless the listener is on loopback.
        return Ok(next.run(request).await);
    };

    if is_public(request.method(), request.uri().path()) {
        return Ok(next.run(request).await);
    }

    let presented = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    match presented {
        Some(token) if constant_time_eq(token.as_bytes(), expected.as_bytes()) => Ok(next.run(request).await),
        _ => Err(ApiError::Unauthorized),
    }
}

/// Comparing tokens byte by byte with `==` leaks their prefix through timing.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_endpoints_stay_public() {
        assert!(is_public(&Method::GET, "/healthz"));
        assert!(is_public(&Method::GET, "/readyz"));
        assert!(!is_public(&Method::GET, "/api/v1/pools"));
        assert!(!is_public(&Method::GET, "/metrics"), "metrics can reveal topology and must be protected");
    }

    #[test]
    fn the_dashboard_loads_but_its_data_does_not() {
        // The shell has to arrive for the operator to have somewhere to type
        // the token. Everything it then asks for is still refused without one.
        assert!(is_public(&Method::GET, "/"));
        assert!(is_public(&Method::GET, "/assets/app.js"));
        assert!(is_public(&Method::GET, "/databases"), "a hard refresh on a client-side route");
        assert!(!is_public(&Method::GET, "/api/v1/summary"));
        assert!(!is_public(&Method::GET, "/api"));
    }

    #[test]
    fn only_reads_are_public() {
        assert!(!is_public(&Method::POST, "/"));
        assert!(!is_public(&Method::DELETE, "/anything"));
    }

    #[test]
    fn token_comparison_is_length_safe() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secreT"));
        assert!(!constant_time_eq(b"secret", b"secret-longer"));
    }
}
