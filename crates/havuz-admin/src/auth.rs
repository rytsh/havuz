//! Bearer token middleware.

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;

use crate::error::ApiError;
use crate::state::AdminState;

/// Paths that stay reachable without a token.
///
/// Health endpoints are probed by orchestrators that have no credentials, and
/// they expose nothing beyond liveness.
fn is_public(path: &str) -> bool {
    matches!(path, "/healthz" | "/readyz")
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

    if is_public(request.uri().path()) {
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
        assert!(is_public("/healthz"));
        assert!(is_public("/readyz"));
        assert!(!is_public("/api/v1/pools"));
        assert!(!is_public("/metrics"), "metrics can reveal topology and must be protected");
    }

    #[test]
    fn token_comparison_is_length_safe() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secreT"));
        assert!(!constant_time_eq(b"secret", b"secret-longer"));
    }
}
