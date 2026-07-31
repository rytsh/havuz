//! API errors.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0} not found")]
    NotFound(String),
    #[error("{0} already exists")]
    Conflict(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("{0}")]
    Internal(String),
}

impl ApiError {
    fn status(&self) -> StatusCode {
        match self {
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::NotFound(_) => StatusCode::NOT_FOUND,
            ApiError::Conflict(_) => StatusCode::CONFLICT,
            ApiError::Unauthorized => StatusCode::UNAUTHORIZED,
            ApiError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Stable machine-readable discriminator, so the UI does not have to match
    /// on human-readable text.
    fn code(&self) -> &'static str {
        match self {
            ApiError::BadRequest(_) => "bad_request",
            ApiError::NotFound(_) => "not_found",
            ApiError::Conflict(_) => "conflict",
            ApiError::Unauthorized => "unauthorized",
            ApiError::Internal(_) => "internal",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status();
        if status == StatusCode::INTERNAL_SERVER_ERROR {
            tracing::error!(error = %self, "admin request failed");
        }
        (status, Json(json!({ "error": { "code": self.code(), "message": self.to_string() } }))).into_response()
    }
}

impl From<havuz_core::StoreError> for ApiError {
    fn from(e: havuz_core::StoreError) -> Self {
        match e {
            // A rejected mutation is the operator's fault, not ours, and the
            // validation message is the useful part.
            havuz_core::StoreError::Invalid(inner) => ApiError::BadRequest(inner.to_string()),
            other => ApiError::Internal(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_match_the_failure_kind() {
        assert_eq!(ApiError::BadRequest("x".into()).status(), StatusCode::BAD_REQUEST);
        assert_eq!(ApiError::NotFound("pool".into()).status(), StatusCode::NOT_FOUND);
        assert_eq!(ApiError::Conflict("pool".into()).status(), StatusCode::CONFLICT);
        assert_eq!(ApiError::Unauthorized.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(ApiError::Internal("x".into()).status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn invalid_state_becomes_a_client_error_not_a_500() {
        let store_err = havuz_core::StoreError::Invalid(havuz_core::StateError::NoTargets("app_main".into()));
        let api: ApiError = store_err.into();
        assert_eq!(api.status(), StatusCode::BAD_REQUEST);
        assert!(api.to_string().contains("app_main"));
    }

    #[test]
    fn codes_are_stable_identifiers() {
        assert_eq!(ApiError::NotFound("x".into()).code(), "not_found");
        assert_eq!(ApiError::Unauthorized.code(), "unauthorized");
    }
}
