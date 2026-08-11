//! Application errors.
//!
//! Browser routes render the branded HTML shell. The outer response-policy middleware converts
//! API and enhanced-JSON failures into a stable JSON envelope and applies no-store headers.
//! Raw backend diagnostics are logged server-side and never enter either representation.

use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use thiserror::Error;

use crate::view_model::{ErrorView, Text};

#[derive(Debug, Error)]
pub enum AppError {
    /// Malformed/empty input (missing title, blank body, unknown category).
    #[error("invalid_request: {0}")]
    InvalidRequest(String),

    /// No gateway-injected identity on a state-changing POST (defense in depth behind SSO).
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    /// CSRF double-submit check failed on a POST.
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// A referenced category/thread does not exist.
    #[error("not_found: {0}")]
    NotFound(String),

    /// Optimistic concurrency failed; the user must reload instead of overwriting newer state.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Unexpected internal failure (store I/O).
    #[error("server_error: {0}")]
    Internal(String),
}

impl AppError {
    fn parts(&self) -> (StatusCode, &'static str, String) {
        match self {
            AppError::InvalidRequest(d) => (StatusCode::BAD_REQUEST, "Invalid request", d.clone()),
            AppError::Unauthorized(d) => (StatusCode::UNAUTHORIZED, "Not signed in", d.clone()),
            AppError::Forbidden(d) => (StatusCode::FORBIDDEN, "Request blocked", d.clone()),
            AppError::NotFound(d) => (StatusCode::NOT_FOUND, "Not found", d.clone()),
            AppError::Conflict(d) => (StatusCode::CONFLICT, "Changed elsewhere", d.clone()),
            AppError::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong",
                "The discussion service is temporarily unavailable. Please retry.".to_string(),
            ),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, heading, message) = self.parts();
        let html = crate::views::shell::error(&ErrorView {
            heading: Text(heading.to_string()),
            message: Text(message),
            correlation_id: None,
        });
        (status, Html(html)).into_response()
    }
}

/// Store failures collapse to a 500 server_error.
impl From<crate::store::StoreError> for AppError {
    fn from(e: crate::store::StoreError) -> Self {
        match e {
            crate::store::StoreError::InvalidOperation(message) => {
                AppError::InvalidRequest(message)
            }
            crate::store::StoreError::NotFound(message) => AppError::NotFound(message),
            crate::store::StoreError::Conflict(message) => AppError::Conflict(message),
            crate::store::StoreError::Backend(message) => {
                tracing::error!(error = %message, "Agora Store backend failure");
                AppError::Internal(
                    "The discussion store is temporarily unavailable. Please retry.".to_string(),
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::body::to_bytes;
    use axum::response::IntoResponse;

    use super::AppError;
    use crate::store::StoreError;

    #[tokio::test]
    async fn backend_error_body_never_contains_raw_store_details() {
        let raw = "postgres://user:secret@db/internal relation missing";
        let response = AppError::from(StoreError::Backend(raw.to_string())).into_response();
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(!body.contains(raw));
        assert!(!body.contains("postgres://"));
        assert!(body.contains("temporarily unavailable"));
    }
}
