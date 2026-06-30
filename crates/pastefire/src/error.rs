//! Application errors, rendered as branded HTML pages.
//!
//! Pastefire is a browser-facing app, so a failure renders the enterprise error page (same
//! app-bar + design tokens) rather than a JSON envelope. Store failures collapse to a 500;
//! a missing/expired paste is a 404; a CSRF/ownership rejection is a 400/403.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    /// Malformed/rejected request (e.g. CSRF mismatch).
    #[error("bad_request: {0}")]
    BadRequest(String),

    /// Authenticated but not allowed (e.g. deleting someone else's paste).
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// No such paste, or it has expired.
    #[error("not_found: {0}")]
    NotFound(String),

    /// Unexpected internal failure (store I/O).
    #[error("server_error: {0}")]
    Internal(String),
}

impl AppError {
    /// Map to `(status, heading, message)` for the rendered error page.
    fn parts(&self) -> (StatusCode, &'static str, String) {
        match self {
            AppError::BadRequest(d) => (StatusCode::BAD_REQUEST, "Request rejected", d.clone()),
            AppError::Forbidden(d) => (StatusCode::FORBIDDEN, "Not allowed", d.clone()),
            AppError::NotFound(d) => (StatusCode::NOT_FOUND, "Not found", d.clone()),
            AppError::Internal(d) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something went wrong",
                d.clone(),
            ),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, heading, message) = self.parts();
        // No gateway identity is plumbed through the error path, so the app-bar shows the
        // generic "Pastefire" lockup.
        crate::handlers::render_error(status, heading, &message, None).into_response()
    }
}

/// Store failures collapse to a 500 server_error — the snippet itself is never wrong, only
/// the underlying storage can fail (DB I/O).
impl From<crate::store::StoreError> for AppError {
    fn from(e: crate::store::StoreError) -> Self {
        AppError::Internal(e.to_string())
    }
}
