//! Application errors, rendered as branded HTML pages.
//!
//! Agora is a browser-facing app (no JSON API surface), so a failure renders the same
//! enterprise shell as a friendly error page with the correct status code — never a raw
//! JSON envelope. Store failures collapse to a 500.

use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use thiserror::Error;

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
        let html = crate::handlers::render_error(heading, &message);
        (status, Html(html)).into_response()
    }
}

/// Store failures collapse to a 500 server_error.
impl From<crate::store::StoreError> for AppError {
    fn from(e: crate::store::StoreError) -> Self {
        AppError::Internal(e.to_string())
    }
}
