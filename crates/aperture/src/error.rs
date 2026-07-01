//! Application errors, rendered as branded HTML pages.
//!
//! Aperture is a browser-facing app, so a failure renders the enterprise error page (same
//! app-bar + design tokens) rather than a JSON envelope. Store/blob failures collapse to a 500;
//! a missing file/token is a 404; a CSRF/validation rejection is a 400; a non-owner access is a
//! 403.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    /// Malformed/rejected request (e.g. CSRF mismatch, empty/oversized upload).
    #[error("bad_request: {0}")]
    BadRequest(String),

    /// Authenticated but not allowed (e.g. viewing/deleting someone else's file).
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// No such file, or no such share token.
    #[error("not_found: {0}")]
    NotFound(String),

    /// The resource existed but is no longer available (an expired share link).
    #[error("gone: {0}")]
    Gone(String),

    /// Unexpected internal failure (metadata or object-store I/O).
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
            AppError::Gone(d) => (StatusCode::GONE, "Link expired", d.clone()),
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
        crate::handlers::render_error(status, heading, &message, None).into_response()
    }
}

/// Metadata-store failures collapse to a 500 server_error.
impl From<crate::store::StoreError> for AppError {
    fn from(e: crate::store::StoreError) -> Self {
        AppError::Internal(e.to_string())
    }
}

/// Object-store failures: a missing blob is a 404, everything else a 500.
impl From<crate::blobs::BlobError> for AppError {
    fn from(e: crate::blobs::BlobError) -> Self {
        match e {
            crate::blobs::BlobError::NotFound => {
                AppError::NotFound("The stored file is no longer available.".to_string())
            }
            crate::blobs::BlobError::Backend(m) => AppError::Internal(m),
        }
    }
}
