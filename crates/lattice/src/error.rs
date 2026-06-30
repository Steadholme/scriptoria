//! Error responses.
//!
//! Failures render a small HOLDFAST-styled HTML error page with the correct status code, so a
//! browser hitting the wiki always sees a coherent page (never a raw framework string).

use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    /// CSRF check failed on a state-changing POST.
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// Unexpected internal failure (store I/O).
    #[error("server_error: {0}")]
    Internal(String),
}

impl AppError {
    fn parts(&self) -> (StatusCode, String) {
        match self {
            AppError::Forbidden(d) => (StatusCode::FORBIDDEN, d.clone()),
            AppError::Internal(d) => (StatusCode::INTERNAL_SERVER_ERROR, d.clone()),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, detail) = self.parts();
        let title = match status {
            StatusCode::FORBIDDEN => "Forbidden",
            _ => "Something went wrong",
        };
        let body = crate::render::error_page(status.as_u16(), title, &detail);
        (status, Html(body)).into_response()
    }
}

/// Store failures collapse to a 500 server_error.
impl From<crate::store::StoreError> for AppError {
    fn from(e: crate::store::StoreError) -> Self {
        AppError::Internal(e.to_string())
    }
}
