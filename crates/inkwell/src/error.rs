//! Error type + responses.
//!
//! Form/page failures render a small branded HTML error page; the few machine paths still
//! get a sensible status code. 401s additionally carry `WWW-Authenticate`. Keeping one enum
//! mirrors the keystone/keyward/beacon error seam.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    /// Malformed/incomplete form input (empty title, etc.).
    #[error("invalid_request: {0}")]
    InvalidRequest(String),

    /// No gateway-injected identity, or a failed CSRF check.
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    /// Authenticated, but not the owner of the targeted post.
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// No such post / slug.
    #[error("not_found: {0}")]
    NotFound(String),

    /// Slug collision on create (the UNIQUE(slug) guard).
    #[error("conflict: {0}")]
    Conflict(String),

    /// Unexpected internal failure (store I/O).
    #[error("server_error: {0}")]
    Internal(String),
}

impl AppError {
    fn parts(&self) -> (StatusCode, String, bool) {
        match self {
            AppError::InvalidRequest(d) => (StatusCode::BAD_REQUEST, d.clone(), false),
            AppError::Unauthorized(d) => (StatusCode::UNAUTHORIZED, d.clone(), true),
            AppError::Forbidden(d) => (StatusCode::FORBIDDEN, d.clone(), false),
            AppError::NotFound(d) => (StatusCode::NOT_FOUND, d.clone(), false),
            AppError::Conflict(d) => (StatusCode::CONFLICT, d.clone(), false),
            AppError::Internal(d) => (StatusCode::INTERNAL_SERVER_ERROR, d.clone(), false),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, description, www_authenticate) = self.parts();
        let body = crate::handlers::error_page(status, &description);
        let mut response = (status, Html(body)).into_response();
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("private, no-store"),
        );
        if www_authenticate {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        response
    }
}

/// Store failures collapse to their HTTP shape: a slug conflict is a 409, everything else 500.
impl From<crate::store::StoreError> for AppError {
    fn from(e: crate::store::StoreError) -> Self {
        match e {
            crate::store::StoreError::Conflict(m) => AppError::Conflict(m),
            crate::store::StoreError::Backend(m) => AppError::Internal(m),
        }
    }
}
