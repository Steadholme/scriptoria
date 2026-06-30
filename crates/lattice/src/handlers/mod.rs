//! HTTP handlers.
//!
//! - [`health`] — unauthenticated liveness probe (`/healthz`).
//! - [`pages`] — the wiki: index, page view, editor (GET/POST), history, and the 404 fallback,
//!   all server-rendered and reading the Sluice-injected `X-Auth-*` for the editor identity.
//! - [`coherence`] — maintenance view: stale pages + heuristic contradiction candidates.

pub mod coherence;
pub mod health;
pub mod pages;
