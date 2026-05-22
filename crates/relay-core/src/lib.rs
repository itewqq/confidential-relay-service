//! Relay core: OpenAI-compatible reverse proxy with SSE streaming support.
//!
//! Security: This crate intentionally contains NO filesystem I/O for request/
//! response data and NO logging of payload content.

#![deny(unsafe_code)]

pub mod config;
pub mod error;
pub mod proxy;
pub mod router;
pub mod secrets;
