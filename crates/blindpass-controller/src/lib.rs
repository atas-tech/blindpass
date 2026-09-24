// SPDX-License-Identifier: AGPL-3.0-only

//! Rust HTTP controller for the retained SPS machine contract and local admin API.

pub mod admin_socket;
pub mod app;
pub mod config;
pub mod observability;
pub(crate) mod routes;
pub mod seed;
pub mod store;

/// Abruptly terminate at a persistence boundary in the dedicated P02 crash
/// test build. The feature is absent from normal controller builds.
#[inline]
pub(crate) fn p02_test_failpoint(name: &str) {
    #[cfg(feature = "p02-test-failpoints")]
    if std::env::var("BLINDPASS_TEST_MODE").as_deref() == Ok("1")
        && std::env::var("BLINDPASS_TEST_FAILPOINT").as_deref() == Ok(name)
    {
        std::process::exit(86);
    }

    #[cfg(not(feature = "p02-test-failpoints"))]
    let _ = name;
}

pub const PROTOCOL_VERSION: &str = blindpass_core::PROTOCOL_VERSION;
