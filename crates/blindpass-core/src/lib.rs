// SPDX-License-Identifier: AGPL-3.0-only

//! Shared, dependency-free contracts for the host broker and future controller.
//!
//! The broker deliberately keeps its wire protocol and policy decisions in a
//! small crate that can be exercised without starting a privileged daemon.
//! OS-derived identity is still resolved by `blindpass-broker`; these types do
//! not treat caller-supplied process identifiers as authority.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod clock;
pub mod custody;
pub mod delivery;
pub mod identity;
pub mod policy;
pub mod protocol;
pub mod secret;
pub mod signing;

pub const PROTOCOL_VERSION: &str = "blindpass-broker/0.1";
pub const MAX_FRAME_BYTES: usize = 4096;
pub const MAX_CREDENTIAL_BYTES: usize = 64 * 1024;
