// SPDX-License-Identifier: AGPL-3.0-only

//! The replacement controller will own the HTTP/database contract in P02.
//! P01 keeps this crate in the shared workspace so core interfaces are compiled
//! by every server-side target from the beginning.

pub const PROTOCOL_VERSION: &str = blindpass_core::PROTOCOL_VERSION;
