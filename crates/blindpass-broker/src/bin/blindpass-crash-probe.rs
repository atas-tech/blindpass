// SPDX-License-Identifier: AGPL-3.0-only

//! Deliberately aborting probe used only to verify P01 core-dump handling.

fn main() {
    let canary = String::from("P01-CRASH-CANARY");
    std::hint::black_box(&canary);
    std::process::abort();
}
