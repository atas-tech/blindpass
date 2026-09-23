// SPDX-License-Identifier: AGPL-3.0-only

//! Deliberately aborting probe used only to verify P01 core-dump handling.
//! Its per-run dummy canary arrives on stdin so it is not compiled in or put in
//! process arguments.

fn main() {
    let mut canary = String::new();
    if std::io::Read::read_to_string(&mut std::io::stdin(), &mut canary).is_err()
        || canary.is_empty()
    {
        std::process::abort();
    }
    std::hint::black_box(&canary);
    std::process::abort();
}
