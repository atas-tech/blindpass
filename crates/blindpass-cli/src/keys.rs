// SPDX-License-Identifier: AGPL-3.0-only

use blindpass_core::deployment::{DEFAULT_KEYS_DIR, check_keys, initialize_keys};
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Args)]
pub struct KeysCommand {
    #[command(subcommand)]
    action: KeysAction,
}

#[derive(Debug, Subcommand)]
enum KeysAction {
    /// Explicitly create new controller keys; existing trust is never replaced.
    Init {
        #[arg(long)]
        directory: Option<PathBuf>,
    },
    /// Validate the private controller directory and all three raw keys.
    Check {
        #[arg(long)]
        directory: Option<PathBuf>,
    },
}

pub fn run(command: KeysCommand) -> Result<(), String> {
    let (initialize, directory) = match command.action {
        KeysAction::Init { directory } => (true, directory),
        KeysAction::Check { directory } => (false, directory),
    };
    let directory = directory.unwrap_or_else(|| {
        std::env::var_os("BLINDPASS_KEYS_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_KEYS_DIR))
    });
    if initialize {
        initialize_keys(&directory).map_err(|_| "key initialization refused: directory unsafe, busy, or existing key material; no trust was replaced".to_owned())?;
        println!(
            "Controller keys initialized. Protect this directory and include it in encrypted recovery backups."
        );
    } else {
        check_keys(&directory)
            .map_err(|_| "controller keys missing, unsafe, busy, or invalid".to_owned())?;
        println!("Controller keys are valid.");
    }
    Ok(())
}
