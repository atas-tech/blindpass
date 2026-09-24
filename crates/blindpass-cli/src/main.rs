// SPDX-License-Identifier: AGPL-3.0-only

use clap::{Args, Parser, Subcommand};
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Command as ProcessCommand, ExitCode};

const DEFAULT_ADMIN_SOCKET: &str = "/run/blindpass-controller/admin.sock";

#[derive(Debug, Parser)]
#[command(name = "blindpass", about = "Local Blindpass administration")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Admin(AdminCommand),
    /// Apply controller database migrations and exit.
    Migrate,
}

#[derive(Debug, Args)]
struct AdminCommand {
    #[command(subcommand)]
    command: AdminAction,
}

#[derive(Debug, Subcommand)]
enum AdminAction {
    /// Create the first administrator and print its one-time temporary password.
    Bootstrap {
        #[arg(long, default_value = "admin")]
        username: String,
        #[arg(long, default_value = "Blindpass administrator")]
        display_name: String,
        #[arg(long, default_value = DEFAULT_ADMIN_SOCKET)]
        socket: PathBuf,
    },
    /// Mint a one-use, 15-minute token for HTTP setup.
    BootstrapToken {
        #[arg(long, default_value = DEFAULT_ADMIN_SOCKET)]
        socket: PathBuf,
    },
    /// Seed agents from a JSON fixture in controller test mode.
    Seed {
        #[arg(long)]
        fixture: PathBuf,
    },
    /// Reset an operator password through the local administration socket.
    ResetPassword {
        id: String,
        #[arg(long, default_value = DEFAULT_ADMIN_SOCKET)]
        socket: PathBuf,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("blindpass: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    let command = match cli.command {
        Command::Migrate => return run_migrate(),
        Command::Admin(AdminCommand { command }) => command,
    };
    let (socket, request) = match command {
        AdminAction::Bootstrap {
            username,
            display_name,
            socket,
        } => (
            socket,
            json!({"command":"bootstrap","username":username,"display_name":display_name}),
        ),
        AdminAction::BootstrapToken { socket } => (socket, json!({"command":"bootstrap-token"})),
        AdminAction::Seed { fixture } => return run_seed(&fixture),
        AdminAction::ResetPassword { id, socket } => {
            (socket, json!({"command":"reset-password","id":id}))
        }
    };
    let response = call_admin_socket(&socket, &request)?;
    if response.get("error").is_some() {
        let error = response
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("admin_request_failed");
        return Err(error.to_owned());
    }
    let output = serde_json::to_string_pretty(&response)
        .map_err(|_| "could not format administration response".to_owned())?;
    println!("{output}");
    Ok(())
}

fn run_migrate() -> Result<(), String> {
    run_controller(&[std::ffi::OsStr::new("migrate")])
}

fn run_seed(fixture: &std::path::Path) -> Result<(), String> {
    run_controller(&[
        std::ffi::OsStr::new("seed"),
        std::ffi::OsStr::new("--fixture"),
        fixture.as_os_str(),
    ])
}

fn run_controller(args: &[&std::ffi::OsStr]) -> Result<(), String> {
    let controller = std::env::current_exe()
        .map_err(|_| "cannot locate installed CLI binary".to_owned())?
        .with_file_name("blindpass-controller");
    let status = ProcessCommand::new(controller)
        .args(args)
        .status()
        .map_err(|_| "cannot run colocated controller binary".to_owned())?;
    if status.success() {
        Ok(())
    } else {
        Err("controller command failed".to_owned())
    }
}

fn call_admin_socket(socket_path: &PathBuf, request: &Value) -> Result<Value, String> {
    let mut stream = UnixStream::connect(socket_path)
        .map_err(|_| "cannot connect to local administration socket".to_owned())?;
    let encoded = serde_json::to_vec(request)
        .map_err(|_| "could not encode administration request".to_owned())?;
    stream
        .write_all(&encoded)
        .and_then(|()| stream.write_all(b"\n"))
        .map_err(|_| "could not write to local administration socket".to_owned())?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|_| "could not finish local administration request".to_owned())?;
    let mut response = Vec::new();
    stream
        .take(8 * 1024)
        .read_to_end(&mut response)
        .map_err(|_| "could not read local administration response".to_owned())?;
    serde_json::from_slice(&response)
        .map_err(|_| "local administration returned an invalid response".to_owned())
}
