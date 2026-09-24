// SPDX-License-Identifier: AGPL-3.0-only

use blindpass_controller::{
    admin_socket::{bind_admin_socket, serve_admin_socket},
    app::build_app,
    config::Config,
    observability,
    store::Store,
};
use std::future::IntoFuture;
use std::process::ExitCode;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("blindpass-controller: {message}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Vec<String>) -> Result<(), String> {
    match args.as_slice() {
        [command] if command == "check-config" => {
            Config::from_env().map_err(|error| error.to_string())?;
            println!("Controller configuration is valid.");
            Ok(())
        }
        [command] if command == "serve" => serve().await,
        [command] if command == "--help" || command == "-h" => {
            print_help();
            Ok(())
        }
        [] => {
            print_help();
            Err("a command is required".to_owned())
        }
        _ => {
            print_help();
            Err("expected `serve` or `check-config`".to_owned())
        }
    }
}

async fn serve() -> Result<(), String> {
    let config = Config::from_env().map_err(|error| error.to_string())?;
    observability::init(config.log_format()).map_err(str::to_owned)?;
    let store = Store::connect(config.database_url())
        .await
        .map_err(|_| "controller database initialization failed".to_owned())?;
    let sweep_store = store.clone();
    let audit_retention_days = config.audit_retention_days();
    let sweep_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            match sweep_store.sweep_expired(60).await {
                Ok(removed) if removed > 0 => {
                    tracing::info!(
                        records_removed = removed,
                        "expired controller records removed"
                    );
                }
                Ok(_) => {}
                Err(_) => tracing::warn!("controller retention sweep failed"),
            }
            match sweep_store.sweep_audit(audit_retention_days).await {
                Ok(removed) if removed > 0 => {
                    tracing::info!(records_removed = removed, "old audit records removed");
                }
                Ok(_) => {}
                Err(_) => tracing::warn!("controller audit retention sweep failed"),
            }
        }
    });
    let listener = TcpListener::bind(config.listen())
        .await
        .map_err(|_| "controller listener could not bind".to_owned())?;
    tracing::info!(address = %listener.local_addr().map_err(|_| "controller listener address unavailable")?, "controller listening");
    let admin_socket = bind_admin_socket(config.admin_socket_path())
        .map_err(|_| "local administration socket could not bind")?;
    let mut admin_task = tokio::spawn(serve_admin_socket(admin_socket, store.clone()));
    let app = build_app(config, Some(store));
    let server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .into_future();
    tokio::pin!(server);
    let result = tokio::select! {
        result = &mut server => result.map_err(|_| "controller server stopped unexpectedly".to_owned()),
        socket = &mut admin_task => {
            match socket {
                Ok(Ok(())) => Err("local administration socket stopped unexpectedly".to_owned()),
                Ok(Err(_)) | Err(_) => Err("local administration socket failed".to_owned()),
            }
        }
    };
    sweep_task.abort();
    admin_task.abort();
    result
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("register SIGTERM handler");
        signal.recv().await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}

fn print_help() {
    println!(
        "blindpass-controller <command>\n\nCommands:\n  serve        Run the local controller\n  check-config Validate configuration without starting the server"
    );
}
