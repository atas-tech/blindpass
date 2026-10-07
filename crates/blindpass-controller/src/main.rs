// SPDX-License-Identifier: AGPL-3.0-only

use axum::serve::ListenerExt;
use blindpass_controller::{
    admin_socket::{bind_admin_socket, serve_admin_socket},
    app::{build_app, build_app_with_ownership},
    config::Config,
    observability,
    owned_transport::{OwnedListener, TransportShutdown},
    ownership_session::claim_ownership,
    recovery_authority::ProcessOwnership,
    seed::{SeedRequest, seed_fixture},
    store::{FleetSigner, Store, StoreError},
    upgrade::PreUpgradeBackup,
};
use std::future::IntoFuture;
use std::io::Read;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use tokio::net::TcpListener;

mod healthcheck;

#[tokio::main]
async fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            if serde_json::from_str::<serde_json::Value>(&message).is_ok() {
                eprintln!("{message}");
            } else {
                eprintln!("blindpass-controller: {message}");
            }
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Vec<String>) -> Result<(), String> {
    match args.as_slice() {
        [command] if command == "--build-info" => {
            println!(
                "{}",
                serde_json::json!({
                    "version": env!("CARGO_PKG_VERSION"),
                    "schema_version": blindpass_controller::store::SCHEMA_VERSION,
                    "protocol_version": blindpass_controller::PROTOCOL_VERSION,
                    "console_embedded": blindpass_controller::embedded_ui::console_embedded(),
                    "input_embedded": blindpass_controller::embedded_ui::input_embedded(),
                })
            );
            Ok(())
        }
        [command] if command == "--version" || command == "-V" => {
            println!("blindpass-controller {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        [command] if command == "check-config" => {
            let config = Config::from_env().map_err(|error| error.to_string())?;
            config
                .require_authority()
                .map_err(|error| error.to_string())?;
            if config.is_test_mode() {
                // Test mode skips the ownership requirement, mounts the seed
                // route and trusts loopback forwarding. Say so on the one
                // command operators run to validate a profile.
                eprintln!(
                    "warning: BLINDPASS_TEST_MODE=1 is set; this is a test fixture, not a deployment"
                );
            }
            println!("Controller configuration is valid.");
            Ok(())
        }
        [command] if command == "healthcheck" => healthcheck::run(),
        [command, rest @ ..] if command == "backup" => {
            blindpass_controller::backup::run_command(rest)
                .await
                .map_err(|error| error.to_string())
        }
        [command, rest @ ..] if command == "restore" => {
            blindpass_controller::restore::run_command(rest)
                .await
                .map_err(|error| error.to_string())
        }
        [command, rest @ ..] if command == "handoff" => {
            blindpass_controller::handoff::run_command(rest)
                .await
                .map_err(|error| error.to_string())
        }
        [command, rest @ ..] if command == "migrate" => migrate(rest).await,
        [command] if command == "reconcile-clock" => reconcile_clock().await,
        [command, flag, path] if command == "seed" && flag == "--fixture" => {
            seed(Path::new(path)).await
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
            Err(
                "expected `serve`, `migrate`, `backup`, `restore`, `handoff`, `reconcile-clock`, `seed --fixture <file>`, `healthcheck` or `check-config`"
                    .to_owned(),
            )
        }
    }
}

async fn seed(path: &Path) -> Result<(), String> {
    let config = Config::from_env().map_err(|error| error.to_string())?;
    if !config.is_test_mode() {
        return Err("fixture seeding requires BLINDPASS_TEST_MODE=1".to_owned());
    }
    let file = std::fs::File::open(path).map_err(|_| "cannot open test fixture".to_owned())?;
    let mut contents = Vec::new();
    file.take(8 * 1024 + 1)
        .read_to_end(&mut contents)
        .map_err(|_| "cannot read test fixture".to_owned())?;
    if contents.len() > 8 * 1024 {
        return Err("test fixture is too large".to_owned());
    }
    let request: SeedRequest =
        serde_json::from_slice(&contents).map_err(|_| "test fixture is invalid".to_owned())?;
    let store = Store::connect(config.database_url())
        .await
        .map_err(|_| "controller database initialization failed".to_owned())?;
    let result = seed_fixture(&store, request).await;
    store.close().await;
    let response = result.map_err(|_| "test fixture seeding failed".to_owned())?;
    let output = serde_json::to_string(&response)
        .map_err(|_| "test fixture response could not be encoded".to_owned())?;
    println!("{output}");
    Ok(())
}

async fn reconcile_clock() -> Result<(), String> {
    let config = Config::from_env().map_err(|error| error.to_string())?;
    let ownership = claim_ownership(&config, true).await?;
    let result = if let Some(session) = ownership.as_ref() {
        let context = config
            .authority_context()
            .expect("validated authority context");
        Store::reconcile_clock_owned(
            config.database_url(),
            session.owner.clone(),
            &context.issuer_key_id,
        )
        .await
    } else {
        Store::reconcile_clock(config.database_url()).await
    };
    let summary = result.map_err(|_| "controller clock reconciliation failed".to_owned())?;
    let output = serde_json::to_string(&summary)
        .map_err(|_| "clock reconciliation summary could not be encoded".to_owned())?;
    println!("{output}");
    Ok(())
}

async fn migrate(args: &[String]) -> Result<(), String> {
    let upgrade = PreUpgradeBackup::from_args(args).map_err(str::to_owned)?;
    let config = Config::from_env().map_err(|error| error.to_string())?;
    let ownership = claim_ownership(&config, true).await?;
    if let Some(session) = ownership.as_ref() {
        let context = config
            .authority_context()
            .expect("validated authority context");
        let outcome = Store::migrate_owned(config.database_url(), config.clock_tolerance_ms(), session.owner.clone(), &context.issuer_key_id, upgrade.as_ref())
            .await.map_err(|error| match error {
                StoreError::InvalidInput(reason) => format!("controller database migration refused: {reason}"),
                _ => "controller database migration failed; protected current-schema initialization or verified upgrade required".to_owned(),
            })?;
        if outcome.backup_taken {
            println!(
                "{}",
                serde_json::to_string(&outcome)
                    .map_err(|_| "migration summary could not be encoded".to_owned())?
            );
        }
    } else {
        let store = Store::connect(config.database_url())
            .await
            .map_err(|_| "controller database migration failed".to_owned())?;
        store.close().await;
    }
    println!("Controller database migrations complete.");
    Ok(())
}

async fn serve() -> Result<(), String> {
    let config = Config::from_env().map_err(|error| error.to_string())?;
    observability::init(config.log_format()).map_err(str::to_owned)?;
    // The detached protected guard precedes controller database/clock writes.
    // No startup creates authority metadata or retries a used active revision.
    let mut ownership = claim_ownership(&config, false).await?;
    let result = if let Some(session) = ownership.as_ref() {
        let context = config
            .authority_context()
            .expect("validated authority context");
        Store::connect_existing_owned(
            config.database_url(),
            config.clock_tolerance_ms(),
            session.owner.clone(),
            &context.issuer_key_id,
        )
        .await
    } else if config.is_test_mode() {
        Store::connect_with_tolerance(config.database_url(), config.clock_tolerance_ms()).await
    } else {
        Store::connect_existing(config.database_url(), config.clock_tolerance_ms()).await
    };
    let store = result.map_err(|error| {
        serde_json::json!({"event":"startup_failed","reason":store_reason(&error)}).to_string()
    })?;
    let close_store = store.clone();
    let listener = TcpListener::bind(config.listen())
        .await
        .map_err(|_| "controller listener could not bind".to_owned())?;
    let admin_socket = bind_admin_socket(config.admin_socket_path())
        .map_err(|_| "local administration socket could not bind")?;
    // Fleet expiry signs OperationClosed documents, so the maintenance store
    // carries the same issuer as the HTTP application.
    let sweep_store = match config.issuer_keypair() {
        Some(keypair) => store
            .clone()
            .with_fleet_signer(FleetSigner::new(std::sync::Arc::clone(keypair))),
        None => store.clone(),
    };
    // Recovery review commands need the same signer-bearing store as the HTTP application.
    let admin_store = sweep_store.clone();
    let clock_task = store.spawn_clock_monitor();
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
            match sweep_store.expire_fleet_state().await {
                Ok(summary)
                    if summary.expired_approvals
                        + summary.expired_operations
                        + summary.expired_grants
                        > 0 =>
                {
                    tracing::info!(
                        approvals = summary.expired_approvals,
                        operations = summary.expired_operations,
                        grants = summary.expired_grants,
                        "expired fleet authorization records"
                    );
                }
                Ok(_) => {}
                Err(_) => tracing::warn!("fleet expiry sweep failed"),
            }
            if sweep_store.prune_fleet_state().await.is_err() {
                tracing::warn!("fleet retention sweep failed");
            }
        }
    });
    tracing::info!(address = %listener.local_addr().map_err(|_| "controller listener address unavailable")?, "controller listening");
    let mut admin_task = tokio::spawn(serve_admin_socket(admin_socket, admin_store));
    let tls_config = config.tls_config();
    let app = match ownership.as_ref() {
        Some(session) => build_app_with_ownership(config, Some(store), session.owner.clone()),
        None => build_app(config, Some(store)),
    };
    let service = app.into_make_service_with_connect_info::<std::net::SocketAddr>();
    let transport_owner = ownership.as_ref().map(|session| session.owner.clone());
    let transport_shutdown = Arc::new(TransportShutdown::default());
    let stop_transports = transport_shutdown.clone();
    let (result, admin_completed) = {
        let server = async move {
            if let Some(tls_config) = tls_config {
                // ListenerExt's wrapper preserves the concrete SocketAddr peer
                // through Axum's generic ConnectInfo implementation.
                let listener = OwnedListener::with_shutdown(
                    blindpass_controller::tls::TlsListener::new(listener, tls_config),
                    transport_owner.clone(),
                    transport_shutdown.clone(),
                )
                .tap_io(|_| {});
                axum::serve(listener, service)
                    .with_graceful_shutdown(shutdown_signal(transport_owner, transport_shutdown))
                    .into_future()
                    .await
            } else {
                let listener = OwnedListener::with_shutdown(
                    listener,
                    transport_owner.clone(),
                    transport_shutdown.clone(),
                )
                .tap_io(|_| {});
                axum::serve(listener, service)
                    .with_graceful_shutdown(shutdown_signal(transport_owner, transport_shutdown))
                    .into_future()
                    .await
            }
        };
        tokio::pin!(server);
        tokio::select! {
            result = &mut server => (result.map_err(|_| "controller server stopped unexpectedly".to_owned()), false),
            socket = &mut admin_task => {
                let result = match socket {
                    Ok(Ok(())) => Err("local administration socket stopped unexpectedly".to_owned()),
                    Ok(Err(_)) | Err(_) => Err("local administration socket failed".to_owned()),
                };
                (result, true)
            }
        }
    }; // Drop the listener/server future before resource drainage.
    if let Some(session) = ownership.as_ref() {
        session.owner.fence();
    }
    stop_transports.stop();
    sweep_task.abort();
    clock_task.abort();
    if !admin_completed {
        admin_task.abort();
    }
    let drained = tokio::time::timeout(std::time::Duration::from_secs(4), async {
        let _ = sweep_task.await;
        let _ = clock_task.await;
        if !admin_completed {
            let _ = (&mut admin_task).await;
        }
        if let Some(session) = ownership.as_mut() {
            session.monitor.abort();
            let _ = (&mut session.monitor).await;
        }
        close_store.close().await;
        if let Some(session) = ownership.as_mut() {
            session.owner.quiesce().await.map_err(|_| ())?;
            session.close_authority().await;
        }
        Ok::<(), ()>(())
    })
    .await;
    if !matches!(drained, Ok(Ok(()))) {
        return Err("controller shutdown did not drain within bound".to_owned());
    }
    // Ending local tracked work is not authenticated old-host stop proof or
    // proof of rollback/absence of ambiguous server-side COMMITs.
    result
}

fn store_reason(error: &StoreError) -> &'static str {
    blindpass_controller::app::store_failure_reason(error)
}

async fn shutdown_signal(owner: Option<Arc<ProcessOwnership>>, transports: Arc<TransportShutdown>) {
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
    if let Some(owner) = owner {
        owner.fence();
    }
    transports.stop();
}

fn print_help() {
    println!(
        "blindpass-controller <command>\n\nCommands:\n  serve                  Run the local controller\n  migrate                Apply database migrations and exit\n  backup key-init --output <file> [--role signing|recipient --certificate-output <file>]\n                         Create a protected credential (a role also writes its certificate)\n  backup create --output <directory> (--signing-credential-file <file> --recipient-certificate-file <file> | --recovery-key-file <file>)\n                         Capture and verify an encrypted complete backup\n  backup verify --archive <file> (--recipient-key-file <file> --signing-certificate-file <file> | --recovery-key-file <file>) --work-directory <directory> [--expected-archive-sha256 <hex>]\n                         Verify a backup in private staging\n  backup cleanup --work-directory <directory>\n                         Remove interrupted private staging under a custody lock\n  restore --archive <file> (--recipient-key-file <file> --signing-certificate-file <file> | --recovery-key-file <file>) [--expected-archive-sha256 <hex>] [--staging-directory <tmpfs-dir>] --destination <new-private-root> --authority-url-file <file> --tenant-id <id> --owner-id <id> --recovery-id <id>\n                         Publish authenticated SQLite state, remaining fenced\n  handoff export --output <directory> (--signing-credential-file <file> --recipient-certificate-file <file> | --recovery-key-file <file>) --handoff-id <id>\n  handoff import --archive <file> --receipt <file> (--recipient-key-file <file> --signing-certificate-file <file> | --recovery-key-file <file>) [--staging-directory <tmpfs-dir>] --destination <new-private-root> --authority-url-file <file> --tenant-id <id> --owner-id <id>\n  handoff abort --handoff-id <id> [--output <directory>]\n                         Planned same-owner SQLite handoff: fenced source export, import, abort\n  reconcile-clock        Recover from a detected database clock regression\n  seed --fixture <file>  Seed a test-mode fixture\n  check-config           Validate configuration without starting the server\n  healthcheck            Probe local readiness with bounded, verified transport"
    );
}
