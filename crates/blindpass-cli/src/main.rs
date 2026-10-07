// SPDX-License-Identifier: AGPL-3.0-only

use blindpass_core::fleet::node_key_fingerprint;
use blindpass_core::secret::wipe;
use blindpass_core::signing::base64_url_decode;
use clap::{Args, Parser, Subcommand};
use serde_json::{Value, json};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, ExitCode, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_ADMIN_SOCKET: &str = "/run/blindpass-controller/admin.sock";

mod keys;

#[derive(Debug, Parser)]
#[command(name = "blindpass", version, about = "Local Blindpass administration")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Admin(AdminCommand),
    /// Apply controller database migrations and exit. An older supported schema
    /// is migrated only after an encrypted pre-upgrade backup is published and
    /// verified; the backup directory and one credential model are then required.
    Migrate {
        #[arg(long)]
        pre_upgrade_backup_dir: Option<PathBuf>,
        #[command(flatten)]
        seal: SealCredentials,
    },
    /// Explicit controller key creation and private-file validation.
    Keys(keys::KeysCommand),
    /// Create or verify an authenticated complete controller backup.
    Backup(BackupCommand),
    /// Restore authenticated SQLite state into a new private, fenced destination.
    Restore(RestoreCommand),
    /// Report controller-observed state through the authenticated operator API.
    Status(StatusCommand),
    /// Planned same-owner SQLite handoff: export a fenced source, import into a
    /// new private root, or abort before anything activated. Not a restore.
    Handoff(HandoffCommand),
}

/// How an archive is sealed (ADR 0013): the single recovery credential of the
/// earlier model, or a signing credential plus the offline recipient's certificate.
#[derive(Debug, Args)]
struct SealCredentials {
    #[arg(long, conflicts_with_all = ["signing_credential_file", "recipient_certificate_file"])]
    recovery_key_file: Option<PathBuf>,
    /// Signing credential (private key and certificate) kept on the backup host.
    #[arg(long, requires = "recipient_certificate_file")]
    signing_credential_file: Option<PathBuf>,
    /// Certificate-only file of the offline recipient; never its private key.
    #[arg(long, requires = "signing_credential_file")]
    recipient_certificate_file: Option<PathBuf>,
}
impl SealCredentials {
    fn is_empty(&self) -> bool {
        self.recovery_key_file.is_none() && self.signing_credential_file.is_none()
    }
    fn require(&self) -> Result<(), String> {
        if self.recovery_key_file.is_some() != self.signing_credential_file.is_some() {
            Ok(())
        } else {
            Err("choose --recovery-key-file or both --signing-credential-file and --recipient-certificate-file".to_owned())
        }
    }
    fn push<'a>(&'a self, out: &mut Vec<&'a std::ffi::OsStr>) {
        use std::ffi::OsStr;
        if let Some(key) = &self.recovery_key_file {
            out.extend([OsStr::new("--recovery-key-file"), key.as_os_str()]);
        }
        if let (Some(signing), Some(recipient)) = (
            &self.signing_credential_file,
            &self.recipient_certificate_file,
        ) {
            out.extend([
                OsStr::new("--signing-credential-file"),
                signing.as_os_str(),
                OsStr::new("--recipient-certificate-file"),
                recipient.as_os_str(),
            ]);
        }
    }
}

/// How an archive is opened: the single recovery credential, or the offline
/// recipient key with the signer's certificate (certificate-only is enough).
#[derive(Debug, Args)]
struct OpenCredentials {
    #[arg(long, conflicts_with_all = ["recipient_key_file", "signing_certificate_file"])]
    recovery_key_file: Option<PathBuf>,
    #[arg(long, requires = "signing_certificate_file")]
    recipient_key_file: Option<PathBuf>,
    #[arg(long, requires = "recipient_key_file")]
    signing_certificate_file: Option<PathBuf>,
}
impl OpenCredentials {
    fn require(&self) -> Result<(), String> {
        if self.recovery_key_file.is_some() != self.recipient_key_file.is_some() {
            Ok(())
        } else {
            Err("choose --recovery-key-file or both --recipient-key-file and --signing-certificate-file".to_owned())
        }
    }
    fn push<'a>(&'a self, out: &mut Vec<&'a std::ffi::OsStr>) {
        use std::ffi::OsStr;
        if let Some(key) = &self.recovery_key_file {
            out.extend([OsStr::new("--recovery-key-file"), key.as_os_str()]);
        }
        if let (Some(key), Some(certificate)) =
            (&self.recipient_key_file, &self.signing_certificate_file)
        {
            out.extend([
                OsStr::new("--recipient-key-file"),
                key.as_os_str(),
                OsStr::new("--signing-certificate-file"),
                certificate.as_os_str(),
            ]);
        }
    }
}

#[derive(Debug, Args)]
struct HandoffCommand {
    #[command(subcommand)]
    command: HandoffAction,
}

#[derive(Debug, Subcommand)]
enum HandoffAction {
    /// Seal the verified archive and retire the fenced source.
    Export {
        #[arg(long)]
        output: PathBuf,
        #[command(flatten)]
        seal: SealCredentials,
        #[arg(long)]
        handoff_id: String,
    },
    /// Publish the archive into a new private root under the same owner.
    Import {
        #[arg(long)]
        archive: PathBuf,
        #[arg(long)]
        receipt: PathBuf,
        #[command(flatten)]
        open: OpenCredentials,
        /// Private tmpfs directory for decrypted material (default: the runtime
        /// directory, then /dev/shm); persistent disk is refused.
        #[arg(long)]
        staging_directory: Option<PathBuf>,
        #[arg(long)]
        destination: PathBuf,
        #[arg(long)]
        authority_url_file: PathBuf,
        #[arg(long)]
        tenant_id: String,
        #[arg(long)]
        owner_id: String,
    },
    /// Un-retire the source while the authority record is still the exported one.
    Abort {
        #[arg(long)]
        handoff_id: String,
        /// Also delete this handoff's transfer files from the export directory.
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

fn run_handoff(command: HandoffCommand) -> Result<(), String> {
    use std::ffi::OsStr;
    match command.command {
        HandoffAction::Export {
            output,
            seal,
            handoff_id,
        } => {
            seal.require()?;
            let mut arguments = vec![
                OsStr::new("handoff"),
                OsStr::new("export"),
                OsStr::new("--output"),
                output.as_os_str(),
            ];
            seal.push(&mut arguments);
            arguments.extend([OsStr::new("--handoff-id"), OsStr::new(&handoff_id)]);
            run_controller(&arguments)
        }
        HandoffAction::Import {
            archive,
            receipt,
            open,
            staging_directory,
            destination,
            authority_url_file,
            tenant_id,
            owner_id,
        } => {
            open.require()?;
            let mut arguments = vec![
                OsStr::new("handoff"),
                OsStr::new("import"),
                OsStr::new("--archive"),
                archive.as_os_str(),
                OsStr::new("--receipt"),
                receipt.as_os_str(),
            ];
            open.push(&mut arguments);
            if let Some(staging) = &staging_directory {
                arguments.extend([OsStr::new("--staging-directory"), staging.as_os_str()]);
            }
            arguments.extend([
                OsStr::new("--destination"),
                destination.as_os_str(),
                OsStr::new("--authority-url-file"),
                authority_url_file.as_os_str(),
                OsStr::new("--tenant-id"),
                OsStr::new(&tenant_id),
                OsStr::new("--owner-id"),
                OsStr::new(&owner_id),
            ]);
            run_controller(&arguments)
        }
        HandoffAction::Abort { handoff_id, output } => {
            let mut arguments = vec![
                OsStr::new("handoff"),
                OsStr::new("abort"),
                OsStr::new("--handoff-id"),
                OsStr::new(&handoff_id),
            ];
            if let Some(output) = &output {
                arguments.extend([OsStr::new("--output"), output.as_os_str()]);
            }
            run_controller(&arguments)
        }
    }
}

#[derive(Debug, Args)]
struct StatusCommand {
    #[command(flatten)]
    http: HttpOptions,
    /// Summarize every registered node: online (seen within 45 s), stale (120 s),
    /// offline or revoked, with no key material or capabilities.
    #[arg(long, required = true)]
    nodes: bool,
    /// Exit non-zero unless at least one node is active and every active node is
    /// online. For migration and rollback gates.
    #[arg(long)]
    require_online: bool,
}

#[derive(Debug, Args)]
struct RestoreCommand {
    #[arg(long)]
    archive: PathBuf,
    #[command(flatten)]
    open: OpenCredentials,
    /// Refuse any archive whose SHA-256 is not the one recorded off-host.
    #[arg(long)]
    expected_archive_sha256: Option<String>,
    /// Private tmpfs directory for decrypted material (default: the runtime
    /// directory, then /dev/shm); persistent disk is refused.
    #[arg(long)]
    staging_directory: Option<PathBuf>,
    #[arg(long)]
    destination: PathBuf,
    #[arg(long)]
    authority_url_file: PathBuf,
    /// Required for a PostgreSQL archive: private file holding the empty target
    /// database URL. A SQLite archive must not set it.
    #[arg(long)]
    database_url_file: Option<PathBuf>,
    #[arg(long)]
    tenant_id: String,
    #[arg(long)]
    owner_id: String,
    #[arg(long)]
    recovery_id: String,
}
fn run_restore(command: RestoreCommand) -> Result<(), String> {
    use std::ffi::OsStr;
    command.open.require()?;
    let mut arguments = vec![
        OsStr::new("restore"),
        OsStr::new("--archive"),
        command.archive.as_os_str(),
    ];
    command.open.push(&mut arguments);
    if let Some(digest) = &command.expected_archive_sha256 {
        arguments.extend([OsStr::new("--expected-archive-sha256"), OsStr::new(digest)]);
    }
    if let Some(staging) = &command.staging_directory {
        arguments.extend([OsStr::new("--staging-directory"), staging.as_os_str()]);
    }
    arguments.extend([
        OsStr::new("--destination"),
        command.destination.as_os_str(),
        OsStr::new("--authority-url-file"),
        command.authority_url_file.as_os_str(),
        OsStr::new("--tenant-id"),
        OsStr::new(&command.tenant_id),
        OsStr::new("--owner-id"),
        OsStr::new(&command.owner_id),
        OsStr::new("--recovery-id"),
        OsStr::new(&command.recovery_id),
    ]);
    if let Some(url) = &command.database_url_file {
        arguments.extend([OsStr::new("--database-url-file"), url.as_os_str()]);
    }
    run_controller(&arguments)
}

#[derive(Debug, Args)]
struct BackupCommand {
    #[command(subcommand)]
    command: BackupAction,
}
#[derive(Debug, Subcommand)]
enum BackupAction {
    /// Create a private credential; never overwrite. Without `--role` this is the
    /// single recovery key of the earlier model; `--role signing|recipient` with
    /// `--certificate-output` also writes the certificate-only file (ADR 0013).
    KeyInit {
        #[arg(long)]
        output: PathBuf,
        #[arg(long, value_parser = ["signing", "recipient"], requires = "certificate_output")]
        role: Option<String>,
        #[arg(long, requires = "role")]
        certificate_output: Option<PathBuf>,
    },
    /// Snapshot initialized state, authenticate/encrypt and verify before publication.
    Create {
        #[arg(long)]
        output: PathBuf,
        #[command(flatten)]
        seal: SealCredentials,
    },
    /// Verify using private staging; never activate restored state.
    Verify {
        #[arg(long)]
        archive: PathBuf,
        #[command(flatten)]
        open: OpenCredentials,
        #[arg(long)]
        work_directory: PathBuf,
        /// Refuse any archive whose SHA-256 is not the one recorded off-host.
        #[arg(long)]
        expected_archive_sha256: Option<String>,
    },
    /// Remove interrupted private staging under an exclusive custody lock.
    Cleanup {
        #[arg(long)]
        work_directory: PathBuf,
    },
}

fn run_backup(command: BackupCommand) -> Result<(), String> {
    use std::ffi::OsStr;
    match command.command {
        BackupAction::KeyInit {
            output,
            role,
            certificate_output,
        } => {
            let mut arguments = vec![
                OsStr::new("backup"),
                OsStr::new("key-init"),
                OsStr::new("--output"),
                output.as_os_str(),
            ];
            if let (Some(role), Some(certificate)) = (&role, &certificate_output) {
                arguments.extend([
                    OsStr::new("--role"),
                    OsStr::new(role),
                    OsStr::new("--certificate-output"),
                    certificate.as_os_str(),
                ]);
            }
            run_controller(&arguments)
        }
        BackupAction::Create { output, seal } => {
            seal.require()?;
            let mut arguments = vec![
                OsStr::new("backup"),
                OsStr::new("create"),
                OsStr::new("--output"),
                output.as_os_str(),
            ];
            seal.push(&mut arguments);
            run_controller(&arguments)
        }
        BackupAction::Verify {
            archive,
            open,
            work_directory,
            expected_archive_sha256,
        } => {
            open.require()?;
            let mut arguments = vec![
                OsStr::new("backup"),
                OsStr::new("verify"),
                OsStr::new("--archive"),
                archive.as_os_str(),
            ];
            open.push(&mut arguments);
            arguments.extend([OsStr::new("--work-directory"), work_directory.as_os_str()]);
            if let Some(digest) = &expected_archive_sha256 {
                arguments.extend([OsStr::new("--expected-archive-sha256"), OsStr::new(digest)]);
            }
            run_controller(&arguments)
        }
        BackupAction::Cleanup { work_directory } => run_controller(&[
            OsStr::new("backup"),
            OsStr::new("cleanup"),
            OsStr::new("--work-directory"),
            work_directory.as_os_str(),
        ]),
    }
}

#[derive(Debug, Args)]
struct AdminCommand {
    #[command(flatten)]
    http: HttpOptions,
    #[command(subcommand)]
    command: AdminAction,
}

#[derive(Debug, Args, Default)]
struct HttpOptions {
    /// Controller origin for authenticated fleet administration.
    #[arg(long, global = true)]
    controller_url: Option<String>,
    /// Exact controller-approved browser origin; defaults to --controller-url.
    #[arg(long, global = true)]
    origin: Option<String>,
    /// Operator username for authenticated fleet administration.
    #[arg(long, global = true)]
    username: Option<String>,
    /// Read the operator password from stdin (never from a command-line value).
    #[arg(long, global = true)]
    password_stdin: bool,
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
    /// Recover from a detected database clock regression. Removes expiring
    /// state created under the regressed clock and revokes operator sessions.
    ReconcileClock,
    /// Reset an operator password through the local administration socket. This
    /// is also the recovery for a locked-out account: it clears every sign-in
    /// lock, revokes the operator's sessions and prints a temporary password.
    ResetPassword {
        /// The operator's username (as the console shows it, any letter case) or
        /// its id. `blindpass admin operators list` shows both.
        #[arg(value_name = "OPERATOR")]
        id: String,
        #[arg(long, default_value = DEFAULT_ADMIN_SOCKET)]
        socket: PathBuf,
    },
    /// Show operators (id, username, role, state) through the local
    /// administration socket, without opening the database.
    Operators {
        #[command(subcommand)]
        command: OperatorsAction,
    },
    /// Review and complete a restored controller's quarantined state through the
    /// recovering controller's local administration socket (never an API call).
    Recovery {
        #[command(subcommand)]
        command: RecoveryAction,
    },
    /// Manage one-use node enrollment requests through the controller API.
    Enrollment {
        #[command(subcommand)]
        command: EnrollmentAction,
    },
    /// Rotate or revoke a registered node through the controller API.
    Node {
        #[command(subcommand)]
        command: NodeAction,
    },
}

#[derive(Debug, Subcommand)]
enum OperatorsAction {
    /// List operators: id, username, role and sign-in lock state. Identity and
    /// state only; never a password, hash or session.
    List {
        /// Print the raw JSON answer instead of a table.
        #[arg(long)]
        json: bool,
        #[arg(long, default_value = DEFAULT_ADMIN_SOCKET)]
        socket: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum RecoveryAction {
    /// Open gates, node coverage and undecided items. Changes nothing.
    Status {
        #[arg(long, default_value = DEFAULT_ADMIN_SOCKET)]
        socket: PathBuf,
    },
    /// List and decide quarantined operations, grants and accounts.
    Review {
        #[command(subcommand)]
        command: RecoveryReviewAction,
    },
    /// Waive a node that cannot report. Its broker trust is revoked; it must be
    /// re-enrolled after activation.
    WaiveNode {
        node_id: String,
        #[arg(long)]
        operator: String,
        #[arg(long, default_value = "")]
        note: String,
        #[arg(long, default_value = DEFAULT_ADMIN_SOCKET)]
        socket: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum RecoveryReviewAction {
    /// One page (100 items) of items with their decisions.
    List {
        #[arg(long, default_value_t = 0)]
        offset: u64,
        #[arg(long, default_value = DEFAULT_ADMIN_SOCKET)]
        socket: PathBuf,
    },
    /// Record accept|reject|revoke for one item, or for every undecided item of a
    /// category when --subject is omitted. Decisions can change until `complete`.
    Decide {
        #[arg(long)]
        category: String,
        #[arg(long)]
        subject: Option<String>,
        #[arg(long, default_value = "")]
        related: String,
        #[arg(long)]
        decision: String,
        #[arg(long)]
        operator: String,
        #[arg(long, default_value = "")]
        note: String,
        #[arg(long, default_value = DEFAULT_ADMIN_SOCKET)]
        socket: PathBuf,
    },
    /// Declare the review complete. Refused while an item is undecided or a node is
    /// neither covered nor waived. Final: decisions and waivers close.
    Complete {
        #[arg(long)]
        operator: String,
        #[arg(long, default_value = DEFAULT_ADMIN_SOCKET)]
        socket: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum EnrollmentAction {
    /// Create an enrollment token and write it once to a new mode-0600 file.
    Create {
        name: String,
        #[arg(long)]
        token_file: PathBuf,
    },
    /// List enrollment requests.
    List,
    /// Approve a submitted node after comparing its displayed fingerprint.
    Approve {
        id: String,
        #[arg(long)]
        expected_fingerprint: String,
    },
    /// Reject a submitted node after comparing its displayed fingerprint.
    Reject {
        id: String,
        #[arg(long)]
        expected_fingerprint: String,
    },
}

#[derive(Debug, Subcommand)]
enum NodeAction {
    /// Revoke a node; --confirm must repeat the node ID.
    Revoke {
        id: String,
        #[arg(long)]
        confirm: String,
    },
    /// Stage broker-prepared public keys from `blindpass-node rotate-prepare`.
    Rotate {
        id: String,
        #[arg(long)]
        metadata_file: PathBuf,
        #[arg(long)]
        expected_fingerprint: String,
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
    let admin = match cli.command {
        Command::Migrate {
            pre_upgrade_backup_dir,
            seal,
        } => return run_migrate(pre_upgrade_backup_dir, &seal),
        Command::Keys(command) => return keys::run(command),
        Command::Backup(command) => return run_backup(command),
        Command::Restore(command) => return run_restore(command),
        Command::Status(command) => return run_status(command),
        Command::Handoff(command) => return run_handoff(command),
        Command::Admin(admin) => admin,
    };
    let AdminCommand { http, command } = admin;
    if matches!(
        command,
        AdminAction::Enrollment { .. } | AdminAction::Node { .. }
    ) {
        return run_fleet_admin(&http, command);
    }
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
        AdminAction::ReconcileClock => {
            return run_controller(&[std::ffi::OsStr::new("reconcile-clock")]);
        }
        AdminAction::ResetPassword { id, socket } => {
            (socket, json!({"command":"reset-password","id":id}))
        }
        AdminAction::Recovery { command } => return run_recovery(command),
        AdminAction::Operators { command } => return run_operators(command),
        AdminAction::Enrollment { .. } | AdminAction::Node { .. } => unreachable!(),
    };
    let response = call_admin_socket(&socket, &request)?;
    if response.get("error").is_some() {
        let error = response
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("admin_request_failed");
        return Err(explain_admin_error(error));
    }
    let output = serde_json::to_string_pretty(&response)
        .map_err(|_| "could not format administration response".to_owned())?;
    println!("{output}");
    Ok(())
}

fn admin_call(socket: &PathBuf, request: &Value) -> Result<Value, String> {
    let response = call_admin_socket(socket, request)?;
    match response.get("error").and_then(Value::as_str) {
        Some(error) => Err(explain_admin_error(error)),
        None => Ok(response),
    }
}

/// Fixed guidance for the operator-reference errors; every other code is shown
/// unchanged. Never echoes what the operator typed.
fn explain_admin_error(code: &str) -> String {
    let guidance = match code {
        "operator_not_found" => {
            "no enabled operator has that id or username; run `blindpass admin operators list` to see them"
        }
        "operator_ambiguous" => {
            "two operators differ only by letter case; use the id shown by `blindpass admin operators list`"
        }
        "operator_disabled" => {
            "that operator is disabled; a password reset applies to enabled operators only"
        }
        "invalid_operator_id" => {
            "give an operator id or username (letters, digits, '.', '_', '@', '-', up to 64 characters)"
        }
        _ => return code.to_owned(),
    };
    format!("{code}: {guidance}")
}

fn run_operators(command: OperatorsAction) -> Result<(), String> {
    let OperatorsAction::List { json, socket } = command;
    let response = admin_call(&socket, &json!({"command":"operators-list"}))?;
    if json {
        return print_json(&response);
    }
    let rows = response
        .get("operators")
        .and_then(Value::as_array)
        .ok_or_else(|| "unexpected operators response".to_owned())?;
    let text = |row: &Value, name: &str| {
        row.get(name)
            .and_then(Value::as_str)
            .unwrap_or("-")
            .to_owned()
    };
    let number = |row: &Value, name: &str| row.get(name).and_then(Value::as_u64).unwrap_or(0);
    let mut table = vec![[
        "ID".to_owned(),
        "USERNAME".to_owned(),
        "ROLE".to_owned(),
        "STATE".to_owned(),
    ]];
    for row in rows {
        let mut state = Vec::new();
        if row.get("disabled").and_then(Value::as_bool) == Some(true) {
            state.push("disabled".to_owned());
        }
        if row.get("must_change_password").and_then(Value::as_bool) == Some(true) {
            state.push("must change password".to_owned());
        }
        let locked = number(row, "account_locked_seconds");
        if locked > 0 {
            state.push(format!("locked {locked}s"));
        }
        let sources = number(row, "source_locks");
        if sources > 0 {
            state.push(format!("{sources} source(s) locked"));
        }
        if state.is_empty() {
            state.push("ok".to_owned());
        }
        table.push([
            text(row, "id"),
            text(row, "username"),
            text(row, "role"),
            state.join(", "),
        ]);
    }
    let widths: Vec<usize> = (0..3)
        .map(|column| table.iter().map(|row| row[column].len()).max().unwrap_or(0))
        .collect();
    for row in &table {
        println!(
            "{:<w0$}  {:<w1$}  {:<w2$}  {}",
            row[0],
            row[1],
            row[2],
            row[3],
            w0 = widths[0],
            w1 = widths[1],
            w2 = widths[2]
        );
    }
    Ok(())
}

fn run_recovery(command: RecoveryAction) -> Result<(), String> {
    match command {
        RecoveryAction::Status { socket } => {
            print_json(&admin_call(&socket, &json!({"command":"recovery-status"}))?)
        }
        RecoveryAction::WaiveNode {
            node_id,
            operator,
            note,
            socket,
        } => print_json(&admin_call(
            &socket,
            &json!({"command":"recovery-waive-node","node_id":node_id,"operator":operator,"note":note}),
        )?),
        RecoveryAction::Review { command } => match command {
            RecoveryReviewAction::List { offset, socket } => print_json(&admin_call(
                &socket,
                &json!({"command":"recovery-review-list","offset":offset}),
            )?),
            RecoveryReviewAction::Complete { operator, socket } => print_json(&admin_call(
                &socket,
                &json!({"command":"recovery-review-complete","operator":operator}),
            )?),
            RecoveryReviewAction::Decide {
                category,
                subject,
                related,
                decision,
                operator,
                note,
                socket,
            } => {
                let decide = |subject: &str, related: &str| {
                    admin_call(
                        &socket,
                        &json!({"command":"recovery-review-decide","category":category,"subject_id":subject,
                            "related_id":related,"decision":decision,"operator":operator,"note":note}),
                    )
                };
                if let Some(subject) = subject {
                    decide(&subject, &related)?;
                    return print_json(&json!({"decided":1}));
                }
                // Whole category: undecided items only, read page by page.
                let mut decided = 0_u64;
                let mut offset = 0_u64;
                loop {
                    let page = admin_call(
                        &socket,
                        &json!({"command":"recovery-review-list","offset":offset}),
                    )?;
                    let items = page["items"].as_array().cloned().unwrap_or_default();
                    for item in &items {
                        if item["category"] == category.as_str() && item["decision"].is_null() {
                            decide(
                                item["subject_id"].as_str().unwrap_or_default(),
                                item["related_id"].as_str().unwrap_or_default(),
                            )?;
                            decided += 1;
                        }
                    }
                    offset += items.len() as u64;
                    if items.is_empty() || offset >= page["total"].as_u64().unwrap_or(0) {
                        break;
                    }
                }
                print_json(&json!({"decided":decided}))
            }
        },
    }
}

fn run_migrate(
    pre_upgrade_backup_dir: Option<PathBuf>,
    seal: &SealCredentials,
) -> Result<(), String> {
    let mut args = vec![std::ffi::OsStr::new("migrate")];
    match &pre_upgrade_backup_dir {
        Some(directory) => {
            seal.require()?;
            args.extend([
                std::ffi::OsStr::new("--pre-upgrade-backup-dir"),
                directory.as_os_str(),
            ]);
            seal.push(&mut args);
        }
        // A credential without a backup directory must never be ignored silently.
        None if !seal.is_empty() => {
            return Err("--pre-upgrade-backup-dir is required with a backup credential".to_owned());
        }
        None => {}
    }
    run_controller(&args)
}

fn run_seed(fixture: &std::path::Path) -> Result<(), String> {
    run_controller(&[
        std::ffi::OsStr::new("seed"),
        std::ffi::OsStr::new("--fixture"),
        fixture.as_os_str(),
    ])
}

fn run_fleet_admin(options: &HttpOptions, command: AdminAction) -> Result<(), String> {
    with_operator_session(options, |session| match command {
        AdminAction::Enrollment { command } => run_enrollment_action(session, command),
        AdminAction::Node { command } => run_node_action(session, command),
        _ => unreachable!(),
    })
}

fn with_operator_session(
    options: &HttpOptions,
    action: impl FnOnce(&mut AdminHttpSession) -> Result<(), String>,
) -> Result<(), String> {
    let controller_url = required_option(options.controller_url.as_deref(), "--controller-url")?;
    let controller_url = validate_origin(controller_url)?;
    let origin = options
        .origin
        .as_deref()
        .map(validate_origin)
        .transpose()?
        .unwrap_or_else(|| controller_url.clone());
    let username = required_option(options.username.as_deref(), "--username")?;
    if !options.password_stdin {
        return Err("fleet commands require --password-stdin".to_owned());
    }
    let password = read_password_stdin()?;
    let session_result = AdminHttpSession::login(&controller_url, &origin, username, &password);
    let mut password_bytes = password.into_bytes();
    wipe(&mut password_bytes);
    let mut session = session_result?;
    if session.must_change_password {
        let _ = session.logout();
        return Err(
            "change the temporary password in the controller UI before using fleet commands"
                .to_owned(),
        );
    }

    let result = action(&mut session);
    let logout = session.logout();
    match (result, logout) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), _) => Err(error),
        (Ok(()), Err(_)) => {
            Err("command completed, but the controller session could not be logged out".to_owned())
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct NodeCounts {
    online: u64,
    stale: u64,
    offline: u64,
    revoked: u64,
}

/// Projects only identity, state and timing. Key fingerprints, capabilities and
/// names stay out of the report so it can be pasted into a change record.
fn summarize_nodes(items: &[Value]) -> Result<(NodeCounts, Vec<Value>), String> {
    let mut counts = NodeCounts::default();
    let mut rows = Vec::with_capacity(items.len());
    for item in items {
        let id = item
            .get("id")
            .and_then(Value::as_str)
            .ok_or("controller returned an invalid node")?;
        let status = item
            .get("status")
            .and_then(Value::as_str)
            .ok_or("controller returned an invalid node")?;
        match status {
            "online" => counts.online += 1,
            "stale" => counts.stale += 1,
            "offline" => counts.offline += 1,
            "revoked" => counts.revoked += 1,
            _ => return Err("controller returned an unknown node status".to_owned()),
        }
        rows.push(json!({
            "id":id,
            "status":status,
            "key_version":item.get("key_version"),
            "last_seen_at":item.get("last_seen_at"),
            "rotation_pending":item.get("rotation_pending"),
            "revocation_pending":item.get("revocation_pending"),
        }));
    }
    Ok((counts, rows))
}

fn run_status(command: StatusCommand) -> Result<(), String> {
    let require_online = command.require_online;
    with_operator_session(&command.http, |session| {
        let mut items = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..1_000 {
            let path = match cursor.as_deref() {
                Some(cursor) if valid_cursor(cursor) => {
                    format!("/api/v3/nodes?limit=100&cursor={cursor}")
                }
                Some(_) => return Err("controller returned an invalid node cursor".to_owned()),
                None => "/api/v3/nodes?limit=100".to_owned(),
            };
            let page = session.get(&path)?;
            let page_items = page
                .get("items")
                .and_then(Value::as_array)
                .ok_or("controller returned an invalid node page")?;
            items.extend(page_items.iter().cloned());
            cursor = page
                .get("next_cursor")
                .and_then(Value::as_str)
                .map(str::to_owned);
            if cursor.is_none() {
                break;
            }
        }
        if cursor.is_some() {
            return Err("node listing exceeded the page limit".to_owned());
        }
        let (counts, rows) = summarize_nodes(&items)?;
        let active = counts.online + counts.stale + counts.offline;
        let all_active_online = active > 0 && counts.online == active;
        print_json(&json!({
            "total":rows.len(),
            "online":counts.online,
            "stale":counts.stale,
            "offline":counts.offline,
            "revoked":counts.revoked,
            "all_active_online":all_active_online,
            "nodes":rows,
        }))?;
        if require_online && active == 0 {
            return Err("no active node is registered".to_owned());
        }
        if require_online && !all_active_online {
            return Err("not every active node is online".to_owned());
        }
        Ok(())
    })
}

fn run_enrollment_action(
    session: &mut AdminHttpSession,
    command: EnrollmentAction,
) -> Result<(), String> {
    match command {
        EnrollmentAction::Create { name, token_file } => {
            let mut token_file = ReservedTokenFile::create(token_file)?;
            let mut response = session.post("/api/v3/enrollments", &json!({"name":name}))?;
            let token = response
                .get("token")
                .and_then(Value::as_str)
                .ok_or("controller did not return an enrollment token")?;
            token_file.write(token.as_bytes())?;
            let summary = json!({
                "id": response.get("id"),
                "node_id": response.get("node_id"),
                "expires_at": response.get("expires_at"),
                "token_file": token_file.path.display().to_string()
            });
            if let Some(object) = response.as_object_mut() {
                object.remove("token");
            }
            print_json(&summary)
        }
        EnrollmentAction::List => {
            let mut items = Vec::new();
            let mut cursor: Option<String> = None;
            for _ in 0..1_000 {
                let path = match cursor.as_deref() {
                    Some(cursor) if valid_cursor(cursor) => {
                        format!("/api/v3/enrollments?limit=100&cursor={cursor}")
                    }
                    Some(_) => {
                        return Err("controller returned an invalid enrollment cursor".to_owned());
                    }
                    None => "/api/v3/enrollments?limit=100".to_owned(),
                };
                let page = session.get(&path)?;
                let page_items = page
                    .get("items")
                    .and_then(Value::as_array)
                    .ok_or("controller returned an invalid enrollment page")?;
                items.extend(page_items.iter().cloned());
                cursor = page
                    .get("next_cursor")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                if cursor.is_none() {
                    return print_json(&json!({"items":items,"next_cursor":null}));
                }
            }
            Err("enrollment listing exceeded the page limit".to_owned())
        }
        EnrollmentAction::Approve {
            id,
            expected_fingerprint,
        } => decide_enrollment(session, &id, &expected_fingerprint, true),
        EnrollmentAction::Reject {
            id,
            expected_fingerprint,
        } => decide_enrollment(session, &id, &expected_fingerprint, false),
    }
}

fn decide_enrollment(
    session: &mut AdminHttpSession,
    id: &str,
    expected_fingerprint: &str,
    approve: bool,
) -> Result<(), String> {
    if !valid_fingerprint(expected_fingerprint) {
        return Err(
            "--expected-fingerprint must be 64 lowercase hexadecimal characters".to_owned(),
        );
    }
    let path = format!("/api/v3/enrollments/{}", encode_path_segment(id));
    let enrollment = session.get(&path)?;
    if enrollment.get("status").and_then(Value::as_str) != Some("submitted") {
        return Err("enrollment is not in submitted state".to_owned());
    }
    if enrollment.get("fingerprint").and_then(Value::as_str) != Some(expected_fingerprint) {
        return Err("submitted fingerprint does not match --expected-fingerprint".to_owned());
    }
    let version = enrollment
        .get("version")
        .and_then(Value::as_i64)
        .filter(|version| *version > 0)
        .ok_or("controller returned an invalid enrollment version")?;
    let action = if approve { "approve" } else { "reject" };
    let result = session.post(
        &format!("{path}/{action}"),
        &json!({
            "expected_fingerprint": expected_fingerprint,
            "expected_version": version
        }),
    )?;
    print_json(&result)
}

fn run_node_action(session: &mut AdminHttpSession, command: NodeAction) -> Result<(), String> {
    match command {
        NodeAction::Revoke { id, confirm } => {
            if id != confirm {
                return Err("--confirm must exactly repeat the node ID".to_owned());
            }
            let result = session.delete(&format!("/api/v3/nodes/{}", encode_path_segment(&id)))?;
            print_json(&result)
        }
        NodeAction::Rotate {
            id,
            metadata_file,
            expected_fingerprint,
        } => rotate_node_key(session, &id, &metadata_file, &expected_fingerprint),
    }
}

fn rotate_node_key(
    session: &mut AdminHttpSession,
    id: &str,
    metadata_file: &Path,
    expected_fingerprint: &str,
) -> Result<(), String> {
    let metadata = fs::read(metadata_file)
        .map_err(|_| "cannot read broker rotation metadata file".to_owned())?;
    if metadata.len() > 16 * 1024 {
        return Err("broker rotation metadata exceeds its size limit".to_owned());
    }
    let metadata: Value = serde_json::from_slice(&metadata)
        .map_err(|_| "broker rotation metadata is invalid JSON".to_owned())?;
    let signing_public = metadata
        .get("signing_pub")
        .and_then(Value::as_str)
        .ok_or("broker rotation metadata is missing signing_pub")?;
    let recipient_public = metadata
        .get("recipient_pub")
        .and_then(Value::as_str)
        .ok_or("broker rotation metadata is missing recipient_pub")?;
    let fingerprint = metadata
        .get("fingerprint")
        .and_then(Value::as_str)
        .ok_or("broker rotation metadata is missing fingerprint")?;
    let candidate_version = metadata
        .get("key_version")
        .and_then(Value::as_i64)
        .filter(|version| *version > 1)
        .ok_or("broker rotation metadata has an invalid key_version")?;
    let signing_key = base64_url_decode(signing_public, 32)
        .ok_or("broker rotation metadata has an invalid signing key")?;
    let recipient_key = base64_url_decode(recipient_public, 32)
        .ok_or("broker rotation metadata has an invalid recipient key")?;
    let computed_fingerprint = node_key_fingerprint(&signing_key, &recipient_key)
        .map_err(|_| "broker rotation metadata has invalid node public keys".to_owned())?;
    if !valid_fingerprint(fingerprint)
        || computed_fingerprint != fingerprint
        || fingerprint != expected_fingerprint
    {
        return Err("broker key fingerprint does not match --expected-fingerprint".to_owned());
    }

    let node_path = format!("/api/v3/nodes/{}", encode_path_segment(id));
    let node = session.get(&node_path)?;
    if node.get("status").and_then(Value::as_str) == Some("revoked")
        || node.get("rotation_pending").and_then(Value::as_bool) == Some(true)
    {
        return Err("node is revoked or already has a pending key rotation".to_owned());
    }
    let current_version = node
        .get("key_version")
        .and_then(Value::as_i64)
        .filter(|version| *version > 0)
        .ok_or("controller returned an invalid node key version")?;
    if candidate_version != current_version + 1 {
        return Err("candidate key version is not the next node key version".to_owned());
    }
    let result = session.post(
        &format!("{node_path}/rotate-key"),
        &json!({
            "expected_key_version": current_version,
            "expected_fingerprint": fingerprint,
            "signing_pub": signing_public,
            "recipient_pub": recipient_public
        }),
    )?;
    print_json(&result)
}

struct PrivateCookieJar {
    path: PathBuf,
}

impl PrivateCookieJar {
    fn create() -> Result<Self, String> {
        let directory = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .filter(|path| {
                path.is_absolute()
                    && std::fs::symlink_metadata(path).is_ok_and(|metadata| {
                        metadata.is_dir() && metadata.permissions().mode() & 0o077 == 0
                    })
            })
            .unwrap_or_else(std::env::temp_dir);
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system clock is before Unix epoch".to_owned())?
            .as_nanos();
        for attempt in 0..16_u8 {
            let path = directory.join(format!(
                ".blindpass-cli-session-{}-{time}-{attempt}",
                std::process::id()
            ));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(file) => {
                    drop(file);
                    return Ok(Self { path });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err("cannot create a private controller session file".to_owned()),
            }
        }
        Err("cannot allocate a private controller session file".to_owned())
    }
}

impl Drop for PrivateCookieJar {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

struct AdminHttpSession {
    controller_url: String,
    origin: String,
    csrf_token: String,
    must_change_password: bool,
    cookie_jar: PrivateCookieJar,
    logged_out: bool,
}

impl AdminHttpSession {
    fn login(
        controller_url: &str,
        origin: &str,
        username: &str,
        password: &str,
    ) -> Result<Self, String> {
        let cookie_jar = PrivateCookieJar::create()?;
        let pre_session = format!("blindpass-cli-{}", std::process::id());
        #[derive(serde::Serialize)]
        struct LoginInput<'a> {
            username: &'a str,
            password: &'a str,
        }
        let mut body = serde_json::to_vec(&LoginInput { username, password })
            .map_err(|_| "could not encode operator login".to_owned())?;
        let url = format!("{controller_url}/api/v3/admin/session/login");
        let response = curl_request(
            "POST",
            &url,
            origin,
            &cookie_jar.path,
            None,
            Some(&pre_session),
            Some(&body),
        );
        wipe(&mut body);
        let (status, response) = response?;
        let response = parse_response(status, response)?;
        if status != 200 {
            return Err(response_error(status, &response));
        }
        let csrf_token = response
            .get("csrf_token")
            .and_then(Value::as_str)
            .filter(|token| token.len() == 43 && token.bytes().all(is_base64url_byte))
            .ok_or("controller returned an invalid session CSRF token")?
            .to_owned();
        let must_change_password = response
            .get("must_change_password")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        Ok(Self {
            controller_url: controller_url.to_owned(),
            origin: origin.to_owned(),
            csrf_token,
            must_change_password,
            cookie_jar,
            logged_out: false,
        })
    }

    fn get(&self, path: &str) -> Result<Value, String> {
        self.request("GET", path, None)
    }

    fn post(&self, path: &str, body: &Value) -> Result<Value, String> {
        let body = serde_json::to_vec(body)
            .map_err(|_| "could not encode controller request".to_owned())?;
        self.request("POST", path, Some(&body))
    }

    fn delete(&self, path: &str) -> Result<Value, String> {
        self.request("DELETE", path, None)
    }

    fn request(&self, method: &str, path: &str, body: Option<&[u8]>) -> Result<Value, String> {
        if !path.starts_with('/') || path.starts_with("//") {
            return Err("controller request path is invalid".to_owned());
        }
        let url = format!("{}{path}", self.controller_url);
        let (status, response) = curl_request(
            method,
            &url,
            &self.origin,
            &self.cookie_jar.path,
            Some(&self.csrf_token),
            None,
            body,
        )?;
        let response = parse_response(status, response)?;
        if !(200..300).contains(&status) {
            return Err(response_error(status, &response));
        }
        Ok(response)
    }

    fn logout(&mut self) -> Result<(), String> {
        if self.logged_out {
            return Ok(());
        }
        let result = self.request("POST", "/api/v3/admin/session/logout", None);
        if result.is_ok() {
            self.logged_out = true;
        }
        result.map(|_| ())
    }
}

fn curl_request(
    method: &str,
    url: &str,
    origin: &str,
    cookie_jar: &Path,
    csrf_token: Option<&str>,
    pre_session_csrf: Option<&str>,
    body: Option<&[u8]>,
) -> Result<(u16, Vec<u8>), String> {
    let mut command = ProcessCommand::new("curl");
    command
        .arg("--disable")
        .arg("--silent")
        .arg("--show-error")
        .arg("--connect-timeout")
        .arg("5")
        .arg("--max-time")
        .arg("30")
        .arg("--proto")
        .arg("=https,http")
        .arg("--request")
        .arg(method)
        .arg("--url")
        .arg(url)
        .arg("--header")
        .arg(format!("Origin: {origin}"))
        .arg("--header")
        .arg("Accept: application/json")
        .arg("--cookie-jar")
        .arg(cookie_jar)
        .arg("--write-out")
        .arg("\n__BLINDPASS_HTTP_STATUS__%{http_code}");
    if csrf_token.is_some() {
        command.arg("--cookie").arg(cookie_jar);
    }
    if let Some(token) = csrf_token {
        command
            .arg("--header")
            .arg(format!("X-CSRF-Token: {token}"));
    }
    if let Some(token) = pre_session_csrf {
        command
            .arg("--header")
            .arg(format!("Cookie: bp_csrf={token}"))
            .arg("--header")
            .arg(format!("X-CSRF-Token: {token}"));
    }
    if body.is_some() {
        command
            .arg("--header")
            .arg("Content-Type: application/json")
            .arg("--data-binary")
            .arg("@-")
            .stdin(Stdio::piped());
    } else {
        command.stdin(Stdio::null());
    }
    command.stdout(Stdio::piped()).stderr(Stdio::null());
    let mut child = command
        .spawn()
        .map_err(|_| "cannot start curl for the controller request".to_owned())?;
    if let Some(body) = body {
        let mut stdin = child
            .stdin
            .take()
            .ok_or("cannot send controller request body")?;
        stdin
            .write_all(body)
            .map_err(|_| "cannot send controller request body".to_owned())?;
    }
    let output = child
        .wait_with_output()
        .map_err(|_| "cannot read controller response".to_owned())?;
    if !output.status.success() {
        return Err("curl could not complete the controller request".to_owned());
    }
    let marker = b"\n__BLINDPASS_HTTP_STATUS__";
    let marker_at = output
        .stdout
        .windows(marker.len())
        .rposition(|window| window == marker)
        .ok_or("curl returned a response without an HTTP status")?;
    let status_bytes = &output.stdout[marker_at + marker.len()..];
    let status = std::str::from_utf8(status_bytes)
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or("curl returned an invalid HTTP status")?;
    Ok((status, output.stdout[..marker_at].to_vec()))
}

fn parse_response(status: u16, body: Vec<u8>) -> Result<Value, String> {
    if body.is_empty() && status == 204 {
        return Ok(Value::Null);
    }
    serde_json::from_slice(&body).map_err(|_| "controller returned invalid JSON".to_owned())
}

fn response_error(status: u16, body: &Value) -> String {
    let code = body
        .get("error")
        .and_then(Value::as_str)
        .filter(|code| !code.is_empty() && code.bytes().all(is_error_code_byte))
        .unwrap_or("http_error");
    format!("controller returned HTTP {status} ({code})")
}

fn read_password_stdin() -> Result<String, String> {
    let mut password = String::new();
    std::io::stdin()
        .read_line(&mut password)
        .map_err(|_| "cannot read operator password from stdin".to_owned())?;
    if password.len() > 1_025 {
        return Err("operator password exceeds its input limit".to_owned());
    }
    if password.ends_with('\n') {
        password.pop();
        if password.ends_with('\r') {
            password.pop();
        }
    }
    if password.is_empty() {
        return Err("operator password from stdin is empty".to_owned());
    }
    Ok(password)
}

fn validate_origin(value: &str) -> Result<String, String> {
    let origin = value.trim_end_matches('/');
    if origin.is_empty()
        || origin
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        || origin.contains(['?', '#', '@'])
    {
        return Err("controller URL and origin must be plain HTTP(S) origins".to_owned());
    }
    let (scheme, authority) = origin
        .split_once("://")
        .ok_or("controller URL and origin must be plain HTTP(S) origins")?;
    if !matches!(scheme, "https" | "http") || authority.is_empty() || authority.contains('/') {
        return Err("controller URL and origin must be plain HTTP(S) origins".to_owned());
    }
    if scheme == "http" && !is_loopback_authority(authority) {
        return Err("unencrypted HTTP is allowed only for a loopback controller".to_owned());
    }
    Ok(origin.to_owned())
}

fn is_loopback_authority(authority: &str) -> bool {
    authority == "localhost"
        || authority.starts_with("localhost:")
        || authority == "127.0.0.1"
        || authority.starts_with("127.0.0.1:")
        || authority == "[::1]"
        || authority.starts_with("[::1]:")
}

fn required_option<'a>(value: Option<&'a str>, name: &str) -> Result<&'a str, String> {
    value
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("fleet commands require {name}"))
}

fn valid_fingerprint(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_cursor(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(is_base64url_byte)
}

fn is_base64url_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

fn is_error_code_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

fn encode_path_segment(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

struct ReservedTokenFile {
    path: PathBuf,
    file: Option<File>,
    completed: bool,
}

impl ReservedTokenFile {
    fn create(path: PathBuf) -> Result<Self, String> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|_| "token file already exists or cannot be created".to_owned())?;
        Ok(Self {
            path,
            file: Some(file),
            completed: false,
        })
    }

    fn write(&mut self, content: &[u8]) -> Result<(), String> {
        let file = self
            .file
            .as_mut()
            .ok_or("cannot write enrollment token file")?;
        if file
            .write_all(content)
            .and_then(|()| file.sync_all())
            .is_err()
        {
            return Err("cannot write enrollment token file".to_owned());
        }
        self.completed = true;
        Ok(())
    }
}

impl Drop for ReservedTokenFile {
    fn drop(&mut self) {
        if !self.completed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn print_json(value: &Value) -> Result<(), String> {
    let output = serde_json::to_string_pretty(value)
        .map_err(|_| "could not format controller response".to_owned())?;
    println!("{output}");
    Ok(())
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
        .take(256 * 1024)
        .read_to_end(&mut response)
        .map_err(|_| "could not read local administration response".to_owned())?;
    serde_json::from_slice(&response)
        .map_err(|_| "local administration returned an invalid response".to_owned())
}
