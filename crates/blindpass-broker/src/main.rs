// SPDX-License-Identifier: AGPL-3.0-only

use blindpass_broker::{BrokerConfig, BrokerState, load_protected_credential, run};
use blindpass_core::delivery::{CredentialFormat, DeliveryPolicy};
use blindpass_core::identity::WorkloadRegistration;
use std::path::PathBuf;
use std::time::Duration;

fn main() {
    if let Err(error) = run_from_args(std::env::args().skip(1).collect()) {
        eprintln!("blindpass-broker: {error}");
        std::process::exit(1);
    }
}

fn run_from_args(args: Vec<String>) -> Result<(), String> {
    let mut config = BrokerConfig::default();
    let mut state = BrokerState::new(DeliveryPolicy {
        max_bytes: blindpass_core::MAX_CREDENTIAL_BYTES,
        deadline: Duration::from_secs(2),
        format: CredentialFormat::NonEmpty,
    });
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--loader-socket" => {
                config.loader_socket = PathBuf::from(next(&args, &mut index)?);
            }
            "--workload-socket" => {
                config.workload_socket = PathBuf::from(next(&args, &mut index)?);
            }
            "--map" => {
                let mapping = next(&args, &mut index)?;
                let (unit, credential) = mapping
                    .split_once('=')
                    .ok_or("--map requires UNIT=CREDENTIAL")?;
                state
                    .loader_policy
                    .map_unit(unit, credential)
                    .map_err(|error| error.to_string())?;
            }
            "--credential" => {
                let source = next(&args, &mut index)?;
                let (name, path) = source
                    .split_once('=')
                    .ok_or("--credential requires NAME=/root-owned/file")?;
                let value = load_protected_credential(PathBuf::from(path).as_path())
                    .map_err(|error| error.to_string())?;
                state
                    .credentials
                    .insert_secret(name, value)
                    .map_err(|error| error.to_string())?;
            }
            "--workload" => {
                let registration = next(&args, &mut index)?;
                let fields: Vec<&str> = registration.split(':').collect();
                if fields.len() != 5 {
                    return Err("--workload requires NODE:WORKLOAD:UNIT:UID:INVOCATION".to_owned());
                }
                state.workloads.push(WorkloadRegistration {
                    node_id: fields[0].to_owned(),
                    workload_id: fields[1].to_owned(),
                    unit: fields[2].to_owned(),
                    account: format!("uid:{}", fields[3]),
                    invocation_id: fields[4].to_owned(),
                });
            }
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            unknown => return Err(format!("unknown argument {unknown}")),
        }
        index += 1;
    }
    run(config, state).map_err(|error| error.to_string())
}

fn next(args: &[String], index: &mut usize) -> Result<String, String> {
    *index += 1;
    args.get(*index)
        .cloned()
        .ok_or_else(|| "missing option value".to_owned())
}

fn print_help() {
    println!(
        "blindpass-broker --loader-socket PATH --workload-socket PATH \\
         --map UNIT=CREDENTIAL --credential NAME=/root-owned/file \\
         [--workload NODE:WORKLOAD:UNIT:UID:INVOCATION]"
    );
}
