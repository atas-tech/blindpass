// SPDX-License-Identifier: AGPL-3.0-only

use blindpass_broker::{
    BrokerConfig, BrokerState, DEFAULT_CREDENTIAL_LIFETIME, DEFAULT_CUSTODY_KEY_LIFETIME,
    DeliveryFault, run,
};
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
    let mut config = BrokerConfig {
        delivery_fault: configured_delivery_fault()?,
        ..BrokerConfig::default()
    };
    let key_lifetime = configured_test_lifetime(
        "BLINDPASS_P01_CUSTODY_KEY_TTL_MS",
        DEFAULT_CUSTODY_KEY_LIFETIME,
    )?;
    let credential_lifetime = configured_test_lifetime(
        "BLINDPASS_P01_CREDENTIAL_TTL_MS",
        DEFAULT_CREDENTIAL_LIFETIME,
    )?;
    config.identity_lookup_delay =
        configured_test_lifetime("BLINDPASS_P01_IDENTITY_LOOKUP_DELAY_MS", Duration::ZERO)?;
    let mut state = BrokerState::with_lifetimes(
        DeliveryPolicy {
            max_bytes: blindpass_core::MAX_CREDENTIAL_BYTES,
            format: CredentialFormat::NonEmpty,
        },
        key_lifetime,
        credential_lifetime,
    );
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--loader-socket" => {
                config.loader_socket = PathBuf::from(next(&args, &mut index)?);
            }
            "--workload-socket" => {
                config.workload_socket = PathBuf::from(next(&args, &mut index)?);
            }
            "--provision-socket" => {
                config.provision_socket = PathBuf::from(next(&args, &mut index)?);
            }
            "--workload-group" => {
                config.workload_group = Some(next(&args, &mut index)?);
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
            "--workload" => {
                let registration = next(&args, &mut index)?;
                state
                    .workloads
                    .push(parse_workload_registration(&registration)?);
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

fn parse_workload_registration(value: &str) -> Result<WorkloadRegistration, String> {
    const FORMAT: &str = "--workload requires NODE:WORKLOAD:UNIT:UID:INVOCATION";
    let (node, rest) = value.split_once(':').ok_or(FORMAT)?;
    let (workload, rest) = rest.split_once(':').ok_or(FORMAT)?;
    let (rest, invocation) = rest.rsplit_once(':').ok_or(FORMAT)?;
    let (unit, uid) = rest.rsplit_once(':').ok_or(FORMAT)?;
    if node.is_empty()
        || workload.is_empty()
        || unit.is_empty()
        || invocation.is_empty()
        || uid.parse::<u32>().is_err()
    {
        return Err(FORMAT.to_owned());
    }
    Ok(WorkloadRegistration {
        node_id: node.to_owned(),
        workload_id: workload.to_owned(),
        unit: unit.to_owned(),
        account: format!("uid:{uid}"),
        invocation_id: invocation.to_owned(),
    })
}

fn configured_delivery_fault() -> Result<Option<DeliveryFault>, String> {
    let Some(value) = std::env::var_os("BLINDPASS_P01_DELIVERY_FAULT") else {
        return Ok(None);
    };
    if std::env::var("BLINDPASS_P01_TEST_MODE").as_deref() != Ok("1") {
        return Err("BLINDPASS_P01_DELIVERY_FAULT requires BLINDPASS_P01_TEST_MODE=1".to_owned());
    }
    let value = value
        .to_str()
        .ok_or("BLINDPASS_P01_DELIVERY_FAULT is not valid UTF-8")?;
    DeliveryFault::parse(value).map(Some).map_err(str::to_owned)
}

fn configured_test_lifetime(variable: &str, default: Duration) -> Result<Duration, String> {
    let Some(value) = std::env::var_os(variable) else {
        return Ok(default);
    };
    let text = value
        .to_str()
        .ok_or_else(|| format!("{variable} is not valid UTF-8"))?;
    configured_test_lifetime_value(
        variable,
        Some(text),
        std::env::var("BLINDPASS_P01_TEST_MODE").as_deref() == Ok("1"),
        default,
    )
}

fn configured_test_lifetime_value(
    variable: &str,
    value: Option<&str>,
    test_mode: bool,
    default: Duration,
) -> Result<Duration, String> {
    let Some(value) = value else {
        return Ok(default);
    };
    if !test_mode {
        return Err(format!("{variable} requires BLINDPASS_P01_TEST_MODE=1"));
    }
    let milliseconds = value
        .parse::<u64>()
        .map_err(|_| format!("{variable} must be an integer number of milliseconds"))?;
    if milliseconds == 0 {
        return Err(format!("{variable} must be greater than zero"));
    }
    Ok(Duration::from_millis(milliseconds))
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
         --map UNIT=CREDENTIAL --provision-socket PATH [--workload-group GROUP] \\
         [--workload NODE:WORKLOAD:UNIT:UID:INVOCATION]"
    );
}

#[cfg(test)]
mod tests {
    use super::{configured_test_lifetime_value, parse_workload_registration};
    use std::time::Duration;

    #[test]
    fn lifetime_test_overrides_are_gated_and_positive() {
        let default = Duration::from_secs(30);
        assert_eq!(
            configured_test_lifetime_value("TTL", None, false, default).unwrap(),
            default
        );
        assert!(configured_test_lifetime_value("TTL", Some("10"), false, default).is_err());
        assert_eq!(
            configured_test_lifetime_value("TTL", Some("250"), true, default).unwrap(),
            Duration::from_millis(250)
        );
        assert!(configured_test_lifetime_value("TTL", Some("0"), true, default).is_err());
        assert!(configured_test_lifetime_value("TTL", Some("NaN"), true, default).is_err());
    }

    #[test]
    fn workload_parser_preserves_colons_in_unit_names() {
        let registration =
            parse_workload_registration("node:work:foo:bar.service:1001:inv").unwrap();
        assert_eq!(registration.unit, "foo:bar.service");
        assert_eq!(registration.account, "uid:1001");
        assert!(parse_workload_registration("node:work:unit:bad:inv").is_err());
    }
}
