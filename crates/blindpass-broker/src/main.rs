// SPDX-License-Identifier: AGPL-3.0-only

use blindpass_broker::{
    BrokerConfig, BrokerState, CONSUME_CRASH_FLAG, DEFAULT_CREDENTIAL_LIFETIME,
    DEFAULT_CUSTODY_KEY_LIFETIME, DeliveryFault, resolve_profile_options, run,
};
use blindpass_core::delivery::{CredentialFormat, DeliveryPolicy};
use blindpass_core::identity::WorkloadRegistration;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Duration;

fn main() {
    if let Err(error) = run_from_args(std::env::args().skip(1).collect()) {
        eprintln!("blindpass-broker: {error}");
        std::process::exit(1);
    }
}

fn run_from_args(args: Vec<String>) -> Result<(), String> {
    if args.as_slice() == ["--version"] {
        println!("blindpass-broker {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let mut config = BrokerConfig {
        delivery_fault: configured_delivery_fault()?,
        ..BrokerConfig::default()
    };
    let key_lifetime = configured_test_lifetime(
        "BLINDPASS_P01_CUSTODY_KEY_TTL_MS",
        DEFAULT_CUSTODY_KEY_LIFETIME,
    )?;
    // Production setting (default one hour, never beyond a week). The test-mode
    // millisecond override below still wins when explicitly enabled.
    let credential_lifetime = configured_test_lifetime(
        "BLINDPASS_P01_CREDENTIAL_TTL_MS",
        credential_lifetime_option(&args)?.unwrap_or(DEFAULT_CREDENTIAL_LIFETIME),
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
    if let Some(flag) =
        consume_crash_hook(std::env::var("BLINDPASS_P01_TEST_MODE").as_deref() == Ok("1"))
    {
        state.enable_consume_crash_hook(flag);
    }
    let mut mapped_credentials = BTreeSet::new();
    let mut profile_options = Vec::new();
    let mut fulfillment_sources = Vec::new();
    let mut fulfillment_destinations = Vec::new();
    let mut fulfillment_lifetime = None;
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
            "--control-socket" => {
                config.control_socket = PathBuf::from(next(&args, &mut index)?);
            }
            "--key-directory" => {
                config.key_directory = PathBuf::from(next(&args, &mut index)?);
            }
            "--workload-group" => {
                config.workload_group = Some(next(&args, &mut index)?);
            }
            "--node-group" => {
                config.node_group = Some(next(&args, &mut index)?);
            }
            "--browser-runtime" => {
                config.browser_runtime_enabled = true;
            }
            "--browser-resources" => {
                config.browser_resources_enabled = true;
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
                mapped_credentials.insert(credential.to_owned());
            }
            "--credential-profile" => {
                profile_options.push(next(&args, &mut index)?);
            }
            // Parsed before the state exists; skip the value here.
            "--credential-lifetime-seconds" => {
                next(&args, &mut index)?;
            }
            "--fulfillment-source" => {
                fulfillment_sources.push(next(&args, &mut index)?);
            }
            "--fulfillment-destination" => {
                fulfillment_destinations.push(next(&args, &mut index)?);
            }
            "--fulfillment-offer-lifetime-seconds" => {
                let value = next(&args, &mut index)?;
                if fulfillment_lifetime.is_some() {
                    return Err(
                        "--fulfillment-offer-lifetime-seconds was given more than once".to_owned(),
                    );
                }
                fulfillment_lifetime = Some(parse_fulfillment_offer_lifetime(&value)?);
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
    install_credential_profiles(&mut state, &profile_options, &mapped_credentials)?;
    install_fulfillment(
        &mut state,
        &fulfillment_sources,
        &fulfillment_destinations,
        fulfillment_lifetime.unwrap_or(DEFAULT_FULFILLMENT_OFFER_LIFETIME),
    )?;
    run(config, state).map_err(|error| error.to_string())
}

/// The one-use recipient key never outlives three minutes, so this is also the
/// ceiling for the operator's choice.
const MAX_FULFILLMENT_OFFER_LIFETIME_SECONDS: u64 = 180;
const DEFAULT_FULFILLMENT_OFFER_LIFETIME: Duration =
    Duration::from_secs(MAX_FULFILLMENT_OFFER_LIFETIME_SECONDS);

fn parse_fulfillment_offer_lifetime(value: &str) -> Result<Duration, String> {
    let invalid = || {
        format!(
            "--fulfillment-offer-lifetime-seconds must be an integer from 1 to \
             {MAX_FULFILLMENT_OFFER_LIFETIME_SECONDS}"
        )
    };
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid());
    }
    let seconds = value.parse::<u64>().map_err(|_| invalid())?;
    if !(1..=MAX_FULFILLMENT_OFFER_LIFETIME_SECONDS).contains(&seconds) {
        return Err(invalid());
    }
    Ok(Duration::from_secs(seconds))
}

/// Install the local fulfillment ceilings after every `--map` is known. A unit
/// that is not mapped is a startup error, so a typo can never leave a
/// fulfillment ceiling silently inert. With neither flag the broker refuses
/// every fulfillment, which is the default.
fn install_fulfillment(
    state: &mut BrokerState,
    sources: &[String],
    destinations: &[String],
    offer_lifetime: Duration,
) -> Result<(), String> {
    state
        .configure_fulfillment(sources, destinations, offer_lifetime)
        .map_err(|error| format!("--fulfillment-source/--fulfillment-destination: {error}"))?;
    for unit in sources {
        eprintln!("blindpass-broker: fulfillment source {unit}");
    }
    for unit in destinations {
        eprintln!("blindpass-broker: fulfillment destination {unit}");
    }
    Ok(())
}

/// Resolve every `--credential-profile` after all `--map` entries are known (the
/// options may appear in any order) and install them. Any problem is a startup
/// error, so a typo can never leave a credential silently unvalidated.
fn install_credential_profiles(
    state: &mut BrokerState,
    options: &[String],
    mapped_credentials: &BTreeSet<String>,
) -> Result<(), String> {
    for (credential, profile) in resolve_profile_options(options, mapped_credentials)? {
        eprintln!(
            "blindpass-broker: credential profile {credential}={}",
            profile.name()
        );
        state.set_credential_profile(&credential, profile);
    }
    Ok(())
}

/// Credentials live only in broker memory. A longer lifetime keeps a
/// pre-provisioned value available to an unattended timer but widens how long a
/// plaintext copy sits in memory, so it is an explicit operator choice with a
/// hard ceiling. A broker restart or reboot still empties custody.
const MIN_CREDENTIAL_LIFETIME_SECONDS: u64 = 60;
const MAX_CREDENTIAL_LIFETIME_SECONDS: u64 = 7 * 24 * 60 * 60;

fn parse_credential_lifetime_seconds(value: &str) -> Result<Duration, String> {
    let invalid = || {
        format!(
            "--credential-lifetime-seconds must be an integer from \
             {MIN_CREDENTIAL_LIFETIME_SECONDS} to {MAX_CREDENTIAL_LIFETIME_SECONDS}"
        )
    };
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid());
    }
    let seconds = value.parse::<u64>().map_err(|_| invalid())?;
    if !(MIN_CREDENTIAL_LIFETIME_SECONDS..=MAX_CREDENTIAL_LIFETIME_SECONDS).contains(&seconds) {
        return Err(invalid());
    }
    Ok(Duration::from_secs(seconds))
}

fn credential_lifetime_option(args: &[String]) -> Result<Option<Duration>, String> {
    let mut lifetime = None;
    let mut index = 0;
    while index < args.len() {
        if args[index] == "--credential-lifetime-seconds" {
            let value = args
                .get(index + 1)
                .ok_or_else(|| "missing option value".to_owned())?;
            if lifetime.is_some() {
                return Err("--credential-lifetime-seconds was given more than once".to_owned());
            }
            lifetime = Some(parse_credential_lifetime_seconds(value)?);
            index += 1;
        }
        index += 1;
    }
    Ok(lifetime)
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
        invocation_id: Some(invocation.to_owned()),
    })
}

/// The crash-after-consume-intent hook exists only in test mode; the
/// production unit never sets `BLINDPASS_P01_TEST_MODE`.
fn consume_crash_hook(test_mode: bool) -> Option<PathBuf> {
    test_mode.then(|| PathBuf::from(CONSUME_CRASH_FLAG))
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
         --map UNIT=CREDENTIAL --provision-socket PATH --control-socket PATH \\
         --key-directory PATH \\
         [--workload-group GROUP] [--node-group GROUP] [--browser-resources] [--browser-runtime] \\
         [--credential-profile CREDENTIAL=password-file]... \\
         [--credential-lifetime-seconds 60..604800] \\
         [--fulfillment-source UNIT]... [--fulfillment-destination UNIT]... \\
         [--fulfillment-offer-lifetime-seconds 1..180] \\
         [--workload NODE:WORKLOAD:UNIT:UID:INVOCATION]"
    );
}

#[cfg(test)]
mod tests {
    use super::{
        configured_test_lifetime_value, consume_crash_hook, install_credential_profiles,
        parse_workload_registration, run_from_args,
    };
    use blindpass_broker::{BrokerState, CredentialProfile};
    use blindpass_core::delivery::DeliveryPolicy;
    use std::collections::BTreeSet;

    #[test]
    fn consume_crash_hook_is_armed_only_in_test_mode() {
        assert_eq!(consume_crash_hook(false), None);
        assert_eq!(
            consume_crash_hook(true),
            Some(std::path::PathBuf::from(
                "/run/blindpass/test/crash-after-consume-intent"
            ))
        );
    }
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

    fn arguments(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn credential_profiles_install_for_the_mapped_credential_only() {
        let mut state = BrokerState::new(DeliveryPolicy::default());
        let mapped: BTreeSet<String> = ["restic-password".to_owned()].into();
        install_credential_profiles(
            &mut state,
            &arguments(&["restic-password=password-file"]),
            &mapped,
        )
        .unwrap();
        assert_eq!(
            state.credential_profile("restic-password"),
            Some(CredentialProfile::PasswordFile)
        );
        assert_eq!(state.credential_profile("api-key"), None);
    }

    #[test]
    fn credential_profile_startup_errors_occur_before_the_broker_runs() {
        // Each argument list fails while parsing, before `run`, so none of these
        // can bind a socket even when the test runs as root.
        let unknown = run_from_args(arguments(&[
            "--credential-profile",
            "restic-password=json",
            "--map",
            "example-backup.service=restic-password",
        ]))
        .unwrap_err();
        assert!(unknown.contains("unknown credential profile"), "{unknown}");
        let unmapped = run_from_args(arguments(&[
            "--map",
            "example-backup.service=restic-password",
            "--credential-profile",
            "other-password=password-file",
        ]))
        .unwrap_err();
        assert!(unmapped.contains("not mapped"), "{unmapped}");
        let missing_value = run_from_args(arguments(&["--credential-profile"])).unwrap_err();
        assert!(
            missing_value.contains("missing option value"),
            "{missing_value}"
        );
    }

    #[test]
    fn credential_lifetime_option_is_bounded_and_rejects_bad_values_before_running() {
        use super::parse_credential_lifetime_seconds;
        assert_eq!(
            parse_credential_lifetime_seconds("3600").unwrap(),
            Duration::from_secs(3600)
        );
        assert_eq!(
            parse_credential_lifetime_seconds("604800").unwrap(),
            Duration::from_secs(604_800)
        );
        for bad in [
            "59", "0", "604801", "-1", "1.5", "", "abc", " 3600", "3600 ",
        ] {
            assert!(
                parse_credential_lifetime_seconds(bad).is_err(),
                "{bad:?} must be refused"
            );
        }
        // Parse errors surface before the broker binds anything.
        let invalid =
            run_from_args(arguments(&["--credential-lifetime-seconds", "10"])).unwrap_err();
        assert!(
            invalid.contains("--credential-lifetime-seconds"),
            "{invalid}"
        );
        let missing = run_from_args(arguments(&["--credential-lifetime-seconds"])).unwrap_err();
        assert!(missing.contains("missing option value"), "{missing}");
        let repeated = run_from_args(arguments(&[
            "--credential-lifetime-seconds",
            "3600",
            "--credential-lifetime-seconds",
            "7200",
        ]))
        .unwrap_err();
        assert!(repeated.contains("more than once"), "{repeated}");
    }

    #[test]
    fn p10_m01_fulfillment_lifetime_is_bounded_to_the_one_use_key_ceiling() {
        use super::parse_fulfillment_offer_lifetime;
        assert_eq!(
            parse_fulfillment_offer_lifetime("180").unwrap(),
            Duration::from_secs(180)
        );
        assert_eq!(
            parse_fulfillment_offer_lifetime("1").unwrap(),
            Duration::from_secs(1)
        );
        for bad in ["0", "181", "-1", "1.5", "", "abc", " 30", "30 ", "+30"] {
            assert!(
                parse_fulfillment_offer_lifetime(bad).is_err(),
                "{bad:?} must be refused"
            );
        }
    }

    #[test]
    fn p10_m02_fulfillment_units_must_be_mapped_before_the_broker_runs() {
        use super::install_fulfillment;
        let mut state = BrokerState::new(DeliveryPolicy::default());
        state
            .loader_policy
            .map_unit("recipient.service", "api-token")
            .unwrap();
        install_fulfillment(
            &mut state,
            &arguments(&["recipient.service"]),
            &arguments(&["recipient.service"]),
            Duration::from_secs(60),
        )
        .unwrap();
        let unmapped = install_fulfillment(
            &mut state,
            &arguments(&["other.service"]),
            &[],
            Duration::from_secs(60),
        )
        .unwrap_err();
        assert!(unmapped.contains("--fulfillment-"), "{unmapped}");

        // The same failures surface from the command line, before any socket is bound.
        let from_arguments = run_from_args(arguments(&[
            "--map",
            "recipient.service=api-token",
            "--fulfillment-destination",
            "other.service",
        ]))
        .unwrap_err();
        assert!(
            from_arguments.contains("--fulfillment-"),
            "{from_arguments}"
        );
        let too_long =
            run_from_args(arguments(&["--fulfillment-offer-lifetime-seconds", "181"])).unwrap_err();
        assert!(
            too_long.contains("--fulfillment-offer-lifetime-seconds"),
            "{too_long}"
        );
        let missing = run_from_args(arguments(&["--fulfillment-source"])).unwrap_err();
        assert!(missing.contains("missing option value"), "{missing}");
        let repeated = run_from_args(arguments(&[
            "--fulfillment-offer-lifetime-seconds",
            "30",
            "--fulfillment-offer-lifetime-seconds",
            "60",
        ]))
        .unwrap_err();
        assert!(repeated.contains("more than once"), "{repeated}");
    }
}
