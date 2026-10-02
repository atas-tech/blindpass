// SPDX-License-Identifier: AGPL-3.0-only

//! Disposable root VM persistence probe. Fixed generated metadata only; no
//! website, browser, credential or cleanup acceptance is implied by this test.
use blindpass_broker::session_journal::{
    Reservation, RevokeHandle, SessionBinding, SessionJournal, SessionReceipt, SessionState,
};
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::time::Duration;

fn binding() -> SessionBinding {
    SessionBinding {
        node_id: "vm-node-a".into(),
        workload_id: "vm-workload-a".into(),
        recipe_fingerprint: "a".repeat(64),
        operation_id: "vm-operation-1".into(),
        idempotency_key: "vm-retry-1".into(),
        request_event_key: None,
        workload_unit: "vm-agent-1.service".into(),
        workload_invocation: "a".repeat(32),
        resource: "vm-report-1".into(),
        account: "vm-primary".into(),
    }
}
fn receipt() -> SessionReceipt {
    SessionReceipt {
        original_deadline_ms: 301_000,
        revoke_handle: RevokeHandle::Fixture {
            account: "vm-primary".into(),
            session_reference: "VM-NONBEARER-REFERENCE".into(),
        },
        browser_unit: "blindpass-browser-vm.service".into(),
        browser_invocation: "b".repeat(32),
    }
}
fn seed() -> Result<SessionJournal, ()> {
    let mut journal = SessionJournal::open().map_err(|_| ())?;
    if journal.reserve(binding(), 1_000).map_err(|_| ())? != Reservation::New {
        return Err(());
    }
    journal
        .record_helper(
            "vm-operation-1",
            "blindpass-login-helper@vm-fixture.service",
            &"c".repeat(32),
            1_000,
        )
        .map_err(|_| ())?;
    journal
        .record_login(
            "vm-operation-1",
            receipt().original_deadline_ms,
            receipt().revoke_handle,
            1_001,
        )
        .map_err(|_| ())?;
    Ok(journal)
}
fn main() {
    if run().is_err() {
        eprintln!("P05-JOURNAL-VM failed");
        std::process::exit(1);
    }
}
fn run() -> Result<(), ()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [mode] if mode == "seed-hold" => {
            let _journal = seed()?;
            println!("P05-JOURNAL-VM durable_login_intent=ready");
            std::io::stdout().flush().map_err(|_| ())?;
            loop {
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        [mode] if mode == "recover" => {
            let mut journal = SessionJournal::open().map_err(|_| ())?;
            if journal.reserve(binding(), 1_002).map_err(|_| ())?
                != Reservation::Existing(SessionState::BlockedUncertain)
            {
                return Err(());
            }
            let pending = journal.pending();
            if pending.len() != 1
                || pending[0].revoke_handle.as_ref() != Some(&receipt().revoke_handle)
                || pending[0].browser_unit.is_some()
            {
                return Err(());
            }
            println!(
                "P05-JOURNAL-VM killed_writer=recovered handle=preserved retry=blocked_uncertain"
            );
            Ok(())
        }
        [mode] if mode == "diskfull" => {
            let mut journal = seed()?;
            let fill = "/var/lib/blindpass/broker/sessions/fill";
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(fill)
                .map_err(|_| ())?;
            let error = file.write_all(&[0u8; 262_144]).err().ok_or(())?;
            if error.raw_os_error() != Some(28) {
                return Err(());
            }
            if journal.activate("vm-operation-1", receipt(), 1_002).is_ok()
                || journal.reserve(binding(), 1_003).is_ok()
            {
                return Err(());
            }
            drop(file);
            std::fs::remove_file(fill).map_err(|_| ())?;
            drop(journal);
            let mut restored = SessionJournal::open().map_err(|_| ())?;
            if restored.reserve(binding(), 1_004).map_err(|_| ())?
                != Reservation::Existing(SessionState::BlockedUncertain)
            {
                return Err(());
            }
            if restored.pending()[0].revoke_handle.as_ref() != Some(&receipt().revoke_handle) {
                return Err(());
            }
            println!(
                "P05-JOURNAL-VM actual_enospc=observed effects=fenced durable_intent=preserved retry=blocked_uncertain"
            );
            Ok(())
        }
        _ => Err(()),
    }
}
