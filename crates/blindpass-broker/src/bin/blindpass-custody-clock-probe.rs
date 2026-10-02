// SPDX-License-Identifier: AGPL-3.0-only
//! Disposable guest recipient-key clock probe. No plaintext or key is output.
use blindpass_core::clock::{ClockSource, SystemClock};
use blindpass_core::custody::{EphemeralCustody, RecipientKeyPair};
use blindpass_core::secret::SecretBytes;
use std::io::{Read, Write};
use std::time::{Duration, Instant};

fn main() {
    if run().is_err() {
        eprintln!("custody_clock_probe_failed");
        std::process::exit(70);
    }
}

fn run() -> Result<(), ()> {
    let mode = std::env::args().nth(1).ok_or(())?;
    if !matches!(mode.as_str(), "live" | "expired") || std::env::args().count() != 2 {
        return Err(());
    }
    let mut random = vec![0; 32];
    std::fs::File::open("/dev/urandom")
        .map_err(|_| ())?
        .read_exact(&mut random)
        .map_err(|_| ())?;
    let canary = SecretBytes::new(random);
    let mut custody = EphemeralCustody::new(Duration::from_millis(3000));
    let public = custody.provision("p05-clock-recipient").map_err(|_| ())?;
    let sealed = RecipientKeyPair::seal(&public, canary.as_bytes(), &[]).map_err(|_| ())?;
    let boot = SystemClock.sample().map_err(|_| ())?.boottime_ms;
    let runnable = Instant::now();
    println!("P05-CUSTODY-CLOCK key_ready=true");
    std::io::stdout().flush().map_err(|_| ())?;
    let mut signal = [0];
    std::io::stdin().read_exact(&mut signal).map_err(|_| ())?;
    if signal != *b"\n" {
        return Err(());
    }
    let elapsed_boot = SystemClock
        .sample()
        .map_err(|_| ())?
        .boottime_ms
        .checked_sub(boot)
        .ok_or(())?;
    let elapsed_runnable = runnable.elapsed().as_millis();
    let result = custody.open_once("p05-clock-recipient", &sealed.enc, &sealed.ciphertext, &[]);
    if mode == "expired" {
        if elapsed_boot < 3000 || elapsed_runnable >= 3000 || result.is_ok() || !custody.is_empty()
        {
            return Err(());
        }
    } else if elapsed_boot >= 3000 || result.map_err(|_| ())?.as_bytes() != canary.as_bytes() {
        return Err(());
    }
    if custody
        .open_once("p05-clock-recipient", &sealed.enc, &sealed.ciphertext, &[])
        .is_ok()
    {
        return Err(());
    }
    println!(
        "P05-CUSTODY-CLOCK mode={mode} boottime_elapsed_ms={elapsed_boot} runnable_elapsed_ms={elapsed_runnable} one_use=true source_output=none"
    );
    Ok(())
}
