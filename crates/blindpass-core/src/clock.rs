// SPDX-License-Identifier: AGPL-3.0-only

use std::ffi::{c_int, c_long};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClockSample {
    pub boot_id: Option<String>,
    pub boottime_ms: i64,
    pub host_wall_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClockAnchor {
    pub boot_id: Option<String>,
    pub boottime_ms: i64,
    pub database_ms: i64,
    pub host_wall_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockError {
    Unavailable,
}

/// Injectable source used by the controller store's clock monitor. Production
/// uses `SystemClock`; tests can supply deterministic boot and wall readings.
pub trait ClockSource: Send + Sync {
    fn sample(&self) -> Result<ClockSample, ClockError>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl ClockSource for SystemClock {
    fn sample(&self) -> Result<ClockSample, ClockError> {
        let host_wall_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ClockError::Unavailable)?
            .as_millis()
            .try_into()
            .map_err(|_| ClockError::Unavailable)?;
        Ok(ClockSample {
            boot_id: fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .ok()
                .map(|id| id.trim().to_owned())
                .filter(|id| !id.is_empty()),
            boottime_ms: boottime_milliseconds()?,
            host_wall_ms,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunningClockCheck {
    pub database_regressed: bool,
    pub host_regressed: bool,
    pub database_advanced: bool,
    pub host_advanced: bool,
}

pub fn check_running_clock(
    previous_database_ms: i64,
    previous_host_ms: i64,
    current_database_ms: i64,
    current_host_ms: i64,
    monotonic_elapsed_ms: i64,
    tolerance_ms: i64,
) -> RunningClockCheck {
    let expected_database_ms = previous_database_ms.saturating_add(monotonic_elapsed_ms);
    let expected_host_ms = previous_host_ms.saturating_add(monotonic_elapsed_ms);
    RunningClockCheck {
        database_regressed: current_database_ms.saturating_add(tolerance_ms) < expected_database_ms,
        host_regressed: current_host_ms.saturating_add(tolerance_ms) < expected_host_ms,
        database_advanced: current_database_ms > expected_database_ms.saturating_add(tolerance_ms),
        host_advanced: current_host_ms > expected_host_ms.saturating_add(tolerance_ms),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupClockCheck {
    SameBoot,
    BootChangedOrUnknown,
    DatabaseRegressed,
    HostRegressed,
    BothRegressed,
}

pub fn check_startup_clock(
    previous: &ClockAnchor,
    current: &ClockAnchor,
    tolerance_ms: i64,
) -> StartupClockCheck {
    let Some(previous_boot_id) = previous.boot_id.as_deref() else {
        return StartupClockCheck::BootChangedOrUnknown;
    };
    let Some(current_boot_id) = current.boot_id.as_deref() else {
        return StartupClockCheck::BootChangedOrUnknown;
    };
    if previous_boot_id != current_boot_id || current.boottime_ms < previous.boottime_ms {
        return StartupClockCheck::BootChangedOrUnknown;
    }
    let elapsed_ms = current.boottime_ms - previous.boottime_ms;
    let expected_database_ms = previous.database_ms.saturating_add(elapsed_ms);
    let expected_host_ms = previous.host_wall_ms.saturating_add(elapsed_ms);
    let database_regressed =
        current.database_ms.saturating_add(tolerance_ms) < expected_database_ms;
    let host_regressed = current.host_wall_ms.saturating_add(tolerance_ms) < expected_host_ms;
    match (database_regressed, host_regressed) {
        (true, true) => StartupClockCheck::BothRegressed,
        (true, false) => StartupClockCheck::DatabaseRegressed,
        (false, true) => StartupClockCheck::HostRegressed,
        (false, false) => StartupClockCheck::SameBoot,
    }
}

#[cfg(target_os = "linux")]
fn boottime_milliseconds() -> Result<i64, ClockError> {
    #[repr(C)]
    struct Timespec {
        tv_sec: c_long,
        tv_nsec: c_long,
    }

    unsafe extern "C" {
        fn clock_gettime(clock_id: c_int, time: *mut Timespec) -> c_int;
    }

    const CLOCK_BOOTTIME: c_int = 7;
    let mut time = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `time` points to a writable `timespec` with the Linux ABI layout.
    let result = unsafe { clock_gettime(CLOCK_BOOTTIME, &mut time) };
    if result != 0 {
        return Err(ClockError::Unavailable);
    }
    #[cfg(target_pointer_width = "64")]
    let (seconds, nanoseconds) = (time.tv_sec, time.tv_nsec);
    #[cfg(target_pointer_width = "32")]
    let (seconds, nanoseconds) = (i64::from(time.tv_sec), i64::from(time.tv_nsec));
    Ok(seconds.saturating_mul(1_000) + nanoseconds / 1_000_000)
}

#[cfg(not(target_os = "linux"))]
fn boottime_milliseconds() -> Result<i64, ClockError> {
    Err(ClockError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::{ClockAnchor, StartupClockCheck, check_running_clock, check_startup_clock};

    fn anchor(
        boot_id: Option<&str>,
        boottime_ms: i64,
        database_ms: i64,
        host_wall_ms: i64,
    ) -> ClockAnchor {
        ClockAnchor {
            boot_id: boot_id.map(str::to_owned),
            boottime_ms,
            database_ms,
            host_wall_ms,
        }
    }

    #[test]
    fn running_clock_tolerance_distinguishes_small_and_large_steps() {
        let within = check_running_clock(10_000, 20_000, 9_000, 19_000, 1_000, 2_000);
        assert!(!within.database_regressed && !within.host_regressed);
        let beyond = check_running_clock(10_000, 20_000, 7_999, 17_999, 1_000, 2_000);
        assert!(beyond.database_regressed && beyond.host_regressed);
    }

    #[test]
    fn running_clock_detects_database_and_host_regressions_independently() {
        let database = check_running_clock(10_000, 20_000, 7_000, 21_000, 1_000, 2_000);
        assert!(database.database_regressed);
        assert!(!database.host_regressed);
        let host = check_running_clock(10_000, 20_000, 11_000, 17_000, 1_000, 2_000);
        assert!(!host.database_regressed);
        assert!(host.host_regressed);
    }

    #[test]
    fn forward_clock_steps_do_not_fence() {
        let forward = check_running_clock(10_000, 20_000, 20_000, 30_000, 1_000, 2_000);
        assert!(!forward.database_regressed && !forward.host_regressed);
        assert!(forward.database_advanced && forward.host_advanced);
    }

    #[test]
    fn startup_clock_checks_boot_identity_and_both_wall_clocks() {
        let previous = anchor(Some("boot-a"), 10_000, 100_000, 200_000);
        let same_now = anchor(Some("boot-a"), 20_000, 110_000, 210_000);
        let same = check_startup_clock(&previous, &same_now, 2_000);
        assert_eq!(same, StartupClockCheck::SameBoot);
        let changed_now = anchor(Some("boot-b"), 20_000, 110_000, 210_000);
        let changed = check_startup_clock(&previous, &changed_now, 2_000);
        assert_eq!(changed, StartupClockCheck::BootChangedOrUnknown);
        let unknown_now = anchor(None, 20_000, 110_000, 210_000);
        let unknown = check_startup_clock(&previous, &unknown_now, 2_000);
        assert_eq!(unknown, StartupClockCheck::BootChangedOrUnknown);
    }

    #[test]
    fn startup_clock_tolerance_and_independent_regressions() {
        let previous = anchor(Some("boot-a"), 10_000, 100_000, 200_000);
        let within_now = anchor(Some("boot-a"), 20_000, 108_001, 208_001);
        let within = check_startup_clock(&previous, &within_now, 2_000);
        assert_eq!(within, StartupClockCheck::SameBoot);
        let database_now = anchor(Some("boot-a"), 20_000, 107_999, 210_000);
        let database = check_startup_clock(&previous, &database_now, 2_000);
        assert_eq!(database, StartupClockCheck::DatabaseRegressed);
        let host_now = anchor(Some("boot-a"), 20_000, 210_000, 207_999);
        let host = check_startup_clock(&previous, &host_now, 2_000);
        assert_eq!(host, StartupClockCheck::HostRegressed);
    }
}
