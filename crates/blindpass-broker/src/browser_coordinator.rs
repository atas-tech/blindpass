// SPDX-License-Identifier: AGPL-3.0-only
//! Root browser actors. Only signed candidates retaining their original kernel
//! process can enter this pipeline; external IO never holds the broker mutex.
use crate::browser_proxy::{
    BrowserPeerBinding, BrowserProxy, BrowserProxySlot, ProxyError, ReadyBrowserContext,
};
use crate::runtime_identity::{RuntimeBinding, RuntimeIdentityBook, RuntimeIdentityListener};
use crate::runtime_manager::RuntimeManagerClient;
use crate::session_journal::{SessionJournal, SessionReceipt};
use crate::{BrokerError, BrokerState, BrowserPreparation, BrowserResource};
use blindpass_core::fleet::Grant;
use blindpass_core::identity::{PeerIdentity, WorkloadRequest};
use blindpass_core::secret::SecretBytes;
use std::collections::{BTreeMap, BTreeSet};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
pub(crate) struct BrowserCandidate {
    pub(crate) grant: Grant,
    pub(crate) resource: BrowserResource,
    pub(crate) original: crate::original_workload::OriginalWorkloadLease,
}
struct RuntimeConfig {
    helper_uid: u32,
    workload_group: u32,
    helper_book: Arc<RuntimeIdentityBook>,
    browser_book: Arc<RuntimeIdentityBook>,
}
#[repr(C)]
struct Passwd {
    name: *mut std::ffi::c_char,
    password: *mut std::ffi::c_char,
    uid: u32,
    gid: u32,
    gecos: *mut std::ffi::c_char,
    dir: *mut std::ffi::c_char,
    shell: *mut std::ffi::c_char,
}
unsafe extern "C" {
    fn getpwnam(name: *const std::ffi::c_char) -> *mut Passwd;
}
fn helper_uid() -> Result<u32, BrokerError> {
    let name = std::ffi::CString::new("blindpass-login").expect("static user");
    // NSS lookup occurs once before coordinator listener/actor threads start.
    let entry = unsafe { getpwnam(name.as_ptr()) };
    if entry.is_null() {
        return Err(BrokerError::Configuration(
            "browser_helper_user_unavailable",
        ));
    }
    let uid = unsafe { (*entry).uid };
    if uid == 0 {
        return Err(BrokerError::Configuration("browser_helper_user_invalid"));
    }
    Ok(uid)
}
/// External effects of the dispatcher. Production talks to the runtime
/// manager, the administrator revocation channel and real threads; tests
/// substitute fakes so scheduling and recovery decisions run deterministically.
pub(crate) trait DispatchEnv {
    /// Class-wide stop of the managed helper/browser units and stale backends.
    fn recover_runtimes(&mut self) -> Result<(), &'static str>;
    /// Account-wide website revoke through the administrator channel. A known
    /// handle is not enough: a lost reply or interrupted helper may have
    /// created another session.
    fn revoke_account(
        &mut self,
        resource: &BrowserResource,
        operation: &str,
        administrator: &SecretBytes,
    ) -> bool;
    /// Run the actor for a prepared login. A failure must drop `slot` unrun,
    /// which releases the dispatcher's registration.
    fn launch(&mut self, job: Box<crate::PreparedBrowserLogin>, slot: ActorSlot) -> Result<(), ()>;
}
struct ProductionEnv {
    state: Arc<Mutex<BrokerState>>,
    journal: Arc<Mutex<SessionJournal>>,
    config: Arc<RuntimeConfig>,
}
impl DispatchEnv for ProductionEnv {
    fn recover_runtimes(&mut self) -> Result<(), &'static str> {
        RuntimeManagerClient::connect().and_then(|mut manager| manager.recover())
    }
    fn revoke_account(
        &mut self,
        resource: &BrowserResource,
        operation: &str,
        administrator: &SecretBytes,
    ) -> bool {
        let Some(deadline) = crate::grants::boottime_ms()
            .ok()
            .and_then(|now| now.checked_add(5000))
        else {
            return false;
        };
        crate::session_revoker::RevocationClient::prepare(
            resource,
            operation,
            administrator,
            deadline,
        )
        .inspect_err(|_| {
            eprintln!("blindpass-browser: recovery_waiting stage=administrator-preflight");
        })
        .is_ok_and(|mut revoker| {
            let revoked = revoker.revoke_account().is_ok();
            if !revoked {
                eprintln!("blindpass-browser: recovery_waiting stage=website-cleanup");
            }
            let _ = revoker.close();
            revoked
        })
    }
    fn launch(&mut self, job: Box<crate::PreparedBrowserLogin>, slot: ActorSlot) -> Result<(), ()> {
        let state = Arc::clone(&self.state);
        let journal = Arc::clone(&self.journal);
        let config = Arc::clone(&self.config);
        // If spawning fails the closure (and the slot inside it) is dropped,
        // releasing the registration. The consumed journal intent stays
        // uncertain; no source has reached a helper and no retry may replay
        // login.
        std::thread::Builder::new()
            .name("blindpass-browser-session".into())
            .spawn(move || {
                let _slot = slot;
                run_actor(job, state, journal, config);
            })
            .map(|_| ())
            .map_err(|_| ())
    }
}
pub(crate) fn start(
    state: Arc<Mutex<BrokerState>>,
    workload_group: &str,
) -> Result<(), BrokerError> {
    let helper_uid = helper_uid()?;
    let helper_group = crate::lookup_gid("blindpass-login")?;
    let runtime_group = crate::lookup_gid("blindpass-runtime")?;
    let workload_group = crate::lookup_gid(workload_group)?;
    let journal = SessionJournal::open().map_err(BrokerError::Configuration)?;
    // Startup has no actor authority. Stop all fixed managed helper/browser
    // classes and remove only protected stale backends before allowing any
    // actor. A failure here must not take native delivery down with it: the
    // dispatcher keeps browser dispatch disabled and retries until a class-wide
    // recovery succeeds, so no actor ever starts before one has.
    let startup = RuntimeManagerClient::connect().and_then(|mut manager| manager.recover());
    let journal = Arc::new(Mutex::new(journal));
    let helper_book = Arc::new(RuntimeIdentityBook::new_private_helper());
    let browser_book = Arc::new(RuntimeIdentityBook::new());
    let helper_listener =
        RuntimeIdentityListener::bind_private_helper(helper_group, Arc::clone(&helper_book))
            .map_err(BrokerError::Configuration)?;
    let browser_listener = RuntimeIdentityListener::bind(runtime_group, Arc::clone(&browser_book))
        .map_err(BrokerError::Configuration)?;
    for (name, listener) in [
        ("bp-helper-proof", helper_listener),
        ("bp-browser-proof", browser_listener),
    ] {
        std::thread::Builder::new()
            .name(name.into())
            .spawn(move || {
                let _ = listener.serve(Arc::new(AtomicBool::new(false)));
            })
            .map_err(BrokerError::Io)?;
    }
    let config = Arc::new(RuntimeConfig {
        helper_uid,
        workload_group,
        helper_book,
        browser_book,
    });
    let mut dispatcher = Dispatcher::new(Arc::clone(&state), Arc::clone(&journal));
    if startup.is_ok() {
        dispatcher.mark_startup_recovered();
    } else {
        eprintln!("blindpass-browser: startup_recovery_waiting stage=manager-cleanup");
    }
    // Owner retention must see every record that survived the restart before
    // the first request can be admitted.
    dispatcher.sync_unresolved();
    let mut env = ProductionEnv {
        state,
        journal,
        config,
    };
    std::thread::Builder::new()
        .name("bp-browser-disp".into())
        .spawn(move || {
            loop {
                let Ok(boot) = crate::grants::boottime_ms() else {
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                };
                dispatcher.iteration(boot, &mut env);
                std::thread::sleep(Duration::from_millis(100));
            }
        })
        .map_err(BrokerError::Io)?;
    Ok(())
}
/// Records examined per recovery pass: bounds how long the dispatcher thread
/// can spend in administrator network calls before it dispatches again.
const MAX_RECOVERIES_PER_PASS: usize = 4;
/// Retry spacing after a failed attempt. Records whose processes are known
/// terminated retry quickly; others only repeat the revoke (the only thing a
/// light pass can do for them) about once per helper lifetime.
const RETRY_MS: u64 = 5_000;
const SLOW_RETRY_MS: u64 = 60_000;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecoveryMode {
    /// No actor is running: a class-wide stop proves every pending record's
    /// processes are gone, so a confirmed revoke may close the record.
    Full,
    /// Actors are running: a class-wide stop would kill their units. Revoke
    /// the account for pending records that belong to no running actor, and
    /// close one only where its processes are already known terminated.
    Light,
}
struct Schedule {
    delivery: u64,
    maintenance: u64,
    recovery: u64,
    unfence: u64,
    startup: u64,
}
pub(crate) struct Dispatcher {
    state: Arc<Mutex<BrokerState>>,
    journal: Arc<Mutex<SessionJournal>>,
    active: Arc<AtomicUsize>,
    /// Grant ids with a running actor, for the candidate loop.
    running_grants: BTreeSet<String>,
    /// Operation ids with a running actor. Registered by the dispatcher thread
    /// BEFORE the actor is spawned and removed when its `ActorSlot` drops, so a
    /// pending record that belongs to a live actor is never touched by recovery.
    running_operations: Arc<Mutex<BTreeSet<String>>>,
    finished_sender: std::sync::mpsc::Sender<String>,
    finished_receiver: std::sync::mpsc::Receiver<String>,
    /// Operation ids whose helper/browser processes are known terminated:
    /// the records pending when the first class-wide recovery succeeded and
    /// those pending at each later class-wide recovery with no actor running.
    terminated: BTreeSet<String>,
    startup_recovered: bool,
    schedule: Schedule,
    published: BTreeSet<String>,
    /// Next recovery attempt and consecutive failures per operation id.
    attempts: BTreeMap<String, (u64, u32)>,
}
impl Dispatcher {
    pub(crate) fn new(state: Arc<Mutex<BrokerState>>, journal: Arc<Mutex<SessionJournal>>) -> Self {
        let (finished_sender, finished_receiver) = std::sync::mpsc::channel();
        Self {
            state,
            journal,
            active: Arc::new(AtomicUsize::new(0)),
            running_grants: BTreeSet::new(),
            running_operations: Arc::new(Mutex::new(BTreeSet::new())),
            finished_sender,
            finished_receiver,
            terminated: BTreeSet::new(),
            startup_recovered: false,
            schedule: Schedule {
                delivery: 0,
                maintenance: 0,
                recovery: 0,
                unfence: 0,
                startup: 0,
            },
            published: BTreeSet::new(),
            attempts: BTreeMap::new(),
        }
    }
    /// The startup class-wide recovery succeeded. No actor can have started
    /// before this, so every record pending now is from a previous broker
    /// lifetime and its processes are gone.
    pub(crate) fn mark_startup_recovered(&mut self) {
        self.startup_recovered = true;
        self.remember_terminated();
    }
    fn remember_terminated(&mut self) {
        if let Ok(journal) = self.journal.lock() {
            self.terminated.extend(
                journal
                    .pending()
                    .into_iter()
                    .map(|record| record.binding.operation_id.clone()),
            );
        }
    }
    /// Refresh owner retention's view of unfinished journal records.
    pub(crate) fn sync_unresolved(&self) {
        if let Ok(mut state) = self.state.lock()
            && let Ok(journal) = self.journal.lock()
        {
            state.sync_browser_unresolved_requests(&journal);
        }
    }
    /// One scheduling step at BOOTTIME `boot`. Nothing here may wait on a
    /// pending journal record: exclusivity is enforced per account and
    /// workload by `SessionJournal::reserve`, so a record blocks only what it
    /// names.
    pub(crate) fn iteration(&mut self, boot: u64, env: &mut dyn DispatchEnv) {
        if boot >= self.schedule.delivery {
            if let Ok(mut state) = self.state.lock()
                && let Ok(journal) = self.journal.lock()
            {
                state.retry_browser_closures(&journal, &mut self.published);
                state.sync_browser_unresolved_requests(&journal);
            }
            self.schedule.delivery = boot.saturating_add(5_000);
        }
        if boot >= self.schedule.maintenance {
            self.maintain();
            self.schedule.maintenance = boot.saturating_add(60_000);
        }
        if boot >= self.schedule.unfence {
            self.try_unfence();
            self.schedule.unfence = boot.saturating_add(5_000);
        }
        if !self.startup_recovered {
            if boot >= self.schedule.startup {
                self.schedule.startup = boot.saturating_add(5_000);
                if env.recover_runtimes().is_ok() {
                    eprintln!("blindpass-browser: startup_recovery_complete");
                    self.mark_startup_recovered();
                }
            }
            if !self.startup_recovered {
                return;
            }
        }
        if boot >= self.schedule.recovery
            && self
                .journal
                .lock()
                .is_ok_and(|journal| !journal.pending().is_empty())
        {
            let mode = if self.active.load(Ordering::Acquire) == 0 {
                RecoveryMode::Full
            } else {
                RecoveryMode::Light
            };
            self.recover(mode, boot, env);
            self.schedule.recovery = boot.saturating_add(5_000);
        }
        self.dispatch(env);
    }
    /// Time-bound maintenance: retention prune, the independent-maximum
    /// release, and owner retention. All use signed controller time.
    fn maintain(&mut self) {
        if let Ok(observed) = time(&self.state)
            && let Ok(mut journal) = self.journal.lock()
        {
            let _ = journal.prune(observed);
            let released = journal.release_expired(observed);
            drop(journal);
            if let Ok(released) = released {
                for session in &released {
                    eprintln!("blindpass-browser: record_released stage=independent-maximum");
                    if session.had_original_deadline
                        && let Ok(mut state) = self.state.lock()
                        && let Ok(journal) = self.journal.lock()
                    {
                        let _ = state.publish_browser_closure(
                            &journal,
                            &session.node_id,
                            &session.idempotency_key,
                        );
                    }
                }
            }
        }
        if let Ok(mut state) = self.state.lock() {
            if let Ok(journal) = self.journal.lock() {
                state.sync_browser_unresolved_requests(&journal);
            }
            let _ = state.prune_crowded_owners();
        }
    }
    /// A failed journal write fences it for new work until a durable no-op
    /// snapshot succeeds; recovery and dispatch resume the moment it does.
    fn try_unfence(&mut self) {
        if let Ok(mut journal) = self.journal.lock()
            && journal.is_fenced()
            && journal.try_unfence()
        {
            eprintln!("blindpass-browser: journal_unfenced");
        }
    }
    fn recover(&mut self, mode: RecoveryMode, boot: u64, env: &mut dyn DispatchEnv) {
        recover_pending(
            &RecoveryContext {
                state: &self.state,
                journal: &self.journal,
                running: &self.running_operations,
            },
            mode,
            boot,
            &mut self.terminated,
            &mut self.attempts,
            env,
        );
    }
    fn dispatch(&mut self, env: &mut dyn DispatchEnv) {
        while let Ok(id) = self.finished_receiver.try_recv() {
            self.running_grants.remove(&id);
        }
        // New work cannot start while the journal is fenced; preparing would
        // only copy source bytes before `reserve` refused.
        if self.journal.lock().is_ok_and(|journal| journal.is_fenced()) {
            return;
        }
        let candidates = self
            .state
            .lock()
            .map(|state| state.browser_dispatch_candidates())
            .unwrap_or_default();
        for candidate in candidates {
            if self.active.load(Ordering::Acquire) >= 16
                || self.running_grants.contains(&candidate.grant.id)
            {
                continue;
            }
            // The journal refuses a second unfinished operation for the same
            // account or workload (and any replayed grant). Skip such a
            // candidate here rather than preparing it every tick.
            if self.journal.lock().is_ok_and(|journal| {
                journal.admission_blocked(
                    candidate.resource.account(),
                    &candidate.grant.unit,
                    &candidate.grant.id,
                )
            }) {
                continue;
            }
            if candidate
                .original
                .ensure_current(Instant::now() + Duration::from_secs(2))
                .is_err()
            {
                continue;
            }
            let request = WorkloadRequest {
                node_id: candidate.grant.node_id.clone(),
                workload_id: candidate.grant.workload_id.clone(),
                claimed_unit: candidate.grant.unit.clone(),
                claimed_invocation_id: candidate.grant.invocation_id.clone(),
                operation: format!("consume:{}", candidate.grant.id),
            };
            let prepared = {
                let Ok(mut state) = self.state.lock() else {
                    continue;
                };
                let Ok(mut journal) = self.journal.lock() else {
                    continue;
                };
                let prepared = state.prepare_browser_login(
                    candidate.original.identity(),
                    &request,
                    &candidate.resource,
                    &mut journal,
                );
                // Same critical section as the reservation: owner retention
                // never observes a reserved record without its key.
                state.sync_browser_unresolved_requests(&journal);
                prepared
            };
            let Ok(BrowserPreparation::Login(job)) = prepared else {
                continue;
            };
            let id = job.grant_id().to_owned();
            let operation = job.operation_id().to_owned();
            self.running_grants.insert(id.clone());
            if let Ok(mut running) = self.running_operations.lock() {
                running.insert(operation.clone());
            }
            self.active.fetch_add(1, Ordering::AcqRel);
            let slot = ActorSlot {
                count: Arc::clone(&self.active),
                finished: self.finished_sender.clone(),
                id,
                operation,
                running_operations: Arc::clone(&self.running_operations),
            };
            let _ = env.launch(job, slot);
        }
    }
}
struct RecoveryContext<'a> {
    state: &'a Arc<Mutex<BrokerState>>,
    journal: &'a Arc<Mutex<SessionJournal>>,
    running: &'a Arc<Mutex<BTreeSet<String>>>,
}
fn recover_pending(
    context: &RecoveryContext<'_>,
    mode: RecoveryMode,
    boot: u64,
    terminated: &mut BTreeSet<String>,
    attempts: &mut BTreeMap<String, (u64, u32)>,
    env: &mut dyn DispatchEnv,
) {
    let (state, journal) = (context.state, context.journal);
    let running = context
        .running
        .lock()
        .map(|running| running.clone())
        .unwrap_or_default();
    let mut records = journal
        .lock()
        .map(|journal| journal.pending().into_iter().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    attempts.retain(|operation, _| {
        records
            .iter()
            .any(|record| record.binding.operation_id == *operation)
    });
    // A record that belongs to a live actor is that actor's to clean up.
    records.retain(|record| !running.contains(&record.binding.operation_id));
    if records.is_empty() {
        return;
    }
    if mode == RecoveryMode::Full {
        if env.recover_runtimes().is_err() {
            eprintln!("blindpass-browser: recovery_waiting stage=manager-cleanup");
            return;
        }
        // No actor was running and none can start while this thread recovers:
        // every pending record's helper and browser are stopped.
        terminated.extend(
            records
                .iter()
                .map(|record| record.binding.operation_id.clone()),
        );
    }
    let mut examined = 0;
    for record in records {
        let operation = record.binding.operation_id.clone();
        if examined >= MAX_RECOVERIES_PER_PASS {
            break;
        }
        if attempts
            .get(&operation)
            .is_some_and(|(next, _)| boot < *next)
        {
            continue;
        }
        examined += 1;
        let processes_terminated = terminated.contains(&operation);
        let failures = attempts
            .get(&operation)
            .map_or(0, |(_, failures)| *failures);
        let delay = if processes_terminated && failures < 3 {
            RETRY_MS
        } else {
            SLOW_RETRY_MS
        };
        attempts.insert(
            operation.clone(),
            (boot.saturating_add(delay), failures + 1),
        );
        let input = state
            .lock()
            .ok()
            .and_then(|mut state| state.browser_recovery_input(&record).ok());
        let Some((resource, administrator, observed)) = input else {
            // Trusted time and the administrator credential arrive when the node
            // reconnects and the operator re-provisions. Waiting for them is not a
            // failed revoke, so it never moves the record into the slow tier.
            attempts.insert(operation, (boot.saturating_add(RETRY_MS), failures));
            eprintln!("blindpass-browser: recovery_waiting stage=recipe-time-administrator");
            continue;
        };
        if !journal.lock().is_ok_and(|mut journal| {
            journal
                .begin_revoke(&record.binding.operation_id, observed)
                .is_ok()
        }) {
            eprintln!("blindpass-browser: recovery_waiting stage=journal-withdrawal");
            continue;
        }
        let revoked = env.revoke_account(&resource, &record.binding.operation_id, &administrator);
        if let Ok(observed) = time(state)
            && let Ok(mut state) = state.lock()
            && let Ok(mut journal) = journal.lock()
        {
            let closed = journal
                .reconcile(
                    &record.binding.operation_id,
                    revoked,
                    processes_terminated,
                    observed,
                )
                .is_ok();
            if closed && record.original_deadline_ms.is_some() {
                let _ = state.publish_browser_closure(
                    &journal,
                    &record.binding.node_id,
                    &record.binding.idempotency_key,
                );
            }
            state.sync_browser_unresolved_requests(&journal);
        }
    }
}
fn time(state: &Arc<Mutex<BrokerState>>) -> Result<u64, ()> {
    state
        .lock()
        .map_err(|_| ())?
        .browser_trusted_time()
        .map_err(|_| ())
}
/// Dispatcher registration of one running actor. Dropping it (the actor ended
/// or never started) releases capacity and the operation's running mark.
pub(crate) struct ActorSlot {
    count: Arc<AtomicUsize>,
    finished: std::sync::mpsc::Sender<String>,
    id: String,
    operation: String,
    running_operations: Arc<Mutex<BTreeSet<String>>>,
}
impl Drop for ActorSlot {
    fn drop(&mut self) {
        if let Ok(mut running) = self.running_operations.lock() {
            running.remove(&self.operation);
        }
        self.count.fetch_sub(1, Ordering::AcqRel);
        let _ = self.finished.send(self.id.clone());
    }
}
struct PublicAuthorityGuard {
    alive: Arc<AtomicBool>,
    slot: Arc<BrowserProxySlot>,
    stop: Arc<AtomicBool>,
}
impl Drop for PublicAuthorityGuard {
    fn drop(&mut self) {
        self.alive.store(false, Ordering::Release);
        self.slot.clear();
        self.stop.store(true, Ordering::Release);
    }
}
/// Run the lock-free preparation first, then only journal work under the
/// shared journal mutex. Keeping the two phases in one function lets a test
/// assert that the mutex is free during the first and held during the second.
fn journaled_step<C, A, T>(
    journal: &Mutex<SessionJournal>,
    context: &mut C,
    prepare: impl FnOnce(&mut C) -> Result<A, ()>,
    record: impl FnOnce(&mut C, A, &mut SessionJournal) -> Result<T, ()>,
) -> Result<T, ()> {
    let prepared = prepare(context)?;
    let mut journal = journal.lock().map_err(|_| ())?;
    record(context, prepared, &mut journal)
}
/// Termination requests to the runtime manager, with a fresh connection when
/// the actor's own is missing or dead (a session can outlive the manager's
/// restart by tens of minutes).
trait ManagerLink {
    fn terminate_unit(&mut self, peer: &PeerIdentity, browser: bool) -> Result<(), &'static str>;
}
impl ManagerLink for RuntimeManagerClient {
    fn terminate_unit(&mut self, peer: &PeerIdentity, browser: bool) -> Result<(), &'static str> {
        self.terminate(peer, browser)
    }
}
fn terminate_with_reconnect<M: ManagerLink>(
    link: &mut Option<M>,
    connect: impl FnOnce() -> Option<M>,
    peer: &PeerIdentity,
    browser: bool,
) -> bool {
    if let Some(manager) = link.as_mut()
        && manager.terminate_unit(peer, browser).is_ok()
    {
        return true;
    }
    // Termination of an exact unit/invocation is idempotent, so a second
    // attempt on a new connection is safe after a lost reply.
    *link = connect();
    link.as_mut()
        .is_some_and(|manager| manager.terminate_unit(peer, browser).is_ok())
}
/// What the actor knows about its own effects when it cleans up.
struct CleanupFacts {
    /// An exact helper identity was proved (and so can be terminated).
    helper_identified: bool,
    /// The private helper stage was entered at all.
    helper_attempted: bool,
    /// An exact browser identity was proved.
    browser_verified: bool,
    /// A channel to the browser supervisor was opened.
    supervisor_connected: bool,
}
struct CleanupOutcome {
    website_revoked: bool,
    helper_stopped: bool,
    browser_stopped: bool,
}
trait CleanupActions {
    fn terminate_helper(&mut self) -> bool;
    /// Revoke the known session by handle, or the whole account when no
    /// session was recorded.
    fn revoke_website(&mut self) -> bool;
    /// True only when the supervisor acknowledged the stop.
    fn stop_supervisor(&mut self) -> bool;
    fn terminate_browser(&mut self) -> bool;
}
/// The website revoke never depends on the helper having been stopped: a
/// helper that cannot be verified stopped keeps the record blocked (through
/// `helper_stopped`), and recovery stops it and revokes the whole account
/// again, which also covers a login the helper completes late.
fn run_cleanup(actions: &mut dyn CleanupActions, facts: &CleanupFacts) -> CleanupOutcome {
    let helper_stopped = if facts.helper_identified {
        actions.terminate_helper()
    } else {
        !facts.helper_attempted
    };
    let website_revoked = actions.revoke_website();
    let stop_acknowledged = facts.supervisor_connected && actions.stop_supervisor();
    let browser_stopped = if facts.browser_verified {
        actions.terminate_browser()
    } else {
        // Never connected: nothing was started. Connected without a verified
        // identity (failed prepare or proof): unverified unless stopped.
        !facts.supervisor_connected || stop_acknowledged
    };
    CleanupOutcome {
        website_revoked,
        helper_stopped,
        browser_stopped,
    }
}
struct ActorCleanup<'a> {
    manager: &'a mut Option<RuntimeManagerClient>,
    helper: Option<&'a PeerIdentity>,
    browser: Option<&'a PeerIdentity>,
    revoker: &'a mut Option<crate::session_revoker::RevocationClient>,
    supervisor: &'a mut Option<crate::browser_supervisor::SupervisorClient>,
    session: Option<&'a crate::ApprovedSession>,
}
impl CleanupActions for ActorCleanup<'_> {
    fn terminate_helper(&mut self) -> bool {
        self.helper.is_some_and(|peer| {
            terminate_with_reconnect(
                self.manager,
                || RuntimeManagerClient::connect().ok(),
                peer,
                false,
            )
        })
    }
    fn revoke_website(&mut self) -> bool {
        let Some(revoker) = self.revoker.as_mut() else {
            return false;
        };
        match self.session {
            Some(session) => revoker.revoke_session(session.revoke_handle()).is_ok(),
            None => revoker.revoke_account().is_ok(),
        }
    }
    fn stop_supervisor(&mut self) -> bool {
        self.supervisor
            .as_mut()
            .is_some_and(|browser| browser.stop().is_ok())
    }
    fn terminate_browser(&mut self) -> bool {
        self.browser.is_some_and(|peer| {
            terminate_with_reconnect(
                self.manager,
                || RuntimeManagerClient::connect().ok(),
                peer,
                true,
            )
        })
    }
}
fn run_actor(
    mut job: Box<crate::PreparedBrowserLogin>,
    state: Arc<Mutex<BrokerState>>,
    journal: Arc<Mutex<SessionJournal>>,
    config: Arc<RuntimeConfig>,
) {
    let alive = Arc::new(AtomicBool::new(true));
    let slot = Arc::new(BrowserProxySlot::new());
    let stop_proxy = Arc::new(AtomicBool::new(false));
    let _public_guard = PublicAuthorityGuard {
        alive: Arc::clone(&alive),
        slot: Arc::clone(&slot),
        stop: Arc::clone(&stop_proxy),
    };
    let grant = job.grant.clone();
    let deadline = job.deadline_boottime_ms;
    let authority_state = Arc::clone(&state);
    let current = || {
        authority_state
            .lock()
            .is_ok_and(|state| state.authorize_browser_grant(&grant).is_ok())
    };
    let handoff = || current() && crate::grants::boottime_ms().is_ok_and(|now| now < deadline);
    let mut manager = RuntimeManagerClient::connect().ok();
    let mut helper_identity = None;
    let mut helper_attempted = false;
    let mut browser_runtime = None;
    let mut revoker = None;
    let mut supervisor = None;
    let mut session = None;
    let mut proxy_task = None;
    let mut stage = "authority";
    let result = (|| -> Result<(), ()> {
        if !handoff() {
            return Err(());
        }
        stage = "administrator-preflight";
        revoker = Some(job.begin_revocation().map_err(|_| ())?);
        stage = "helper-proof";
        helper_attempted = true;
        let helper = crate::private_helper::begin_private_login(
            &config.helper_book,
            config.helper_uid,
            &[0, job.original_workload.identity().uid],
            deadline,
        )
        .map_err(|_| ())?;
        helper_identity = Some(helper.identity().clone());
        stage = "helper-metadata";
        manager
            .as_mut()
            .ok_or(())?
            .inspect(helper.identity(), false)
            .map_err(|_| ())?;
        if !handoff() {
            return Err(());
        }
        // The original-lease and administrator revalidation can wait seconds
        // on the manager; it runs before, never under, the shared journal lock.
        let exchange = journaled_step(
            &journal,
            &mut job,
            |job| {
                let source = job.take_checked_source(revoker.as_ref().ok_or(())?);
                let observed = time(&state)?;
                source.map(|source| (source, observed)).map_err(|_| ())
            },
            |job, (source, observed), journal| {
                job.journal_helper_exchange(source, helper, journal, observed)
                    .map_err(|_| ())
            },
        )?;
        stage = "private-login";
        let reply = exchange.execute(revoker.as_ref().ok_or(())?, handoff);
        let observed = time(&state)?;
        stage = "session-journal";
        session = Some(
            job.stage_reply(reply, &mut *journal.lock().map_err(|_| ())?, observed)
                .map_err(|status| {
                    eprintln!(
                        "blindpass-browser: helper_reply_failed code={}",
                        status.as_str()
                    );
                })?,
        );
        if !handoff() {
            return Err(());
        }
        stage = "browser-prepare";
        // Retained before `prepare`: a failed prepare may already have started
        // a browser, so cleanup must still see (and try to stop) this channel.
        supervisor =
            Some(crate::browser_supervisor::SupervisorClient::connect(deadline).map_err(|_| ())?);
        let hint = supervisor
            .as_mut()
            .ok_or(())?
            .prepare(&job.resource, job.operation_id())
            .map_err(|_| ())?;
        let mut excluded = vec![0, config.helper_uid];
        if let Ok(state) = state.lock() {
            for workload in &state.workloads {
                if let Some(uid) = workload
                    .account
                    .strip_prefix("uid:")
                    .and_then(|uid| uid.parse::<u32>().ok())
                {
                    excluded.push(uid);
                }
            }
        }
        excluded.sort_unstable();
        excluded.dedup();
        let ticket = config
            .browser_book
            .register_for(
                RuntimeBinding::browser_activation(&excluded).map_err(|_| ())?,
                Duration::from_secs(5),
            )
            .map_err(|_| ())?;
        supervisor
            .as_mut()
            .ok_or(())?
            .prove(ticket.challenge())
            .map_err(|_| ())?;
        stage = "browser-proof";
        let runtime = Arc::new(ticket.wait().map_err(|_| ())?);
        browser_runtime = Some(Arc::clone(&runtime));
        runtime
            .ensure_current(Instant::now() + Duration::from_secs(2))
            .map_err(|_| ())?;
        stage = "browser-metadata";
        manager
            .as_mut()
            .ok_or(())?
            .inspect(runtime.identity(), true)
            .map_err(|_| ())?;
        runtime
            .ensure_current(Instant::now() + Duration::from_secs(2))
            .map_err(|_| ())?;
        let session = session.as_ref().ok_or(())?;
        let (boot, observed) = state
            .lock()
            .map_err(|_| ())?
            .browser_clock_anchor()
            .map_err(|_| ())?;
        let session_deadline =
            session_boot_deadline(session.original_deadline_ms(), observed, boot)?;
        if !handoff() {
            return Err(());
        }
        stage = "browser-journal";
        journal
            .lock()
            .map_err(|_| ())?
            .activate(
                job.operation_id(),
                SessionReceipt {
                    original_deadline_ms: session.original_deadline_ms(),
                    revoke_handle: session.revoke_handle().clone(),
                    browser_unit: runtime.identity().unit.clone().ok_or(())?,
                    browser_invocation: runtime.identity().invocation_id.clone().ok_or(())?,
                },
                observed,
            )
            .map_err(|_| ())?;
        journal
            .lock()
            .map_err(|_| ())?
            .guard_context(job.operation_id(), &alive)
            .map_err(|_| ())?;
        if !handoff() {
            return Err(());
        }
        stage = "browser-import";
        supervisor
            .as_mut()
            .ok_or(())?
            .import(session, session_deadline)
            .map_err(|error| {
                stage = match error {
                    crate::browser_supervisor::SupervisorError::Unavailable => {
                        "browser-import-local"
                    }
                    crate::browser_supervisor::SupervisorError::Uncertain => {
                        "browser-import-remote"
                    }
                };
            })?;
        if !handoff() {
            return Err(());
        }
        stage = "browser-publish";
        let context_handle = supervisor.as_mut().ok_or(())?.publish().map_err(|_| ())?;
        let ready_state = Arc::clone(&state);
        let ready_journal = Arc::clone(&journal);
        let ready_alive = Arc::clone(&alive);
        let ready_runtime = Arc::clone(&runtime);
        let ready_grant = grant.clone();
        let ready_authority: Arc<dyn Fn() -> bool + Send + Sync> = Arc::new(move || {
            if !ready_alive.load(Ordering::Acquire) || ready_runtime.ensure_alive().is_err() {
                return false;
            }
            let Ok(state) = ready_state.lock() else {
                return false;
            };
            if state.authorize_browser_grant(&ready_grant).is_err() {
                return false;
            }
            let Ok(time) = state.browser_trusted_time() else {
                return false;
            };
            drop(state);
            ready_journal.lock().is_ok_and(|journal| {
                journal.context_is_active(
                    &ready_grant.id,
                    ready_runtime.identity().unit.as_deref().unwrap_or(""),
                    ready_runtime
                        .identity()
                        .invocation_id
                        .as_deref()
                        .unwrap_or(""),
                    time,
                )
            })
        });
        let operation = job.operation_id().to_owned();
        let context = ReadyBrowserContext::new(
            BrowserPeerBinding::new(
                &grant.workload_id,
                &grant.unit,
                job.original_workload.identity().uid,
                &grant.invocation_id,
            )
            .map_err(|_| ())?,
            session_deadline,
            hint.discovery_hint().2,
            Arc::clone(&ready_authority),
            Arc::new(move |until| open_backend(&operation, until)),
        )
        .map_err(|_| ())?;
        slot.activate(context).map_err(|_| ())?;
        stage = "proxy-publish";
        let proxy =
            BrowserProxy::bind(&grant.workload_id, config.workload_group, Arc::clone(&slot))
                .map_err(|_| ())?;
        let proxy_stop = Arc::clone(&stop_proxy);
        let proxy_alive = Arc::clone(&alive);
        proxy_task = Some(std::thread::spawn(move || {
            if proxy.serve(proxy_stop, Arc::new(|_| {})).is_err() {
                proxy_alive.store(false, Ordering::Release);
            }
        }));
        let availability = journal.lock().map_err(|_| ())?.availability();
        state.lock().map_err(|_| ())?.browser_ready.insert(
            grant.request_event_key.clone().ok_or(())?,
            BrowserReadyMetadata {
                grant: grant.clone(),
                context: context_handle,
                deadline: session_deadline,
                alive: Arc::clone(&alive),
                journal_alive: availability,
            },
        );
        stage = "ready-maintenance";
        let mut next_manager = Instant::now();
        while ready_authority()
            && crate::grants::boottime_ms().is_ok_and(|now| now < session_deadline)
            && supervisor.as_mut().ok_or(())?.check_ready().is_ok()
        {
            if Instant::now() >= next_manager {
                job.revalidate_original_workload(Instant::now() + Duration::from_secs(2))
                    .map_err(|_| ())?;
                runtime
                    .ensure_current(Instant::now() + Duration::from_secs(2))
                    .map_err(|_| ())?;
                next_manager = Instant::now() + Duration::from_secs(5);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Ok(())
    })();
    if result.is_err() {
        eprintln!("blindpass-browser: actor_failed stage={stage}");
    }
    // Withdraw public authority before any logout/termination request.
    alive.store(false, Ordering::Release);
    slot.clear();
    stop_proxy.store(true, Ordering::Release);
    if let Ok(mut state) = state.lock()
        && let Some(key) = grant.request_event_key.as_deref()
    {
        state.browser_ready.remove(key);
        if result.is_err() {
            let _ = state.cancel_browser_operation(job.original_workload.authorization(), key);
        }
    }
    if let Ok(time) = time(&state)
        && let Ok(mut journal) = journal.lock()
    {
        let _ = journal.begin_revoke(job.operation_id(), time);
    }
    let supervisor_connected = supervisor.is_some();
    let outcome = run_cleanup(
        &mut ActorCleanup {
            manager: &mut manager,
            helper: helper_identity.as_ref(),
            browser: browser_runtime.as_ref().map(|runtime| runtime.identity()),
            revoker: &mut revoker,
            supervisor: &mut supervisor,
            session: session.as_ref(),
        },
        &CleanupFacts {
            helper_identified: helper_identity.is_some(),
            helper_attempted,
            browser_verified: browser_runtime.is_some(),
            supervisor_connected,
        },
    );
    if let Some(task) = proxy_task {
        let _ = task.join();
    }
    if let Ok(time) = time(&state)
        && let Ok(mut state) = state.lock()
        && let Ok(mut journal) = journal.lock()
        && journal
            .reconcile(
                job.operation_id(),
                outcome.website_revoked,
                outcome.helper_stopped && outcome.browser_stopped,
                time,
            )
            .is_ok()
        && session.is_some()
    {
        let _ = state.finish_browser_operation(&job, &journal);
    }
    if let Some(revoker) = &mut revoker {
        let _ = revoker.close();
    }
}
#[derive(Debug)]
pub(crate) struct BrowserReadyMetadata {
    pub(crate) grant: Grant,
    pub(crate) context: String,
    pub(crate) deadline: u64,
    pub(crate) alive: Arc<AtomicBool>,
    pub(crate) journal_alive: Arc<AtomicBool>,
}
fn session_boot_deadline(original: u64, controller: u64, boot: u64) -> Result<u64, ()> {
    // The pinned outside supervisor samples /proc/uptime in 10ms quanta.
    // Anchor both clocks at the same BOOTTIME sample and shorten by two quanta
    // so rounding/read ordering cannot extend the absolute website deadline.
    let remaining = original
        .checked_sub(controller)
        .filter(|remaining| *remaining <= 1_800_000)
        .ok_or(())?;
    boot.checked_add(
        remaining
            .checked_sub(20)
            .filter(|remaining| *remaining > 0)
            .ok_or(())?,
    )
    .ok_or(())
}
fn open_backend(
    operation: &str,
    until: Instant,
) -> Result<std::os::unix::net::UnixStream, ProxyError> {
    if Instant::now() >= until {
        return Err(ProxyError::Unavailable);
    }
    let path =
        crate::browser_supervisor::backend_path(operation).map_err(|_| ProxyError::Unavailable)?;
    for parent in [
        std::path::Path::new("/run/blindpass-backends"),
        path.parent().ok_or(ProxyError::Unavailable)?,
    ] {
        let m = std::fs::symlink_metadata(parent).map_err(|_| ProxyError::Unavailable)?;
        if !m.is_dir() || m.uid() != 0 || m.gid() != 0 || m.mode() & 0o7777 != 0o700 {
            return Err(ProxyError::Unavailable);
        }
    }
    let before = std::fs::symlink_metadata(&path).map_err(|_| ProxyError::Unavailable)?;
    if !before.file_type().is_socket()
        || before.uid() != 0
        || before.gid() != 0
        || before.mode() & 0o7777 != 0o600
        || before.nlink() != 1
    {
        return Err(ProxyError::Unavailable);
    }
    let now = crate::grants::boottime_ms().map_err(|_| ProxyError::Unavailable)?;
    let remaining = u64::try_from(until.saturating_duration_since(Instant::now()).as_millis())
        .map_err(|_| ProxyError::Unavailable)?
        .min(5000);
    let stream = crate::private_helper::connect_until(
        &path,
        now.checked_add(remaining).ok_or(ProxyError::Unavailable)?,
    )
    .map_err(|_| ProxyError::Unavailable)?;
    crate::os_identity::require_root_peer(&stream).map_err(|_| ProxyError::Unavailable)?;
    let after = std::fs::symlink_metadata(path).map_err(|_| ProxyError::Unavailable)?;
    if before.dev() != after.dev() || before.ino() != after.ino() {
        return Err(ProxyError::Unavailable);
    }
    Ok(stream)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn session_boot_mapping_never_adds_uptime_sampling_lifetime() {
        assert_eq!(session_boot_deadline(301000, 1000, 23456), Ok(323436));
        for original in [1000, 1010, 1020, 1801001] {
            assert!(session_boot_deadline(original, 1000, 23456).is_err());
        }
        assert!(session_boot_deadline(301000, 1000, u64::MAX).is_err());
    }
    #[test]
    fn actor_exit_withdraws_public_authority_even_without_cleanup() {
        let alive = Arc::new(AtomicBool::new(true));
        let stop = Arc::new(AtomicBool::new(false));
        let guard = PublicAuthorityGuard {
            alive: Arc::clone(&alive),
            slot: Arc::new(BrowserProxySlot::new()),
            stop: Arc::clone(&stop),
        };
        drop(guard);
        assert!(!alive.load(Ordering::Acquire));
        assert!(stop.load(Ordering::Acquire));
    }
    #[test]
    fn actor_slot_drop_releases_capacity_the_running_mark_and_reports_the_original_id() {
        let count = Arc::new(AtomicUsize::new(1));
        let (finished, receiver) = std::sync::mpsc::channel();
        let running = Arc::new(Mutex::new(BTreeSet::from(
            ["operation_original".to_owned()],
        )));
        drop(ActorSlot {
            count: Arc::clone(&count),
            finished,
            id: "gr_original_actor_0123456789".into(),
            operation: "operation_original".into(),
            running_operations: Arc::clone(&running),
        });
        assert_eq!(count.load(Ordering::Acquire), 0);
        assert!(running.lock().unwrap().is_empty());
        assert_eq!(receiver.try_recv().unwrap(), "gr_original_actor_0123456789");
    }

    // ---- dispatcher, recovery and cleanup behaviour ------------------------

    use crate::session_journal::{RevokeHandle, SessionBinding, SessionState};

    #[derive(Default)]
    struct FakeEnv {
        recover_fails: bool,
        recover_calls: usize,
        revoke_ok: bool,
        revoke_calls: Vec<String>,
        fail_launch: bool,
        launched: Vec<(Box<crate::PreparedBrowserLogin>, ActorSlot)>,
        registered_before_launch: Vec<bool>,
    }
    impl DispatchEnv for FakeEnv {
        fn recover_runtimes(&mut self) -> Result<(), &'static str> {
            self.recover_calls += 1;
            if self.recover_fails {
                Err("runtime_management_unavailable")
            } else {
                Ok(())
            }
        }
        fn revoke_account(
            &mut self,
            _resource: &BrowserResource,
            operation: &str,
            _administrator: &SecretBytes,
        ) -> bool {
            self.revoke_calls.push(operation.to_owned());
            self.revoke_ok
        }
        fn launch(
            &mut self,
            job: Box<crate::PreparedBrowserLogin>,
            slot: ActorSlot,
        ) -> Result<(), ()> {
            self.registered_before_launch.push(
                slot.running_operations
                    .lock()
                    .unwrap()
                    .contains(&slot.operation),
            );
            if self.fail_launch {
                drop(slot);
                return Err(());
            }
            self.launched.push((job, slot));
            Ok(())
        }
    }
    struct Harness {
        directory: std::path::PathBuf,
        state: Arc<Mutex<BrokerState>>,
        journal: Arc<Mutex<SessionJournal>>,
        dispatcher: Dispatcher,
        resource: BrowserResource,
        now: u64,
    }
    impl Harness {
        /// `prepare` fills the journal, which is then reopened as a restart
        /// would: every unfinished record becomes `blocked_uncertain`. The
        /// dispatcher starts with startup recovery NOT yet marked.
        fn new(
            label: &str,
            prepare: impl FnOnce(&mut SessionJournal, &BrowserResource, u64),
        ) -> Self {
            let (directory, state, _grant, resource, mut journal) =
                crate::tests::browser_grant_fixture(label);
            let now = state.browser_trusted_time().unwrap();
            prepare(&mut journal, &resource, now);
            drop(journal);
            let journal =
                SessionJournal::open_at(&directory.join("sessions"), crate::effective_uid())
                    .unwrap();
            let state = Arc::new(Mutex::new(state));
            let journal = Arc::new(Mutex::new(journal));
            let dispatcher = Dispatcher::new(Arc::clone(&state), Arc::clone(&journal));
            Self {
                directory,
                state,
                journal,
                dispatcher,
                resource,
                now,
            }
        }
        /// Startup recovery has succeeded without capturing a cohort, so every
        /// record is one created while running.
        fn recovered_without_cohort(&mut self) {
            self.dispatcher.startup_recovered = true;
        }
        fn candidates(&self) -> usize {
            self.state
                .lock()
                .unwrap()
                .browser_dispatch_candidates()
                .len()
        }
        fn state_of(&self, operation: &str) -> Option<SessionState> {
            self.journal
                .lock()
                .unwrap()
                .pending()
                .into_iter()
                .find(|record| record.binding.operation_id == operation)
                .map(|record| record.state)
        }
        fn pending(&self) -> usize {
            self.journal.lock().unwrap().pending().len()
        }
    }
    impl Drop for Harness {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.directory);
        }
    }
    fn binding_for(
        resource: &BrowserResource,
        operation: &str,
        account: &str,
        unit: &str,
        resource_id: &str,
    ) -> SessionBinding {
        SessionBinding {
            node_id: "node-a".into(),
            workload_id: "workload-a".into(),
            operation_id: operation.into(),
            idempotency_key: format!("key-{operation}"),
            request_event_key: None,
            workload_unit: unit.into(),
            workload_invocation: "a".repeat(32),
            resource: resource_id.into(),
            recipe_fingerprint: resource.recipe_fingerprint().unwrap(),
            account: account.into(),
        }
    }
    /// A record the recovery path can actually revoke: the catalog resource's
    /// account and recipe.
    fn recoverable(
        journal: &mut SessionJournal,
        resource: &BrowserResource,
        operation: &str,
        created: u64,
    ) {
        journal
            .reserve(
                binding_for(
                    resource,
                    operation,
                    "primary",
                    "agent.service",
                    "report-primary",
                ),
                created,
            )
            .unwrap();
    }
    fn with_login(
        journal: &mut SessionJournal,
        resource: &BrowserResource,
        operation: &str,
        created: u64,
    ) {
        recoverable(journal, resource, operation, created);
        journal
            .record_helper(
                operation,
                "blindpass-login-helper@fixture.service",
                &"c".repeat(32),
                created + 1,
            )
            .unwrap();
        journal
            .record_login(
                operation,
                created + 300_000,
                RevokeHandle::Fixture {
                    account: "primary".into(),
                    session_reference: "a".repeat(32),
                },
                created + 2,
            )
            .unwrap();
    }
    fn other_account(journal: &mut SessionJournal, resource: &BrowserResource, now: u64) {
        journal
            .reserve(
                binding_for(
                    resource,
                    "operation-x",
                    "isolation",
                    "other.service",
                    "report-other",
                ),
                now - 10,
            )
            .unwrap();
    }

    #[test]
    fn a_blocked_record_for_another_account_never_stalls_dispatch() {
        let mut h = Harness::new("coord-other-account", |journal, resource, now| {
            other_account(journal, resource, now);
        });
        h.dispatcher.mark_startup_recovered();
        let mut env = FakeEnv::default(); // revoke fails: the record stays blocked
        h.dispatcher.iteration(0, &mut env);
        assert_eq!(
            h.state_of("operation-x"),
            Some(SessionState::BlockedUncertain)
        );
        assert_eq!(
            env.launched.len(),
            1,
            "account primary is dispatched while account isolation stays blocked"
        );
        assert_eq!(h.pending(), 2);
        // The blocked record is retried on its own schedule, not every tick.
        let calls = env.recover_calls;
        h.dispatcher.iteration(100, &mut env);
        assert_eq!(env.recover_calls, calls);
    }

    #[test]
    fn a_blocked_record_refuses_its_own_account_without_consuming_the_grant() {
        let mut h = Harness::new("coord-same-account", |journal, resource, now| {
            recoverable(journal, resource, "operation-x", now - 10);
        });
        h.dispatcher.mark_startup_recovered();
        let mut env = FakeEnv::default();
        for tick in 0..5 {
            h.dispatcher.iteration(tick * 100, &mut env);
        }
        assert!(env.launched.is_empty());
        assert_eq!(h.candidates(), 1, "the signed grant was never consumed");
        assert_eq!(h.pending(), 1);
    }

    #[test]
    fn an_unrecoverable_record_blocks_its_account_only_until_the_independent_maximum() {
        // The administrator edited the recipe and restarted: recovery can never
        // build a revocation for the old record.
        for (label, age, released) in [
            ("coord-recent-stale", 10, false),
            (
                "coord-old-stale",
                crate::session_journal::RELEASE_AFTER_MS + 1_000,
                true,
            ),
        ] {
            let mut h = Harness::new(label, |journal, resource, now| {
                let mut stale = binding_for(
                    resource,
                    "operation-x",
                    "primary",
                    "agent.service",
                    "report-primary",
                );
                stale.recipe_fingerprint = "b".repeat(64);
                journal.reserve(stale, now - age).unwrap();
            });
            h.dispatcher.mark_startup_recovered();
            let mut env = FakeEnv {
                revoke_ok: true,
                ..FakeEnv::default()
            };
            h.state
                .lock()
                .unwrap()
                .browser_recovery_input(&h.journal.lock().unwrap().pending()[0].clone())
                .unwrap_err();
            h.dispatcher.iteration(0, &mut env);
            assert!(env.revoke_calls.is_empty(), "no revocation can be prepared");
            assert_eq!(env.launched.len(), usize::from(released), "{label}");
            assert_eq!(h.state_of("operation-x").is_none(), released, "{label}");
        }
    }

    #[test]
    fn light_recovery_leaves_running_actor_records_alone() {
        let mut h = Harness::new("coord-light-running", |journal, resource, now| {
            recoverable(journal, resource, "operation-run", now - 10);
        });
        h.dispatcher.mark_startup_recovered();
        h.dispatcher.active.fetch_add(1, Ordering::AcqRel);
        h.dispatcher
            .running_operations
            .lock()
            .unwrap()
            .insert("operation-run".into());
        let mut env = FakeEnv {
            revoke_ok: true,
            ..FakeEnv::default()
        };
        h.dispatcher.iteration(0, &mut env);
        assert_eq!(
            env.recover_calls, 0,
            "never a class-wide stop under live actors"
        );
        assert!(
            env.revoke_calls.is_empty(),
            "the running actor owns its record"
        );
        assert_eq!(
            h.state_of("operation-run"),
            Some(SessionState::BlockedUncertain)
        );
    }

    #[test]
    fn light_recovery_closes_a_record_from_before_startup_without_a_class_wide_stop() {
        let mut h = Harness::new("coord-light-cohort", |journal, resource, now| {
            recoverable(journal, resource, "operation-old", now - 10);
        });
        // Startup recovery succeeded with this record pending.
        h.dispatcher.mark_startup_recovered();
        // An unrelated actor is running.
        h.dispatcher.active.fetch_add(1, Ordering::AcqRel);
        h.dispatcher
            .running_operations
            .lock()
            .unwrap()
            .insert("operation-other".into());
        let mut env = FakeEnv {
            revoke_ok: true,
            ..FakeEnv::default()
        };
        h.dispatcher.iteration(0, &mut env);
        assert_eq!(env.recover_calls, 0);
        assert_eq!(env.revoke_calls, ["operation-old"]);
        assert_eq!(h.state_of("operation-old"), None, "closed");
        assert_eq!(
            env.launched.len(),
            1,
            "the freed account dispatches at once"
        );
    }

    #[test]
    fn light_recovery_revokes_but_never_closes_a_record_created_while_running() {
        let mut h = Harness::new("coord-light-runtime", |journal, resource, now| {
            recoverable(journal, resource, "operation-new", now - 10);
        });
        h.recovered_without_cohort();
        h.dispatcher.active.fetch_add(1, Ordering::AcqRel);
        let mut env = FakeEnv {
            revoke_ok: true,
            ..FakeEnv::default()
        };
        h.dispatcher.iteration(0, &mut env);
        assert_eq!(env.revoke_calls, ["operation-new"]);
        assert_eq!(
            h.state_of("operation-new"),
            Some(SessionState::BlockedUncertain)
        );
        assert!(env.launched.is_empty(), "its account stays blocked");
        // Repeated only about once per helper lifetime.
        h.dispatcher.iteration(5_000, &mut env);
        h.dispatcher.iteration(30_000, &mut env);
        assert_eq!(env.revoke_calls.len(), 1);
        h.dispatcher.iteration(61_000, &mut env);
        assert_eq!(env.revoke_calls.len(), 2);
        assert_eq!(env.recover_calls, 0);
        // Idle again: the class-wide stop proves its processes gone.
        h.dispatcher.active.store(0, Ordering::Release);
        h.dispatcher.iteration(122_000, &mut env);
        assert_eq!(env.recover_calls, 1);
        assert_eq!(
            h.state_of("operation-new"),
            None,
            "closed after the full pass"
        );
    }

    #[test]
    fn full_recovery_needs_the_class_wide_stop_and_publishes_confirmed_closures() {
        let mut h = Harness::new("coord-full", |journal, resource, now| {
            with_login(journal, resource, "operation-old", now - 100);
        });
        h.recovered_without_cohort();
        let mut env = FakeEnv {
            recover_fails: true,
            revoke_ok: true,
            ..FakeEnv::default()
        };
        h.dispatcher.iteration(0, &mut env);
        assert_eq!(env.recover_calls, 1);
        assert!(
            env.revoke_calls.is_empty(),
            "no revoke before the class-wide stop"
        );
        assert_eq!(h.pending(), 1);
        env.recover_fails = false;
        h.dispatcher.iteration(5_000, &mut env);
        assert_eq!(env.revoke_calls, ["operation-old"]);
        assert_eq!(h.state_of("operation-old"), None, "closed");
        assert!(
            h.state
                .lock()
                .unwrap()
                .pending_node_events(100)
                .iter()
                .any(|event| event.idempotency_key.starts_with("event_browser_closed_")),
            "closure published for the record that had a login"
        );
    }

    #[test]
    fn recovery_waiting_for_an_input_retries_quickly_however_long_the_input_takes() {
        // After a broker restart the administrator credential (and trusted time)
        // arrive when the operator re-provisions and the node reconnects, which can
        // take longer than a few retries. An unavailable input is not a failed
        // revoke: it must never push the record into the slow retry tier.
        let mut h = Harness::new("coord-input-wait", |journal, resource, now| {
            with_login(journal, resource, "operation-old", now - 100);
        });
        h.recovered_without_cohort();
        let destination =
            crate::destination_key("blindpass-session-revoker@.service", "fixture-admin");
        let administrator = h
            .state
            .lock()
            .unwrap()
            .credentials
            .remove(&destination)
            .unwrap();
        let mut env = FakeEnv {
            revoke_ok: true,
            ..FakeEnv::default()
        };
        for boot in (0..=30_000).step_by(5_000) {
            h.dispatcher.iteration(boot, &mut env);
        }
        assert!(env.revoke_calls.is_empty(), "no administrator, no revoke");
        h.state
            .lock()
            .unwrap()
            .credentials
            .insert_secret(&destination, administrator)
            .unwrap();
        h.dispatcher.iteration(35_000, &mut env);
        assert_eq!(
            env.revoke_calls,
            ["operation-old"],
            "the revoke runs one retry interval after the input arrives"
        );
        assert_eq!(h.state_of("operation-old"), None, "closed");
    }

    #[test]
    fn released_record_with_a_login_publishes_its_closure() {
        let mut h = Harness::new("coord-release-publish", |journal, resource, now| {
            with_login(
                journal,
                resource,
                "operation-old",
                now - crate::session_journal::RELEASE_AFTER_MS - 5_000,
            );
        });
        h.recovered_without_cohort();
        h.dispatcher.active.fetch_add(1, Ordering::AcqRel); // light: no revoke closes it
        let mut env = FakeEnv::default();
        h.dispatcher.iteration(0, &mut env);
        assert_eq!(
            h.state_of("operation-old"),
            None,
            "released by the independent maximum"
        );
        assert!(
            h.state
                .lock()
                .unwrap()
                .pending_node_events(100)
                .iter()
                .any(|event| event.idempotency_key.starts_with("event_browser_closed_"))
        );
    }

    #[test]
    fn startup_recovery_failure_disables_browser_dispatch_until_a_later_success() {
        let mut h = Harness::new("coord-startup", |journal, resource, now| {
            recoverable(journal, resource, "operation-old", now - 10);
        });
        let mut env = FakeEnv {
            recover_fails: true,
            revoke_ok: true,
            ..FakeEnv::default()
        };
        h.dispatcher.iteration(0, &mut env);
        assert_eq!(env.recover_calls, 1);
        assert!(env.launched.is_empty());
        assert_eq!(
            h.candidates(),
            1,
            "native delivery is unaffected; the grant waits"
        );
        h.dispatcher.iteration(1_000, &mut env);
        assert_eq!(env.recover_calls, 1, "retries are spaced");
        assert!(
            env.revoke_calls.is_empty(),
            "no recovery work before startup recovery"
        );
        env.recover_fails = false;
        h.dispatcher.iteration(5_000, &mut env);
        assert!(h.dispatcher.terminated.contains("operation-old"));
        assert_eq!(env.revoke_calls, ["operation-old"]);
        assert_eq!(
            env.launched.len(),
            1,
            "dispatch resumes once recovery succeeded"
        );
        // The record created by this dispatch is not part of any cohort.
        assert!(
            !h.dispatcher
                .terminated
                .contains(env.launched[0].0.operation_id())
        );
    }

    #[test]
    fn actor_registration_precedes_launch_and_drop_releases_it() {
        let mut h = Harness::new("coord-registration", |_, _, _| {});
        h.dispatcher.mark_startup_recovered();
        let mut env = FakeEnv::default();
        h.dispatcher.iteration(0, &mut env);
        assert_eq!(env.registered_before_launch, [true]);
        let (job, slot) = env.launched.pop().unwrap();
        let operation = job.operation_id().to_owned();
        assert!(
            h.dispatcher
                .running_operations
                .lock()
                .unwrap()
                .contains(&operation)
        );
        assert_eq!(h.dispatcher.active.load(Ordering::Acquire), 1);
        drop(slot);
        assert!(h.dispatcher.running_operations.lock().unwrap().is_empty());
        assert_eq!(h.dispatcher.active.load(Ordering::Acquire), 0);
        assert_eq!(
            h.dispatcher.finished_receiver.try_recv().unwrap(),
            job.grant_id()
        );
    }

    #[test]
    fn failed_launch_releases_the_registration_and_leaves_the_intent_uncertain() {
        let mut h = Harness::new("coord-launch-failure", |_, _, _| {});
        h.dispatcher.mark_startup_recovered();
        let mut env = FakeEnv {
            fail_launch: true,
            ..FakeEnv::default()
        };
        h.dispatcher.iteration(0, &mut env);
        assert_eq!(env.registered_before_launch, [true]);
        assert!(h.dispatcher.running_operations.lock().unwrap().is_empty());
        assert_eq!(h.dispatcher.active.load(Ordering::Acquire), 0);
        assert_eq!(
            h.pending(),
            1,
            "no login may be replayed for the consumed grant"
        );
        assert_eq!(h.candidates(), 0);
    }

    #[test]
    fn a_fenced_journal_is_retried_and_dispatch_and_recovery_resume() {
        let mut h = Harness::new("coord-fence", |journal, resource, now| {
            recoverable(journal, resource, "operation-old", now - 10);
        });
        h.dispatcher.mark_startup_recovered();
        {
            let mut journal = h.journal.lock().unwrap();
            journal.fail_next_write_for_test();
            let other = binding_for(
                &h.resource,
                "operation-y",
                "isolation",
                "other.service",
                "report-other",
            );
            assert!(journal.reserve(other, h.now).is_err());
            assert!(journal.is_fenced());
            journal.fail_next_write_for_test(); // the first unfence attempt fails too
        }
        let mut env = FakeEnv {
            revoke_ok: true,
            ..FakeEnv::default()
        };
        h.dispatcher.iteration(0, &mut env);
        assert!(h.journal.lock().unwrap().is_fenced());
        assert!(env.launched.is_empty(), "no new work while fenced");
        assert!(
            env.revoke_calls.is_empty(),
            "recovery cannot journal while fenced"
        );
        h.dispatcher.iteration(5_000, &mut env);
        assert!(!h.journal.lock().unwrap().is_fenced());
        assert_eq!(
            env.revoke_calls,
            ["operation-old"],
            "recovery proceeds once unfenced"
        );
        assert_eq!(env.launched.len(), 1);
    }

    // ---- cleanup ----------------------------------------------------------

    #[derive(Default)]
    struct FakeActions {
        helper: bool,
        revoke: bool,
        stop: bool,
        browser: bool,
        log: Vec<&'static str>,
    }
    impl CleanupActions for FakeActions {
        fn terminate_helper(&mut self) -> bool {
            self.log.push("helper");
            self.helper
        }
        fn revoke_website(&mut self) -> bool {
            self.log.push("revoke");
            self.revoke
        }
        fn stop_supervisor(&mut self) -> bool {
            self.log.push("stop");
            self.stop
        }
        fn terminate_browser(&mut self) -> bool {
            self.log.push("browser");
            self.browser
        }
    }
    fn facts(identified: bool, attempted: bool, verified: bool, connected: bool) -> CleanupFacts {
        CleanupFacts {
            helper_identified: identified,
            helper_attempted: attempted,
            browser_verified: verified,
            supervisor_connected: connected,
        }
    }

    #[test]
    fn website_revoke_never_depends_on_helper_termination() {
        let mut actions = FakeActions {
            helper: false,
            revoke: true,
            stop: true,
            browser: true,
            ..FakeActions::default()
        };
        let outcome = run_cleanup(&mut actions, &facts(true, true, true, true));
        assert_eq!(actions.log, ["helper", "revoke", "stop", "browser"]);
        assert!(
            outcome.website_revoked,
            "revoked although the helper is unverified"
        );
        assert!(!outcome.helper_stopped);
        assert!(outcome.browser_stopped);
        // The record is not closed: processes are unverified, so the account
        // stays blocked for the recovery that stops the helper and revokes again.
        let (directory, _state, _grant, resource, mut journal) =
            crate::tests::browser_grant_fixture("coord-cleanup-journal");
        journal
            .reserve(
                binding_for(
                    &resource,
                    "operation-c",
                    "primary",
                    "agent.service",
                    "report-primary",
                ),
                1_000,
            )
            .unwrap();
        assert!(
            journal
                .reconcile(
                    "operation-c",
                    outcome.website_revoked,
                    outcome.helper_stopped && outcome.browser_stopped,
                    1_001
                )
                .is_err()
        );
        assert_eq!(journal.pending().len(), 1);
        drop(journal);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn helper_never_started_needs_no_termination_but_an_unproved_helper_is_unverified() {
        let mut none = FakeActions {
            revoke: true,
            ..FakeActions::default()
        };
        let outcome = run_cleanup(&mut none, &facts(false, false, false, false));
        assert!(outcome.helper_stopped && outcome.browser_stopped);
        assert_eq!(none.log, ["revoke"], "nothing to terminate or stop");
        let mut unproved = FakeActions::default();
        let outcome = run_cleanup(&mut unproved, &facts(false, true, false, false));
        assert!(
            !outcome.helper_stopped,
            "entered helper stage, identity never proved"
        );
        assert!(!outcome.website_revoked);
    }

    #[test]
    fn a_supervisor_without_a_verified_browser_is_unverified_unless_stop_was_acknowledged() {
        // Connected, prepare failed: the supervisor may have started a browser.
        let mut failed = FakeActions {
            revoke: true,
            stop: false,
            ..FakeActions::default()
        };
        let outcome = run_cleanup(&mut failed, &facts(false, false, false, true));
        assert!(!outcome.browser_stopped);
        assert_eq!(failed.log, ["revoke", "stop"]);
        let mut acknowledged = FakeActions {
            revoke: true,
            stop: true,
            ..FakeActions::default()
        };
        assert!(run_cleanup(&mut acknowledged, &facts(false, false, false, true)).browser_stopped);
        // A verified browser is judged by its termination, not the stop.
        let mut verified = FakeActions {
            revoke: true,
            stop: true,
            browser: false,
            ..FakeActions::default()
        };
        assert!(!run_cleanup(&mut verified, &facts(false, false, true, true)).browser_stopped);
        let mut verified = FakeActions {
            revoke: true,
            stop: false,
            browser: true,
            ..FakeActions::default()
        };
        assert!(run_cleanup(&mut verified, &facts(false, false, true, true)).browser_stopped);
    }

    struct FakeManager {
        ok: bool,
        calls: std::rc::Rc<std::cell::Cell<u32>>,
    }
    impl ManagerLink for FakeManager {
        fn terminate_unit(&mut self, _: &PeerIdentity, _: bool) -> Result<(), &'static str> {
            self.calls.set(self.calls.get() + 1);
            if self.ok {
                Ok(())
            } else {
                Err("runtime_management_unavailable")
            }
        }
    }
    fn peer() -> PeerIdentity {
        PeerIdentity::fixture(
            61001,
            61001,
            "blindpass-login-helper@proof.service",
            &"a".repeat(32),
            "uid:61001",
        )
    }
    #[test]
    fn termination_reconnects_once_when_the_manager_connection_is_missing_or_dead() {
        let calls = std::rc::Rc::new(std::cell::Cell::new(0));
        let manager = |ok| FakeManager {
            ok,
            calls: std::rc::Rc::clone(&calls),
        };
        // A healthy connection is used as is.
        let mut link = Some(manager(true));
        assert!(terminate_with_reconnect(
            &mut link,
            || panic!("no reconnect"),
            &peer(),
            false
        ));
        assert_eq!(calls.get(), 1);
        // A dead one is replaced and the request repeated.
        calls.set(0);
        let mut link = Some(manager(false));
        assert!(terminate_with_reconnect(
            &mut link,
            || Some(manager(true)),
            &peer(),
            true
        ));
        assert_eq!(calls.get(), 2);
        assert!(link.is_some());
        // A missing one is connected.
        calls.set(0);
        let mut link: Option<FakeManager> = None;
        assert!(terminate_with_reconnect(
            &mut link,
            || Some(manager(true)),
            &peer(),
            false
        ));
        assert_eq!(calls.get(), 1);
        // No manager at all, or a replacement that fails too, is unverified.
        let mut link: Option<FakeManager> = None;
        assert!(!terminate_with_reconnect(
            &mut link,
            || None,
            &peer(),
            false
        ));
        let mut link = Some(manager(false));
        assert!(!terminate_with_reconnect(
            &mut link,
            || Some(manager(false)),
            &peer(),
            false
        ));
    }

    #[test]
    fn journal_lock_is_free_during_revalidation_and_held_only_while_recording() {
        let (directory, _state, _grant, _resource, journal) =
            crate::tests::browser_grant_fixture("coord-lock-seam");
        let journal = Mutex::new(journal);
        let mut order = Vec::new();
        let result = journaled_step(
            &journal,
            &mut order,
            |order| {
                // The bounded manager/pidfd revalidation runs here.
                order.push(("revalidate", journal.try_lock().is_ok()));
                Ok(7_u64)
            },
            |order, value, _journal| {
                order.push(("record", journal.try_lock().is_err()));
                Ok(value)
            },
        );
        assert_eq!(result, Ok(7));
        assert_eq!(order, [("revalidate", true), ("record", true)]);
        // A failed revalidation never takes the lock at all.
        let mut touched = false;
        let result: Result<(), ()> = journaled_step(
            &journal,
            &mut touched,
            |_| Err(()),
            |touched, (): (), _| {
                *touched = true;
                Ok(())
            },
        );
        assert!(result.is_err() && !touched);
        drop(journal);
        let _ = std::fs::remove_dir_all(directory);
    }
}
