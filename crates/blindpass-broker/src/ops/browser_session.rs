// SPDX-License-Identifier: AGPL-3.0-only

//! Trusted resource selection and independent validation before cookie import.
//! Inputs are administrator configuration and a protected helper response;
//! this module grants no workload authority and exposes no browser endpoint.

use crate::private_helper::{HelperReply, HelperStatus};
use crate::session_journal::RevokeHandle;
use blindpass_core::canon::{Value, canonicalize_value, parse_json};
use blindpass_core::fleet::Grant;
use blindpass_core::secret::SecretBytes;
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};

const INVALID_RESOURCE: &str = "browser_resource_invalid";
const INVALID_SESSION: &str = "browser_session_invalid";
#[derive(Debug)]
pub enum BrowserPreparation {
    Login(Box<PreparedBrowserLogin>),
    Existing(crate::session_journal::SessionState),
}
pub struct PreparedBrowserLogin {
    pub(crate) grant: Grant,
    pub(crate) original_workload: crate::original_workload::OriginalWorkloadLease,
    pub(crate) resource: BrowserResource,
    pub(crate) helper_job: Option<SecretBytes>,
    pub(crate) source_expiry: crate::CredentialExpiry,
    pub(crate) revocation_credential: Option<SecretBytes>,
    pub(crate) event_keys: [String; 2],
    pub(crate) deadline_boottime_ms: u64,
}
impl std::fmt::Debug for PreparedBrowserLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedBrowserLogin")
            .field("operation_id", &self.grant.operation_id)
            .field("resource", &self.resource)
            .field("job", &"[protected]")
            .finish_non_exhaustive()
    }
}
impl PreparedBrowserLogin {
    pub(crate) fn source_is_current(&self) -> bool {
        self.source_expiry.current()
    }
    /// Execute outside the broker state mutex. Consumes the source job even
    /// on failure; a second call cannot trigger another private login.
    #[must_use]
    pub fn call_helper<F: Fn() -> bool>(
        &mut self,
        helper: crate::private_helper::VerifiedPrivateHelper,
        revoker: &crate::session_revoker::RevocationClient,
        journal: &mut crate::session_journal::SessionJournal,
        trusted_time_ms: u64,
        current_authority: F,
    ) -> HelperReply {
        match self.prepare_helper_exchange(helper, revoker, journal, trusted_time_ms) {
            Ok(exchange) => exchange.execute(revoker, current_authority),
            Err(status) => HelperReply::Status(status),
        }
    }
    /// Take the one-use source job and durably bind the proved helper. Return
    /// before any source write so callers can release journal/state locks.
    /// Embedding callers that already hold a journal exclusively may use this;
    /// the coordinator calls the two halves separately so that the bounded
    /// kernel/manager revalidation never runs under the shared journal mutex.
    pub fn prepare_helper_exchange(
        &mut self,
        helper: crate::private_helper::VerifiedPrivateHelper,
        revoker: &crate::session_revoker::RevocationClient,
        journal: &mut crate::session_journal::SessionJournal,
        trusted_time_ms: u64,
    ) -> Result<PreparedHelperExchange, HelperStatus> {
        let job = self.take_checked_source(revoker)?;
        self.journal_helper_exchange(job, helper, journal, trusted_time_ms)
    }
    /// First half of `prepare_helper_exchange`: consume the one-use source job
    /// and run every check that waits on the original kernel/manager lease
    /// (up to 5 s) or the administrator channel. It takes no journal, so it
    /// cannot hold the journal lock. The job is consumed even on failure; a
    /// second call cannot trigger another private login.
    pub fn take_checked_source(
        &mut self,
        revoker: &crate::session_revoker::RevocationClient,
    ) -> Result<SecretBytes, HelperStatus> {
        let job = self.helper_job.take().ok_or(HelperStatus::InvalidRequest)?;
        if !self.source_is_current()
            || self
                .revalidate_original_workload(
                    std::time::Instant::now() + std::time::Duration::from_secs(5),
                )
                .is_err()
            || !revoker.ready_for(&self.resource, &self.grant.operation_id)
        {
            return Err(HelperStatus::Unavailable);
        }
        Ok(job)
    }
    /// Second half: persist the proved helper identity. Only journal work.
    pub fn journal_helper_exchange(
        &self,
        job: SecretBytes,
        helper: crate::private_helper::VerifiedPrivateHelper,
        journal: &mut crate::session_journal::SessionJournal,
        trusted_time_ms: u64,
    ) -> Result<PreparedHelperExchange, HelperStatus> {
        let helper = helper.record(
            journal,
            &self.grant.operation_id,
            trusted_time_ms,
            self.deadline_boottime_ms,
        )?;
        Ok(PreparedHelperExchange {
            helper,
            job,
            original_workload: self.original_workload.clone(),
            resource: self.resource.clone(),
            operation: self.grant.operation_id.clone(),
            source_expiry: self.source_expiry,
        })
    }
    /// Revalidate the original kernel/manager lease outside the state mutex.
    pub fn revalidate_original_workload(
        &self,
        deadline: std::time::Instant,
    ) -> Result<(), crate::os_identity::OsIdentityError> {
        self.original_workload.ensure_current(deadline)
    }
    /// Online administrator preflight outside the broker state mutex. The
    /// protected administrator copy is single-use and never enters the helper.
    pub fn begin_revocation(
        &mut self,
    ) -> Result<crate::session_revoker::RevocationClient, crate::session_revoker::RevocationError>
    {
        let credential = self
            .revocation_credential
            .take()
            .ok_or(crate::session_revoker::RevocationError::Unavailable)?;
        self.revalidate_original_workload(
            std::time::Instant::now() + std::time::Duration::from_secs(5),
        )
        .map_err(|_| crate::session_revoker::RevocationError::Unavailable)?;
        crate::session_revoker::RevocationClient::prepare(
            &self.resource,
            &self.grant.operation_id,
            &credential,
            self.deadline_boottime_ms,
        )
    }
    /// Save the nonbearer handle BEFORE checking permission for handoff. A
    /// denied/cancelled operation still needs server-side reconciliation.
    pub fn stage_reply(
        &self,
        reply: HelperReply,
        journal: &mut crate::session_journal::SessionJournal,
        trusted_time_ms: u64,
    ) -> Result<ApprovedSession, HelperStatus> {
        let protected = match reply {
            HelperReply::Session(protected) => protected,
            HelperReply::Status(status) => return Err(status),
        };
        let session = self
            .resource
            .validate_session(protected, trusted_time_ms)
            .map_err(|_| HelperStatus::Uncertain)?;
        journal
            .record_login(
                &self.grant.operation_id,
                session.original_deadline_ms,
                session.revoke_handle.clone(),
                trusted_time_ms,
            )
            .map_err(|_| HelperStatus::Uncertain)?;
        Ok(session)
    }
    #[must_use]
    pub fn grant_id(&self) -> &str {
        &self.grant.id
    }
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.grant.operation_id
    }
    #[must_use]
    pub fn event_keys(&self) -> &[String; 2] {
        &self.event_keys
    }
}
/// Owned source exchange with no journal/state borrow. Dropping it discards
/// its one-use source buffer, permission and private helper channel.
pub struct PreparedHelperExchange {
    helper: crate::private_helper::JournaledPrivateHelper,
    job: SecretBytes,
    original_workload: crate::original_workload::OriginalWorkloadLease,
    resource: BrowserResource,
    operation: String,
    source_expiry: crate::CredentialExpiry,
}
impl std::fmt::Debug for PreparedHelperExchange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedHelperExchange([protected, single-use])")
    }
}
impl PreparedHelperExchange {
    #[must_use]
    pub fn execute<F: Fn() -> bool>(
        self,
        revoker: &crate::session_revoker::RevocationClient,
        current_authority: F,
    ) -> HelperReply {
        let authority = || self.original_workload.ensure_alive().is_ok() && current_authority();
        self.helper.request_guarded(
            &self.job,
            || {
                authority()
                    && self.source_expiry.current()
                    && revoker.ready_for(&self.resource, &self.operation)
            },
            authority,
        )
    }
}
#[derive(Clone)]
pub struct BrowserResource {
    resource_id: String,
    workload_ids: Vec<String>,
    credential_unit: String,
    credential_name: String,
    kind: String,
    origin: String,
    hostname: String,
    login_origin: String,
    account: String,
    session_max_ms: u64,
    org_id: Option<u32>,
    pins: Vec<String>,
    revocation: Option<RevocationProfile>,
}
/// Administrator-only fixed revocation profile. No endpoint or selector is
/// accepted from the workload; the managed application backend path is fixed.
#[derive(Clone)]
pub struct RevocationProfile {
    kind: String,
    credential_unit: String,
    credential_name: String,
    user_id: Option<u32>,
}
impl std::fmt::Debug for RevocationProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RevocationProfile([administrator])")
    }
}
impl RevocationProfile {
    fn from_value(value: &Value, application: &str) -> Result<Self, &'static str> {
        let expected = if application == "fixture" {
            "fixture-admin"
        } else {
            "grafana-admin"
        };
        fields(
            value,
            &["kind", "credential_unit", "credential_name"],
            if application == "fixture" {
                &[]
            } else {
                &["user_id"]
            },
        )
        .map_err(|_| INVALID_RESOURCE)?;
        let kind = text(value, "kind")?;
        let unit = text(value, "credential_unit")?;
        let name = text(value, "credential_name")?;
        let user_id = if application == "fixture" {
            None
        } else {
            Some(
                u32::try_from(number(value, "user_id")?)
                    .ok()
                    .filter(|id| *id > 0)
                    .ok_or(INVALID_RESOURCE)?,
            )
        };
        if kind != expected || unit != "blindpass-session-revoker@.service" || !identifier(name) {
            return Err(INVALID_RESOURCE);
        }
        Ok(Self {
            kind: kind.into(),
            credential_unit: unit.into(),
            credential_name: name.into(),
            user_id,
        })
    }
    #[must_use]
    pub fn credential_destination(&self) -> (&str, &str) {
        (&self.credential_unit, &self.credential_name)
    }
    pub fn validate_credential(&self, credential: &SecretBytes) -> Result<(), &'static str> {
        let text = std::str::from_utf8(credential.as_bytes())
            .map_err(|_| "browser_revocation_unavailable")?;
        let valid = if self.kind == "fixture-admin" {
            text.len() == 64
                && text
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        } else {
            account_name(text)
        };
        if valid {
            Ok(())
        } else {
            Err("browser_revocation_unavailable")
        }
    }
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut entries = vec![
            ("kind", string(&self.kind)),
            ("credential_unit", string(&self.credential_unit)),
            ("credential_name", string(&self.credential_name)),
        ];
        if let Some(id) = self.user_id {
            entries.push(("user_id", Value::Unsigned(u64::from(id))));
        }
        object(entries)
    }
    pub(crate) fn accepts_handle(&self, account: &str, handle: &RevokeHandle) -> bool {
        match handle {
            RevokeHandle::Fixture {
                account: selected, ..
            } => self.kind == "fixture-admin" && selected == account,
            RevokeHandle::GrafanaManaged {
                account: selected,
                user_id,
                ..
            } => {
                self.kind == "grafana-admin"
                    && selected == account
                    && self.user_id == Some(*user_id)
            }
        }
    }
}
impl std::fmt::Debug for BrowserResource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrowserResource")
            .field("resource_id", &self.resource_id)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}
pub struct ApprovedCookie {
    name: String,
    value: SecretBytes,
    domain: String,
    http_only: bool,
    same_site: String,
    expires: u64,
}
impl std::fmt::Debug for ApprovedCookie {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApprovedCookie")
            .field("name", &self.name)
            .field("value", &"[protected]")
            .finish_non_exhaustive()
    }
}
#[derive(Debug)]
pub struct ApprovedSession {
    original_deadline_ms: u64,
    pub(crate) recipe_fingerprint: String,
    revoke_handle: RevokeHandle,
    cookies: Vec<ApprovedCookie>,
}
impl ApprovedSession {
    #[must_use]
    pub fn original_deadline_ms(&self) -> u64 {
        self.original_deadline_ms
    }
    #[must_use]
    pub fn revoke_handle(&self) -> &RevokeHandle {
        &self.revoke_handle
    }
    #[must_use]
    pub fn cookies(&self) -> &[ApprovedCookie] {
        &self.cookies
    }
    /// Only for a verified fresh runtime importer. This is protected IPC data,
    /// never a model result, audit record or auth-state file.
    pub fn cookie_import(&self) -> Result<SecretBytes, &'static str> {
        let mut value = Value::Array(
            self.cookies
                .iter()
                .map(|cookie| {
                    object(vec![
                        ("name", string(&cookie.name)),
                        (
                            "value",
                            string(
                                std::str::from_utf8(cookie.value.as_bytes())
                                    .expect("validated cookie ASCII"),
                            ),
                        ),
                        ("domain", string(&cookie.domain)),
                        ("path", string("/")),
                        ("secure", Value::Bool(true)),
                        ("httpOnly", Value::Bool(cookie.http_only)),
                        ("sameSite", string(&cookie.same_site)),
                        ("expires", Value::Unsigned(cookie.expires)),
                    ])
                })
                .collect(),
        );
        let result = canonicalize_value(&value)
            .map(SecretBytes::new)
            .map_err(|_| INVALID_SESSION);
        crate::private_helper::wipe_value(&mut value);
        result
    }
}
impl BrowserResource {
    pub fn from_value(value: &Value) -> Result<Self, &'static str> {
        fields(
            value,
            &[
                "resource_id",
                "workload_ids",
                "credential_unit",
                "credential_name",
                "configuration",
            ],
            &["revocation"],
        )
        .map_err(|_| INVALID_RESOURCE)?;
        let resource_id = text(value, "resource_id")?;
        let workload_ids = value
            .get("workload_ids")
            .and_then(Value::as_array)
            .ok_or(INVALID_RESOURCE)?;
        if !identifier(resource_id) || !(1..=16).contains(&workload_ids.len()) {
            return Err(INVALID_RESOURCE);
        }
        let mut seen = HashSet::new();
        let workload_ids = workload_ids
            .iter()
            .map(|value| {
                let name = value
                    .as_str()
                    .filter(|name| identifier(name))
                    .ok_or(INVALID_RESOURCE)?;
                if !seen.insert(name) {
                    return Err(INVALID_RESOURCE);
                }
                Ok(name.to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let credential_unit = text(value, "credential_unit")?;
        let credential_name = text(value, "credential_name")?;
        if !unit_name(credential_unit) || !identifier(credential_name) {
            return Err(INVALID_RESOURCE);
        }
        let configuration = value.get("configuration").ok_or(INVALID_RESOURCE)?;
        fields(
            configuration,
            &["kind", "origin", "account", "sessionMaxMs"],
            &["loginOrigin", "orgId", "certificateSpkiPins"],
        )
        .map_err(|_| INVALID_RESOURCE)?;
        let kind = text(configuration, "kind")?;
        let account = text(configuration, "account")?;
        let session_max_ms = number(configuration, "sessionMaxMs")?;
        if !matches!(kind, "fixture" | "grafana-managed")
            || !account_name(account)
            || !(1_000..=1_800_000).contains(&session_max_ms)
        {
            return Err(INVALID_RESOURCE);
        }
        let origin = text(configuration, "origin")?;
        let hostname = origin_hostname(origin)?;
        let login_origin = match configuration.get("loginOrigin") {
            Some(value) => value.as_str().ok_or(INVALID_RESOURCE)?,
            None => origin,
        };
        origin_hostname(login_origin)?;
        let org_id = match configuration.get("orgId") {
            Some(value) => Some(
                u32::try_from(
                    value
                        .as_u64()
                        .filter(|id| *id > 0)
                        .ok_or(INVALID_RESOURCE)?,
                )
                .map_err(|_| INVALID_RESOURCE)?,
            ),
            None => None,
        };
        if kind == "fixture" && (login_origin != origin || org_id.is_some())
            || kind == "grafana-managed" && org_id.is_none()
        {
            return Err(INVALID_RESOURCE);
        }
        let pins = match configuration.get("certificateSpkiPins") {
            None => vec![],
            Some(Value::Array(pins)) if pins.len() <= 2 => {
                let mut seen = HashSet::new();
                pins.iter()
                    .map(|pin| {
                        let pin = pin.as_str().ok_or(INVALID_RESOURCE)?;
                        if pin.len() != 44
                            || !pin.is_ascii()
                            || !pin.ends_with('=')
                            || !seen.insert(pin)
                        {
                            return Err(INVALID_RESOURCE);
                        }
                        let normalized = pin[..43].replace('+', "-").replace('/', "_");
                        if blindpass_core::signing::base64_url_decode(&normalized, 32).is_none() {
                            return Err(INVALID_RESOURCE);
                        }
                        Ok(pin.to_owned())
                    })
                    .collect::<Result<Vec<_>, _>>()?
            }
            _ => return Err(INVALID_RESOURCE),
        };
        let revocation = value
            .get("revocation")
            .map(|profile| RevocationProfile::from_value(profile, kind))
            .transpose()?;
        if revocation.as_ref().is_some_and(|profile| {
            profile.credential_unit == credential_unit && profile.credential_name == credential_name
        }) {
            return Err(INVALID_RESOURCE);
        }
        Ok(Self {
            resource_id: resource_id.into(),
            workload_ids,
            credential_unit: credential_unit.into(),
            credential_name: credential_name.into(),
            kind: kind.into(),
            origin: origin.into(),
            hostname,
            login_origin: login_origin.into(),
            account: account.into(),
            session_max_ms,
            org_id,
            pins,
            revocation,
        })
    }
    #[must_use]
    pub fn permits(&self, workload: &str, resource: &str) -> bool {
        resource == self.resource_id && self.workload_ids.iter().any(|allowed| allowed == workload)
    }
    #[must_use]
    pub fn credential_destination(&self) -> (&str, &str) {
        (&self.credential_unit, &self.credential_name)
    }
    #[must_use]
    pub fn resource_id(&self) -> &str {
        &self.resource_id
    }
    pub fn recipe_fingerprint(&self) -> Result<String, &'static str> {
        let bytes = canonicalize_value(&self.to_value()).map_err(|_| INVALID_RESOURCE)?;
        let digest = blindpass_core::custody::sha256(&bytes).map_err(|_| INVALID_RESOURCE)?;
        Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
    }
    #[must_use]
    pub fn account(&self) -> &str {
        &self.account
    }
    #[must_use]
    pub fn configuration(&self) -> Value {
        let mut entries = vec![
            ("kind", string(&self.kind)),
            ("origin", string(&self.origin)),
            ("loginOrigin", string(&self.login_origin)),
            ("account", string(&self.account)),
            ("sessionMaxMs", Value::Unsigned(self.session_max_ms)),
            (
                "certificateSpkiPins",
                Value::Array(self.pins.iter().map(|pin| string(pin)).collect()),
            ),
        ];
        if let Some(org_id) = self.org_id {
            entries.push(("orgId", Value::Unsigned(u64::from(org_id))));
        }
        object(entries)
    }
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut entries = vec![
            ("resource_id", string(&self.resource_id)),
            (
                "workload_ids",
                Value::Array(self.workload_ids.iter().map(|id| string(id)).collect()),
            ),
            ("credential_unit", string(&self.credential_unit)),
            ("credential_name", string(&self.credential_name)),
            ("configuration", self.configuration()),
        ];
        if let Some(profile) = &self.revocation {
            entries.push(("revocation", profile.to_value()));
        }
        object(entries)
    }
    #[must_use]
    pub fn revocation_profile(&self) -> Option<&RevocationProfile> {
        self.revocation.as_ref()
    }
    pub fn helper_job(&self, password: &SecretBytes) -> Result<SecretBytes, &'static str> {
        let password =
            std::str::from_utf8(password.as_bytes()).map_err(|_| "browser_credential_invalid")?;
        if !(8..=512).contains(&password.len()) {
            return Err("browser_credential_invalid");
        }
        let mut value = object(vec![
            ("version", Value::Unsigned(1)),
            ("configuration", self.configuration()),
            (
                "credential",
                object(vec![
                    ("account", string(&self.account)),
                    ("password", string(password)),
                ]),
            ),
        ]);
        let result = canonicalize_value(&value)
            .map(SecretBytes::new)
            .map_err(|_| "browser_credential_invalid");
        crate::private_helper::wipe_value(&mut value);
        result
    }
    pub fn validate_session(
        &self,
        protected: SecretBytes,
        trusted_time_ms: u64,
    ) -> Result<ApprovedSession, &'static str> {
        if protected.len() > 16_384 || trusted_time_ms == 0 {
            return Err(INVALID_SESSION);
        }
        let mut value =
            parse_json(std::str::from_utf8(protected.as_bytes()).map_err(|_| INVALID_SESSION)?)
                .map_err(|_| INVALID_SESSION)?;
        let result = self.validate_parsed(&value, trusted_time_ms);
        crate::private_helper::wipe_value(&mut value);
        result
    }
    fn validate_parsed(&self, value: &Value, now: u64) -> Result<ApprovedSession, &'static str> {
        fields(
            value,
            &["status", "cookies", "originalDeadlineMs", "revokeHandle"],
            &[],
        )?;
        if text(value, "status")? != "authenticated" {
            return Err(INVALID_SESSION);
        }
        let deadline = number(value, "originalDeadlineMs")?;
        if deadline <= now
            || deadline
                > now
                    .checked_add(self.session_max_ms)
                    .ok_or(INVALID_SESSION)?
        {
            return Err(INVALID_SESSION);
        }
        let handle = value.get("revokeHandle").ok_or(INVALID_SESSION)?;
        if text(handle, "account")? != self.account || text(handle, "kind")? != self.kind {
            return Err(INVALID_SESSION);
        }
        let revoke_handle = if self.kind == "fixture" {
            fields(handle, &["kind", "account", "sessionReference"], &[])?;
            let reference = text(handle, "sessionReference")?;
            if reference.len() != 32
                || !reference
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(INVALID_SESSION);
            }
            RevokeHandle::Fixture {
                account: self.account.clone(),
                session_reference: reference.into(),
            }
        } else {
            fields(handle, &["kind", "account", "userId", "orgId"], &[])?;
            let user_id = u32::try_from(number(handle, "userId")?)
                .ok()
                .filter(|id| *id > 0)
                .ok_or(INVALID_SESSION)?;
            let org_id = u32::try_from(number(handle, "orgId")?).map_err(|_| INVALID_SESSION)?;
            if self.org_id != Some(org_id) {
                return Err(INVALID_SESSION);
            }
            RevokeHandle::GrafanaManaged {
                account: self.account.clone(),
                user_id,
                org_id,
            }
        };
        if self
            .revocation
            .as_ref()
            .is_some_and(|profile| !profile.accepts_handle(&self.account, &revoke_handle))
        {
            return Err(INVALID_SESSION);
        }
        let cookies = value
            .get("cookies")
            .and_then(Value::as_array)
            .ok_or(INVALID_SESSION)?;
        let required = if self.kind == "fixture" {
            "__Host-bp-fixture"
        } else {
            "grafana_session"
        };
        if cookies.is_empty() || cookies.len() > if self.kind == "fixture" { 1 } else { 2 } {
            return Err(INVALID_SESSION);
        }
        let mut names = HashSet::new();
        let mut approved = Vec::new();
        for cookie in cookies {
            fields(
                cookie,
                &[
                    "name", "value", "domain", "path", "secure", "httpOnly", "sameSite", "expires",
                ],
                &[],
            )?;
            let name = text(cookie, "name")?;
            let value = text(cookie, "value")?;
            let http_only = match cookie.get("httpOnly") {
                Some(Value::Bool(value)) => *value,
                _ => return Err(INVALID_SESSION),
            };
            let same_site = text(cookie, "sameSite")?;
            let expires = number(cookie, "expires")?;
            let expiry_ms = expires.checked_mul(1000).ok_or(INVALID_SESSION)?;
            if name != required
                && !(self.kind == "grafana-managed" && name == "grafana_session_expiry")
                || !names.insert(name)
                || text(cookie, "domain")? != self.hostname
                || text(cookie, "path")? != "/"
                || cookie.get("secure") != Some(&Value::Bool(true))
                || name == required && !http_only
                || !matches!(same_site, "Strict" | "Lax")
                || self.kind == "fixture" && same_site != "Strict"
                || value.is_empty()
                || value.len() > 4096
                || !value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
                || expiry_ms <= now
                || expiry_ms > deadline
            {
                return Err(INVALID_SESSION);
            }
            approved.push(ApprovedCookie {
                name: name.into(),
                value: SecretBytes::from_slice(value.as_bytes()),
                domain: self.hostname.clone(),
                http_only,
                same_site: same_site.into(),
                expires,
            });
        }
        if !names.contains(required) {
            return Err(INVALID_SESSION);
        }
        Ok(ApprovedSession {
            original_deadline_ms: deadline,
            recipe_fingerprint: self.recipe_fingerprint()?,
            revoke_handle,
            cookies: approved,
        })
    }
}
fn origin_hostname(origin: &str) -> Result<String, &'static str> {
    let authority = origin
        .strip_prefix("https://")
        .filter(|value| {
            !value.is_empty()
                && value.len() <= 260
                && !value.contains(['/', '\\', '?', '#', '@', '%'])
                && value.is_ascii()
                && !value
                    .bytes()
                    .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        })
        .ok_or(INVALID_RESOURCE)?;
    let (hostname, port) = if authority.starts_with('[') {
        let end = authority.find(']').ok_or(INVALID_RESOURCE)?;
        let ip = authority[1..end]
            .parse::<Ipv6Addr>()
            .map_err(|_| INVALID_RESOURCE)?;
        if ip.to_string() != authority[1..end] {
            return Err(INVALID_RESOURCE);
        }
        (&authority[..=end], &authority[end + 1..])
    } else {
        let (hostname, port) = authority.find(':').map_or((authority, ""), |index| {
            (&authority[..index], &authority[index..])
        });
        if let Ok(ip) = hostname.parse::<Ipv4Addr>() {
            if ip.to_string() != hostname {
                return Err(INVALID_RESOURCE);
            }
        } else if hostname.len() > 253
            || hostname.rsplit('.').next().is_some_and(|label| {
                label.bytes().all(|b| b.is_ascii_digit())
                    || label.strip_prefix("0x").is_some_and(|hex| {
                        !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit())
                    })
            })
            || !hostname.bytes().any(|byte| byte.is_ascii_lowercase())
            || hostname.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
        {
            return Err(INVALID_RESOURCE);
        }
        (hostname, port)
    };
    if !port.is_empty() {
        let port_text = port.strip_prefix(':').ok_or(INVALID_RESOURCE)?;
        let number = port_text
            .parse::<u16>()
            .ok()
            .filter(|port| *port > 0 && *port != 443)
            .ok_or(INVALID_RESOURCE)?;
        if number.to_string() != port_text {
            return Err(INVALID_RESOURCE);
        }
    }
    Ok(hostname.to_owned())
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}
fn unit_name(value: &str) -> bool {
    value.ends_with(".service")
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'@' | b':')
        })
}
fn account_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value.as_bytes()[0].is_ascii_lowercase()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}
fn fields(value: &Value, required: &[&str], optional: &[&str]) -> Result<(), &'static str> {
    if value.as_object().is_some_and(|fields| {
        let mut names = HashSet::new();
        required
            .iter()
            .all(|key| fields.iter().any(|(name, _)| name == key))
            && fields.iter().all(|(key, _)| {
                names.insert(key.as_str())
                    && (required.contains(&key.as_str()) || optional.contains(&key.as_str()))
            })
    }) {
        Ok(())
    } else {
        Err(INVALID_SESSION)
    }
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, &'static str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or(INVALID_SESSION)
}
fn number(value: &Value, key: &str) -> Result<u64, &'static str> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or(INVALID_SESSION)
}
fn object(fields: Vec<(&str, Value)>) -> Value {
    Value::Object(
        fields
            .into_iter()
            .map(|(key, value)| (key.into(), value))
            .collect(),
    )
}
fn string(value: &str) -> Value {
    Value::String(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use blindpass_core::canon::{Value, canonicalize_value, parse_json};
    use blindpass_core::secret::SecretBytes;
    fn fixture() -> BrowserResource {
        BrowserResource::from_value(&parse_json(r#"{"resource_id":"report-primary","workload_ids":["workload-a"],"credential_unit":"blindpass-login-helper@.service","credential_name":"primary-password","configuration":{"kind":"fixture","origin":"https://127.0.0.1:4443","account":"primary","sessionMaxMs":300000}}"#).unwrap()).unwrap()
    }
    fn session() -> Value {
        parse_json(r#"{"status":"authenticated","originalDeadlineMs":301000,"revokeHandle":{"kind":"fixture","account":"primary","sessionReference":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"cookies":[{"name":"__Host-bp-fixture","value":"P05-COOKIE-CANARY","domain":"127.0.0.1","path":"/","secure":true,"httpOnly":true,"sameSite":"Strict","expires":301}]}"#).unwrap()
    }
    fn protected(value: Value) -> SecretBytes {
        SecretBytes::new(canonicalize_value(&value).unwrap())
    }
    fn replace(value: &mut Value, key: &str, next: Value) {
        let Value::Object(fields) = value else {
            panic!("object")
        };
        let field = fields.iter_mut().find(|(name, _)| name == key).unwrap();
        field.1 = next;
    }
    #[test]
    fn approved_resource_compiles_fixed_helper_job_and_rejects_unapproved_workloads() {
        let resource = fixture();
        assert!(resource.permits("workload-a", "report-primary"));
        assert!(!resource.permits("workload-b", "report-primary"));
        assert!(!resource.permits("workload-a", "https://unapproved.invalid"));
        let password = SecretBytes::from_slice(b"P05-SOURCE-CANARY");
        let job = resource.helper_job(&password).unwrap();
        let value = parse_json(std::str::from_utf8(job.as_bytes()).unwrap()).unwrap();
        assert_eq!(value.get("version").and_then(Value::as_u64), Some(1));
        assert_eq!(
            value
                .get("credential")
                .unwrap()
                .get("account")
                .and_then(Value::as_str),
            Some("primary")
        );
        assert!(!format!("{resource:?} {job:?}").contains("P05-SOURCE-CANARY"));
        assert!(
            resource
                .helper_job(&SecretBytes::from_slice(b"short"))
                .is_err()
        );
    }
    #[test]
    fn importer_accepts_only_protected_bound_fixture_envelope() {
        let result = fixture()
            .validate_session(protected(session()), 1_000)
            .unwrap();
        assert_eq!(result.original_deadline_ms, 301_000);
        assert_eq!(
            result.revoke_handle,
            RevokeHandle::Fixture {
                account: "primary".into(),
                session_reference: "a".repeat(32)
            }
        );
        assert!(!format!("{result:?}").contains("P05-COOKIE-CANARY"));
        assert_eq!(result.cookies().len(), 1);
    }
    #[test]
    fn importer_rejects_cookie_substitution_attributes_unknown_fields_and_deadline_extension() {
        for (key, value) in [
            ("name", Value::String("other-session".into())),
            ("domain", Value::String(".127.0.0.1".into())),
            ("path", Value::String("/unapproved".into())),
            ("secure", Value::Bool(false)),
            ("httpOnly", Value::Bool(false)),
            ("sameSite", Value::String("None".into())),
            ("value", Value::String("bad; value".into())),
            ("expires", Value::Unsigned(302)),
            ("expires", Value::Integer(-1)),
        ] {
            let mut value0 = session();
            let Value::Array(cookies) = &mut value0.as_object_mut_for_test("cookies") else {
                panic!("array")
            };
            replace(&mut cookies[0], key, value);
            assert!(
                fixture()
                    .validate_session(protected(value0), 1_000)
                    .is_err()
            );
        }
        for deadline in [1_000, 301_001, 9_007_199_254_740_991] {
            let mut value = session();
            replace(&mut value, "originalDeadlineMs", Value::Unsigned(deadline));
            assert!(fixture().validate_session(protected(value), 1_000).is_err());
        }
        let mut value = session();
        let Value::Object(fields) = &mut value else {
            panic!("object")
        };
        fields.push(("password".into(), Value::String("P05-SOURCE-CANARY".into())));
        assert!(fixture().validate_session(protected(value), 1_000).is_err());
    }
    trait FieldMut {
        fn as_object_mut_for_test(&mut self, key: &str) -> &mut Value;
    }
    impl FieldMut for Value {
        fn as_object_mut_for_test(&mut self, key: &str) -> &mut Value {
            let Value::Object(fields) = self else {
                panic!("object")
            };
            &mut fields.iter_mut().find(|(name, _)| name == key).unwrap().1
        }
    }
    #[test]
    fn importer_rejects_handle_substitution_duplicate_or_empty_cookie_and_malformed_json() {
        let mut value = session();
        replace(
            value.as_object_mut_for_test("revokeHandle"),
            "account",
            Value::String("isolation".into()),
        );
        assert!(fixture().validate_session(protected(value), 1_000).is_err());
        let mut value = session();
        let Value::Array(cookies) = value.as_object_mut_for_test("cookies") else {
            panic!("array")
        };
        cookies.push(cookies[0].clone());
        assert!(fixture().validate_session(protected(value), 1_000).is_err());
        let mut value = session();
        replace(&mut value, "cookies", Value::Array(vec![]));
        assert!(fixture().validate_session(protected(value), 1_000).is_err());
        for bytes in [
            b"{\"status\":\"authenticated\",\"status\":\"uncertain\"}".as_slice(),
            b"garbage",
            &[0xff],
        ] {
            assert!(
                fixture()
                    .validate_session(SecretBytes::from_slice(bytes), 1_000)
                    .is_err()
            );
        }
    }
    #[test]
    fn trusted_recipe_rejects_capture_selectors_unsafe_origins_and_mismatched_account() {
        let base = fixture().to_value();
        for origin in [
            "http://127.0.0.1:4443",
            "https://user:password@example.invalid",
            "https://example.invalid/path",
            "https://example.invalid?token=private",
            "https://example.invalid:443",
            "https://EXAMPLE.invalid",
            "https://2130706433",
        ] {
            let mut value = base.clone();
            replace(
                value.as_object_mut_for_test("configuration"),
                "origin",
                Value::String(origin.into()),
            );
            assert!(BrowserResource::from_value(&value).is_err());
        }
        let mut value = base.clone();
        let Value::Object(fields) = value.as_object_mut_for_test("configuration") else {
            panic!("object")
        };
        fields.push(("selectors".into(), Value::String("arbitrary".into())));
        assert!(BrowserResource::from_value(&value).is_err());
        let mut value = base;
        replace(
            value.as_object_mut_for_test("configuration"),
            "loginOrigin",
            Value::String("https://different.invalid".into()),
        );
        assert!(BrowserResource::from_value(&value).is_err());
    }
    #[test]
    fn duplicate_optional_configuration_and_non_ascii_pins_are_rejected_without_panics() {
        let mut value = fixture().to_value();
        let Value::Object(fields) = value.as_object_mut_for_test("configuration") else {
            panic!("object")
        };
        fields.push((
            "loginOrigin".into(),
            Value::String("https://unapproved.invalid".into()),
        ));
        assert!(BrowserResource::from_value(&value).is_err());
        let mut value = fixture().to_value();
        replace(
            value.as_object_mut_for_test("configuration"),
            "certificateSpkiPins",
            Value::Array(vec![Value::String(format!("{}é=", "A".repeat(41)))]),
        );
        assert!(BrowserResource::from_value(&value).is_err());
    }
    #[test]
    fn managed_grafana_envelope_requires_exact_org_and_only_the_two_approved_cookies() {
        let mut value = fixture().to_value();
        let config = value.as_object_mut_for_test("configuration");
        replace(config, "kind", Value::String("grafana-managed".into()));
        let Value::Object(fields) = config else {
            panic!("object")
        };
        fields.push(("orgId".into(), Value::Unsigned(1)));
        let resource = BrowserResource::from_value(&value).unwrap();
        let mut value = session();
        replace(
            &mut value,
            "revokeHandle",
            parse_json(r#"{"kind":"grafana-managed","account":"primary","userId":1,"orgId":1}"#)
                .unwrap(),
        );
        let Value::Array(cookies) = value.as_object_mut_for_test("cookies") else {
            panic!("array")
        };
        replace(
            &mut cookies[0],
            "name",
            Value::String("grafana_session".into()),
        );
        replace(&mut cookies[0], "sameSite", Value::String("Lax".into()));
        let mut expiry = cookies[0].clone();
        replace(
            &mut expiry,
            "name",
            Value::String("grafana_session_expiry".into()),
        );
        replace(&mut expiry, "httpOnly", Value::Bool(false));
        cookies.push(expiry);
        let result = resource
            .validate_session(protected(value.clone()), 1_000)
            .unwrap();
        assert_eq!(result.cookies().len(), 2);
        assert!(!format!("{result:?}").contains("P05-COOKIE-CANARY"));
        let imported = result.cookie_import().unwrap();
        assert!(
            imported
                .as_bytes()
                .windows(17)
                .any(|bytes| bytes == b"P05-COOKIE-CANARY")
        );
        replace(
            value.as_object_mut_for_test("revokeHandle"),
            "orgId",
            Value::Unsigned(2),
        );
        assert!(resource.validate_session(protected(value), 1_000).is_err());
    }
    #[test]
    fn importer_requires_the_administrator_bound_managed_user_before_cookie_import() {
        let mut config = fixture().to_value();
        replace(
            config.as_object_mut_for_test("configuration"),
            "kind",
            string("grafana-managed"),
        );
        if let Value::Object(fields) = config.as_object_mut_for_test("configuration") {
            fields.push(("orgId".into(), Value::Unsigned(1)));
        }
        if let Value::Object(fields) = &mut config {
            fields.push(("revocation".into(), parse_json(r#"{"kind":"grafana-admin","credential_unit":"blindpass-session-revoker@.service","credential_name":"grafana-admin","user_id":2}"#).unwrap()));
        }
        let resource = BrowserResource::from_value(&config).unwrap();
        let mut envelope = session();
        replace(
            &mut envelope,
            "revokeHandle",
            parse_json(r#"{"kind":"grafana-managed","account":"primary","userId":3,"orgId":1}"#)
                .unwrap(),
        );
        let Value::Array(cookies) = envelope.as_object_mut_for_test("cookies") else {
            panic!("array")
        };
        replace(&mut cookies[0], "name", string("grafana_session"));
        replace(&mut cookies[0], "sameSite", string("Lax"));
        assert!(
            resource
                .validate_session(protected(envelope.clone()), 1_000)
                .is_err()
        );
        replace(
            envelope.as_object_mut_for_test("revokeHandle"),
            "userId",
            Value::Unsigned(2),
        );
        assert!(
            resource
                .validate_session(protected(envelope), 1_000)
                .is_ok()
        );
    }
    #[test]
    fn revocation_configuration_is_strict_and_changes_the_complete_recipe_binding() {
        let mut value = fixture().to_value();
        let profile = parse_json(r#"{"kind":"fixture-admin","credential_unit":"blindpass-session-revoker@.service","credential_name":"fixture-admin"}"#).unwrap();
        if let Value::Object(fields) = &mut value {
            fields.push(("revocation".into(), profile.clone()));
        }
        let resource = BrowserResource::from_value(&value).unwrap();
        assert_ne!(
            resource.recipe_fingerprint().unwrap(),
            fixture().recipe_fingerprint().unwrap()
        );
        for (key, field) in [
            ("kind", string("grafana-admin")),
            ("credential_unit", string("agent.service")),
            ("credential_name", string("../admin")),
        ] {
            let mut value = value.clone();
            replace(value.as_object_mut_for_test("revocation"), key, field);
            assert!(BrowserResource::from_value(&value).is_err());
        }
        let mut changed = value.clone();
        replace(
            changed.as_object_mut_for_test("revocation"),
            "credential_name",
            string("replacement-admin"),
        );
        assert_ne!(
            resource.recipe_fingerprint().unwrap(),
            BrowserResource::from_value(&changed)
                .unwrap()
                .recipe_fingerprint()
                .unwrap()
        );
        let mut shared = value.clone();
        replace(
            &mut shared,
            "credential_unit",
            string("blindpass-session-revoker@.service"),
        );
        replace(&mut shared, "credential_name", string("fixture-admin"));
        assert!(BrowserResource::from_value(&shared).is_err());
        for additional in ["endpoint", "user_id", "credential_name"] {
            let mut invalid = value.clone();
            if let Value::Object(fields) = invalid.as_object_mut_for_test("revocation") {
                fields.push((additional.into(), string("arbitrary")));
            }
            assert!(BrowserResource::from_value(&invalid).is_err());
        }
    }
}
