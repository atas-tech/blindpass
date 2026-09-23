// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    UnsupportedHost(&'static str),
    PermissionDenied(&'static str),
    BindingMismatch(&'static str),
    UnknownRegistration,
    InvalidRequest(&'static str),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedHost(reason) => write!(formatter, "unsupported_host:{reason}"),
            Self::PermissionDenied(reason) => write!(formatter, "permission_denied:{reason}"),
            Self::BindingMismatch(reason) => write!(formatter, "binding_mismatch:{reason}"),
            Self::UnknownRegistration => formatter.write_str("unknown_registration"),
            Self::InvalidRequest(reason) => write!(formatter, "invalid_request:{reason}"),
        }
    }
}

impl std::error::Error for IdentityError {}

/// Identity resolved from the kernel and system manager for a socket peer.
///
/// There is intentionally no raw PID field. A pidfd is represented by the
/// boolean capability marker after the broker has completed its lookup; the
/// raw descriptor never crosses into the request or audit model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    pub uid: u32,
    pub gid: u32,
    pub pidfd_supported: bool,
    pub unit: Option<String>,
    pub invocation_id: Option<String>,
    pub account: Option<String>,
}

impl PeerIdentity {
    #[must_use]
    pub fn fixture(uid: u32, gid: u32, unit: &str, invocation_id: &str, account: &str) -> Self {
        Self {
            uid,
            gid,
            pidfd_supported: true,
            unit: Some(unit.to_owned()),
            invocation_id: Some(invocation_id.to_owned()),
            account: Some(account.to_owned()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoaderAuthorization {
    pub unit: String,
    pub invocation_id: String,
    pub credential_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoaderPolicy {
    mappings: BTreeMap<String, String>,
}

impl LoaderPolicy {
    #[must_use]
    pub fn new() -> Self {
        Self {
            mappings: BTreeMap::new(),
        }
    }

    pub fn map_unit(&mut self, unit: &str, credential_name: &str) -> Result<(), IdentityError> {
        validate_name(unit, "unit")?;
        validate_name(credential_name, "credential")?;
        if self.mappings.contains_key(unit) {
            return Err(IdentityError::InvalidRequest("duplicate unit mapping"));
        }
        self.mappings
            .insert(unit.to_owned(), credential_name.to_owned());
        Ok(())
    }

    #[must_use]
    pub fn credential_for(&self, unit: &str) -> Option<&str> {
        self.mappings.get(unit).map(String::as_str)
    }

    pub fn authorize(
        &self,
        peer: &PeerIdentity,
        claimed_unit: &str,
    ) -> Result<LoaderAuthorization, IdentityError> {
        if !peer.pidfd_supported {
            return Err(IdentityError::UnsupportedHost("SO_PEERPIDFD unavailable"));
        }
        if peer.uid != 0 {
            return Err(IdentityError::PermissionDenied(
                "credential-loader requires uid 0",
            ));
        }
        validate_name(claimed_unit, "unit")?;
        let authenticated_unit = peer
            .unit
            .as_deref()
            .ok_or(IdentityError::UnsupportedHost("system unit lookup failed"))?;
        if authenticated_unit != claimed_unit {
            return Err(IdentityError::BindingMismatch(
                "routing unit does not match authenticated unit",
            ));
        }
        let invocation_id = peer
            .invocation_id
            .as_deref()
            .filter(|value| !value.is_empty())
            .ok_or(IdentityError::UnsupportedHost("invocation lookup failed"))?;
        let credential_name = self
            .credential_for(authenticated_unit)
            .ok_or(IdentityError::UnknownRegistration)?;
        Ok(LoaderAuthorization {
            unit: authenticated_unit.to_owned(),
            invocation_id: invocation_id.to_owned(),
            credential_name: credential_name.to_owned(),
        })
    }
}

impl Default for LoaderPolicy {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadRegistration {
    pub node_id: String,
    pub workload_id: String,
    pub unit: String,
    pub account: String,
    pub invocation_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadRequest {
    pub node_id: String,
    pub workload_id: String,
    pub claimed_unit: String,
    pub claimed_invocation_id: String,
    pub operation: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkloadAuthorization {
    pub node_id: String,
    pub workload_id: String,
    pub unit: String,
    pub invocation_id: String,
    pub operation: String,
}

pub fn authorize_workload(
    peer: &PeerIdentity,
    request: &WorkloadRequest,
    registrations: &[WorkloadRegistration],
) -> Result<WorkloadAuthorization, IdentityError> {
    if !peer.pidfd_supported {
        return Err(IdentityError::UnsupportedHost("SO_PEERPIDFD unavailable"));
    }
    if peer.uid == 0 {
        return Err(IdentityError::PermissionDenied(
            "workload socket rejects root and broker peers",
        ));
    }
    validate_name(&request.node_id, "node")?;
    validate_name(&request.workload_id, "workload")?;
    validate_name(&request.claimed_unit, "unit")?;
    validate_name(&request.claimed_invocation_id, "invocation")?;
    validate_name(&request.operation, "operation")?;

    let unit = peer
        .unit
        .as_deref()
        .ok_or(IdentityError::UnsupportedHost("system unit lookup failed"))?;
    let invocation_id = peer
        .invocation_id
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or(IdentityError::UnsupportedHost("invocation lookup failed"))?;
    let account = peer
        .account
        .as_deref()
        .ok_or(IdentityError::UnsupportedHost("account lookup failed"))?;

    if request.claimed_unit != unit || request.claimed_invocation_id != invocation_id {
        return Err(IdentityError::BindingMismatch(
            "self-reported unit or invocation differs from OS identity",
        ));
    }
    let registration = registrations
        .iter()
        .find(|candidate| {
            candidate.node_id == request.node_id
                && candidate.workload_id == request.workload_id
                && candidate.unit == unit
                && candidate.account == account
                && candidate.invocation_id == invocation_id
        })
        .ok_or(IdentityError::UnknownRegistration)?;
    Ok(WorkloadAuthorization {
        node_id: registration.node_id.clone(),
        workload_id: registration.workload_id.clone(),
        unit: registration.unit.clone(),
        invocation_id: registration.invocation_id.clone(),
        operation: request.operation.clone(),
    })
}

fn validate_name(value: &str, field: &'static str) -> Result<(), IdentityError> {
    if value.is_empty()
        || value.len() > 256
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(IdentityError::InvalidRequest(field));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        IdentityError, LoaderPolicy, PeerIdentity, WorkloadRegistration, WorkloadRequest,
        authorize_workload,
    };

    #[test]
    fn loader_requires_root_and_authenticated_pidfd_identity() {
        let mut policy = LoaderPolicy::new();
        policy
            .map_unit("blindpass-consumer.service", "api-key")
            .unwrap();
        assert_eq!(
            policy.map_unit("blindpass-consumer.service", "other-key"),
            Err(IdentityError::InvalidRequest("duplicate unit mapping"))
        );
        let user_peer = PeerIdentity::fixture(
            1000,
            1000,
            "blindpass-consumer.service",
            "invocation-a",
            "blindpass",
        );
        assert_eq!(
            policy.authorize(&user_peer, "blindpass-consumer.service"),
            Err(IdentityError::PermissionDenied(
                "credential-loader requires uid 0"
            ))
        );

        let mut unsupported = user_peer.clone();
        unsupported.uid = 0;
        unsupported.pidfd_supported = false;
        assert_eq!(
            policy.authorize(&unsupported, "blindpass-consumer.service"),
            Err(IdentityError::UnsupportedHost("SO_PEERPIDFD unavailable"))
        );
    }

    #[test]
    fn loader_rejects_forged_routing_name() {
        let mut policy = LoaderPolicy::new();
        policy.map_unit("real.service", "api-key").unwrap();
        let peer = PeerIdentity::fixture(0, 0, "real.service", "invocation-a", "root");
        assert_eq!(
            policy.authorize(&peer, "forged.service"),
            Err(IdentityError::BindingMismatch(
                "routing unit does not match authenticated unit"
            ))
        );
    }

    #[test]
    fn workload_requires_registered_account_unit_and_invocation() {
        let peer = PeerIdentity::fixture(
            1001,
            1001,
            "blindpass-agent.service",
            "invocation-a",
            "blindpass-agent",
        );
        let registration = WorkloadRegistration {
            node_id: "node-a".to_owned(),
            workload_id: "workload-a".to_owned(),
            unit: "blindpass-agent.service".to_owned(),
            account: "blindpass-agent".to_owned(),
            invocation_id: "invocation-a".to_owned(),
        };
        let request = WorkloadRequest {
            node_id: "node-a".to_owned(),
            workload_id: "workload-a".to_owned(),
            claimed_unit: "blindpass-agent.service".to_owned(),
            claimed_invocation_id: "invocation-a".to_owned(),
            operation: "health".to_owned(),
        };
        assert!(authorize_workload(&peer, &request, std::slice::from_ref(&registration)).is_ok());

        let mut stale = request;
        stale.claimed_invocation_id = "invocation-old".to_owned();
        assert_eq!(
            authorize_workload(&peer, &stale, &[registration]),
            Err(IdentityError::BindingMismatch(
                "self-reported unit or invocation differs from OS identity"
            ))
        );
    }
}
