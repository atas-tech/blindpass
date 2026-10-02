// SPDX-License-Identifier: AGPL-3.0-only
//! The original accepted process lease, never reconstructed from caller labels,
//! current same-unit membership, durable metadata or a numeric PID.
use crate::os_identity::{LivePeer, OsIdentityError};
use blindpass_core::fleet::Grant;
use blindpass_core::identity::{PeerIdentity, WorkloadAuthorization};
use std::sync::Arc;
use std::time::Instant;

pub(crate) const MAX_ORIGINAL_WORKLOAD_LEASES: usize = 16;
#[derive(Clone)]
enum OriginalPeer {
    Kernel(Arc<LivePeer>),
    #[cfg(test)]
    Fixture {
        identity: PeerIdentity,
        alive: Arc<std::sync::atomic::AtomicBool>,
    },
}
#[derive(Clone)]
pub struct OriginalWorkloadLease {
    event_key: String,
    authorization: WorkloadAuthorization,
    peer: OriginalPeer,
}
impl std::fmt::Debug for OriginalWorkloadLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OriginalWorkloadLease([kernel-bound])")
    }
}
impl OriginalWorkloadLease {
    pub(crate) fn captured(
        event_key: &str,
        authorization: WorkloadAuthorization,
        peer: Arc<LivePeer>,
    ) -> Result<Self, &'static str> {
        let result = Self {
            event_key: event_key.into(),
            authorization,
            peer: OriginalPeer::Kernel(peer),
        };
        if result.identity().uid == 0
            || result.identity().unit.as_deref() != Some(result.authorization.unit.as_str())
            || result.identity().invocation_id.as_deref()
                != Some(result.authorization.invocation_id.as_str())
            || result.ensure_alive().is_err()
        {
            return Err("browser_original_owner_unavailable");
        }
        Ok(result)
    }
    #[must_use]
    pub fn identity(&self) -> &PeerIdentity {
        match &self.peer {
            OriginalPeer::Kernel(peer) => peer.identity(),
            #[cfg(test)]
            OriginalPeer::Fixture { identity, .. } => identity,
        }
    }
    pub fn ensure_alive(&self) -> Result<(), OsIdentityError> {
        match &self.peer {
            OriginalPeer::Kernel(peer) => peer.ensure_alive(),
            #[cfg(test)]
            OriginalPeer::Fixture { alive, .. } => {
                if alive.load(std::sync::atomic::Ordering::Acquire) {
                    Ok(())
                } else {
                    Err(OsIdentityError::PeerExitedBeforeLookup)
                }
            }
        }
    }
    /// Bounded manager revalidation on the retained original pidfd. Perform
    /// outside the broker state mutex before starting source/handoff IO.
    pub fn ensure_current(&self, deadline: Instant) -> Result<(), OsIdentityError> {
        match &self.peer {
            OriginalPeer::Kernel(peer) => peer.ensure_current(deadline),
            #[cfg(test)]
            OriginalPeer::Fixture { .. } => self.ensure_alive(),
        }
    }
    pub(crate) fn authorization(&self) -> &WorkloadAuthorization {
        &self.authorization
    }
    pub(crate) fn matches(&self, grant: &Grant) -> bool {
        grant.request_event_key.as_deref() == Some(self.event_key.as_str())
            && grant.node_id == self.authorization.node_id
            && grant.workload_id == self.authorization.workload_id
            && grant.unit == self.authorization.unit
            && grant.invocation_id == self.authorization.invocation_id
            && self.identity().account.as_deref() == Some(grant.account.as_str())
            && self.ensure_alive().is_ok()
    }
    #[cfg(test)]
    pub(crate) fn fixture(
        event_key: &str,
        authorization: WorkloadAuthorization,
        identity: PeerIdentity,
    ) -> (Self, Arc<std::sync::atomic::AtomicBool>) {
        let alive = Arc::new(std::sync::atomic::AtomicBool::new(true));
        (
            Self {
                event_key: event_key.into(),
                authorization,
                peer: OriginalPeer::Fixture {
                    identity,
                    alive: Arc::clone(&alive),
                },
            },
            alive,
        )
    }
}
