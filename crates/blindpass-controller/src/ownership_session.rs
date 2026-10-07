// SPDX-License-Identifier: AGPL-3.0-only

//! Claims external process ownership for the controller binary's commands.

use crate::{
    config::Config,
    recovery_authority::{Authority, ProcessOwnership},
};
use std::sync::Arc;

pub struct OwnershipSession {
    pub owner: Arc<ProcessOwnership>,
    pub monitor: tokio::task::JoinHandle<()>,
    // The owner shares this pool for broker-trust and recovery work, so it must outlive
    // every owner operation; closing it right after the claim fences the first caller.
    authority: Option<Authority>,
}

impl OwnershipSession {
    /// Closes the shared authority pool. Call only after the owner has quiesced.
    pub async fn close_authority(&mut self) {
        if let Some(authority) = self.authority.take() {
            authority.close().await;
        }
    }
}

impl Drop for OwnershipSession {
    fn drop(&mut self) {
        self.owner.fence();
        self.monitor.abort();
    }
}

pub async fn claim_ownership(
    config: &Config,
    maintenance: bool,
) -> Result<Option<OwnershipSession>, String> {
    config.require_authority().map_err(|error| serde_json::json!({"event":"startup_failed","reason":"configuration_invalid","detail":error.to_string()}).to_string())?;
    let Some(url) = config.authority_url() else {
        return Ok(None);
    };
    let context = config
        .authority_context()
        .ok_or("invalid authority configuration")?;
    let error = || serde_json::json!({"event":"startup_failed","reason":"fenced"}).to_string();
    let authority = Authority::connect_existing(url)
        .await
        .map_err(|_| error())?;
    let result = async {
        let record = authority.read(&context).await.map_err(|_| error())?;
        if maintenance && record.phase != "fenced" {
            return Err(error());
        }
        let owner = Arc::new(
            authority
                .claim_process(&context, &record)
                .await
                .map_err(|_| error())?,
        );
        let monitor = owner.spawn_monitor();
        Ok(OwnershipSession {
            owner,
            monitor,
            authority: None,
        })
    }
    .await;
    match result {
        Ok(mut session) => {
            session.authority = Some(authority);
            Ok(Some(session))
        }
        Err(error) => {
            authority.close().await;
            Err(error)
        }
    }
}
