// SPDX-License-Identifier: AGPL-3.0-only

//! Shared, test-only fixture operation for the HTTP seed route and CLI.

use crate::routes::admin_policy::validated_seed_policy_json;
use crate::routes::auth::{
    hash_api_key, hash_refresh_token, mint_seed_admin_token, new_api_key, random_uuid, ring_from_id,
};
use crate::store::Store;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedRequest {
    pub agents: Vec<String>,
    #[serde(default)]
    pub policy: Option<Value>,
    #[serde(default)]
    pub rotated_agents: Vec<String>,
    #[serde(default)]
    pub revoked_agents: Vec<String>,
    #[serde(default)]
    pub local_admin: bool,
}

#[derive(Serialize)]
pub struct LocalAdminSeed {
    pub operator_id: String,
    pub username: String,
    pub temporary_password: String,
    pub session_id: String,
    pub csrf_token: String,
    pub refresh_token: String,
}

#[derive(Serialize)]
pub struct SeedResponse {
    pub access_token: String,
    pub workspace_id: String,
    pub user_id: String,
    pub agents: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_admin: Option<LocalAdminSeed>,
}

#[derive(Debug, Clone, Copy)]
pub enum SeedError {
    InvalidAgents,
    InvalidPolicy,
    Conflict,
    Internal,
}

pub async fn seed_fixture(
    store: &Store,
    jwt_secret: &[u8],
    request: SeedRequest,
) -> Result<SeedResponse, SeedError> {
    let SeedRequest {
        agents: fixture_agents,
        policy,
        rotated_agents,
        revoked_agents,
        local_admin,
    } = request;
    let agent_ids = fixture_agents.iter().cloned().collect::<BTreeSet<_>>();
    let rotated_count = rotated_agents.len();
    let revoked_count = revoked_agents.len();
    let rotated = rotated_agents.into_iter().collect::<BTreeSet<_>>();
    let revoked = revoked_agents.into_iter().collect::<BTreeSet<_>>();
    if fixture_agents.is_empty()
        || fixture_agents.len() > 64
        || fixture_agents.iter().any(|agent| agent.trim().is_empty())
        || agent_ids.len() != fixture_agents.len()
        || rotated.len() != rotated_count
        || revoked.len() != revoked_count
        || !rotated.is_subset(&agent_ids)
        || !revoked.is_subset(&agent_ids)
    {
        return Err(SeedError::InvalidAgents);
    }
    let policy = policy
        .map(|value| validated_seed_policy_json(value).ok_or(SeedError::InvalidPolicy))
        .transpose()?;
    for agent_id in &fixture_agents {
        if store
            .agent_by_agent_id(agent_id)
            .await
            .map_err(|_| SeedError::Internal)?
            .is_some()
        {
            return Err(SeedError::Conflict);
        }
    }
    if policy.is_some()
        && store
            .policy_document()
            .await
            .map_err(|_| SeedError::Internal)?
            .is_some()
    {
        return Err(SeedError::Conflict);
    }
    if local_admin
        && store
            .has_active_admin()
            .await
            .map_err(|_| SeedError::Internal)?
    {
        return Err(SeedError::Conflict);
    }
    let mut agents = BTreeMap::new();
    for agent_id in fixture_agents {
        let row_id = random_uuid();
        let mut api_key = new_api_key(&row_id);
        let hash = hash_api_key(&api_key).map_err(|_| SeedError::Internal)?;
        store
            .create_agent_with_id(
                &row_id,
                &agent_id,
                &format!("{agent_id} Display"),
                ring_from_id(&agent_id),
                &hash,
            )
            .await
            .map_err(|_| SeedError::Conflict)?;
        if rotated.contains(&agent_id) {
            api_key = new_api_key(&row_id);
            let rotated_hash = hash_api_key(&api_key).map_err(|_| SeedError::Internal)?;
            store
                .replace_agent_api_key_hash(&agent_id, 1, &rotated_hash)
                .await
                .map_err(|_| SeedError::Internal)?
                .ok_or(SeedError::Conflict)?;
        }
        if revoked.contains(&agent_id)
            && !store
                .revoke_agent(&agent_id)
                .await
                .map_err(|_| SeedError::Internal)?
        {
            return Err(SeedError::Conflict);
        }
        agents.insert(agent_id, api_key);
    }
    if let Some(policy) = policy {
        store
            .replace_policy_document(1, &policy, "test-seed")
            .await
            .map_err(|_| SeedError::Internal)?
            .ok_or(SeedError::Conflict)?;
    }
    let local_admin = if local_admin {
        let operator_id = random_uuid();
        let temporary_password = random_seed_token();
        let password_hash = hash_api_key(&temporary_password).map_err(|_| SeedError::Internal)?;
        if !store
            .bootstrap_local_operator(&operator_id, "admin", "Test administrator", &password_hash)
            .await
            .map_err(|_| SeedError::Internal)?
        {
            return Err(SeedError::Conflict);
        }
        let refresh_token = random_seed_token();
        let refresh_hash = hash_refresh_token(&refresh_token).ok_or(SeedError::Internal)?;
        let session = store
            .create_browser_session(&operator_id, &refresh_hash, 30 * 24 * 60 * 60)
            .await
            .map_err(|_| SeedError::Internal)?
            .ok_or(SeedError::Internal)?;
        Some(LocalAdminSeed {
            operator_id,
            username: "admin".to_owned(),
            temporary_password,
            session_id: session.session_id,
            csrf_token: session.csrf_secret,
            refresh_token,
        })
    } else {
        None
    };
    let user_id = random_uuid();
    let access_token = mint_seed_admin_token(jwt_secret, &user_id, store.tenant_id())
        .map_err(|_| SeedError::Internal)?;
    Ok(SeedResponse {
        access_token,
        workspace_id: store.tenant_id().to_owned(),
        user_id,
        agents,
        local_admin,
    })
}

fn random_seed_token() -> String {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::{SeedRequest, seed_fixture};
    use crate::store::Store;

    #[test]
    fn fixture_rejects_unknown_fields_instead_of_silently_ignoring_them() {
        let parsed = serde_json::from_str::<SeedRequest>(r#"{"agents":["one"],"surprise":true}"#);
        assert!(parsed.is_err());
    }

    #[tokio::test]
    async fn duplicate_fixture_agents_are_rejected_without_partial_seed() {
        let store = Store::connect("sqlite::memory:").await.unwrap();
        let result = seed_fixture(
            &store,
            &[b'A'; 32],
            SeedRequest {
                agents: vec!["duplicate-agent".to_owned(), "duplicate-agent".to_owned()],
                policy: None,
                rotated_agents: Vec::new(),
                revoked_agents: Vec::new(),
                local_admin: false,
            },
        )
        .await;
        assert!(result.is_err());
        assert!(store.list_admin_agents().await.unwrap().is_empty());
        store.close().await;
    }

    #[tokio::test]
    async fn fixture_can_seed_validated_policy_with_agents() {
        let store = Store::connect("sqlite::memory:").await.unwrap();
        let request: SeedRequest = serde_json::from_str(
            r#"{"agents":["policy-agent"],"policy":{"secret_registry":[],"exchange_policy":[]}}"#,
        )
        .unwrap();
        let response = seed_fixture(&store, &[b'A'; 32], request).await.unwrap();
        assert!(response.agents.contains_key("policy-agent"));
        assert!(response.local_admin.is_none());
        let record = store
            .policy_document()
            .await
            .unwrap()
            .expect("seeded policy");
        let policy: serde_json::Value = serde_json::from_str(&record.document_json).unwrap();
        assert_eq!(
            policy,
            serde_json::json!({"secret_registry":[],"exchange_policy":[]})
        );
        store.close().await;
    }

    #[tokio::test]
    async fn invalid_policy_is_rejected_before_fixture_agents_are_written() {
        let store = Store::connect("sqlite::memory:").await.unwrap();
        let request: SeedRequest = serde_json::from_str(
            r#"{"agents":["policy-agent"],"policy":{"secret_registry":[],"exchange_policy":[{"ruleId":"invalid","secretName":"unknown","mode":"allow"}]}}"#,
        )
        .unwrap();
        assert!(seed_fixture(&store, &[b'A'; 32], request).await.is_err());
        assert!(store.list_admin_agents().await.unwrap().is_empty());
        assert!(store.policy_document().await.unwrap().is_none());
        store.close().await;
    }

    #[tokio::test]
    async fn fixture_can_include_rotated_and_revoked_agents() {
        let store = Store::connect("sqlite::memory:").await.unwrap();
        let request: SeedRequest = serde_json::from_str(
            r#"{"agents":["active-agent","rotated-agent","revoked-agent"],"rotated_agents":["rotated-agent"],"revoked_agents":["revoked-agent"]}"#,
        )
        .unwrap();
        let response = seed_fixture(&store, &[b'A'; 32], request).await.unwrap();
        let rotated = store
            .agent_by_agent_id("rotated-agent")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rotated.key_version, 2);
        assert!(crate::routes::auth::verify_api_key(
            &response.agents["rotated-agent"],
            &rotated.api_key_hash
        ));
        let revoked = store
            .agent_by_agent_id("revoked-agent")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(revoked.status, "revoked");
        let active = store
            .agent_by_agent_id("active-agent")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(active.status, "active");
        store.close().await;
    }

    #[tokio::test]
    async fn fixture_rejects_unknown_rotation_target_before_writing_agents() {
        let store = Store::connect("sqlite::memory:").await.unwrap();
        let request: SeedRequest = serde_json::from_str(
            r#"{"agents":["active-agent"],"rotated_agents":["missing-agent"]}"#,
        )
        .unwrap();
        assert!(seed_fixture(&store, &[b'A'; 32], request).await.is_err());
        assert!(store.list_admin_agents().await.unwrap().is_empty());
        store.close().await;
    }

    #[tokio::test]
    async fn existing_later_agent_blocks_fixture_before_earlier_agent_is_written() {
        let store = Store::connect("sqlite::memory:").await.unwrap();
        store
            .create_agent("existing-agent", "Existing", None, "dummy-hash")
            .await
            .unwrap();
        let request: SeedRequest =
            serde_json::from_str(r#"{"agents":["new-agent","existing-agent"]}"#).unwrap();
        assert!(seed_fixture(&store, &[b'A'; 32], request).await.is_err());
        assert!(
            store
                .agent_by_agent_id("new-agent")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .agent_by_agent_id("existing-agent")
                .await
                .unwrap()
                .is_some()
        );
        store.close().await;
    }

    #[tokio::test]
    async fn fixture_can_create_a_local_admin_session_for_vm_clients() {
        let store = Store::connect("sqlite::memory:").await.unwrap();
        let request: SeedRequest =
            serde_json::from_str(r#"{"agents":["vm-agent"],"local_admin":true}"#).unwrap();
        let response = seed_fixture(&store, &[b'A'; 32], request).await.unwrap();
        let value = serde_json::to_value(response).unwrap();
        let admin = &value["local_admin"];
        let session_id = admin["session_id"].as_str().expect("session id");
        let session = store
            .browser_session_by_id(session_id)
            .await
            .unwrap()
            .expect("active session");
        assert_eq!(session.operator.role, "admin");
        assert!(session.operator.must_change_password);
        assert_eq!(session.csrf_secret, admin["csrf_token"]);
        assert!(crate::routes::auth::verify_api_key(
            admin["temporary_password"]
                .as_str()
                .expect("temporary password"),
            &session.operator.password_hash
        ));
        store.close().await;
    }

    #[tokio::test]
    async fn existing_admin_blocks_local_admin_fixture_before_agent_writes() {
        let store = Store::connect("sqlite::memory:").await.unwrap();
        assert!(
            store
                .bootstrap_local_operator("existing-admin", "existing", "Existing", "dummy-hash")
                .await
                .unwrap()
        );
        let request: SeedRequest =
            serde_json::from_str(r#"{"agents":["vm-agent"],"local_admin":true}"#).unwrap();
        assert!(seed_fixture(&store, &[b'A'; 32], request).await.is_err());
        assert!(store.list_admin_agents().await.unwrap().is_empty());
        store.close().await;
    }
}
