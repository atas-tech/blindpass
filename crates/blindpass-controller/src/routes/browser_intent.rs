// SPDX-License-Identifier: AGPL-3.0-only
//! Apply a versioned browser intent after the node route verified its signature.
//! A workload requests execution; only the existing named operator path approves.
use super::authorization::{
    FleetRuleInput, GrantIssuanceError, ensure_operation_grants, sanitize_purpose,
};
use crate::app::AppState;
use crate::store::{
    AuditDraft, BrokerOperationEvent, OperationApprovalDraft, OperationCreateOutcome,
    OperationRecord,
};
use blindpass_core::canon::canonicalize_json;
use blindpass_core::custody::sha256;
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BrowserIntent {
    request_version: u64,
    node_id: String,
    workload_id: String,
    unit: String,
    account: String,
    invocation_id: String,
    action: String,
    mode: String,
    purpose: String,
    resource_id: String,
    ttl_seconds: u64,
    observed_at_ms: i64,
}
#[derive(Debug)]
pub(super) enum IntentFailure {
    Rejected,
    Conflict,
    Unavailable,
}
fn hash(bytes: &[u8]) -> Result<String, IntentFailure> {
    sha256(bytes)
        .map(|digest| digest.iter().map(|byte| format!("{byte:02x}")).collect())
        .map_err(|_| IntentFailure::Unavailable)
}
fn canonical(value: &Value) -> Result<String, IntentFailure> {
    canonicalize_json(&value.to_string())
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .ok_or(IntentFailure::Unavailable)
}
fn id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

pub(super) async fn apply_verified_request(
    state: &AppState,
    node_id: &str,
    key: &str,
    body: &str,
    body_hash: &str,
    duplicate: bool,
) -> Result<bool, IntentFailure> {
    let intent: BrowserIntent = serde_json::from_str(body).map_err(|_| IntentFailure::Rejected)?;
    if intent.request_version != 2
        || intent.node_id != node_id
        || !id(&intent.workload_id)
        || !id(&intent.resource_id)
        || !id(key)
        || key.len() < 16
        || intent.action != "browser.session"
        || intent.mode != "browser_session"
        || intent.invocation_id.len() != 32
        || !intent
            .invocation_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || !(1..=120).contains(&intent.ttl_seconds)
        || intent.purpose.len() > 512
        || intent
            .purpose
            .chars()
            .any(|ch| matches!(ch, '\r' | '\n' | '\0'))
    {
        return Err(IntentFailure::Rejected);
    }
    let store = state.store.as_ref().ok_or(IntentFailure::Unavailable)?;
    let operation_id = format!(
        "op_{}",
        hash(canonical(&json!({"node_id":node_id,"event_key":key}))?.as_bytes())?
    );
    store
        .expire_fleet_state()
        .await
        .map_err(|_| IntentFailure::Unavailable)?;
    if let Some(operation) = store
        .operation_by_id(&operation_id)
        .await
        .map_err(|_| IntentFailure::Unavailable)?
    {
        if operation.request_hash != body_hash
            || operation.node_id != node_id
            || operation.workload_id != intent.workload_id
            || operation.broker_event_key.as_deref() != Some(key)
            || operation.requested_by != format!("workload:{}", intent.workload_id)
        {
            return Err(IntentFailure::Conflict);
        }
        let receipt = store
            .recorded_node_event(node_id, key)
            .await
            .map_err(|_| IntentFailure::Unavailable)?
            .ok_or(IntentFailure::Unavailable)?;
        if receipt.kind != "operation_request" || receipt.body_hash != body_hash {
            return Err(IntentFailure::Conflict);
        }
        finish_issuance(state, &operation).await?;
        return Ok(false);
    }
    if duplicate {
        // A receipt without its original operation must never mint fresh authority.
        return Err(IntentFailure::Unavailable);
    }
    let workload = store
        .workload_by_id(&intent.workload_id)
        .await
        .map_err(|_| IntentFailure::Unavailable)?
        .filter(|w| {
            w.status == "active"
                && w.node_id == node_id
                && w.unit == intent.unit
                && w.account == intent.account
                && w.consumption_mode == intent.mode
        })
        .ok_or(IntentFailure::Rejected)?;
    let node = store
        .node_by_id(node_id)
        .await
        .map_err(|_| IntentFailure::Unavailable)?
        .filter(|n| n.status == "active" && !n.rotation_pending)
        .ok_or(IntentFailure::Rejected)?;
    let now = store
        .database_now_ms()
        .await
        .map_err(|_| IntentFailure::Unavailable)?;
    if intent.observed_at_ms <= 0
        || now.saturating_sub(intent.observed_at_ms) > 60_000
        || intent.observed_at_ms > now.saturating_add(60_000)
        || node.last_seen_at_ms.is_none_or(|seen| {
            now.saturating_sub(seen) > 120_000 || seen > now.saturating_add(60_000)
        })
    {
        return Err(IntentFailure::Rejected);
    }
    let policy = store
        .fleet_policy()
        .await
        .map_err(|_| IntentFailure::Unavailable)?;
    let rules: Vec<FleetRuleInput> = serde_json::from_str::<Value>(&policy.document_json)
        .ok()
        .and_then(|v| v.get("rules").cloned())
        .and_then(|v| serde_json::from_value(v).ok())
        .ok_or(IntentFailure::Unavailable)?;
    let rule = rules
        .iter()
        .find(|rule| rule.action == intent.action && rule.mode == intent.mode);
    let decision = rule.map_or("deny", |r| r.decision.as_str());
    if !matches!(decision, "allow" | "deny" | "pending_approval")
        || rule.is_some_and(|r| r.approval_required != (decision == "pending_approval"))
    {
        return Err(IntentFailure::Unavailable);
    }
    let ttl = intent
        .ttl_seconds
        .min(rule.map_or(120, |r| r.max_ttl_seconds))
        .min(u64::try_from(workload.local_ceiling_seconds).map_err(|_| IntentFailure::Rejected)?);
    if ttl == 0 {
        return Err(IntentFailure::Rejected);
    }
    let expiry = now.saturating_add(if decision == "pending_approval" {
        i64::try_from(state.approval_ttl_seconds)
            .unwrap_or(600)
            .saturating_mul(1000)
    } else {
        (ttl as i64).saturating_mul(1000)
    });
    let purpose = sanitize_purpose(&intent.purpose);
    let identity = canonical(&json!({"tenant_id":store.tenant_id(),"node_id":node_id,
        "workload_id":workload.id,"unit":workload.unit,"account":workload.account,
        "action":intent.action,"mode":intent.mode,"rule_id":rule.map(|r|&r.id),"policy_version":policy.version}))?;
    let summary = canonical(
        &json!({"requester_type":"workload","requester":workload.name,
        "workload_id":workload.id,"action":intent.action,"mode":intent.mode,"resource_id":intent.resource_id,"purpose":purpose}),
    )?;
    let approvers = rule.map_or_else(Vec::new, |r| r.approver_ids.clone());
    if decision == "pending_approval" && approvers.is_empty() {
        return Err(IntentFailure::Unavailable);
    }
    let record=OperationRecord {
        id:operation_id.clone(),workload_id:workload.id.clone(),node_id:node_id.to_owned(),
        invocation_id:intent.invocation_id,action:intent.action,mode:intent.mode,resource_id:intent.resource_id,
        requested_ttl_seconds:ttl as i64,broker_event_key:Some(key.to_owned()),requested_by:format!("workload:{}",workload.id),
        purpose,policy_version:policy.version,decision:decision.to_owned(),
        decision_hash:Some(hash(canonical(&json!({"policy_version":policy.version,"rule_id":rule.map(|r|&r.id),"decision":decision,"ttl_seconds":ttl}))?.as_bytes())?),
        status:match decision {"allow"=>"requested","pending_approval"=>"awaiting_approval",_=>"denied"}.to_owned(),
        approval_id:None,grant_id:None,idempotency_key:hash(canonical(&json!({"node_id":node_id,"event_key":key}))?.as_bytes())?,
        request_hash:body_hash.to_owned(),result_json:None,created_at_ms:now,expires_at_ms:expiry,completed_at_ms:None,version:1,
    };
    let group_scope_hash = hash(identity.as_bytes())?;
    let approver_ids_json =
        serde_json::to_string(&approvers).map_err(|_| IntentFailure::Unavailable)?;
    let approval = (decision == "pending_approval").then(|| OperationApprovalDraft {
        id: format!("oa_{}", record.idempotency_key),
        idempotency_key: format!("oa-for-{}", operation_id),
        requester_summary_json: summary,
        verified_identity_json: identity.clone(),
        rule_id: rule.map_or_else(String::new, |r| r.id.clone()),
        expires_at_ms: expiry,
        approver_ids_json,
        group_scope_hash,
    });
    let audit=AuditDraft {
        action:"fleet.operation_requested".to_owned(),actor_type:"workload".to_owned(),actor_id:Some(workload.id.clone()),
        target_type:"operation".to_owned(),target_id:Some(operation_id),
        metadata:json!({"target_type":"operation","outcome":record.status,"node_id":node_id,"workload_id":workload.id,
            "decision":decision,"policy_version":policy.version,"broker_event_key":key}).as_object().expect("literal object").clone(),
    };
    let event_id = format!("ne_{}", record.idempotency_key);
    let event = BrokerOperationEvent {
        id: &event_id,
        node_id,
        key,
        body_json: body,
        body_hash,
        observed_at_ms: intent.observed_at_ms,
    };
    match store
        .create_browser_operation(
            &record,
            &workload.unit,
            &workload.account,
            ttl as i64,
            approval.as_ref(),
            &audit,
            &event,
        )
        .await
        .map_err(|_| IntentFailure::Unavailable)?
    {
        OperationCreateOutcome::Created(operation) => {
            finish_issuance(state, &operation).await?;
            Ok(true)
        }
        OperationCreateOutcome::Existing(operation) => {
            finish_issuance(state, &operation).await?;
            Ok(false)
        }
        OperationCreateOutcome::Conflict => Err(IntentFailure::Conflict),
        OperationCreateOutcome::Stale => Err(IntentFailure::Unavailable),
    }
}

async fn finish_issuance(
    state: &AppState,
    operation: &OperationRecord,
) -> Result<(), IntentFailure> {
    if operation.decision != "allow" || operation.status != "requested" {
        return Ok(());
    }
    match ensure_operation_grants(state, std::slice::from_ref(&operation.id)).await {
        Ok(()) => Ok(()),
        Err(GrantIssuanceError::Unavailable) => Err(IntentFailure::Unavailable),
        Err(GrantIssuanceError::Stale) => {
            // Concurrent replay/cancel/expiry may have already completed the
            // transition. Otherwise keep the event unACKed for bounded recovery.
            let store = state.store.as_ref().ok_or(IntentFailure::Unavailable)?;
            store
                .expire_fleet_state()
                .await
                .map_err(|_| IntentFailure::Unavailable)?;
            let current = store
                .operation_by_id(&operation.id)
                .await
                .map_err(|_| IntentFailure::Unavailable)?
                .ok_or(IntentFailure::Unavailable)?;
            if current.status == "requested" {
                Err(IntentFailure::Unavailable)
            } else {
                Ok(())
            }
        }
    }
}
