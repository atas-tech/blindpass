// SPDX-License-Identifier: AGPL-3.0-only

use crate::routes::auth::WorkloadIdentity;
use crate::store::Store;
use axum::Json;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use blindpass_core::custody::sha256;
use serde_json::json;

/// Consume a route-specific, tenant-scoped workload budget after identity and
/// workspace checks. `None` means the request may continue; a response means
/// the store was unavailable or the caller exceeded its window.
pub(crate) async fn enforce(
    store: &Store,
    identity: &WorkloadIdentity,
    route: &'static str,
    label: &'static str,
    limit: u32,
    window_ms: u64,
) -> Option<Response> {
    let key = match rate_window_key(route, store.tenant_id(), identity) {
        Ok(key) => key,
        Err(()) => return Some(service_unavailable()),
    };
    let rate = match store.consume_rate_limit(&key, limit, window_ms).await {
        Ok(rate) => rate,
        Err(_) => return Some(service_unavailable()),
    };
    if rate.count <= i64::from(limit) {
        return None;
    }
    if rate.count == i64::from(limit) + 1 {
        let _ = store
            .append_audit(
                "agent_rate_limited",
                "agent",
                Some(&identity.sub),
                "rate_limit",
                Some(route),
                &json!({"action":"agent_rate_limited","route":route,"limit":limit,"used":rate.count}),
            )
            .await;
    }
    Some(
        (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, rate.retry_after_seconds.to_string())],
            Json(json!({
                "error":format!("Too many {label}"),
                "code":"rate_limited",
                "retry_after_seconds":rate.retry_after_seconds,
                "limit":limit,
                "used":rate.count
            })),
        )
            .into_response(),
    )
}

fn rate_window_key(
    route: &str,
    tenant_id: &str,
    identity: &WorkloadIdentity,
) -> Result<String, ()> {
    let (source, provider) = match identity.auth_provider.as_deref() {
        Some(provider) => ("external", provider),
        None => ("local", ""),
    };
    let mut identity_material = Vec::new();
    for component in [route, tenant_id, source, provider, identity.sub.as_str()] {
        let Ok(length) = u64::try_from(component.len()) else {
            return Err(());
        };
        identity_material.extend_from_slice(&length.to_be_bytes());
        identity_material.extend_from_slice(component.as_bytes());
    }
    let digest = match sha256(&identity_material) {
        Ok(digest) => digest,
        Err(_) => return Err(()),
    };
    let identity_key = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(format!("agent-{route}:{tenant_id}:{identity_key}"))
}

fn service_unavailable() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({"error":"service_unavailable"})),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::rate_window_key;
    use crate::routes::auth::WorkloadIdentity;

    fn identity(sub: &str, auth_provider: Option<&str>) -> WorkloadIdentity {
        WorkloadIdentity {
            sub: sub.to_owned(),
            role: "gateway".to_owned(),
            workspace_id: Some("tenant-a".to_owned()),
            workload_mode: None,
            admin: None,
            auth_provider: auth_provider.map(str::to_owned),
            spiffe_id: None,
        }
    }

    #[test]
    fn request_windows_separate_tenant_route_and_external_provider() {
        let local = identity("same-subject", None);
        let external_a = identity("same-subject", Some("provider-a"));
        let external_b = identity("same-subject", Some("provider-b"));

        let base = rate_window_key("request", "tenant-a", &local).unwrap();
        assert_ne!(
            base,
            rate_window_key("request", "tenant-b", &local).unwrap()
        );
        assert_ne!(
            base,
            rate_window_key("exchange", "tenant-a", &local).unwrap()
        );
        assert_ne!(
            rate_window_key("request", "tenant-a", &external_a).unwrap(),
            rate_window_key("request", "tenant-a", &external_b).unwrap()
        );
    }

    #[test]
    fn external_provider_and_subject_delimiters_cannot_collide() {
        let left = identity("issuer:subject", Some("provider"));
        let right = identity("subject", Some("provider:issuer"));
        assert_ne!(
            rate_window_key("request", "tenant-a", &left).unwrap(),
            rate_window_key("request", "tenant-a", &right).unwrap()
        );
    }
}
