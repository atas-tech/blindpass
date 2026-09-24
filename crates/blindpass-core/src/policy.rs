// SPDX-License-Identifier: AGPL-3.0-only

//! Dependency-free exchange policy matching and canonical decision hashing.

use crate::custody::{CryptoError, sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyMode {
    Allow,
    PendingApproval,
    Deny,
}

impl PolicyMode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::PendingApproval => "pending_approval",
            Self::Deny => "deny",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretRegistryEntry {
    pub secret_name: String,
    pub classification: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExchangePolicyRule {
    pub rule_id: String,
    pub secret_name: String,
    pub requester_ids: Option<Vec<String>>,
    pub fulfiller_ids: Option<Vec<String>>,
    pub approver_ids: Option<Vec<String>>,
    pub requester_rings: Option<Vec<String>>,
    pub fulfiller_rings: Option<Vec<String>>,
    pub approver_rings: Option<Vec<String>>,
    pub purposes: Option<Vec<String>>,
    pub same_ring: bool,
    pub allowed_rings: Option<Vec<String>>,
    pub mode: PolicyMode,
    pub approval_reference: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyInput<'a> {
    pub requester_id: &'a str,
    pub requester_workspace_id: Option<&'a str>,
    pub secret_name: &'a str,
    pub purpose: &'a str,
    pub fulfiller_hint: &'a str,
    pub fulfiller_workspace_id: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDecision {
    pub mode: PolicyMode,
    pub approval_required: bool,
    pub rule_id: String,
    pub reason: String,
    pub approval_reference: Option<String>,
    pub requester_ring: Option<String>,
    pub fulfiller_ring: Option<String>,
    pub secret_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEvaluation {
    pub decision: PolicyDecision,
    pub allowed_fulfiller_id: Option<String>,
    pub approver_ids: Option<Vec<String>>,
    pub approver_rings: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default)]
pub struct PolicyDocument {
    registry: Vec<SecretRegistryEntry>,
    rules: Vec<ExchangePolicyRule>,
}

impl PolicyDocument {
    #[must_use]
    pub fn new(registry: Vec<SecretRegistryEntry>, rules: Vec<ExchangePolicyRule>) -> Self {
        Self {
            registry: registry
                .into_iter()
                .map(|mut entry| {
                    entry.secret_name = entry.secret_name.trim().to_owned();
                    entry.classification = entry.classification.trim().to_owned();
                    entry.description = entry
                        .description
                        .map(|value| value.trim().to_owned())
                        .filter(|value| !value.is_empty());
                    entry
                })
                .collect(),
            rules: rules.into_iter().map(normalize_rule).collect(),
        }
    }

    #[must_use]
    pub fn has_secret(&self, secret_name: &str) -> bool {
        self.registry
            .iter()
            .any(|entry| entry.secret_name == secret_name)
    }

    #[must_use]
    pub fn evaluate(&self, input: &PolicyInput<'_>) -> Option<PolicyEvaluation> {
        let registry = self
            .registry
            .iter()
            .find(|entry| entry.secret_name == input.secret_name)?;
        if input.requester_workspace_id.is_some()
            && input.fulfiller_workspace_id.is_some()
            && input.requester_workspace_id != input.fulfiller_workspace_id
        {
            return None;
        }

        let requester_ring = ring_from_agent_id(input.requester_id);
        let fulfiller_ring = ring_from_agent_id(input.fulfiller_hint);
        let rule = self.rules.iter().find(|rule| {
            rule.secret_name == input.secret_name
                && includes(&rule.requester_ids, input.requester_id)
                && includes(&rule.fulfiller_ids, input.fulfiller_hint)
                && includes(&rule.purposes, input.purpose)
                && includes(
                    &rule.requester_rings,
                    requester_ring.as_deref().unwrap_or(""),
                )
                && includes(
                    &rule.fulfiller_rings,
                    fulfiller_ring.as_deref().unwrap_or(""),
                )
                && (!rule.same_ring
                    || (requester_ring.is_some()
                        && requester_ring == fulfiller_ring
                        && includes(&rule.allowed_rings, requester_ring.as_deref().unwrap_or(""))))
        })?;

        let reason = rule.reason.clone().unwrap_or_else(|| match rule.mode {
            PolicyMode::PendingApproval => {
                format!(
                    "exchange for {} requires human approval",
                    registry.classification
                )
            }
            PolicyMode::Deny => {
                format!(
                    "exchange for {} is denied by policy",
                    registry.classification
                )
            }
            PolicyMode::Allow => {
                format!(
                    "exchange allowed by static policy for {}",
                    registry.classification
                )
            }
        });
        Some(PolicyEvaluation {
            decision: PolicyDecision {
                mode: rule.mode,
                approval_required: rule.mode == PolicyMode::PendingApproval,
                rule_id: rule.rule_id.clone(),
                reason,
                approval_reference: rule.approval_reference.clone(),
                requester_ring,
                fulfiller_ring,
                secret_name: input.secret_name.to_owned(),
            },
            allowed_fulfiller_id: (rule.mode == PolicyMode::Allow)
                .then(|| input.fulfiller_hint.to_owned()),
            approver_ids: rule.approver_ids.clone(),
            approver_rings: rule.approver_rings.clone(),
        })
    }
}

pub fn hash_policy_decision(
    decision: &PolicyDecision,
    allowed_fulfiller_id: Option<&str>,
    workspace_id: Option<&str>,
) -> Result<String, CryptoError> {
    let payload = format!(
        "{{\"mode\":{},\"approvalRequired\":{},\"ruleId\":{},\"reason\":{},\"approvalReference\":{},\"requesterRing\":{},\"fulfillerRing\":{},\"secretName\":{},\"allowedFulfillerId\":{},\"workspaceId\":{}}}",
        json_string(decision.mode.as_str()),
        decision.approval_required,
        json_string(&decision.rule_id),
        json_string(&decision.reason),
        json_optional_string(decision.approval_reference.as_deref()),
        json_optional_string(decision.requester_ring.as_deref()),
        json_optional_string(decision.fulfiller_ring.as_deref()),
        json_string(&decision.secret_name),
        json_optional_string(allowed_fulfiller_id),
        json_optional_string(workspace_id),
    );
    let digest = sha256(payload.as_bytes())?;
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(output, "{byte:02x}");
    }
    Ok(output)
}

fn normalize_rule(mut rule: ExchangePolicyRule) -> ExchangePolicyRule {
    rule.rule_id = rule.rule_id.trim().to_owned();
    rule.secret_name = rule.secret_name.trim().to_owned();
    rule.requester_ids = normalize_list(rule.requester_ids);
    rule.fulfiller_ids = normalize_list(rule.fulfiller_ids);
    rule.approver_ids = normalize_list(rule.approver_ids);
    rule.requester_rings = normalize_list(rule.requester_rings);
    rule.fulfiller_rings = normalize_list(rule.fulfiller_rings);
    rule.approver_rings = normalize_list(rule.approver_rings);
    rule.purposes = normalize_list(rule.purposes);
    rule.allowed_rings = normalize_list(rule.allowed_rings);
    rule.approval_reference = rule
        .approval_reference
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    rule.reason = rule
        .reason
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    rule
}

fn normalize_list(values: Option<Vec<String>>) -> Option<Vec<String>> {
    values.map(|values| {
        values
            .into_iter()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .collect()
    })
}

fn includes(values: &Option<Vec<String>>, candidate: &str) -> bool {
    values
        .as_ref()
        .is_none_or(|values| values.is_empty() || values.iter().any(|value| value == candidate))
}

fn ring_from_agent_id(agent_id: &str) -> Option<String> {
    let (_, suffix) = agent_id.split_once("/ring/")?;
    let ring = suffix.split('/').next()?.trim();
    (!ring.is_empty()).then(|| ring.to_owned())
}

fn json_optional_string(value: Option<&str>) -> String {
    value.map_or_else(|| "null".to_owned(), json_string)
}

fn json_string(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{0008}' => output.push_str("\\b"),
            '\u{000c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character <= '\u{001f}' => {
                use std::fmt::Write;
                let _ = write!(output, "\\u{:04x}", character as u32);
            }
            character => output.push(character),
        }
    }
    output.push('"');
    output
}

#[cfg(test)]
mod tests {
    use super::{
        ExchangePolicyRule, PolicyDocument, PolicyInput, PolicyMode, SecretRegistryEntry,
        hash_policy_decision,
    };

    fn rule(
        rule_id: &str,
        secret_name: &str,
        requester_ids: Option<Vec<&str>>,
        fulfiller_ids: Option<Vec<&str>>,
        mode: PolicyMode,
        reason: &str,
    ) -> ExchangePolicyRule {
        ExchangePolicyRule {
            rule_id: rule_id.to_owned(),
            secret_name: secret_name.to_owned(),
            requester_ids: requester_ids
                .map(|values| values.into_iter().map(str::to_owned).collect()),
            fulfiller_ids: fulfiller_ids
                .map(|values| values.into_iter().map(str::to_owned).collect()),
            approver_ids: None,
            requester_rings: None,
            fulfiller_rings: None,
            approver_rings: None,
            purposes: None,
            same_ring: false,
            allowed_rings: None,
            mode,
            approval_reference: None,
            reason: (!reason.is_empty()).then(|| reason.to_owned()),
        }
    }

    #[test]
    fn matches_policy_and_hashes_decisions_compatibly() {
        let policy = PolicyDocument::new(
            vec![SecretRegistryEntry {
                secret_name: "finance.api_key".to_owned(),
                classification: "finance".to_owned(),
                description: None,
            }],
            vec![rule(
                "allow-finance",
                "finance.api_key",
                Some(vec!["agent-a"]),
                Some(vec!["agent-b"]),
                PolicyMode::Allow,
                "",
            )],
        );
        let evaluation = policy
            .evaluate(&PolicyInput {
                requester_id: "agent-a",
                requester_workspace_id: None,
                secret_name: "finance.api_key",
                purpose: "deploy",
                fulfiller_hint: "agent-b",
                fulfiller_workspace_id: None,
            })
            .unwrap();
        assert_eq!(
            evaluation.decision.reason,
            "exchange allowed by static policy for finance"
        );
        assert_eq!(
            hash_policy_decision(
                &evaluation.decision,
                evaluation.allowed_fulfiller_id.as_deref(),
                Some("workspace-p00")
            )
            .unwrap(),
            "6b81aae31baf41a8d34abdc5cf033d111ff6ae2abd25510fb9304f6622407eb4"
        );
        assert!(
            policy
                .evaluate(&PolicyInput {
                    requester_id: "agent-a",
                    requester_workspace_id: None,
                    secret_name: "finance.api_key",
                    purpose: "deploy",
                    fulfiller_hint: "agent-c",
                    fulfiller_workspace_id: None,
                })
                .is_none()
        );
    }

    #[test]
    fn applies_ring_and_workspace_constraints() {
        let mut restricted = rule(
            "approve-restricted",
            "restricted.secret",
            None,
            None,
            PolicyMode::PendingApproval,
            "restricted",
        );
        restricted.requester_rings = Some(vec!["blue".to_owned()]);
        restricted.fulfiller_rings = Some(vec!["blue".to_owned()]);
        restricted.same_ring = true;
        let policy = PolicyDocument::new(
            vec![SecretRegistryEntry {
                secret_name: "restricted.secret".to_owned(),
                classification: "sensitive".to_owned(),
                description: None,
            }],
            vec![restricted],
        );
        assert!(
            policy
                .evaluate(&PolicyInput {
                    requester_id: "agent-a/ring/blue",
                    requester_workspace_id: Some("one"),
                    secret_name: "restricted.secret",
                    purpose: "support",
                    fulfiller_hint: "agent-b/ring/blue",
                    fulfiller_workspace_id: Some("one"),
                })
                .is_some()
        );
        assert!(
            policy
                .evaluate(&PolicyInput {
                    requester_id: "agent-a/ring/blue",
                    requester_workspace_id: Some("one"),
                    secret_name: "restricted.secret",
                    purpose: "support",
                    fulfiller_hint: "agent-b/ring/red",
                    fulfiller_workspace_id: Some("one"),
                })
                .is_none()
        );
        assert!(
            policy
                .evaluate(&PolicyInput {
                    requester_id: "agent-a/ring/blue",
                    requester_workspace_id: Some("one"),
                    secret_name: "restricted.secret",
                    purpose: "support",
                    fulfiller_hint: "agent-b/ring/blue",
                    fulfiller_workspace_id: Some("two"),
                })
                .is_none()
        );
    }
}
