// SPDX-License-Identifier: AGPL-3.0-only

//! Canonical request metadata. Source passwords and private session data never
//! enter these hashes or the persistent retry/withdrawal records.
use crate::{BrokerError, BrowserResource, valid_event_identifier};
use blindpass_core::canon::{Value, canonicalize_value, parse_json};
use blindpass_core::fleet::ConsumptionMode;
use blindpass_core::identity::WorkloadAuthorization;
use blindpass_core::protocol::is_valid_event_key;
use blindpass_core::signing::base64_url_decode;

const INVALID: BrokerError = BrokerError::Configuration("invalid_operation_request");

/// The purpose is shown to a human approver, so it must not carry anything
/// that can hide, reorder or break lines of text: every Unicode control
/// character (C0, DEL, C1, including CR, LF, NUL and TAB) plus invisible
/// format, line-separator and bidirectional characters. The MCP client
/// applies the identical rule before the request leaves the agent.
fn forbidden_purpose_character(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{00AD}'
                | '\u{061C}'
                | '\u{200B}'..='\u{200F}'
                | '\u{2028}'..='\u{2029}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}'
                | '\u{FEFF}'
        )
}
pub(crate) struct RequestInput {
    pub action: String,
    pub mode: ConsumptionMode,
    pub purpose: String,
    pub resource_id: String,
    pub ttl_seconds: u64,
    pub request_key: Option<String>,
}
impl RequestInput {
    pub fn parse(encoded: &str) -> Result<Self, BrokerError> {
        if encoded.is_empty() || encoded.len() > 1_536 {
            return Err(INVALID);
        }
        let bytes =
            base64_url_decode(encoded, encoded.len().saturating_mul(3) / 4).ok_or(INVALID)?;
        let input =
            parse_json(std::str::from_utf8(&bytes).map_err(|_| INVALID)?).map_err(|_| INVALID)?;
        let fields = input
            .as_object()
            .filter(|v| matches!(v.len(), 5 | 6))
            .ok_or(INVALID)?;
        if fields.iter().any(|(key, _)| {
            !matches!(
                key.as_str(),
                "action" | "mode" | "purpose" | "resource_id" | "ttl_seconds" | "request_key"
            )
        }) {
            return Err(INVALID);
        }
        let text = |key| input.get(key).and_then(Value::as_str).ok_or(INVALID);
        let action = text("action")?;
        if !matches!(action, "noop.marker" | "browser.session") {
            return Err(INVALID);
        }
        let mode = ConsumptionMode::parse(text("mode")?).ok_or(INVALID)?;
        let purpose = text("purpose")?;
        if purpose.len() > 512 || purpose.chars().any(forbidden_purpose_character) {
            return Err(INVALID);
        }
        let resource_id = text("resource_id")?;
        if !valid_event_identifier(resource_id) {
            return Err(INVALID);
        }
        let ttl_seconds = input
            .get("ttl_seconds")
            .and_then(Value::as_u64)
            .filter(|v| (1..=3600).contains(v))
            .ok_or(INVALID)?;
        let request_key = match input.get("request_key") {
            None => None,
            Some(Value::String(key))
                if is_valid_event_key(key)
                    && action == "browser.session"
                    && mode == ConsumptionMode::BrowserSession =>
            {
                Some(key.clone())
            }
            _ => return Err(INVALID),
        };
        Ok(Self {
            action: action.into(),
            mode,
            purpose: purpose.into(),
            resource_id: resource_id.into(),
            ttl_seconds,
            request_key,
        })
    }
    pub fn browser_binding(
        &self,
        owner: &WorkloadAuthorization,
        account: &str,
        resource: &BrowserResource,
    ) -> Result<BrowserRequestBinding, BrokerError> {
        let recipe = resource
            .recipe_fingerprint()
            .map_err(BrokerError::Configuration)?;
        let value = Value::Object(vec![
            ("node_id".into(), Value::String(owner.node_id.clone())),
            (
                "workload_id".into(),
                Value::String(owner.workload_id.clone()),
            ),
            ("unit".into(), Value::String(owner.unit.clone())),
            (
                "invocation_id".into(),
                Value::String(owner.invocation_id.clone()),
            ),
            ("account".into(), Value::String(account.into())),
            ("recipe_fingerprint".into(), Value::String(recipe.clone())),
            ("action".into(), Value::String(self.action.clone())),
            ("mode".into(), Value::String(self.mode.as_str().into())),
            ("purpose".into(), Value::String(self.purpose.clone())),
            (
                "resource_id".into(),
                Value::String(self.resource_id.clone()),
            ),
            ("ttl_seconds".into(), Value::Unsigned(self.ttl_seconds)),
        ]);
        let mut bytes = b"blindpass:browser-request:v1\0".to_vec();
        bytes.extend(canonicalize_value(&value).map_err(|_| INVALID)?);
        let digest = blindpass_core::custody::sha256(&bytes).map_err(|_| INVALID)?;
        Ok(BrowserRequestBinding {
            node_id: owner.node_id.clone(),
            unit: owner.unit.clone(),
            request_key: self.request_key.clone(),
            fingerprint: Some(digest.iter().map(|b| format!("{b:02x}")).collect()),
            resource_id: Some(self.resource_id.clone()),
            recipe_fingerprint: Some(recipe),
        })
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BrowserRequestBinding {
    pub node_id: String,
    pub unit: String,
    pub request_key: Option<String>,
    pub fingerprint: Option<String>,
    pub resource_id: Option<String>,
    pub recipe_fingerprint: Option<String>,
}
impl BrowserRequestBinding {
    pub fn withdrawal(owner: &WorkloadAuthorization, key: &str) -> Self {
        Self {
            node_id: owner.node_id.clone(),
            unit: owner.unit.clone(),
            request_key: Some(key.into()),
            fingerprint: None,
            resource_id: None,
            recipe_fingerprint: None,
        }
    }
    pub fn before_admission(&self) -> bool {
        self.fingerprint.is_none()
    }
    pub fn to_value(&self) -> Value {
        let optional = |value: &Option<String>| {
            value
                .as_ref()
                .map_or(Value::Null, |v| Value::String(v.clone()))
        };
        Value::Object(vec![
            ("node_id".into(), Value::String(self.node_id.clone())),
            ("unit".into(), Value::String(self.unit.clone())),
            ("request_key".into(), optional(&self.request_key)),
            ("fingerprint".into(), optional(&self.fingerprint)),
            ("resource_id".into(), optional(&self.resource_id)),
            (
                "recipe_fingerprint".into(),
                optional(&self.recipe_fingerprint),
            ),
        ])
    }
    pub fn from_value(value: &Value) -> Result<Self, BrokerError> {
        let fail = || BrokerError::Configuration("operation records are malformed");
        let fields = value
            .as_object()
            .filter(|v| v.len() == 6)
            .ok_or_else(fail)?;
        if fields.iter().any(|(key, _)| {
            !matches!(
                key.as_str(),
                "node_id"
                    | "unit"
                    | "request_key"
                    | "fingerprint"
                    | "resource_id"
                    | "recipe_fingerprint"
            )
        }) {
            return Err(fail());
        }
        let optional = |key| match value.get(key) {
            Some(Value::Null) => Ok(None),
            Some(Value::String(v)) => Ok(Some(v.clone())),
            _ => Err(fail()),
        };
        let node_id = value
            .get("node_id")
            .and_then(Value::as_str)
            .filter(|v| valid_event_identifier(v))
            .ok_or_else(fail)?
            .to_owned();
        let unit = value
            .get("unit")
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty() && v.len() <= 256 && v.bytes().all(|b| b.is_ascii_graphic()))
            .ok_or_else(fail)?
            .to_owned();
        let request_key = optional("request_key")?;
        let fingerprint = optional("fingerprint")?;
        let resource_id = optional("resource_id")?;
        let recipe_fingerprint = optional("recipe_fingerprint")?;
        let digest = |v: &str| {
            v.len() == 64
                && v.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if request_key.as_ref().is_some_and(|v| !is_valid_event_key(v)) {
            return Err(fail());
        }
        match (&fingerprint, &resource_id, &recipe_fingerprint) {
            (None, None, None) if request_key.is_some() => {}
            (Some(f), Some(r), Some(p)) if digest(f) && valid_event_identifier(r) && digest(p) => {}
            _ => return Err(fail()),
        }
        Ok(Self {
            node_id,
            unit,
            request_key,
            fingerprint,
            resource_id,
            recipe_fingerprint,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn encode(source: &str) -> String {
        blindpass_core::signing::base64_url_encode(source.as_bytes())
    }
    const INPUT: &str = r#"{"action":"browser.session","mode":"browser_session","purpose":"read","resource_id":"report-primary","ttl_seconds":60,"request_key":"retry_0123456789abcdef"}"#;
    #[test]
    fn retry_input_rejects_bad_keys_fields_and_native_mode() {
        assert!(RequestInput::parse(&encode(INPUT)).is_ok());
        for bad in [
            INPUT.replace("retry_0123456789abcdef", "short"),
            INPUT.replace("retry_0123456789abcdef", "retry.invalid_012345"),
            INPUT
                .replace("browser.session", "noop.marker")
                .replace("browser_session", "file"),
            INPUT.replace("\"request_key\"", "\"caller_context\""),
            INPUT.replace("\"retry_0123456789abcdef\"", "null"),
            INPUT.replace("\"ttl_seconds\":60", "\"ttl_seconds\":0"),
            INPUT.replace("\"purpose\":\"read\"", "\"purpose\":\"read\\nreport\""),
            INPUT.replace(
                "\"ttl_seconds\":60",
                "\"ttl_seconds\":60,\"ttl_seconds\":60",
            ),
        ] {
            assert!(RequestInput::parse(&encode(&bad)).is_err());
        }
        assert!(RequestInput::parse(&"A".repeat(1537)).is_err());
    }
    #[test]
    fn retry_input_allows_original_maximum_metadata_within_frame_bound() {
        let source = INPUT
            .replace("\"read\"", &format!("\"{}\"", "é".repeat(256)))
            .replace("retry_0123456789abcdef", &"k".repeat(128));
        let encoded = encode(&source);
        assert!(encoded.len() <= 1536);
        assert!(RequestInput::parse(&encoded).is_ok());
        let over = source.replace(&"é".repeat(256), &"é".repeat(257));
        assert!(RequestInput::parse(&encode(&over)).is_err());
    }
    fn purpose_input(purpose: &str) -> String {
        // Escape everything outside printable ASCII so the control and format
        // characters travel exactly as a client would JSON-encode them.
        let mut escaped = String::new();
        for c in purpose.chars() {
            if c == '"' || c == '\\' {
                escaped.push('\\');
                escaped.push(c);
            } else if c.is_ascii_graphic() || c == ' ' {
                escaped.push(c);
            } else {
                let mut units = [0_u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    escaped.push_str(&format!("\\u{unit:04x}"));
                }
            }
        }
        INPUT.replace(
            "\"purpose\":\"read\"",
            &format!("\"purpose\":\"{escaped}\""),
        )
    }
    fn purpose_accepted(purpose: &str) -> bool {
        RequestInput::parse(&encode(&purpose_input(purpose))).is_ok()
    }
    #[test]
    fn purpose_rejects_every_unicode_control_character() {
        // C0 including TAB and ESC, DEL, the whole C1 block (including NEL),
        // and the original CR/LF/NUL cases.
        for code in (0x00_u32..=0x1f).chain(0x7f..=0x9f) {
            let c = char::from_u32(code).unwrap();
            assert!(c.is_control());
            assert!(
                !purpose_accepted(&format!("read{c}report")),
                "U+{code:04X} must be rejected"
            );
        }
        assert!(!purpose_accepted("\u{0085}"));
        assert!(!purpose_accepted("trailing\t"));
    }
    #[test]
    fn purpose_rejects_invisible_format_and_bidirectional_characters() {
        let mut forbidden = vec![0x00AD, 0x061C, 0xFEFF];
        forbidden.extend(0x200B..=0x200F);
        forbidden.extend(0x2028..=0x2029);
        forbidden.extend(0x202A..=0x202E);
        forbidden.extend(0x2060..=0x2064);
        forbidden.extend(0x2066..=0x2069);
        for code in forbidden {
            let c = char::from_u32(code).unwrap();
            for purpose in [
                format!("{c}"),
                format!("read{c}report"),
                format!("report{c}"),
            ] {
                assert!(!purpose_accepted(&purpose), "U+{code:04X} must be rejected");
            }
        }
    }
    #[test]
    fn purpose_rejects_a_bidi_override_that_would_disguise_text() {
        assert!(!purpose_accepted("approve \u{202E}txt.exe"));
        assert!(!purpose_accepted("\u{2066}isolated\u{2069}"));
        assert!(!purpose_accepted("zero\u{200B}width"));
    }
    #[test]
    fn purpose_keeps_ordinary_international_text_and_the_length_limit() {
        for purpose in [
            "read report",
            "Lesen Sie den Bericht für März",
            "报告 を読む",
            "résumé, naïve: 100% (ok) - 'quoted' \"text\"",
            "emoji \u{1F600}",
            // Neighbours of the forbidden ranges are ordinary characters.
            "\u{00AC}\u{00AE}",
            "\u{200A}\u{2010}\u{2027}\u{202F}\u{205F}\u{FEFE}",
        ] {
            assert!(purpose_accepted(purpose), "{purpose:?} must stay valid");
        }
        assert!(purpose_accepted(&"a".repeat(512)));
        assert!(!purpose_accepted(&"a".repeat(513)));
    }
}
