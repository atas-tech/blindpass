// SPDX-License-Identifier: AGPL-3.0-only

use crate::MAX_FRAME_BYTES;
use crate::identity::WorkloadRequest;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoaderRequest {
    pub claimed_unit: String,
    pub credential_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    Empty,
    TooLarge,
    InvalidUtf8,
    InvalidFrame,
    InvalidField,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "empty_frame",
            Self::TooLarge => "frame_too_large",
            Self::InvalidUtf8 => "invalid_utf8",
            Self::InvalidFrame => "invalid_frame",
            Self::InvalidField => "invalid_field",
        })
    }
}

impl std::error::Error for ProtocolError {}

pub fn parse_loader_request(frame: &[u8]) -> Result<LoaderRequest, ProtocolError> {
    let fields = parse_fields(frame)?;
    if fields.len() != 3 || fields[0] != "LOAD" {
        return Err(ProtocolError::InvalidFrame);
    }
    validate_field(fields[1])?;
    validate_field(fields[2])?;
    Ok(LoaderRequest {
        claimed_unit: fields[1].to_owned(),
        credential_name: fields[2].to_owned(),
    })
}

pub fn parse_workload_request(frame: &[u8]) -> Result<WorkloadRequest, ProtocolError> {
    let fields = parse_fields(frame)?;
    if fields.len() != 6 || fields[0] != "WORK" {
        return Err(ProtocolError::InvalidFrame);
    }
    for field in &fields[1..5] {
        validate_field(field)?;
    }
    validate_operation(fields[5])?;
    Ok(WorkloadRequest {
        node_id: fields[1].to_owned(),
        workload_id: fields[2].to_owned(),
        claimed_unit: fields[3].to_owned(),
        claimed_invocation_id: fields[4].to_owned(),
        operation: fields[5].to_owned(),
    })
}

pub fn error_frame(code: &str) -> Vec<u8> {
    let mut response = b"ERR ".to_vec();
    response.extend_from_slice(code.as_bytes());
    response.push(b'\n');
    response
}

pub fn workload_ok(request: &WorkloadRequest) -> Vec<u8> {
    format!("OK {} {}\n", request.workload_id, request.operation).into_bytes()
}

fn parse_fields(frame: &[u8]) -> Result<Vec<&str>, ProtocolError> {
    if frame.is_empty() {
        return Err(ProtocolError::Empty);
    }
    if frame.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::TooLarge);
    }
    let text = std::str::from_utf8(frame).map_err(|_| ProtocolError::InvalidUtf8)?;
    let text = text.strip_suffix('\n').ok_or(ProtocolError::InvalidFrame)?;
    if text.is_empty() || text.contains(['\r', '\n']) {
        return Err(ProtocolError::InvalidFrame);
    }
    Ok(text.split(' ').collect())
}

fn validate_field(field: &str) -> Result<(), ProtocolError> {
    if field.is_empty() || field.len() > 256 || field.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(ProtocolError::InvalidField);
    }
    Ok(())
}

fn validate_operation(field: &str) -> Result<(), ProtocolError> {
    if field.is_empty()
        || field.len() > 2_048
        || field
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(ProtocolError::InvalidField);
    }
    if let Some(event_key) = field
        .strip_prefix(STATUS_OPERATION_PREFIX)
        .or_else(|| field.strip_prefix(CANCEL_OPERATION_PREFIX))
        .or_else(|| field.strip_prefix(CANCEL_KEY_OPERATION_PREFIX))
        && !is_valid_event_key(event_key)
    {
        return Err(ProtocolError::InvalidField);
    }
    Ok(())
}

/// Operation prefix for a workload asking about one of its own operation
/// requests: `status:<event_key>`.
pub const STATUS_OPERATION_PREFIX: &str = "status:";

/// Stop the browser request owned by this workload invocation.
pub const CANCEL_OPERATION_PREFIX: &str = "cancel:";

/// Stop a browser retry key, including before its request is admitted.
pub const CANCEL_KEY_OPERATION_PREFIX: &str = "cancel-key:";

/// Broker event keys are opaque, 16 to 128 bytes of `[A-Za-z0-9_-]`.
#[must_use]
pub fn is_valid_event_key(value: &str) -> bool {
    (16..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::{ProtocolError, parse_loader_request, parse_workload_request};

    #[test]
    fn parser_accepts_only_bounded_single_line_frames() {
        assert_eq!(
            parse_loader_request(b"LOAD backup.service api-key\n")
                .unwrap()
                .claimed_unit,
            "backup.service"
        );
        assert_eq!(
            parse_workload_request(b"WORK node-a workload-a agent.service inv-a health\n")
                .unwrap()
                .operation,
            "health"
        );
        assert_eq!(
            parse_workload_request(
                b"WORK node-a workload-a agent.service inv-a account:root health\n"
            ),
            Err(ProtocolError::InvalidFrame),
            "the workload protocol does not accept a caller-provided account claim"
        );
        assert_eq!(
            parse_loader_request(b"LOAD backup.service api-key"),
            Err(ProtocolError::InvalidFrame)
        );
        assert_eq!(
            parse_loader_request(b"LOAD backup.service api-key\n\n"),
            Err(ProtocolError::InvalidFrame)
        );
        let request_payload = format!(
            "WORK node-a workload-a agent.service inv-a request:{}\n",
            "A".repeat(1_800)
        );
        assert!(parse_workload_request(request_payload.as_bytes()).is_ok());
        let oversized_payload = format!(
            "WORK node-a workload-a agent.service inv-a request:{}\n",
            "A".repeat(2_049)
        );
        assert_eq!(
            parse_workload_request(oversized_payload.as_bytes()),
            Err(ProtocolError::InvalidField)
        );
    }

    #[test]
    fn status_queries_name_one_broker_event_key() {
        let request = parse_workload_request(
            b"WORK node-a workload-a agent.service inv-a status:event_0123456789abcdef-_\n",
        )
        .unwrap();
        assert_eq!(request.operation, "status:event_0123456789abcdef-_");
        for invalid in [
            "status:",
            "status:short",
            "status:event_with.dot_0123456",
            "status:event:0123456789abcdef",
        ] {
            let frame = format!("WORK node-a workload-a agent.service inv-a {invalid}\n");
            assert_eq!(
                parse_workload_request(frame.as_bytes()),
                Err(ProtocolError::InvalidField),
                "{invalid}"
            );
        }
        let long = format!(
            "WORK node-a workload-a agent.service inv-a status:{}\n",
            "a".repeat(129)
        );
        assert_eq!(
            parse_workload_request(long.as_bytes()),
            Err(ProtocolError::InvalidField)
        );
    }

    #[test]
    fn retry_key_cancellation_uses_bounded_opaque_key() {
        assert!(
            parse_workload_request(
                b"WORK node-a workload-a agent.service inv-a cancel-key:retry_0123456789abcdef\n"
            )
            .is_ok()
        );
        for key in [
            "",
            "short",
            "retry.with.dot_012345",
            "retry:0123456789abcdef",
        ] {
            let frame = format!("WORK node-a workload-a agent.service inv-a cancel-key:{key}\n");
            assert_eq!(
                parse_workload_request(frame.as_bytes()),
                Err(ProtocolError::InvalidField)
            );
        }
    }

    #[test]
    fn cancellation_queries_name_one_broker_event_key() {
        assert!(
            parse_workload_request(
                b"WORK node-a workload-a agent.service inv-a cancel:event_0123456789abcdef-_\n"
            )
            .is_ok()
        );
        for invalid in [
            "cancel:",
            "cancel:short",
            "cancel:event_with.dot_0123456",
            "cancel:event:0123456789abcdef",
        ] {
            let frame = format!("WORK node-a workload-a agent.service inv-a {invalid}\n");
            assert_eq!(
                parse_workload_request(frame.as_bytes()),
                Err(ProtocolError::InvalidField)
            );
        }
    }
}
