// SPDX-License-Identifier: AGPL-3.0-only

//! A small canonical JSON subset for signed fleet documents.
//!
//! Fleet documents only use safe integer numbers. Rejecting decimals, unsafe
//! integers, duplicate properties and excessive nesting keeps signatures
//! stable without adding a JSON dependency to blindpass-core.

use std::collections::HashSet;
use std::fmt;

pub const MAX_CANONICAL_JSON_BYTES: usize = 1024 * 1024;
const MAX_DEPTH: usize = 64;
const MAX_VALUES: usize = 100_000;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalError {
    TooLarge,
    TooDeep,
    TooManyValues,
    InvalidJson,
    InvalidString,
    InvalidNumber,
    DuplicateProperty,
}

impl fmt::Display for CanonicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TooLarge => "canonical JSON exceeds the size limit",
            Self::TooDeep => "canonical JSON exceeds the nesting limit",
            Self::TooManyValues => "canonical JSON exceeds the value limit",
            Self::InvalidJson => "invalid JSON document",
            Self::InvalidString => "invalid JSON string",
            Self::InvalidNumber => "unsupported or unsafe JSON number",
            Self::DuplicateProperty => "duplicate JSON object property",
        })
    }
}

impl std::error::Error for CanonicalError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Null,
    Bool(bool),
    Integer(i64),
    Unsigned(u64),
    String(String),
    Array(Vec<Self>),
    Object(Vec<(String, Self)>),
}

impl Value {
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Object(fields) => fields
                .iter()
                .find_map(|(candidate, value)| (candidate == key).then_some(value)),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Unsigned(value) => Some(*value),
            Self::Integer(value) => u64::try_from(*value).ok(),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_object(&self) -> Option<&[(String, Self)]> {
        match self {
            Self::Object(fields) => Some(fields),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(values) => Some(values),
            _ => None,
        }
    }
}

/// Parse JSON, reject ambiguous or unsupported values, and emit canonical
/// UTF-8 JSON with object keys ordered by UTF-16 code units.
pub fn canonicalize_json(source: &str) -> Result<Vec<u8>, CanonicalError> {
    let value = parse_json(source)?;
    canonicalize_value(&value)
}

/// Parse a JSON value while enforcing the fleet protocol's ambiguity,
/// integer, size and depth limits.
pub fn parse_json(source: &str) -> Result<Value, CanonicalError> {
    if source.len() > MAX_CANONICAL_JSON_BYTES {
        return Err(CanonicalError::TooLarge);
    }
    let mut parser = Parser {
        source,
        offset: 0,
        values: 0,
    };
    let value = parser.value(0)?;
    parser.whitespace();
    if parser.offset != source.len() {
        return Err(CanonicalError::InvalidJson);
    }
    Ok(value)
}

/// Emit a value created by trusted code using the same canonical rules as the
/// parser. This also rejects duplicate keys in programmatically built values.
pub fn canonicalize_value(value: &Value) -> Result<Vec<u8>, CanonicalError> {
    let mut output = Vec::new();
    write_value(value, &mut output, 0)?;
    if output.len() > MAX_CANONICAL_JSON_BYTES {
        return Err(CanonicalError::TooLarge);
    }
    Ok(output)
}

fn write_value(value: &Value, output: &mut Vec<u8>, depth: usize) -> Result<(), CanonicalError> {
    if depth > MAX_DEPTH {
        return Err(CanonicalError::TooDeep);
    }
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Integer(value) => {
            if value.unsigned_abs() > MAX_SAFE_INTEGER {
                return Err(CanonicalError::InvalidNumber);
            }
            output.extend_from_slice(value.to_string().as_bytes());
        }
        Value::Unsigned(value) => {
            if *value > MAX_SAFE_INTEGER {
                return Err(CanonicalError::InvalidNumber);
            }
            output.extend_from_slice(value.to_string().as_bytes());
        }
        Value::String(value) => write_string(value, output),
        Value::Array(values) => {
            output.push(b'[');
            for (index, child) in values.iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                write_value(child, output, depth + 1)?;
            }
            output.push(b']');
        }
        Value::Object(fields) => {
            let mut ordered = fields.iter().collect::<Vec<_>>();
            ordered.sort_by(|left, right| utf16_cmp(&left.0, &right.0));
            output.push(b'{');
            let mut previous: Option<&str> = None;
            for (index, (key, child)) in ordered.iter().enumerate() {
                if previous.is_some_and(|candidate| candidate == key.as_str()) {
                    return Err(CanonicalError::DuplicateProperty);
                }
                if index > 0 {
                    output.push(b',');
                }
                write_string(key, output);
                output.push(b':');
                write_value(child, output, depth + 1)?;
                previous = Some(key.as_str());
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn utf16_cmp(left: &str, right: &str) -> std::cmp::Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

fn write_string(value: &str, output: &mut Vec<u8>) {
    output.push(b'"');
    for character in value.chars() {
        match character {
            '"' => output.extend_from_slice(b"\\\""),
            '\\' => output.extend_from_slice(b"\\\\"),
            '\u{0008}' => output.extend_from_slice(b"\\b"),
            '\u{0009}' => output.extend_from_slice(b"\\t"),
            '\u{000a}' => output.extend_from_slice(b"\\n"),
            '\u{000c}' => output.extend_from_slice(b"\\f"),
            '\u{000d}' => output.extend_from_slice(b"\\r"),
            character if character <= '\u{001f}' => {
                let escaped = format!("\\u{:04x}", u32::from(character));
                output.extend_from_slice(escaped.as_bytes());
            }
            character => {
                let mut bytes = [0; 4];
                output.extend_from_slice(character.encode_utf8(&mut bytes).as_bytes());
            }
        }
    }
    output.push(b'"');
}

struct Parser<'a> {
    source: &'a str,
    offset: usize,
    values: usize,
}

impl Parser<'_> {
    fn value(&mut self, depth: usize) -> Result<Value, CanonicalError> {
        if depth > MAX_DEPTH {
            return Err(CanonicalError::TooDeep);
        }
        self.values += 1;
        if self.values > MAX_VALUES {
            return Err(CanonicalError::TooManyValues);
        }
        self.whitespace();
        match self.peek() {
            Some(b'n') => {
                self.literal(b"null")?;
                Ok(Value::Null)
            }
            Some(b't') => {
                self.literal(b"true")?;
                Ok(Value::Bool(true))
            }
            Some(b'f') => {
                self.literal(b"false")?;
                Ok(Value::Bool(false))
            }
            Some(b'"') => self.string().map(Value::String),
            Some(b'[') => self.array(depth),
            Some(b'{') => self.object(depth),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(CanonicalError::InvalidJson),
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, CanonicalError> {
        self.offset += 1;
        self.whitespace();
        if self.consume(b']') {
            return Ok(Value::Array(Vec::new()));
        }
        let mut values = Vec::new();
        loop {
            values.push(self.value(depth + 1)?);
            self.whitespace();
            if self.consume(b']') {
                return Ok(Value::Array(values));
            }
            if !self.consume(b',') {
                return Err(CanonicalError::InvalidJson);
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, CanonicalError> {
        self.offset += 1;
        self.whitespace();
        if self.consume(b'}') {
            return Ok(Value::Object(Vec::new()));
        }
        let mut fields = Vec::new();
        let mut keys = HashSet::new();
        loop {
            self.whitespace();
            if self.peek() != Some(b'"') {
                return Err(CanonicalError::InvalidJson);
            }
            let key = self.string()?;
            if !keys.insert(key.clone()) {
                return Err(CanonicalError::DuplicateProperty);
            }
            self.whitespace();
            if !self.consume(b':') {
                return Err(CanonicalError::InvalidJson);
            }
            fields.push((key, self.value(depth + 1)?));
            self.whitespace();
            if self.consume(b'}') {
                return Ok(Value::Object(fields));
            }
            if !self.consume(b',') {
                return Err(CanonicalError::InvalidJson);
            }
        }
    }

    fn string(&mut self) -> Result<String, CanonicalError> {
        if !self.consume(b'"') {
            return Err(CanonicalError::InvalidString);
        }
        let mut result = String::new();
        loop {
            let Some(byte) = self.peek() else {
                return Err(CanonicalError::InvalidString);
            };
            match byte {
                b'"' => {
                    self.offset += 1;
                    return Ok(result);
                }
                b'\\' => {
                    self.offset += 1;
                    let escaped = self.peek().ok_or(CanonicalError::InvalidString)?;
                    self.offset += 1;
                    match escaped {
                        b'"' => result.push('"'),
                        b'\\' => result.push('\\'),
                        b'/' => result.push('/'),
                        b'b' => result.push('\u{0008}'),
                        b'f' => result.push('\u{000c}'),
                        b'n' => result.push('\n'),
                        b'r' => result.push('\r'),
                        b't' => result.push('\t'),
                        b'u' => {
                            let first = self.hex_quad()?;
                            let character = if (0xd800..=0xdbff).contains(&first) {
                                if !self.consume(b'\\') || !self.consume(b'u') {
                                    return Err(CanonicalError::InvalidString);
                                }
                                let second = self.hex_quad()?;
                                if !(0xdc00..=0xdfff).contains(&second) {
                                    return Err(CanonicalError::InvalidString);
                                }
                                let scalar = 0x1_0000
                                    + ((u32::from(first) - 0xd800) << 10)
                                    + (u32::from(second) - 0xdc00);
                                char::from_u32(scalar).ok_or(CanonicalError::InvalidString)?
                            } else {
                                if (0xdc00..=0xdfff).contains(&first) {
                                    return Err(CanonicalError::InvalidString);
                                }
                                char::from_u32(u32::from(first))
                                    .ok_or(CanonicalError::InvalidString)?
                            };
                            result.push(character);
                        }
                        _ => return Err(CanonicalError::InvalidString),
                    }
                }
                0x00..=0x1f => return Err(CanonicalError::InvalidString),
                0x20..=0x7f => {
                    result.push(char::from(byte));
                    self.offset += 1;
                }
                _ => {
                    let character = self.source[self.offset..]
                        .chars()
                        .next()
                        .ok_or(CanonicalError::InvalidString)?;
                    result.push(character);
                    self.offset += character.len_utf8();
                }
            }
        }
    }

    fn hex_quad(&mut self) -> Result<u16, CanonicalError> {
        if self.offset + 4 > self.source.len() {
            return Err(CanonicalError::InvalidString);
        }
        let mut value = 0_u16;
        for byte in &self.source.as_bytes()[self.offset..self.offset + 4] {
            value = (value << 4)
                | match byte {
                    b'0'..=b'9' => u16::from(*byte - b'0'),
                    b'a'..=b'f' => u16::from(*byte - b'a' + 10),
                    b'A'..=b'F' => u16::from(*byte - b'A' + 10),
                    _ => return Err(CanonicalError::InvalidString),
                };
        }
        self.offset += 4;
        Ok(value)
    }

    fn number(&mut self) -> Result<Value, CanonicalError> {
        let start = self.offset;
        let negative = self.consume(b'-');
        match self.peek() {
            Some(b'0') => {
                self.offset += 1;
                if self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                    return Err(CanonicalError::InvalidNumber);
                }
            }
            Some(b'1'..=b'9') => {
                self.offset += 1;
                while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                    self.offset += 1;
                }
            }
            _ => return Err(CanonicalError::InvalidNumber),
        }
        if self
            .peek()
            .is_some_and(|byte| matches!(byte, b'.' | b'e' | b'E'))
        {
            return Err(CanonicalError::InvalidNumber);
        }
        let raw = &self.source[start..self.offset];
        if negative {
            let value = raw
                .parse::<i64>()
                .map_err(|_| CanonicalError::InvalidNumber)?;
            if value.unsigned_abs() > MAX_SAFE_INTEGER {
                return Err(CanonicalError::InvalidNumber);
            }
            Ok(Value::Integer(value))
        } else {
            let value = raw
                .parse::<u64>()
                .map_err(|_| CanonicalError::InvalidNumber)?;
            if value > MAX_SAFE_INTEGER {
                return Err(CanonicalError::InvalidNumber);
            }
            Ok(Value::Unsigned(value))
        }
    }

    fn literal(&mut self, literal: &[u8]) -> Result<(), CanonicalError> {
        let end = self.offset + literal.len();
        if self.source.as_bytes().get(self.offset..end) != Some(literal) {
            return Err(CanonicalError::InvalidJson);
        }
        self.offset = end;
        Ok(())
    }

    fn whitespace(&mut self) {
        while self
            .peek()
            .is_some_and(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
        {
            self.offset += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.source.as_bytes().get(self.offset).copied()
    }

    fn consume(&mut self, expected: u8) -> bool {
        if self.peek() == Some(expected) {
            self.offset += 1;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CanonicalError, Value, canonicalize_json, canonicalize_value};

    #[test]
    fn canonicalizes_strings_numbers_and_object_order() {
        assert_eq!(
            canonicalize_json(r#" {"z":-0,"a":"line\n\u0001","c":true} "#).unwrap(),
            br#"{"a":"line\n\u0001","c":true,"z":0}"#
        );
    }

    #[test]
    fn object_keys_use_utf16_code_unit_order() {
        let canonical = canonicalize_json(r#"{"\uE000":1,"\uD800\uDC00":2}"#).unwrap();
        assert_eq!(canonical, "{\"𐀀\":2,\"\u{e000}\":1}".as_bytes());
    }

    #[test]
    fn duplicate_decoded_properties_are_rejected() {
        assert_eq!(
            canonicalize_json(r#"{"name":1,"\u006eame":2}"#),
            Err(CanonicalError::DuplicateProperty)
        );
        assert_eq!(
            canonicalize_value(&Value::Object(vec![
                ("same".to_owned(), Value::Null),
                ("same".to_owned(), Value::Bool(true)),
            ])),
            Err(CanonicalError::DuplicateProperty)
        );
    }

    #[test]
    fn rejects_fractional_unsafe_and_malformed_numbers() {
        for number in ["1.0", "1e2", "01", "9007199254740992", "-9007199254740992"] {
            assert_eq!(
                canonicalize_json(number),
                Err(CanonicalError::InvalidNumber)
            );
        }
    }

    #[test]
    fn rejects_invalid_surrogates_trailing_input_and_unescaped_controls() {
        assert_eq!(
            canonicalize_json(r#""\uD800""#),
            Err(CanonicalError::InvalidString)
        );
        assert_eq!(
            canonicalize_json("null true"),
            Err(CanonicalError::InvalidJson)
        );
        assert_eq!(
            canonicalize_json("\"line\nfeed\""),
            Err(CanonicalError::InvalidString)
        );
    }
}
