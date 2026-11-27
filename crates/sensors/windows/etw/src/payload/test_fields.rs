//! An in-memory [`PayloadFields`] for the decoders' and the registry key table's tests.

use std::collections::HashMap;

use super::PayloadFields;

/// A field value with its ETW type: reading it as another type gives `None`, as `Parser`'s
/// size check does.
#[derive(Debug, Clone)]
pub(crate) enum Value {
    Text(String),
    U16(u16),
    U32(u32),
    Bytes(Vec<u8>),
    Pointer(u64),
}

#[derive(Debug, Default)]
pub(crate) struct Fields(pub(crate) HashMap<&'static str, Value>);

impl Fields {
    pub(crate) fn of(fields: &[(&'static str, Value)]) -> Self {
        Self(fields.iter().cloned().collect())
    }
}

impl PayloadFields for Fields {
    fn text(&self, name: &str) -> Option<String> {
        match self.0.get(name)? {
            Value::Text(text) => Some(text.clone()),
            _ => None,
        }
    }

    fn u16(&self, name: &str) -> Option<u16> {
        match self.0.get(name)? {
            Value::U16(value) => Some(*value),
            _ => None,
        }
    }

    fn u32(&self, name: &str) -> Option<u32> {
        match self.0.get(name)? {
            Value::U32(value) => Some(*value),
            _ => None,
        }
    }

    fn bytes(&self, name: &str) -> Option<Vec<u8>> {
        match self.0.get(name)? {
            Value::Bytes(bytes) => Some(bytes.clone()),
            _ => None,
        }
    }

    fn pointer(&self, name: &str) -> Option<u64> {
        match self.0.get(name)? {
            Value::Pointer(pointer) => Some(*pointer),
            _ => None,
        }
    }
}

pub(crate) fn text_value(text: &str) -> Value {
    Value::Text(text.to_string())
}

pub(crate) fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}
