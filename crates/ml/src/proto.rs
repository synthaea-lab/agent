//! Minimal protobuf wire-format reader — just enough to walk an ONNX `ModelProto`
//! and pull tree structure out of `TreeEnsembleRegressor` nodes (`forest` module).
//!
//! Deliberately not a protobuf library: the agent parses model files from the update
//! channel, so the parsing surface stays small, allocation-light, and fully bounded.
//! Unknown fields are skipped by wire type, exactly as protobuf requires.

use crate::forest::ParseError;

/// Protobuf wire types (the subset that exists).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Wire {
    Varint,
    Fixed64,
    Len,
    Fixed32,
}

pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    pub(crate) fn done(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn byte(&mut self) -> Result<u8, ParseError> {
        let b = *self.buf.get(self.pos).ok_or(ParseError::Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    pub(crate) fn varint(&mut self) -> Result<u64, ParseError> {
        let mut value: u64 = 0;
        for shift in (0..64).step_by(7) {
            let b = self.byte()?;
            value |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(ParseError::Malformed("varint longer than 10 bytes"))
    }

    /// Reads a field tag: (field number, wire type).
    pub(crate) fn tag(&mut self) -> Result<(u64, Wire), ParseError> {
        let key = self.varint()?;
        let wire = match key & 0x7 {
            0 => Wire::Varint,
            1 => Wire::Fixed64,
            2 => Wire::Len,
            5 => Wire::Fixed32,
            _ => return Err(ParseError::Malformed("unknown wire type")),
        };
        Ok((key >> 3, wire))
    }

    /// Reads a length-delimited payload.
    pub(crate) fn bytes(&mut self) -> Result<&'a [u8], ParseError> {
        let len = usize::try_from(self.varint()?).map_err(|_| ParseError::Truncated)?;
        let end = self.pos.checked_add(len).ok_or(ParseError::Truncated)?;
        let slice = self.buf.get(self.pos..end).ok_or(ParseError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    pub(crate) fn skip(&mut self, wire: Wire) -> Result<(), ParseError> {
        match wire {
            Wire::Varint => {
                self.varint()?;
            }
            Wire::Fixed64 => {
                self.pos = self.pos.checked_add(8).ok_or(ParseError::Truncated)?;
                if self.pos > self.buf.len() {
                    return Err(ParseError::Truncated);
                }
            }
            Wire::Len => {
                self.bytes()?;
            }
            Wire::Fixed32 => {
                self.pos = self.pos.checked_add(4).ok_or(ParseError::Truncated)?;
                if self.pos > self.buf.len() {
                    return Err(ParseError::Truncated);
                }
            }
        }
        Ok(())
    }
}

/// Repeated int64: accepts both packed (`Len` of varints) and unpacked (`Varint`)
/// encodings, as protobuf parsers must.
pub(crate) fn read_i64s(
    out: &mut Vec<i64>,
    reader: &mut Reader<'_>,
    wire: Wire,
) -> Result<(), ParseError> {
    match wire {
        Wire::Len => {
            let mut inner = Reader::new(reader.bytes()?);
            while !inner.done() {
                out.push(inner.varint()? as i64);
            }
            Ok(())
        }
        Wire::Varint => {
            out.push(reader.varint()? as i64);
            Ok(())
        }
        _ => Err(ParseError::Malformed(
            "int64 field with non-varint wire type",
        )),
    }
}

/// Repeated float: accepts packed (`Len` of fixed32) and unpacked (`Fixed32`).
pub(crate) fn read_f32s(
    out: &mut Vec<f32>,
    reader: &mut Reader<'_>,
    wire: Wire,
) -> Result<(), ParseError> {
    match wire {
        Wire::Len => {
            let payload = reader.bytes()?;
            if payload.len() % 4 != 0 {
                return Err(ParseError::Malformed("packed float payload not 4-aligned"));
            }
            out.extend(
                payload
                    .chunks_exact(4)
                    .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]])),
            );
            Ok(())
        }
        Wire::Fixed32 => {
            let end = 4usize;
            let mut inner = [0u8; 4];
            let slice = reader
                .buf
                .get(reader.pos..reader.pos + end)
                .ok_or(ParseError::Truncated)?;
            inner.copy_from_slice(slice);
            reader.pos += end;
            out.push(f32::from_le_bytes(inner));
            Ok(())
        }
        _ => Err(ParseError::Malformed(
            "float field with non-fixed32 wire type",
        )),
    }
}
