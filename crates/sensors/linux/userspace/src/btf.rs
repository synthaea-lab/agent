//! Small, bounds-checked reader for the kernel BTF struct-member offsets used by
//! raw scheduler tracepoints. Aya loads BTF for verification, but its public API
//! does not expose struct members for runtime field lookup.

use std::{fs, path::Path};

const BTF_HEADER_LEN: usize = 24;
const BTF_KIND_INT: u32 = 1;
const BTF_KIND_ARRAY: u32 = 3;
const BTF_KIND_STRUCT: u32 = 4;
const BTF_KIND_UNION: u32 = 5;
const BTF_KIND_ENUM: u32 = 6;
const BTF_KIND_FUNC_PROTO: u32 = 13;
const BTF_KIND_VAR: u32 = 14;
const BTF_KIND_DATASEC: u32 = 15;
const BTF_KIND_DECL_TAG: u32 = 17;
const BTF_KIND_ENUM64: u32 = 19;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Endianness {
    Little,
    Big,
}

/// Byte offsets needed to interpret raw `sched_process_*` tracepoint arguments.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SchedulerFieldOffsets {
    pub(crate) task_pid: u32,
    pub(crate) task_comm: u32,
    pub(crate) binprm_filename: u32,
    pub(crate) syscall_args: [u32; 6],
}

/// Reads and parses `/sys/kernel/btf/vmlinux` for the scheduler probe fields.
pub(crate) fn read_scheduler_field_offsets()
-> Result<SchedulerFieldOffsets, Box<dyn std::error::Error + Send + Sync>> {
    parse_scheduler_field_offsets(&fs::read(Path::new("/sys/kernel/btf/vmlinux"))?)
        .map_err(|e| format!("invalid kernel BTF: {e}").into())
}

fn parse_scheduler_field_offsets(data: &[u8]) -> Result<SchedulerFieldOffsets, &'static str> {
    if data.len() < BTF_HEADER_LEN {
        return Err("truncated header");
    }

    let endianness = match data.get(..2) {
        Some([0x9f, 0xeb]) => Endianness::Little,
        Some([0xeb, 0x9f]) => Endianness::Big,
        _ => return Err("invalid magic"),
    };
    if data[2] != 1 {
        return Err("unsupported version");
    }

    let hdr_len = read_u32(data, 4, endianness)? as usize;
    let type_off = read_u32(data, 8, endianness)? as usize;
    let type_len = read_u32(data, 12, endianness)? as usize;
    let str_off = read_u32(data, 16, endianness)? as usize;
    let str_len = read_u32(data, 20, endianness)? as usize;
    if hdr_len < BTF_HEADER_LEN {
        return Err("header length is too short");
    }

    let type_start = hdr_len
        .checked_add(type_off)
        .ok_or("type offset overflow")?;
    let type_end = type_start
        .checked_add(type_len)
        .ok_or("type length overflow")?;
    let str_start = hdr_len
        .checked_add(str_off)
        .ok_or("string offset overflow")?;
    let str_end = str_start
        .checked_add(str_len)
        .ok_or("string length overflow")?;
    if type_end > data.len() || str_end > data.len() || str_start > str_end {
        return Err("type or string section is out of bounds");
    }
    let strings = &data[str_start..str_end];

    let mut task_pid = None;
    let mut task_comm = None;
    let mut binprm_filename = None;
    let mut syscall_args = [None; 6];
    let mut cursor = type_start;
    while cursor < type_end {
        if cursor.checked_add(12).is_none_or(|end| end > type_end) {
            return Err("truncated type record");
        }
        let name_off = read_u32(data, cursor, endianness)?;
        let info = read_u32(data, cursor + 4, endianness)?;
        let kind = (info >> 24) & 0x1f;
        let vlen = (info & 0xffff) as usize;
        let _size_or_type = read_u32(data, cursor + 8, endianness)?;
        let extra_len = type_extra_len(kind, vlen)?;
        let extra_start = cursor + 12;
        let record_end = extra_start
            .checked_add(extra_len)
            .ok_or("type record length overflow")?;
        if record_end > type_end {
            return Err("type payload is out of bounds");
        }

        if kind == BTF_KIND_STRUCT
            && matches_string(strings, name_off, b"task_struct")?
            && (task_pid.is_none() || task_comm.is_none())
        {
            for member_index in 0..vlen {
                let member = extra_start + member_index * 12;
                let member_name = read_u32(data, member, endianness)?;
                if matches_string(strings, member_name, b"pid")? {
                    task_pid = Some(member_byte_offset(data, member + 8, info, endianness)?);
                } else if matches_string(strings, member_name, b"comm")? {
                    task_comm = Some(member_byte_offset(data, member + 8, info, endianness)?);
                }
            }
        } else if kind == BTF_KIND_STRUCT
            && matches_string(strings, name_off, b"linux_binprm")?
            && binprm_filename.is_none()
        {
            for member_index in 0..vlen {
                let member = extra_start + member_index * 12;
                let member_name = read_u32(data, member, endianness)?;
                if matches_string(strings, member_name, b"filename")? {
                    binprm_filename = Some(member_byte_offset(data, member + 8, info, endianness)?);
                }
            }
        } else if kind == BTF_KIND_STRUCT
            && matches_string(strings, name_off, b"pt_regs")?
            && syscall_args.iter().any(Option::is_none)
        {
            for member_index in 0..vlen {
                let member = extra_start + member_index * 12;
                let member_name = read_u32(data, member, endianness)?;

                #[cfg(target_arch = "x86_64")]
                for (index, expected) in [
                    b"di".as_slice(),
                    b"si".as_slice(),
                    b"dx".as_slice(),
                    b"r10".as_slice(),
                    b"r8".as_slice(),
                    b"r9".as_slice(),
                ]
                .iter()
                .enumerate()
                {
                    if matches_string(strings, member_name, expected)? {
                        syscall_args[index] =
                            Some(member_byte_offset(data, member + 8, info, endianness)?);
                    }
                }

                #[cfg(target_arch = "x86")]
                for (index, expected) in [
                    b"bx".as_slice(),
                    b"cx".as_slice(),
                    b"dx".as_slice(),
                    b"si".as_slice(),
                    b"di".as_slice(),
                    b"bp".as_slice(),
                ]
                .iter()
                .enumerate()
                {
                    if matches_string(strings, member_name, expected)? {
                        syscall_args[index] =
                            Some(member_byte_offset(data, member + 8, info, endianness)?);
                    }
                }

                #[cfg(target_arch = "aarch64")]
                if matches_string(strings, member_name, b"regs")? {
                    let member_offset = member_byte_offset(data, member + 8, info, endianness)?;
                    for (index, slot) in syscall_args.iter_mut().enumerate() {
                        *slot = Some(member_offset + (index as u32 * 8));
                    }
                }
            }
        }

        cursor = record_end;
    }
    if cursor != type_end {
        return Err("type section does not end on a record boundary");
    }

    Ok(SchedulerFieldOffsets {
        task_pid: task_pid.ok_or("task_struct.pid is missing")?,
        task_comm: task_comm.ok_or("task_struct.comm is missing")?,
        binprm_filename: binprm_filename.ok_or("linux_binprm.filename is missing")?,
        syscall_args: syscall_arg_offsets(syscall_args)?,
    })
}

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
fn syscall_arg_offsets(offsets: [Option<u32>; 6]) -> Result<[u32; 6], &'static str> {
    let mut result = [0; 6];
    for (index, offset) in offsets.into_iter().enumerate() {
        result[index] = offset.ok_or("pt_regs syscall argument register is missing")?;
    }
    Ok(result)
}

#[cfg(target_arch = "aarch64")]
fn syscall_arg_offsets(offsets: [Option<u32>; 6]) -> Result<[u32; 6], &'static str> {
    let mut result = [0; 6];
    for (index, offset) in offsets.into_iter().enumerate() {
        result[index] = offset.ok_or("pt_regs.regs is missing")?;
    }
    Ok(result)
}

fn type_extra_len(kind: u32, vlen: usize) -> Result<usize, &'static str> {
    match kind {
        BTF_KIND_INT | BTF_KIND_VAR | BTF_KIND_DECL_TAG => Ok(4),
        BTF_KIND_ARRAY => Ok(12),
        BTF_KIND_STRUCT | BTF_KIND_UNION | BTF_KIND_DATASEC | BTF_KIND_ENUM64 => {
            vlen.checked_mul(12).ok_or("type member count overflow")
        }
        BTF_KIND_ENUM => vlen.checked_mul(8).ok_or("enum member count overflow"),
        BTF_KIND_FUNC_PROTO => vlen
            .checked_mul(8)
            .ok_or("function parameter count overflow"),
        // PTR, FWD, TYPEDEF, VOLATILE, CONST, RESTRICT, FUNC, FLOAT and TYPE_TAG.
        0 | 2 | 7..=12 | 16 | 18 => Ok(0),
        _ => Err("unknown type kind"),
    }
}

fn member_byte_offset(
    data: &[u8],
    offset_field: usize,
    info: u32,
    endianness: Endianness,
) -> Result<u32, &'static str> {
    let bit_offset = read_u32(data, offset_field, endianness)?;
    let bitfield_width = if info >> 31 != 0 { bit_offset >> 24 } else { 0 };
    let bit_offset = bit_offset & 0x00ff_ffff;
    if bitfield_width != 0 || bit_offset % 8 != 0 {
        return Err("required member uses a bitfield or unaligned offset");
    }
    Ok(bit_offset / 8)
}

fn matches_string(strings: &[u8], offset: u32, expected: &[u8]) -> Result<bool, &'static str> {
    let start = offset as usize;
    if start >= strings.len() {
        return Err("string offset is out of bounds");
    }
    let tail = &strings[start..];
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or("unterminated string")?;
    Ok(&tail[..end] == expected)
}

fn read_u32(data: &[u8], offset: usize, endianness: Endianness) -> Result<u32, &'static str> {
    let bytes: [u8; 4] = data
        .get(offset..offset.checked_add(4).ok_or("offset overflow")?)
        .ok_or("truncated integer")?
        .try_into()
        .map_err(|_| "truncated integer")?;
    Ok(match endianness {
        Endianness::Little => u32::from_le_bytes(bytes),
        Endianness::Big => u32::from_be_bytes(bytes),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_btf() -> Vec<u8> {
        let strings =
            b"\0task_struct\0pid\0comm\0linux_binprm\0filename\0pt_regs\0di\0si\0dx\0r10\0r8\0r9\0";
        let offset = |needle: &[u8]| {
            strings
                .windows(needle.len() + 1)
                .position(|window| window == [needle, &[0]].concat())
                .expect("string exists") as u32
        };
        let mut types = Vec::new();
        let mut push_u32 = |value: u32| types.extend_from_slice(&value.to_le_bytes());

        // int (id 1)
        push_u32(0);
        push_u32(BTF_KIND_INT << 24);
        push_u32(4);
        push_u32(32);

        // struct task_struct { int pid; int comm; }
        push_u32(offset(b"task_struct"));
        push_u32((BTF_KIND_STRUCT << 24) | 2);
        push_u32(32);
        for (name, bit_offset) in [(b"pid".as_slice(), 24), (b"comm".as_slice(), 64)] {
            push_u32(offset(name));
            push_u32(1);
            push_u32(bit_offset);
        }

        // struct linux_binprm { int filename; }
        push_u32(offset(b"linux_binprm"));
        push_u32((BTF_KIND_STRUCT << 24) | 1);
        push_u32(16);
        push_u32(offset(b"filename"));
        push_u32(1);
        push_u32(80);

        // struct pt_regs { syscall argument registers }
        push_u32(offset(b"pt_regs"));
        push_u32((BTF_KIND_STRUCT << 24) | 6);
        push_u32(168);
        for (name, bit_offset) in [
            (b"di".as_slice(), 112 * 8),
            (b"si".as_slice(), 104 * 8),
            (b"dx".as_slice(), 96 * 8),
            (b"r10".as_slice(), 56 * 8),
            (b"r8".as_slice(), 72 * 8),
            (b"r9".as_slice(), 64 * 8),
        ] {
            push_u32(offset(name));
            push_u32(1);
            push_u32(bit_offset);
        }

        let mut btf = vec![0x9f, 0xeb, 1, 0];
        for value in [
            BTF_HEADER_LEN as u32,
            0,
            types.len() as u32,
            types.len() as u32,
            strings.len() as u32,
        ] {
            btf.extend_from_slice(&value.to_le_bytes());
        }
        btf.extend(types);
        btf.extend_from_slice(strings);
        btf
    }

    #[test]
    fn parses_scheduler_offsets_from_btf() {
        assert_eq!(
            parse_scheduler_field_offsets(&minimal_btf()).unwrap(),
            SchedulerFieldOffsets {
                task_pid: 3,
                task_comm: 8,
                binprm_filename: 10,
                syscall_args: [112, 104, 96, 56, 72, 64],
            }
        );
    }

    #[test]
    fn rejects_truncated_btf() {
        assert!(parse_scheduler_field_offsets(&[0x9f, 0xeb, 1, 0]).is_err());
    }

    #[test]
    fn parses_running_kernel_btf_when_available() {
        let path = Path::new("/sys/kernel/btf/vmlinux");
        if path.exists() {
            let offsets = read_scheduler_field_offsets().expect("running kernel BTF parses");
            assert!(offsets.task_pid < 4096);
            assert!(offsets.task_comm < 4096);
            assert!(offsets.binprm_filename < 4096);
            assert!(offsets.syscall_args.iter().all(|offset| *offset < 4096));
        }
    }
}
