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
const BTF_KIND_FUNC: u32 = 12;
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
    pub(crate) syscall_nr: u32,
}

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
const SYSCALL_NR_FIELD: &[u8] = b"orig_ax";
#[cfg(target_arch = "aarch64")]
const SYSCALL_NR_FIELD: &[u8] = b"syscallno";

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
    let mut syscall_nr = None;
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
            && (syscall_args.iter().any(Option::is_none) || syscall_nr.is_none())
        {
            for member_index in 0..vlen {
                let member = extra_start + member_index * 12;
                let member_name = read_u32(data, member, endianness)?;

                if matches_string(strings, member_name, SYSCALL_NR_FIELD)? {
                    syscall_nr = Some(member_byte_offset(data, member + 8, info, endianness)?);
                }

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
        syscall_nr: syscall_nr.ok_or("pt_regs syscall number field is missing")?,
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

/// Byte offsets the `inode_setattr` LSM hook needs (#1044): where `struct iattr` keeps the
/// validity mask and the two times, and where a dentry keeps its parent and the name pointer of
/// its `d_name` (`d_name`'s offset plus `qstr.name`'s, so the probe does one read).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InodeSetattrOffsets {
    pub(crate) ia_valid: u32,
    pub(crate) ia_atime: u32,
    pub(crate) ia_mtime: u32,
    pub(crate) dentry_parent: u32,
    pub(crate) dentry_name_ptr: u32,
}

/// Reads `/sys/kernel/btf/vmlinux` for the `inode_setattr` hook's fields.
pub(crate) fn read_inode_setattr_offsets()
-> Result<InodeSetattrOffsets, Box<dyn std::error::Error + Send + Sync>> {
    parse_inode_setattr_offsets(&fs::read(Path::new("/sys/kernel/btf/vmlinux"))?)
        .map_err(|e| format!("invalid kernel BTF: {e}").into())
}

/// One type record of the BTF type section.
struct TypeRecord {
    kind: u32,
    name_off: u32,
    info: u32,
    /// `size` for a struct, the target `type` id for a typedef/const/volatile.
    size_or_type: u32,
    /// Where the record's trailing members start.
    extra_start: usize,
}

struct TypeTable<'a> {
    data: &'a [u8],
    endianness: Endianness,
    strings: &'a [u8],
    /// Type id `n` is `records[n - 1]` (id 0 is `void`).
    records: Vec<TypeRecord>,
}

fn parse_type_table(data: &[u8]) -> Result<TypeTable<'_>, &'static str> {
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
    let mut records = Vec::new();
    let mut cursor = type_start;
    while cursor < type_end {
        if cursor.checked_add(12).is_none_or(|end| end > type_end) {
            return Err("truncated type record");
        }
        let info = read_u32(data, cursor + 4, endianness)?;
        let kind = (info >> 24) & 0x1f;
        let vlen = (info & 0xffff) as usize;
        let extra_start = cursor + 12;
        let record_end = extra_start
            .checked_add(type_extra_len(kind, vlen)?)
            .ok_or("type record length overflow")?;
        if record_end > type_end {
            return Err("type payload is out of bounds");
        }
        records.push(TypeRecord {
            kind,
            name_off: read_u32(data, cursor, endianness)?,
            info,
            size_or_type: read_u32(data, cursor + 8, endianness)?,
            extra_start,
        });
        cursor = record_end;
    }
    Ok(TypeTable {
        data,
        endianness,
        strings: &data[str_start..str_end],
        records,
    })
}

impl TypeTable<'_> {
    /// Byte offset of `member` in the struct called `name`, looking inside anonymous
    /// structs and unions (`dentry.d_name` sits in one). The first struct of that name that
    /// has the member wins: BTF can carry several, a forward-declared one has no members.
    fn member_offset(&self, name: &[u8], member: &[u8]) -> Result<Option<u32>, &'static str> {
        for record in &self.records {
            if record.kind == BTF_KIND_STRUCT
                && matches_string(self.strings, record.name_off, name)?
                && let Some(offset) = self.find_member(record, member, 0)?
            {
                return Ok(Some(offset));
            }
        }
        Ok(None)
    }

    /// Parameter names of the kernel function `name` (a `FUNC` record pointing at a
    /// `FUNC_PROTO`), or `None` when BTF has no such function.
    fn function_params(&self, name: &[u8]) -> Result<Option<Vec<Vec<u8>>>, &'static str> {
        for record in &self.records {
            if record.kind != BTF_KIND_FUNC || !matches_string(self.strings, record.name_off, name)?
            {
                continue;
            }
            let proto = (record.size_or_type as usize)
                .checked_sub(1)
                .and_then(|id| self.records.get(id))
                .filter(|proto| proto.kind == BTF_KIND_FUNC_PROTO)
                .ok_or("function type is not a prototype")?;
            let mut params = Vec::new();
            for index in 0..(proto.info & 0xffff) as usize {
                let name_off = read_u32(self.data, proto.extra_start + index * 8, self.endianness)?;
                let start = name_off as usize;
                let tail = self
                    .strings
                    .get(start..)
                    .ok_or("string offset is out of bounds")?;
                let end = tail
                    .iter()
                    .position(|b| *b == 0)
                    .ok_or("unterminated string")?;
                params.push(tail[..end].to_vec());
            }
            return Ok(Some(params));
        }
        Ok(None)
    }

    fn find_member(
        &self,
        record: &TypeRecord,
        member: &[u8],
        depth: u32,
    ) -> Result<Option<u32>, &'static str> {
        // Anonymous nesting is one or two levels in practice; a cycle in a corrupt table
        // must not recurse forever.
        if depth > 4 {
            return Err("anonymous member nesting is too deep");
        }
        let vlen = (record.info & 0xffff) as usize;
        for index in 0..vlen {
            let at = record.extra_start + index * 12;
            let member_name = read_u32(self.data, at, self.endianness)?;
            let member_type = read_u32(self.data, at + 4, self.endianness)?;
            let offset = member_byte_offset(self.data, at + 8, record.info, self.endianness)?;
            if member_name == 0 {
                let inner = (member_type as usize)
                    .checked_sub(1)
                    .and_then(|id| self.records.get(id))
                    .filter(|inner| matches!(inner.kind, BTF_KIND_STRUCT | BTF_KIND_UNION));
                if let Some(inner) = inner
                    && let Some(found) = self.find_member(inner, member, depth + 1)?
                {
                    return Ok(Some(offset + found));
                }
            } else if matches_string(self.strings, member_name, member)? {
                return Ok(Some(offset));
            }
        }
        Ok(None)
    }
}

fn parse_inode_setattr_offsets(data: &[u8]) -> Result<InodeSetattrOffsets, &'static str> {
    let table = parse_type_table(data)?;
    // The probe reads the hook's arguments by position, for `(idmap, dentry, attr)` (kernel
    // 6.3 and later). Before that the first argument was the dentry: reading by this layout
    // there would take the wrong pointers, so the hook stays disabled unless the kernel's own
    // BTF says it has this shape.
    match table.function_params(b"bpf_lsm_inode_setattr")? {
        Some(params) if params == [b"idmap".to_vec(), b"dentry".to_vec(), b"attr".to_vec()] => {}
        Some(_) => return Err("inode_setattr hook arguments are not (idmap, dentry, attr)"),
        None => return Err("kernel has no BPF-LSM inode_setattr hook"),
    }
    let field = |strukt: &[u8], member: &[u8], missing: &'static str| {
        table.member_offset(strukt, member)?.ok_or(missing)
    };
    Ok(InodeSetattrOffsets {
        ia_valid: field(b"iattr", b"ia_valid", "iattr.ia_valid is missing")?,
        ia_atime: field(b"iattr", b"ia_atime", "iattr.ia_atime is missing")?,
        ia_mtime: field(b"iattr", b"ia_mtime", "iattr.ia_mtime is missing")?,
        dentry_parent: field(b"dentry", b"d_parent", "dentry.d_parent is missing")?,
        dentry_name_ptr: field(b"dentry", b"d_name", "dentry.d_name is missing")?
            + field(b"qstr", b"name", "qstr.name is missing")?,
    })
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

    type RegisterFixture = (&'static [(&'static [u8], u32)], (&'static [u8], u32));

    fn minimal_btf(include_syscall_nr: bool) -> Vec<u8> {
        #[cfg(target_arch = "x86_64")]
        let (registers, syscall_nr): RegisterFixture = (
            &[
                (b"di", 112 * 8),
                (b"si", 104 * 8),
                (b"dx", 96 * 8),
                (b"r10", 56 * 8),
                (b"r8", 72 * 8),
                (b"r9", 64 * 8),
            ],
            (b"orig_ax", 120 * 8),
        );
        #[cfg(target_arch = "x86")]
        let (registers, syscall_nr): RegisterFixture = (
            &[
                (b"bx", 0),
                (b"cx", 4 * 8),
                (b"dx", 8 * 8),
                (b"si", 12 * 8),
                (b"di", 16 * 8),
                (b"bp", 20 * 8),
            ],
            (b"orig_ax", 44 * 8),
        );
        #[cfg(target_arch = "aarch64")]
        // pt_regs has regs[31], sp, pc, pstate and orig_x0 before syscallno.
        let (registers, syscall_nr): RegisterFixture = (&[(b"regs", 0)], (b"syscallno", 280));
        let mut strings = b"\0task_struct\0pid\0comm\0linux_binprm\0filename\0pt_regs\0".to_vec();
        for (name, _) in registers {
            strings.extend_from_slice(name);
            strings.push(0);
        }
        if include_syscall_nr {
            strings.extend_from_slice(syscall_nr.0);
            strings.push(0);
        }
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
        push_u32(
            (BTF_KIND_STRUCT << 24) | (registers.len() as u32 + u32::from(include_syscall_nr)),
        );
        #[cfg(target_arch = "x86_64")]
        push_u32(168);
        #[cfg(target_arch = "x86")]
        push_u32(48);
        #[cfg(target_arch = "aarch64")]
        push_u32(320);
        for (name, bit_offset) in registers
            .iter()
            .copied()
            .chain(include_syscall_nr.then_some(syscall_nr))
        {
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
        btf.extend_from_slice(&strings);
        btf
    }

    #[test]
    fn parses_scheduler_offsets_from_btf() {
        #[cfg(target_arch = "x86_64")]
        let expected_args = [112, 104, 96, 56, 72, 64];
        #[cfg(target_arch = "x86")]
        let expected_args = [0, 4, 8, 12, 16, 20];
        #[cfg(target_arch = "aarch64")]
        let expected_args = [0, 8, 16, 24, 32, 40];
        #[cfg(target_arch = "x86_64")]
        let expected_syscall_nr = 120;
        #[cfg(target_arch = "x86")]
        let expected_syscall_nr = 44;
        #[cfg(target_arch = "aarch64")]
        let expected_syscall_nr = 280;
        assert_eq!(
            parse_scheduler_field_offsets(&minimal_btf(true)).unwrap(),
            SchedulerFieldOffsets {
                task_pid: 3,
                task_comm: 8,
                binprm_filename: 10,
                syscall_args: expected_args,
                syscall_nr: expected_syscall_nr,
            }
        );
    }

    /// `dentry { d_parent; union { qstr __d_name; const qstr d_name } }`, `qstr { union { ...
    /// hash_len }; name }` and `iattr`, as the kernel lays them out (the anonymous union is what
    /// the generic lookup exists for).
    fn setattr_btf(params: &[&str]) -> Vec<u8> {
        let strings = b"\0int\0iattr\0ia_valid\0ia_atime\0ia_mtime\0dentry\0d_parent\0d_name\0qstr\0name\0hash_len\0bpf_lsm_inode_setattr\0idmap\0attr\0extra\0".to_vec();
        let offset = |needle: &[u8]| {
            strings
                .windows(needle.len() + 1)
                .position(|window| window == [needle, &[0]].concat())
                .expect("string exists") as u32
        };
        let mut types = Vec::new();
        let mut push_u32 = |value: u32| types.extend_from_slice(&value.to_le_bytes());
        // 1: int
        push_u32(offset(b"int"));
        push_u32(BTF_KIND_INT << 24);
        push_u32(4);
        push_u32(32);
        // 2: struct qstr { int hash_len; int name; } (name at byte 8)
        push_u32(offset(b"qstr"));
        push_u32((BTF_KIND_STRUCT << 24) | 2);
        push_u32(16);
        for (name, bits) in [(&b"hash_len"[..], 0), (&b"name"[..], 64)] {
            push_u32(offset(name));
            push_u32(1);
            push_u32(bits);
        }
        // 3: union { qstr d_name; } (anonymous), at byte 24 of dentry
        push_u32(0);
        push_u32((BTF_KIND_UNION << 24) | 1);
        push_u32(16);
        push_u32(offset(b"d_name"));
        push_u32(2);
        push_u32(0);
        // 4: struct dentry { int d_parent (byte 12); <anon union 3> at byte 24 }
        push_u32(offset(b"dentry"));
        push_u32((BTF_KIND_STRUCT << 24) | 2);
        push_u32(48);
        push_u32(offset(b"d_parent"));
        push_u32(1);
        push_u32(12 * 8);
        push_u32(0);
        push_u32(3);
        push_u32(24 * 8);
        // 5: struct iattr { ia_valid at 0, ia_atime at 32, ia_mtime at 48 }
        push_u32(offset(b"iattr"));
        push_u32((BTF_KIND_STRUCT << 24) | 3);
        push_u32(80);
        for (name, byte) in [
            (&b"ia_valid"[..], 0),
            (&b"ia_atime"[..], 32),
            (&b"ia_mtime"[..], 48),
        ] {
            push_u32(offset(name));
            push_u32(1);
            push_u32(byte * 8);
        }
        // 6: the hook's prototype, 7: bpf_lsm_inode_setattr
        push_u32(0);
        push_u32((BTF_KIND_FUNC_PROTO << 24) | params.len() as u32);
        push_u32(1);
        for param in params {
            push_u32(offset(param.as_bytes()));
            push_u32(1);
        }
        push_u32(offset(b"bpf_lsm_inode_setattr"));
        push_u32(BTF_KIND_FUNC << 24);
        push_u32(6);
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
        btf.extend_from_slice(&strings);
        btf
    }

    const CURRENT_HOOK: [&str; 3] = ["idmap", "dentry", "attr"];

    #[test]
    fn inode_setattr_is_disabled_when_the_hook_has_another_shape() {
        // Before kernel 6.3: no idmap, the dentry is the first argument.
        assert_eq!(
            parse_inode_setattr_offsets(&setattr_btf(&["dentry", "attr"])),
            Err("inode_setattr hook arguments are not (idmap, dentry, attr)")
        );
        assert!(parse_inode_setattr_offsets(&setattr_btf(&["idmap", "dentry", "iattr"])).is_err());
        assert!(
            parse_inode_setattr_offsets(&setattr_btf(&["idmap", "dentry", "attr", "extra"]))
                .is_err()
        );
    }

    #[test]
    fn parses_inode_setattr_offsets_through_the_anonymous_union() {
        assert_eq!(
            parse_inode_setattr_offsets(&setattr_btf(&CURRENT_HOOK)).unwrap(),
            InodeSetattrOffsets {
                ia_valid: 0,
                ia_atime: 32,
                ia_mtime: 48,
                dentry_parent: 12,
                // d_name's union at 24 + d_name at 0 inside it + qstr.name at 8.
                dentry_name_ptr: 32,
            }
        );
    }

    #[test]
    fn inode_setattr_offsets_are_refused_when_a_struct_is_missing() {
        assert!(parse_inode_setattr_offsets(&minimal_btf(true)).is_err());
        assert!(parse_inode_setattr_offsets(&[0x9f, 0xeb, 1, 0]).is_err());
    }

    #[test]
    fn parses_running_kernel_inode_setattr_offsets_when_available() {
        if Path::new("/sys/kernel/btf/vmlinux").exists() {
            let offsets = read_inode_setattr_offsets().expect("running kernel BTF has them");
            assert_eq!(offsets.ia_valid, 0, "ia_valid leads struct iattr");
            assert!(offsets.ia_mtime > offsets.ia_atime);
            assert!(offsets.dentry_parent < 256 && offsets.dentry_name_ptr < 256);
        }
    }

    #[test]
    fn rejects_truncated_btf() {
        assert!(parse_scheduler_field_offsets(&[0x9f, 0xeb, 1, 0]).is_err());
    }

    #[test]
    fn rejects_btf_without_syscall_number_field() {
        assert_eq!(
            parse_scheduler_field_offsets(&minimal_btf(false)),
            Err("pt_regs syscall number field is missing")
        );
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
            assert!(offsets.syscall_nr < 4096);
        }
    }
}
