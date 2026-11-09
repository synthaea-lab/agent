//! Small, bounds-checked reader for the kernel BTF struct-member offsets the probes
//! need at load time. Aya loads BTF for verification, but its public API does not
//! expose struct members for runtime field lookup.

use std::{fs, ops::Range, path::Path};

const VMLINUX_BTF: &str = "/sys/kernel/btf/vmlinux";
const BTF_HEADER_LEN: usize = 24;
const TYPE_RECORD_LEN: usize = 12;
const MEMBER_LEN: usize = 12;
const PARAM_LEN: usize = 8;
const MAX_ANONYMOUS_NESTING: u32 = 4;
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

/// Why kernel BTF does not yield the offsets a probe needs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum BtfError {
    #[error("truncated header")]
    TruncatedHeader,
    #[error("invalid magic")]
    InvalidMagic,
    #[error("unsupported version")]
    UnsupportedVersion,
    #[error("header length is too short")]
    HeaderTooShort,
    #[error("type or string section is out of bounds")]
    SectionOutOfBounds,
    #[error("truncated type record")]
    TruncatedTypeRecord,
    #[error("type payload is out of bounds")]
    TypePayloadOutOfBounds,
    #[error("unknown type kind {0}")]
    UnknownTypeKind(u32),
    #[error("offset arithmetic overflow")]
    Overflow,
    #[error("truncated integer")]
    TruncatedInteger,
    #[error("string offset is out of bounds")]
    StringOutOfBounds,
    #[error("unterminated string")]
    UnterminatedString,
    #[error("required member uses a bitfield or unaligned offset")]
    UnalignedMember,
    #[error("anonymous member nesting is too deep")]
    NestingTooDeep,
    #[error("function type is not a prototype")]
    NotAPrototype,
    #[error("{structure}.{member} is missing")]
    MissingMember {
        structure: &'static str,
        member: &'static str,
    },
    #[error("kernel has no BPF-LSM inode_setattr hook")]
    NoInodeSetattrHook,
    #[error("inode_setattr hook arguments are not (idmap, dentry, attr)")]
    UnexpectedInodeSetattrArguments,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Endianness {
    Little,
    Big,
}

/// Byte offsets needed to interpret raw `sched_process_*` tracepoint arguments.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SchedulerFieldOffsets {
    pub(crate) task_pid: u32,
    /// `task_struct.tgid`: the process id of a task (`pid` is its thread id), #1103.
    pub(crate) task_tgid: u32,
    pub(crate) task_comm: u32,
    pub(crate) binprm_filename: u32,
    pub(crate) syscall_args: [u32; 6],
    pub(crate) syscall_nr: u32,
}

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
const SYSCALL_NR_FIELD: &str = "orig_ax";
#[cfg(target_arch = "aarch64")]
const SYSCALL_NR_FIELD: &str = "syscallno";

/// The `pt_regs` members holding syscall arguments 1 to 6, in order.
#[cfg(target_arch = "x86_64")]
const SYSCALL_ARG_REGISTERS: [&str; 6] = ["di", "si", "dx", "r10", "r8", "r9"];
#[cfg(target_arch = "x86")]
const SYSCALL_ARG_REGISTERS: [&str; 6] = ["bx", "cx", "dx", "si", "di", "bp"];

/// Reads and parses `/sys/kernel/btf/vmlinux` for the scheduler probe fields.
pub(crate) fn read_scheduler_field_offsets()
-> Result<SchedulerFieldOffsets, Box<dyn std::error::Error + Send + Sync>> {
    read_kernel_btf(parse_scheduler_field_offsets)
}

fn parse_scheduler_field_offsets(data: &[u8]) -> Result<SchedulerFieldOffsets, BtfError> {
    let table = TypeTable::parse(data)?;
    Ok(SchedulerFieldOffsets {
        task_pid: table.required_member_offset("task_struct", "pid")?,
        task_tgid: table.required_member_offset("task_struct", "tgid")?,
        task_comm: table.required_member_offset("task_struct", "comm")?,
        binprm_filename: table.required_member_offset("linux_binprm", "filename")?,
        syscall_args: syscall_arg_offsets(&table)?,
        syscall_nr: table.required_member_offset("pt_regs", SYSCALL_NR_FIELD)?,
    })
}

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
fn syscall_arg_offsets(table: &TypeTable<'_>) -> Result<[u32; 6], BtfError> {
    let mut offsets = [0; 6];
    for (offset, register) in offsets.iter_mut().zip(SYSCALL_ARG_REGISTERS) {
        *offset = table.required_member_offset("pt_regs", register)?;
    }
    Ok(offsets)
}

/// The arguments are `regs[0]` to `regs[5]` (x0-x5), eight bytes apart.
#[cfg(target_arch = "aarch64")]
fn syscall_arg_offsets(table: &TypeTable<'_>) -> Result<[u32; 6], BtfError> {
    let regs = table.required_member_offset("pt_regs", "regs")?;
    Ok(std::array::from_fn(|index| regs + index as u32 * 8))
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
    read_kernel_btf(parse_inode_setattr_offsets)
}

fn parse_inode_setattr_offsets(data: &[u8]) -> Result<InodeSetattrOffsets, BtfError> {
    let table = TypeTable::parse(data)?;
    // The probe reads the hook's arguments by position, for `(idmap, dentry, attr)` (kernel
    // 6.3 and later). Before that the first argument was the dentry: reading by this layout
    // there would take the wrong pointers, so the hook stays disabled unless the kernel's own
    // BTF says it has this shape.
    match table.function_params("bpf_lsm_inode_setattr")? {
        Some(params) if params == [&b"idmap"[..], b"dentry", b"attr"] => {}
        Some(_) => return Err(BtfError::UnexpectedInodeSetattrArguments),
        None => return Err(BtfError::NoInodeSetattrHook),
    }
    Ok(InodeSetattrOffsets {
        ia_valid: table.required_member_offset("iattr", "ia_valid")?,
        ia_atime: table.required_member_offset("iattr", "ia_atime")?,
        ia_mtime: table.required_member_offset("iattr", "ia_mtime")?,
        dentry_parent: table.required_member_offset("dentry", "d_parent")?,
        dentry_name_ptr: table.required_member_offset("dentry", "d_name")?
            + table.required_member_offset("qstr", "name")?,
    })
}

/// Byte offsets the exec probe needs to copy argv at `sched_process_exec` (<https://github.com/synthaea-lab/agent/issues/48>): the task's
/// `mm` pointer and the bounds of the argument strings in it (`mm_struct` keeps them inside an
/// anonymous struct, which `member_offset` looks through).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ExecArgvOffsets {
    pub(crate) task_mm: u32,
    pub(crate) mm_arg_start: u32,
    pub(crate) mm_arg_end: u32,
}

/// Reads `/sys/kernel/btf/vmlinux` for the exec probe's argv fields.
pub(crate) fn read_exec_argv_offsets()
-> Result<ExecArgvOffsets, Box<dyn std::error::Error + Send + Sync>> {
    read_kernel_btf(parse_exec_argv_offsets)
}

fn parse_exec_argv_offsets(data: &[u8]) -> Result<ExecArgvOffsets, BtfError> {
    let table = TypeTable::parse(data)?;
    Ok(ExecArgvOffsets {
        task_mm: table.required_member_offset("task_struct", "mm")?,
        mm_arg_start: table.required_member_offset("mm_struct", "arg_start")?,
        mm_arg_end: table.required_member_offset("mm_struct", "arg_end")?,
    })
}

fn read_kernel_btf<T>(
    parse: fn(&[u8]) -> Result<T, BtfError>,
) -> Result<T, Box<dyn std::error::Error + Send + Sync>> {
    let data = fs::read(Path::new(VMLINUX_BTF))?;
    parse(&data).map_err(|e| format!("invalid kernel BTF: {e}").into())
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

impl TypeRecord {
    /// Member, parameter or enumerator count.
    fn vlen(&self) -> usize {
        (self.info & 0xffff) as usize
    }

    /// Set on a struct or union whose member offsets carry a bitfield width.
    fn kind_flag(&self) -> bool {
        self.info >> 31 != 0
    }
}

struct TypeTable<'a> {
    data: &'a [u8],
    endianness: Endianness,
    strings: &'a [u8],
    /// Type id `n` is `records[n - 1]` (id 0 is `void`).
    records: Vec<TypeRecord>,
}

impl<'a> TypeTable<'a> {
    fn parse(data: &'a [u8]) -> Result<Self, BtfError> {
        let endianness = read_endianness(data)?;
        let (types, strings) = section_ranges(data, endianness)?;
        Ok(Self {
            data,
            endianness,
            strings: &data[strings],
            records: read_records(data, types, endianness)?,
        })
    }

    fn required_member_offset(
        &self,
        structure: &'static str,
        member: &'static str,
    ) -> Result<u32, BtfError> {
        self.member_offset(structure, member)?
            .ok_or(BtfError::MissingMember { structure, member })
    }

    /// Byte offset of `member` in the struct called `name`, looking inside anonymous
    /// structs and unions (`dentry.d_name` sits in one). The first struct of that name that
    /// has the member wins: BTF can carry several, a forward-declared one has no members.
    fn member_offset(&self, name: &str, member: &str) -> Result<Option<u32>, BtfError> {
        for record in &self.records {
            if record.kind == BTF_KIND_STRUCT
                && self.name_is(record.name_off, name)?
                && let Some(offset) = self.find_member(record, member, 0)?
            {
                return Ok(Some(offset));
            }
        }
        Ok(None)
    }

    /// Parameter names of the kernel function `name` (a `FUNC` record pointing at a
    /// `FUNC_PROTO`), or `None` when BTF has no such function.
    fn function_params(&self, name: &str) -> Result<Option<Vec<&'a [u8]>>, BtfError> {
        for record in &self.records {
            if record.kind != BTF_KIND_FUNC || !self.name_is(record.name_off, name)? {
                continue;
            }
            let proto = self
                .record_by_id(record.size_or_type)
                .filter(|proto| proto.kind == BTF_KIND_FUNC_PROTO)
                .ok_or(BtfError::NotAPrototype)?;
            let params = (0..proto.vlen())
                .map(|index| {
                    let name_off = self.read_u32(proto.extra_start + index * PARAM_LEN)?;
                    string_at(self.strings, name_off)
                })
                .collect::<Result<_, _>>()?;
            return Ok(Some(params));
        }
        Ok(None)
    }

    /// Only the wanted member's offset has to be byte-aligned: `task_struct` has
    /// bitfields before `pid`.
    fn find_member(
        &self,
        record: &TypeRecord,
        member: &str,
        depth: u32,
    ) -> Result<Option<u32>, BtfError> {
        // Anonymous nesting is one or two levels in practice; a cycle in a corrupt table
        // must not recurse forever.
        if depth > MAX_ANONYMOUS_NESTING {
            return Err(BtfError::NestingTooDeep);
        }
        for index in 0..record.vlen() {
            let at = record.extra_start + index * MEMBER_LEN;
            let member_name = self.read_u32(at)?;
            if member_name == 0 {
                let member_type = self.read_u32(at + 4)?;
                let inner = self
                    .record_by_id(member_type)
                    .filter(|inner| matches!(inner.kind, BTF_KIND_STRUCT | BTF_KIND_UNION));
                if let Some(inner) = inner
                    && let Some(found) = self.find_member(inner, member, depth + 1)?
                {
                    return Ok(Some(self.member_byte_offset(record, at)? + found));
                }
            } else if self.name_is(member_name, member)? {
                return Ok(Some(self.member_byte_offset(record, at)?));
            }
        }
        Ok(None)
    }

    fn member_byte_offset(&self, record: &TypeRecord, member_at: usize) -> Result<u32, BtfError> {
        let raw = self.read_u32(member_at + 8)?;
        let bitfield_width = if record.kind_flag() { raw >> 24 } else { 0 };
        let bit_offset = raw & 0x00ff_ffff;
        if bitfield_width != 0 || bit_offset % 8 != 0 {
            return Err(BtfError::UnalignedMember);
        }
        Ok(bit_offset / 8)
    }

    fn record_by_id(&self, id: u32) -> Option<&TypeRecord> {
        (id as usize)
            .checked_sub(1)
            .and_then(|index| self.records.get(index))
    }

    fn name_is(&self, name_off: u32, expected: &str) -> Result<bool, BtfError> {
        Ok(string_at(self.strings, name_off)? == expected.as_bytes())
    }

    fn read_u32(&self, offset: usize) -> Result<u32, BtfError> {
        read_u32(self.data, offset, self.endianness)
    }
}

fn read_endianness(data: &[u8]) -> Result<Endianness, BtfError> {
    if data.len() < BTF_HEADER_LEN {
        return Err(BtfError::TruncatedHeader);
    }
    let endianness = match data[..2] {
        [0x9f, 0xeb] => Endianness::Little,
        [0xeb, 0x9f] => Endianness::Big,
        _ => return Err(BtfError::InvalidMagic),
    };
    if data[2] != 1 {
        return Err(BtfError::UnsupportedVersion);
    }
    Ok(endianness)
}

/// The type and string sections the header points at, both checked to lie in `data`.
fn section_ranges(
    data: &[u8],
    endianness: Endianness,
) -> Result<(Range<usize>, Range<usize>), BtfError> {
    let field = |offset| read_u32(data, offset, endianness).map(|value| value as usize);
    let header_len = field(4)?;
    if header_len < BTF_HEADER_LEN {
        return Err(BtfError::HeaderTooShort);
    }
    let section = |offset_field, len_field| -> Result<Range<usize>, BtfError> {
        let start = header_len
            .checked_add(field(offset_field)?)
            .ok_or(BtfError::Overflow)?;
        let end = start
            .checked_add(field(len_field)?)
            .ok_or(BtfError::Overflow)?;
        if end > data.len() {
            return Err(BtfError::SectionOutOfBounds);
        }
        Ok(start..end)
    };
    Ok((section(8, 12)?, section(16, 20)?))
}

fn read_records(
    data: &[u8],
    types: Range<usize>,
    endianness: Endianness,
) -> Result<Vec<TypeRecord>, BtfError> {
    let mut records = Vec::new();
    let mut cursor = types.start;
    while cursor < types.end {
        if cursor
            .checked_add(TYPE_RECORD_LEN)
            .is_none_or(|end| end > types.end)
        {
            return Err(BtfError::TruncatedTypeRecord);
        }
        let info = read_u32(data, cursor + 4, endianness)?;
        let kind = (info >> 24) & 0x1f;
        let vlen = (info & 0xffff) as usize;
        let extra_start = cursor + TYPE_RECORD_LEN;
        let record_end = extra_start
            .checked_add(type_extra_len(kind, vlen)?)
            .ok_or(BtfError::Overflow)?;
        if record_end > types.end {
            return Err(BtfError::TypePayloadOutOfBounds);
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
    Ok(records)
}

fn type_extra_len(kind: u32, vlen: usize) -> Result<usize, BtfError> {
    let per_entry = match kind {
        BTF_KIND_INT | BTF_KIND_VAR | BTF_KIND_DECL_TAG => return Ok(4),
        BTF_KIND_ARRAY => return Ok(12),
        BTF_KIND_STRUCT | BTF_KIND_UNION | BTF_KIND_DATASEC | BTF_KIND_ENUM64 => 12,
        BTF_KIND_ENUM | BTF_KIND_FUNC_PROTO => 8,
        // PTR, FWD, TYPEDEF, VOLATILE, CONST, RESTRICT, FUNC, FLOAT and TYPE_TAG.
        0 | 2 | 7..=12 | 16 | 18 => return Ok(0),
        _ => return Err(BtfError::UnknownTypeKind(kind)),
    };
    vlen.checked_mul(per_entry).ok_or(BtfError::Overflow)
}

/// The NUL-terminated string at `offset` in the string section.
fn string_at(strings: &[u8], offset: u32) -> Result<&[u8], BtfError> {
    let tail = strings
        .get(offset as usize..)
        .filter(|tail| !tail.is_empty())
        .ok_or(BtfError::StringOutOfBounds)?;
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(BtfError::UnterminatedString)?;
    Ok(&tail[..end])
}

fn read_u32(data: &[u8], offset: usize, endianness: Endianness) -> Result<u32, BtfError> {
    let end = offset.checked_add(4).ok_or(BtfError::Overflow)?;
    let bytes: [u8; 4] = data
        .get(offset..end)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(BtfError::TruncatedInteger)?;
    Ok(match endianness {
        Endianness::Little => u32::from_le_bytes(bytes),
        Endianness::Big => u32::from_be_bytes(bytes),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn string_offset(strings: &[u8], needle: &[u8]) -> u32 {
        strings
            .windows(needle.len() + 1)
            .position(|window| window == [needle, &[0]].concat())
            .expect("string exists") as u32
    }

    /// A little-endian BTF blob: header, then the type section, then the string section.
    fn assemble_btf(types: &[u8], strings: &[u8]) -> Vec<u8> {
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
        btf.extend_from_slice(types);
        btf.extend_from_slice(strings);
        btf
    }

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
        let mut strings =
            b"\0task_struct\0pid\0comm\0tgid\0linux_binprm\0filename\0pt_regs\0".to_vec();
        for (name, _) in registers {
            strings.extend_from_slice(name);
            strings.push(0);
        }
        if include_syscall_nr {
            strings.extend_from_slice(syscall_nr.0);
            strings.push(0);
        }
        let offset = |needle: &[u8]| string_offset(&strings, needle);
        let mut types = Vec::new();
        let mut push_u32 = |value: u32| types.extend_from_slice(&value.to_le_bytes());

        // int (id 1)
        push_u32(0);
        push_u32(BTF_KIND_INT << 24);
        push_u32(4);
        push_u32(32);

        // struct task_struct { int pid; int comm; int tgid; }
        push_u32(offset(b"task_struct"));
        push_u32((BTF_KIND_STRUCT << 24) | 3);
        push_u32(32);
        for (name, bit_offset) in [
            (b"pid".as_slice(), 24),
            (b"comm".as_slice(), 64),
            (b"tgid".as_slice(), 96),
        ] {
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

        assemble_btf(&types, &strings)
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
                task_tgid: 12,
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
        let offset = |needle: &[u8]| string_offset(&strings, needle);
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
        assemble_btf(&types, &strings)
    }

    const CURRENT_HOOK: [&str; 3] = ["idmap", "dentry", "attr"];

    #[test]
    fn inode_setattr_is_disabled_when_the_hook_has_another_shape() {
        // Before kernel 6.3: no idmap, the dentry is the first argument.
        assert_eq!(
            parse_inode_setattr_offsets(&setattr_btf(&["dentry", "attr"])),
            Err(BtfError::UnexpectedInodeSetattrArguments)
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
    fn parses_running_kernel_exec_argv_offsets_when_available() {
        if Path::new("/sys/kernel/btf/vmlinux").exists() {
            let offsets = read_exec_argv_offsets().expect("running kernel BTF has them");
            // `arg_end` follows `arg_start` (two `unsigned long`s side by side).
            assert_eq!(offsets.mm_arg_end, offsets.mm_arg_start + 8);
            assert!(offsets.task_mm < 8192);
        }
    }

    /// `task_struct { struct { mm } (anonymous) }` and `mm_struct { struct { arg_start; arg_end }
    /// (anonymous) }`, the shape the exec probe's lookup has to look through.
    fn exec_argv_btf() -> Vec<u8> {
        let strings = b"\0int\0task_struct\0mm\0mm_struct\0arg_start\0arg_end\0".to_vec();
        let offset = |needle: &[u8]| string_offset(&strings, needle);
        let mut types = Vec::new();
        let mut push_u32 = |value: u32| types.extend_from_slice(&value.to_le_bytes());
        // 1: int
        push_u32(offset(b"int"));
        push_u32(BTF_KIND_INT << 24);
        push_u32(4);
        push_u32(32);
        // 2: struct { int mm; } (anonymous), mm at byte 8
        push_u32(0);
        push_u32((BTF_KIND_STRUCT << 24) | 1);
        push_u32(16);
        push_u32(offset(b"mm"));
        push_u32(1);
        push_u32(8 * 8);
        // 3: struct task_struct { <anon struct 2> at byte 1000 }
        push_u32(offset(b"task_struct"));
        push_u32((BTF_KIND_STRUCT << 24) | 1);
        push_u32(2048);
        push_u32(0);
        push_u32(2);
        push_u32(1000 * 8);
        // 4: struct { int arg_start; int arg_end; } (anonymous)
        push_u32(0);
        push_u32((BTF_KIND_STRUCT << 24) | 2);
        push_u32(16);
        for (name, byte) in [(&b"arg_start"[..], 0), (&b"arg_end"[..], 8)] {
            push_u32(offset(name));
            push_u32(1);
            push_u32(byte * 8);
        }
        // 5: struct mm_struct { <anon struct 4> at byte 320 }
        push_u32(offset(b"mm_struct"));
        push_u32((BTF_KIND_STRUCT << 24) | 1);
        push_u32(1024);
        push_u32(0);
        push_u32(4);
        push_u32(320 * 8);
        assemble_btf(&types, &strings)
    }

    /// `task_struct` as the kernel lays it out: bitfields (`kind_flag` set) sit before `pid`,
    /// `tgid` and `comm`, and only the wanted members have to be byte-aligned.
    fn task_struct_with_bitfields_btf() -> Vec<u8> {
        let strings = b"\0int\0task_struct\0sched_reset_on_fork\0pid\0tgid\0comm\0".to_vec();
        let offset = |needle: &[u8]| string_offset(&strings, needle);
        let mut types = Vec::new();
        let mut push_u32 = |value: u32| types.extend_from_slice(&value.to_le_bytes());
        push_u32(offset(b"int"));
        push_u32(BTF_KIND_INT << 24);
        push_u32(4);
        push_u32(32);
        push_u32(offset(b"task_struct"));
        push_u32((1 << 31) | (BTF_KIND_STRUCT << 24) | 4);
        push_u32(64);
        // One-bit field at bit 3: unaligned, with a bitfield width in the top byte.
        push_u32(offset(b"sched_reset_on_fork"));
        push_u32(1);
        push_u32((1 << 24) | 3);
        for (name, byte) in [(&b"pid"[..], 16), (&b"tgid"[..], 20), (&b"comm"[..], 24)] {
            push_u32(offset(name));
            push_u32(1);
            push_u32(byte * 8);
        }
        assemble_btf(&types, &strings)
    }

    #[test]
    fn parses_exec_argv_offsets_through_anonymous_structs() {
        assert_eq!(
            parse_exec_argv_offsets(&exec_argv_btf()).unwrap(),
            ExecArgvOffsets {
                task_mm: 1008,
                mm_arg_start: 320,
                mm_arg_end: 328,
            }
        );
    }

    #[test]
    fn exec_argv_offsets_are_refused_when_a_struct_is_missing() {
        assert!(parse_exec_argv_offsets(&minimal_btf(true)).is_err());
    }

    #[test]
    fn task_struct_lookup_steps_over_bitfields_before_the_wanted_members() {
        let btf = task_struct_with_bitfields_btf();
        let table = TypeTable::parse(&btf).unwrap();
        let offset = |member| table.member_offset("task_struct", member).unwrap();
        assert_eq!(offset("pid"), Some(16));
        assert_eq!(offset("tgid"), Some(20));
        assert_eq!(offset("comm"), Some(24));
    }

    fn parse_all(data: &[u8]) -> [bool; 3] {
        [
            parse_scheduler_field_offsets(data).is_ok(),
            parse_inode_setattr_offsets(data).is_ok(),
            parse_exec_argv_offsets(data).is_ok(),
        ]
    }

    #[test]
    fn every_truncation_of_a_valid_blob_is_rejected() {
        for btf in [
            minimal_btf(true),
            setattr_btf(&CURRENT_HOOK),
            exec_argv_btf(),
        ] {
            for len in 0..btf.len() {
                assert_eq!(parse_all(&btf[..len]), [false; 3], "prefix of {len} bytes");
            }
        }
    }

    /// Deterministic xorshift, so a failing input reproduces from the seed.
    struct Xorshift(u64);

    impl Xorshift {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, bound: usize) -> usize {
            (self.next() % bound as u64) as usize
        }
    }

    #[test]
    fn arbitrary_bytes_never_panic_the_parser() {
        let mut rng = Xorshift(0x5eed_b7f0_0dd1_ce55);
        let valid = [
            minimal_btf(true),
            setattr_btf(&CURRENT_HOOK),
            exec_argv_btf(),
        ];
        for round in 0..20_000 {
            let mut data = if round % 2 == 0 {
                valid[rng.below(valid.len())].clone()
            } else {
                let mut random = vec![0x9f, 0xeb, 1, 0];
                random.extend((0..rng.below(512)).map(|_| rng.next() as u8));
                random
            };
            for _ in 0..=rng.below(8) {
                let at = rng.below(data.len());
                data[at] = rng.next() as u8;
            }
            parse_all(&data);
        }
    }

    #[test]
    fn rejects_btf_without_syscall_number_field() {
        assert_eq!(
            parse_scheduler_field_offsets(&minimal_btf(false)),
            Err(BtfError::MissingMember {
                structure: "pt_regs",
                member: SYSCALL_NR_FIELD,
            })
        );
    }

    #[test]
    fn parses_running_kernel_btf_when_available() {
        let path = Path::new("/sys/kernel/btf/vmlinux");
        if path.exists() {
            let offsets = read_scheduler_field_offsets().expect("running kernel BTF parses");
            assert!(offsets.task_pid < 4096);
            assert!(offsets.task_tgid < 4096);
            assert_ne!(offsets.task_tgid, offsets.task_pid);
            assert!(offsets.task_comm < 4096);
            assert!(offsets.binprm_filename < 4096);
            assert!(offsets.syscall_args.iter().all(|offset| *offset < 4096));
            assert!(offsets.syscall_nr < 4096);
        }
    }
}
