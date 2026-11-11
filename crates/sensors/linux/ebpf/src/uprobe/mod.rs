//! Uprobe handlers: userspace attaches them (`sensor-linux-uprobes`) after resolving the
//! library symbols, so these programs only carry the per-call logic.

/// Copies one resolved address into answer slot `$index` of the DNS scratch event `$e`,
/// reading 4 bytes for `AF_INET` and 16 otherwise from the user pointer `$address_ptr`.
/// Evaluates to the helper's `Result`; an index past [`MAX_DNS_ANSWERS`] breaks the
/// enclosing loop.
///
/// Each match arm gives LLVM a constant destination slot. Assigning a `DnsAnswer` at a
/// runtime index caused the BPF target to synthesize a per-answer memset; write into the
/// existing map value instead.
///
/// [`MAX_DNS_ANSWERS`]: sensor_linux_wire::MAX_DNS_ANSWERS
macro_rules! copy_dns_answer {
    ($e:ident, $index:expr, $family:ident, $address_ptr:ident) => {
        match $index {
            0 => copy_dns_answer!(@slot $e, 0, $family, $address_ptr),
            1 => copy_dns_answer!(@slot $e, 1, $family, $address_ptr),
            2 => copy_dns_answer!(@slot $e, 2, $family, $address_ptr),
            3 => copy_dns_answer!(@slot $e, 3, $family, $address_ptr),
            4 => copy_dns_answer!(@slot $e, 4, $family, $address_ptr),
            5 => copy_dns_answer!(@slot $e, 5, $family, $address_ptr),
            6 => copy_dns_answer!(@slot $e, 6, $family, $address_ptr),
            7 => copy_dns_answer!(@slot $e, 7, $family, $address_ptr),
            8 => copy_dns_answer!(@slot $e, 8, $family, $address_ptr),
            9 => copy_dns_answer!(@slot $e, 9, $family, $address_ptr),
            10 => copy_dns_answer!(@slot $e, 10, $family, $address_ptr),
            11 => copy_dns_answer!(@slot $e, 11, $family, $address_ptr),
            12 => copy_dns_answer!(@slot $e, 12, $family, $address_ptr),
            13 => copy_dns_answer!(@slot $e, 13, $family, $address_ptr),
            14 => copy_dns_answer!(@slot $e, 14, $family, $address_ptr),
            15 => copy_dns_answer!(@slot $e, 15, $family, $address_ptr),
            16 => copy_dns_answer!(@slot $e, 16, $family, $address_ptr),
            17 => copy_dns_answer!(@slot $e, 17, $family, $address_ptr),
            18 => copy_dns_answer!(@slot $e, 18, $family, $address_ptr),
            19 => copy_dns_answer!(@slot $e, 19, $family, $address_ptr),
            20 => copy_dns_answer!(@slot $e, 20, $family, $address_ptr),
            21 => copy_dns_answer!(@slot $e, 21, $family, $address_ptr),
            22 => copy_dns_answer!(@slot $e, 22, $family, $address_ptr),
            23 => copy_dns_answer!(@slot $e, 23, $family, $address_ptr),
            _ => break,
        }
    };
    (@slot $e:ident, $slot:literal, $family:ident, $address_ptr:ident) => {{
        // SAFETY: `$e` points to this CPU's writable scratch map value and
        // `$slot` is a compile-time index within the fixed [`MAX_DNS_ANSWERS`]-slot array.
        unsafe { (*$e).answers[$slot].family = $family as u8 };
        if $family == i32::from(crate::AF_INET) {
            // SAFETY: the address pointer came from a user-memory read. The BPF
            // helper validates the source and writes only four bytes to the
            // statically indexed scratch address.
            unsafe {
                aya_ebpf::helpers::bpf_probe_read_user_buf(
                    $address_ptr as *const u8,
                    &mut (&mut (*$e).answers[$slot].address)[..4],
                )
            }
        } else {
            // SAFETY: same user-pointer validation; destination is the full
            // 16-byte field at a statically known map-value offset.
            unsafe {
                aya_ebpf::helpers::bpf_probe_read_user_buf(
                    $address_ptr as *const u8,
                    &mut (*$e).answers[$slot].address,
                )
            }
        }
    }};
}

mod getaddrinfo;
mod gethostbyname;
mod readline;
mod tls;
