/* C shim for the libproc socket-table walk (issue #358).
 *
 * Same reasoning as the EndpointSecurity shim: `socket_fdinfo` and friends
 * (<sys/proc_info.h>) are large, union-heavy structs — transcribing their
 * layout into #[repr(C)] Rust is silent-ABI-drift risk for zero gain. The
 * shim compiles against the SDK's own headers, walks the table in C, and
 * hands Rust one flat record per TCP socket. TCP state constants are mapped
 * to shim-owned values here (TCPS_* macros), never transcribed into Rust.
 *
 * Records are only valid for the duration of the callback.
 */
#ifndef SYNTHAEA_SOCKETS_SHIM_H
#define SYNTHAEA_SOCKETS_SHIM_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum syn_sock_state {
    SYN_SOCK_STATE_OTHER = 0,
    SYN_SOCK_STATE_LISTEN = 1,
    SYN_SOCK_STATE_ESTABLISHED = 2,
};

typedef struct {
    int32_t pid;
    int32_t ppid;
    uint32_t uid; /* effective uid of the owning process */
    uint32_t gid;
    /* Executable path, NUL-terminated; empty when unresolvable. */
    char path[1024];
    uint8_t state; /* enum syn_sock_state */
    uint8_t is_ipv6;
    uint16_t lport; /* host byte order */
    uint16_t rport;
    uint8_t laddr[16]; /* IPv4 in the first 4 bytes when !is_ipv6 */
    uint8_t raddr[16];
} syn_sock_record;

typedef void (*syn_sock_cb)(void *ctx, const syn_sock_record *rec);

/* Walks every visible process's fd table and invokes `cb` once per TCP
 * socket (IPv4/IPv6). Processes that disappear mid-walk or are unreadable
 * (other users' processes when not root) are skipped silently — the caller
 * decides what partial visibility means. Returns 0, or negative when the
 * initial pid enumeration itself fails. */
int32_t syn_sockets_snapshot(syn_sock_cb cb, void *ctx);

#ifdef __cplusplus
}
#endif

#endif /* SYNTHAEA_SOCKETS_SHIM_H */
