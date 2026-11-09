/* C shim for the libproc socket-table walk.
 *
 * socket_fdinfo (<sys/proc_info.h>) is a large union-heavy struct, so the
 * walk stays in C against the SDK's headers and Rust gets one flat record per
 * TCP socket. TCP states map to shim-owned values, never to TCPS_* in Rust.
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
