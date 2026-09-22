/* See sockets_shim.h for why this shim exists. Compiled only on macOS
 * (build.rs), against the SDK's own libproc/proc_info headers. */

#include "sockets_shim.h"

#include <arpa/inet.h>
#include <libproc.h>
#include <netinet/tcp_fsm.h>
#include <stdlib.h>
#include <string.h>
#include <sys/proc_info.h>

static uint8_t map_state(int tcp_state) {
    switch (tcp_state) {
    case TCPS_LISTEN:
        return SYN_SOCK_STATE_LISTEN;
    case TCPS_ESTABLISHED:
        return SYN_SOCK_STATE_ESTABLISHED;
    default:
        return SYN_SOCK_STATE_OTHER;
    }
}

/* Emits every TCP socket of one process. `meta` carries the per-process
 * fields already resolved by the caller (once per pid, not per fd). */
static void walk_pid_sockets(int32_t pid, const syn_sock_record *meta,
                             syn_sock_cb cb, void *ctx) {
    int fds_size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
    if (fds_size <= 0) {
        return;
    }
    struct proc_fdinfo *fds = malloc((size_t)fds_size);
    if (fds == NULL) {
        return;
    }
    fds_size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds, fds_size);
    int fd_count = fds_size > 0 ? fds_size / (int)sizeof(struct proc_fdinfo) : 0;

    for (int i = 0; i < fd_count; i++) {
        if (fds[i].proc_fdtype != PROX_FDTYPE_SOCKET) {
            continue;
        }
        struct socket_fdinfo si;
        int n = proc_pidfdinfo(pid, fds[i].proc_fd, PROC_PIDFDSOCKETINFO, &si,
                               sizeof(si));
        if (n != sizeof(si) || si.psi.soi_kind != SOCKINFO_TCP) {
            continue;
        }
        const struct tcp_sockinfo *tcp = &si.psi.soi_proto.pri_tcp;
        const struct in_sockinfo *in = &tcp->tcpsi_ini;

        syn_sock_record rec = *meta;
        rec.state = map_state(tcp->tcpsi_state);
        rec.lport = ntohs((uint16_t)in->insi_lport);
        rec.rport = ntohs((uint16_t)in->insi_fport);
        if (in->insi_vflag & INI_IPV6) {
            rec.is_ipv6 = 1;
            memcpy(rec.laddr, &in->insi_laddr.ina_6, 16);
            memcpy(rec.raddr, &in->insi_faddr.ina_6, 16);
        } else {
            rec.is_ipv6 = 0;
            memcpy(rec.laddr, &in->insi_laddr.ina_46.i46a_addr4, 4);
            memcpy(rec.raddr, &in->insi_faddr.ina_46.i46a_addr4, 4);
        }
        cb(ctx, &rec);
    }
    free(fds);
}

int32_t syn_sockets_snapshot(syn_sock_cb cb, void *ctx) {
    int pids_size = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
    if (pids_size <= 0) {
        return -1;
    }
    /* Headroom for processes spawned between the two calls. */
    pids_size += 16 * (int)sizeof(pid_t);
    pid_t *pids = malloc((size_t)pids_size);
    if (pids == NULL) {
        return -1;
    }
    pids_size = proc_listpids(PROC_ALL_PIDS, 0, pids, pids_size);
    if (pids_size <= 0) {
        free(pids);
        return -1;
    }
    int pid_count = pids_size / (int)sizeof(pid_t);

    for (int i = 0; i < pid_count; i++) {
        pid_t pid = pids[i];
        if (pid <= 0) {
            continue;
        }
        struct proc_bsdinfo info;
        int n = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
        if (n != sizeof(info)) {
            /* Died mid-walk, or another user's process without root — skip,
             * the caller documents what partial visibility means. */
            continue;
        }
        syn_sock_record meta;
        memset(&meta, 0, sizeof(meta));
        meta.pid = pid;
        meta.ppid = (int32_t)info.pbi_ppid;
        meta.uid = info.pbi_uid;
        meta.gid = info.pbi_gid;
        /* Best-effort; an empty path is forwarded honestly. */
        proc_pidpath(pid, meta.path, sizeof(meta.path));
        walk_pid_sockets(pid, &meta, cb, ctx);
    }
    free(pids);
    return 0;
}
