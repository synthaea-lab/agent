/* See es_shim.h for why this shim exists. Compiled only on macOS (build.rs),
 * against the SDK's own EndpointSecurity headers, so every es_message_t field
 * access below is checked by the C compiler instead of hand-mirrored in Rust. */

#include "es_shim.h"

#include <Block.h>
#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <mach/mach.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/xattr.h>

struct syn_es_client {
    es_client_t *es;
    syn_es_event_cb cb;
    void *ctx;
};

static syn_es_str str_from_token(es_string_token_t token) {
    syn_es_str s = {token.data, token.length};
    return s;
}

static void fill_meta(syn_es_meta *meta, const es_process_t *proc,
                      const es_message_t *msg) {
    meta->pid = audit_token_to_pid(proc->audit_token);
    meta->ppid = proc->ppid;
    meta->uid = audit_token_to_euid(proc->audit_token);
    meta->gid = audit_token_to_egid(proc->audit_token);
    meta->wall_time_ns = (uint64_t)msg->time.tv_sec * 1000000000ull +
                         (uint64_t)msg->time.tv_nsec;
    meta->process_path = str_from_token(proc->executable->path);
}

/* Composes "<dir>/<name>" into buf; returns a str pointing at buf (valid while
 * buf is). Falls back to the name alone if the result would not fit. */
static syn_es_str compose_path(char *buf, size_t buf_len, es_string_token_t dir,
                               es_string_token_t name) {
    int n = snprintf(buf, buf_len, "%.*s/%.*s", (int)dir.length, dir.data,
                     (int)name.length, name.data);
    if (n < 0 || (size_t)n >= buf_len) {
        return str_from_token(name);
    }
    syn_es_str s = {buf, (size_t)n};
    return s;
}

/* Reads one xattr of `path` into buf; returns a str pointing at buf (valid
 * while buf is), or an absent str when the attribute is missing/unreadable —
 * e.g. the read raced the file's writer, which the Rust side treats as
 * "value unavailable", never as an error. */
static syn_es_str read_xattr(const char *path, const char *name, char *buf,
                             size_t buf_len) {
    syn_es_str absent = {NULL, 0};
    ssize_t n = getxattr(path, name, buf, buf_len, 0, 0);
    if (n < 0) {
        return absent;
    }
    syn_es_str s = {buf, (size_t)n};
    return s;
}

static void fill_mount(syn_es_event *ev, const struct statfs *fs, int mounted) {
    ev->kind = mounted ? SYN_ES_KIND_MOUNT : SYN_ES_KIND_UNMOUNT;
    syn_es_str on = {fs->f_mntonname, strnlen(fs->f_mntonname, MNAMELEN)};
    syn_es_str from = {fs->f_mntfromname, strnlen(fs->f_mntfromname, MNAMELEN)};
    syn_es_str type = {fs->f_fstypename, strnlen(fs->f_fstypename, MFSTYPENAMELEN)};
    ev->file_path = on;
    ev->mount_source = from;
    ev->mount_fs_type = type;
    ev->mount_readonly = (fs->f_flags & MNT_RDONLY) ? 1 : 0;
}

static void handle_message(syn_es_client *client, const es_message_t *msg) {
    /* Scratch for composed destination paths and xattr values — must outlive
     * the callback call below, hence declared at this scope. */
    char path_buf[2048];
    char quarantine_buf[1024];
    char wherefroms_buf[4096];

    syn_es_event ev;
    memset(&ev, 0, sizeof(ev));
    fill_meta(&ev.meta, msg->process, msg);

    switch (msg->event_type) {
    case ES_EVENT_TYPE_NOTIFY_EXEC: {
        const es_event_exec_t *exec = &msg->event.exec;
        const es_process_t *target = exec->target;
        ev.kind = SYN_ES_KIND_EXEC;
        /* meta describes the post-exec process; the pre-exec image is the
         * parent-lineage view (see header). exec does not change the pid, so
         * pid/ppid/uid/gid come from the target's own token. */
        ev.meta.pid = audit_token_to_pid(target->audit_token);
        ev.meta.ppid = target->ppid;
        ev.meta.uid = audit_token_to_euid(target->audit_token);
        ev.meta.gid = audit_token_to_egid(target->audit_token);
        ev.meta.process_path = str_from_token(target->executable->path);
        ev.exec_image_path = str_from_token(target->executable->path);
        uint32_t argc = es_exec_arg_count(exec);
        ev.exec_argc_total = argc;
        if (argc > SYN_ES_MAX_ARGV) {
            argc = SYN_ES_MAX_ARGV;
        }
        ev.exec_argc = argc;
        for (uint32_t i = 0; i < argc; i++) {
            ev.exec_argv[i] = str_from_token(es_exec_arg(exec, i));
        }
        ev.exec_signing_id = str_from_token(target->signing_id);
        ev.exec_team_id = str_from_token(target->team_id);
        ev.exec_cs_flags = target->codesigning_flags;
        ev.exec_is_platform_binary = target->is_platform_binary ? 1 : 0;
        ev.exec_parent_path = str_from_token(msg->process->executable->path);
        break;
    }
    case ES_EVENT_TYPE_NOTIFY_OPEN:
        ev.kind = SYN_ES_KIND_OPEN;
        ev.file_path = str_from_token(msg->event.open.file->path);
        ev.open_fflag = msg->event.open.fflag;
        break;
    case ES_EVENT_TYPE_NOTIFY_CREATE: {
        const es_event_create_t *create = &msg->event.create;
        ev.kind = SYN_ES_KIND_CREATE;
        if (create->destination_type == ES_DESTINATION_TYPE_EXISTING_FILE) {
            ev.file_path =
                str_from_token(create->destination.existing_file->path);
        } else {
            ev.file_path = compose_path(path_buf, sizeof(path_buf),
                                        create->destination.new_path.dir->path,
                                        create->destination.new_path.filename);
        }
        break;
    }
    case ES_EVENT_TYPE_NOTIFY_RENAME: {
        const es_event_rename_t *rename = &msg->event.rename;
        ev.kind = SYN_ES_KIND_RENAME;
        ev.rename_old_path = str_from_token(rename->source->path);
        if (rename->destination_type == ES_DESTINATION_TYPE_EXISTING_FILE) {
            ev.file_path =
                str_from_token(rename->destination.existing_file->path);
        } else {
            ev.file_path = compose_path(path_buf, sizeof(path_buf),
                                        rename->destination.new_path.dir->path,
                                        rename->destination.new_path.filename);
        }
        break;
    }
    case ES_EVENT_TYPE_NOTIFY_UNLINK:
        ev.kind = SYN_ES_KIND_UNLINK;
        ev.file_path = str_from_token(msg->event.unlink.target->path);
        break;
    case ES_EVENT_TYPE_NOTIFY_MMAP: {
        const es_event_mmap_t *mmap_ev = &msg->event.mmap;
        /* Only a writable shared mapping mutates the file (see header); the
         * torrent of read-only/private mappings (dyld, mapped resources) is
         * dropped here, before it ever crosses into Rust. */
        if ((mmap_ev->flags & MAP_SHARED) == 0 ||
            (mmap_ev->protection & PROT_WRITE) == 0) {
            return;
        }
        ev.kind = SYN_ES_KIND_MMAP_WRITE_SHARED;
        ev.file_path = str_from_token(mmap_ev->source->path);
        break;
    }
    case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD: {
        if (__builtin_available(macOS 13.0, *)) {
            /* Unlike the older event structs, the BTM event is a pointer
             * member of the union. */
            const es_event_btm_launch_item_add_t *btm =
                msg->event.btm_launch_item_add;
            ev.kind = SYN_ES_KIND_BTM_LAUNCH_ITEM_ADD;
            /* Attribute to the instigating process when BTM identifies one
             * (the XPC caller that asked for the registration); msg->process
             * is otherwise the BTM subsystem itself. */
            if (btm->instigator != NULL) {
                fill_meta(&ev.meta, btm->instigator, msg);
            }
            ev.file_path = str_from_token(btm->item->item_url);
            ev.btm_item_type = (uint32_t)btm->item->item_type;
            ev.btm_legacy = btm->item->legacy ? 1 : 0;
            ev.btm_item_uid = (uint32_t)btm->item->uid;
            ev.btm_app_url = str_from_token(btm->item->app_url);
            ev.btm_executable_path = str_from_token(btm->executable_path);
        } else {
            return;
        }
        break;
    }
    case ES_EVENT_TYPE_NOTIFY_SETEXTATTR: {
        const es_event_setextattr_t *set = &msg->event.setextattr;
        /* Only the quarantine mark is provenance; every other xattr write on
         * the system is dropped here, before crossing into Rust. */
        if (set->extattr.length != strlen("com.apple.quarantine") ||
            memcmp(set->extattr.data, "com.apple.quarantine",
                   set->extattr.length) != 0) {
            return;
        }
        ev.kind = SYN_ES_KIND_QUARANTINE;
        ev.file_path = str_from_token(set->target->path);
        /* getxattr needs a NUL-terminated path; ES tokens are
         * length-delimited, so copy. A path over the scratch size cannot be
         * read back — forward the event without the values. */
        int n = snprintf(path_buf, sizeof(path_buf), "%.*s",
                         (int)set->target->path.length, set->target->path.data);
        if (n >= 0 && (size_t)n < sizeof(path_buf)) {
            ev.quarantine_raw =
                read_xattr(path_buf, "com.apple.quarantine", quarantine_buf,
                           sizeof(quarantine_buf));
            ev.wherefroms_raw =
                read_xattr(path_buf, "com.apple.metadata:kMDItemWhereFroms",
                           wherefroms_buf, sizeof(wherefroms_buf));
        }
        break;
    }
    case ES_EVENT_TYPE_NOTIFY_MOUNT:
        fill_mount(&ev, msg->event.mount.statfs, 1);
        break;
    case ES_EVENT_TYPE_NOTIFY_UNMOUNT:
        fill_mount(&ev, msg->event.unmount.statfs, 0);
        break;
    case ES_EVENT_TYPE_NOTIFY_SIGNAL: {
        const es_event_signal_t *sig = &msg->event.signal;
        /* Tamper filter: only signals aimed at an EndpointSecurity client
         * (this agent, other security tools). The full system-wide signal
         * stream is volume without signal. */
        if (!sig->target->is_es_client) {
            return;
        }
        ev.kind = SYN_ES_KIND_SIGNAL_ES_CLIENT;
        ev.signal_number = sig->sig;
        ev.signal_target_pid = audit_token_to_pid(sig->target->audit_token);
        ev.file_path = str_from_token(sig->target->executable->path);
        break;
    }
    case ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN: {
        if (__builtin_available(macOS 13.0, *)) {
            const es_event_openssh_login_t *ssh = msg->event.openssh_login;
            ev.kind = SYN_ES_KIND_SSH_LOGIN;
            ev.auth_success = ssh->success ? 1 : 0;
            ev.auth_username = str_from_token(ssh->username);
            ev.auth_source_address = str_from_token(ssh->source_address);
        } else {
            return;
        }
        break;
    }
    case ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN: {
        if (__builtin_available(macOS 13.0, *)) {
            const es_event_login_login_t *login = msg->event.login_login;
            ev.kind = SYN_ES_KIND_LOGIN;
            ev.auth_success = login->success ? 1 : 0;
            ev.auth_username = str_from_token(login->username);
        } else {
            return;
        }
        break;
    }
    case ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN: {
        if (__builtin_available(macOS 13.0, *)) {
            const es_event_lw_session_login_t *lw = msg->event.lw_session_login;
            ev.kind = SYN_ES_KIND_LW_LOGIN;
            ev.auth_success = 1; /* loginwindow only reports completed logins */
            ev.auth_username = str_from_token(lw->username);
        } else {
            return;
        }
        break;
    }
    case ES_EVENT_TYPE_NOTIFY_XPC_CONNECT: {
        if (__builtin_available(macOS 14.0, *)) {
            const es_event_xpc_connect_t *xpc = msg->event.xpc_connect;
            ev.kind = SYN_ES_KIND_XPC_CONNECT;
            ev.xpc_service_name = str_from_token(xpc->service_name);
            ev.xpc_domain_type = (uint32_t)xpc->service_domain_type;
        } else {
            return;
        }
        break;
    }
    default:
        /* Not subscribed / not handled — nothing to forward. */
        return;
    }

    client->cb(client->ctx, &ev);
}

int32_t syn_es_client_new(syn_es_event_cb cb, void *ctx,
                          syn_es_client **out_client) {
    syn_es_client *client = calloc(1, sizeof(*client));
    if (client == NULL) {
        return ES_NEW_CLIENT_RESULT_ERR_INTERNAL;
    }
    client->cb = cb;
    client->ctx = ctx;

    es_client_t *es = NULL;
    es_new_client_result_t result =
        es_new_client(&es, ^(es_client_t *c, const es_message_t *msg) {
          (void)c;
          handle_message(client, msg);
        });
    if (result != ES_NEW_CLIENT_RESULT_SUCCESS) {
        free(client);
        return (int32_t)result;
    }
    client->es = es;
    *out_client = client;
    return (int32_t)ES_NEW_CLIENT_RESULT_SUCCESS;
}

int32_t syn_es_subscribe(syn_es_client *client, uint32_t groups) {
    es_event_type_t events[24];
    uint32_t count = 0;
    if (groups & SYN_ES_GROUP_EXEC) {
        events[count++] = ES_EVENT_TYPE_NOTIFY_EXEC;
    }
    if (groups & SYN_ES_GROUP_FILE) {
        events[count++] = ES_EVENT_TYPE_NOTIFY_OPEN;
        events[count++] = ES_EVENT_TYPE_NOTIFY_CREATE;
        events[count++] = ES_EVENT_TYPE_NOTIFY_RENAME;
        events[count++] = ES_EVENT_TYPE_NOTIFY_UNLINK;
        events[count++] = ES_EVENT_TYPE_NOTIFY_MMAP;
    }
    if (groups & SYN_ES_GROUP_PERSISTENCE) {
        /* BTM is macOS 13+; subscribing to an unknown event type fails the
         * whole es_subscribe call on older hosts, so gate it here. */
        if (__builtin_available(macOS 13.0, *)) {
            events[count++] = ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD;
        }
    }
    if (groups & SYN_ES_GROUP_SESSIONS) {
        if (__builtin_available(macOS 13.0, *)) {
            events[count++] = ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN;
            events[count++] = ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN;
            events[count++] = ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOGIN;
        }
    }
    if (groups & SYN_ES_GROUP_PROVENANCE) {
        events[count++] = ES_EVENT_TYPE_NOTIFY_SETEXTATTR;
    }
    if (groups & SYN_ES_GROUP_MOUNT) {
        events[count++] = ES_EVENT_TYPE_NOTIFY_MOUNT;
        events[count++] = ES_EVENT_TYPE_NOTIFY_UNMOUNT;
    }
    if (groups & SYN_ES_GROUP_TAMPER) {
        events[count++] = ES_EVENT_TYPE_NOTIFY_SIGNAL;
    }
    if (groups & SYN_ES_GROUP_XPC) {
        if (__builtin_available(macOS 14.0, *)) {
            events[count++] = ES_EVENT_TYPE_NOTIFY_XPC_CONNECT;
        }
    }
    if (count == 0) {
        return (int32_t)ES_RETURN_SUCCESS;
    }
    return (int32_t)es_subscribe(client->es, events, count);
}

int32_t syn_es_mute_self(syn_es_client *client) {
    audit_token_t token;
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    kern_return_t kr = task_info(mach_task_self(), TASK_AUDIT_TOKEN,
                                 (task_info_t)&token, &count);
    if (kr != KERN_SUCCESS) {
        return (int32_t)ES_RETURN_ERROR;
    }
    return (int32_t)es_mute_process(client->es, &token);
}

void syn_es_client_destroy(syn_es_client *client) {
    if (client == NULL) {
        return;
    }
    if (client->es != NULL) {
        es_unsubscribe_all(client->es);
        es_delete_client(client->es);
    }
    free(client);
}
