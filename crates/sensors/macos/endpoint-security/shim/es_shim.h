/* C shim between libEndpointSecurity and the Rust sensor (issue #32).
 *
 * Why a shim instead of Rust FFI against es_message_t: the message layout is
 * version-dependent (unions of ~100 event structs, fields gated on
 * `message version >= N`), and `es_new_client` takes an Objective-C block.
 * Transcribing that into #[repr(C)] Rust would be a silent-ABI-drift machine.
 * Here the shim is compiled against Apple's own headers on the build machine,
 * so every field access is checked by the C compiler, and Rust only ever sees
 * the flat, stable structs below.
 *
 * String fields point into the es_message_t (or into scratch buffers owned by
 * the shim) and are ONLY valid for the duration of the callback — the Rust
 * side copies what it keeps before returning.
 */
#ifndef SYNTHAEA_ES_SHIM_H
#define SYNTHAEA_ES_SHIM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque client handle. */
typedef struct syn_es_client syn_es_client;

/* Borrowed string: `data` is NULL when the field is absent; not NUL-terminated
 * (length-delimited, mirroring es_string_token_t). */
typedef struct {
    const char *data;
    size_t len;
} syn_es_str;

/* Identity of the acting process, common to every flattened event. */
typedef struct {
    int32_t pid;
    int32_t ppid;
    uint32_t uid; /* effective uid from the audit token */
    uint32_t gid; /* effective gid from the audit token */
    uint64_t wall_time_ns; /* message wall-clock time, ns since the UNIX epoch */
    syn_es_str process_path; /* executable path of the acting process */
} syn_es_meta;

/* Which ES event this flattened record carries. Values are the shim's own,
 * deliberately NOT es_event_type_t ordinals — those shift per SDK release and
 * transcribing them into Rust is exactly the drift this shim exists to avoid. */
enum syn_es_kind {
    SYN_ES_KIND_EXEC = 1,
    SYN_ES_KIND_OPEN = 2,
    SYN_ES_KIND_CREATE = 3,
    SYN_ES_KIND_RENAME = 4,
    SYN_ES_KIND_UNLINK = 5,
    /* mmap with PROT_WRITE on a MAP_SHARED mapping — the only mmap case
     * forwarded (a writable shared mapping mutates the file like a write;
     * everything else, e.g. dyld mapping libraries, is volume without signal). */
    SYN_ES_KIND_MMAP_WRITE_SHARED = 6,
    /* Background Task Management registered a launch item (launchd plist or
     * login item) — macOS 13+; never delivered on older hosts. */
    SYN_ES_KIND_BTM_LAUNCH_ITEM_ADD = 7,
};

/* Argv entries beyond this cap are dropped (argc_total still carries the real
 * count so the Rust side can flag the truncation). 128 covers everything but
 * pathological command lines; compiler/linker invocations that exceed it are
 * exactly the noise a cap exists for. */
#define SYN_ES_MAX_ARGV 128

/* One flattened event. Flat struct rather than a union: a few hundred spare
 * bytes per (stack-allocated, transient) event buys zero union-offset risk on
 * the Rust mirror. Only the fields for `kind` are meaningful; the rest are
 * zeroed. */
typedef struct {
    int32_t kind; /* enum syn_es_kind */
    syn_es_meta meta;

    /* SYN_ES_KIND_EXEC — meta describes the post-exec process (target). */
    syn_es_str exec_image_path;
    uint32_t exec_argc;       /* entries actually present in exec_argv */
    uint32_t exec_argc_total; /* real argc, may exceed SYN_ES_MAX_ARGV */
    syn_es_str exec_argv[SYN_ES_MAX_ARGV];
    syn_es_str exec_signing_id;
    syn_es_str exec_team_id;
    uint32_t exec_cs_flags; /* kernel codesigning flags (CS_VALID & co.) */
    uint8_t exec_is_platform_binary;
    /* Pre-exec image of the exec-ing process (the conventional parent-lineage
     * view: for fork+exec this is the parent's image the child still carried). */
    syn_es_str exec_parent_path;

    /* File events. OPEN/CREATE/UNLINK/MMAP: the target path. RENAME: the new
     * path. BTM: the launch item URL. */
    syn_es_str file_path;
    int32_t open_fflag; /* SYN_ES_KIND_OPEN: kernel fflag (FREAD/FWRITE bits) */
    syn_es_str rename_old_path; /* SYN_ES_KIND_RENAME only */

    /* SYN_ES_KIND_BTM_LAUNCH_ITEM_ADD */
    uint32_t btm_item_type; /* es_btm_item_type_t raw value */
    uint8_t btm_legacy;
    uint32_t btm_item_uid;
    syn_es_str btm_app_url;
    /* Executable path from the launchd plist, when BTM resolves one — the
     * actual persistence payload. */
    syn_es_str btm_executable_path;
} syn_es_event;

/* Subscription groups (bitflags) — the shim owns the mapping to concrete
 * es_event_type_t values so Rust never handles SDK ordinals. */
#define SYN_ES_GROUP_EXEC 0x1u
#define SYN_ES_GROUP_FILE 0x2u
#define SYN_ES_GROUP_PERSISTENCE 0x4u

/* Invoked synchronously on an EndpointSecurity dispatch thread for every
 * subscribed message. `event` and all strings it references are valid only
 * until the callback returns. */
typedef void (*syn_es_event_cb)(void *ctx, const syn_es_event *event);

/* Creates the ES client. Returns the raw es_new_client_result_t value
 * (0 = success; 3 = not entitled, 4 = not permitted/TCC, 5 = not privileged —
 * the Rust side maps these to actionable errors). On success `*out_client` is
 * set and must be released with syn_es_client_destroy from the SAME thread. */
int32_t syn_es_client_new(syn_es_event_cb cb, void *ctx, syn_es_client **out_client);

/* Subscribes to the event types in `groups`. Returns es_return_t (0 success). */
int32_t syn_es_subscribe(syn_es_client *client, uint32_t groups);

/* Mutes this process's own events (the agent writing its spool/alert files
 * must not feed back into the pipeline). Returns es_return_t (0 success). */
int32_t syn_es_mute_self(syn_es_client *client);

/* Unsubscribes and deletes the client. Must be called from the thread that
 * called syn_es_client_new (libEndpointSecurity requirement). */
void syn_es_client_destroy(syn_es_client *client);

#ifdef __cplusplus
}
#endif

#endif /* SYNTHAEA_ES_SHIM_H */
