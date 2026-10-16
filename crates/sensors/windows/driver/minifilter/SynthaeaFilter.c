/*++

Copyright (c) 1999 - 2002  Microsoft Corporation

    Adapted for Synthaea from microsoft/Windows-driver-samples
    (filesys/miniFilter/nullFilter), Microsoft Public License (MS-PL): see
    LICENSE.windows-driver-samples next to this file.

Module Name:

    SynthaeaFilter.c

Abstract:

    This is the main module of the SynthaeaFilter mini filter driver.
    Milestone 2c (#136): it reports successful delete and rename requests
    over the agent communication port. The port
    follows ADR-0012 guardrails 2 and 5: SYSTEM/Administrators-only
    security descriptor, a single connection, and a connect callback that
    accepts only the agent (NT SERVICE\SynthaEDR in its token) and
    validates the client's connection context before accepting it. No
    message callback is registered, so user mode cannot send anything to
    the driver; the channel is kernel -> user only.

Environment:

    Kernel mode

--*/

#include <fltKernel.h>
#include <dontuse.h>
#include <ntintsafe.h>
#include <suppress.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

//---------------------------------------------------------------------------
//      Port protocol (mirrored by the user-mode client, keep in sync)
//---------------------------------------------------------------------------

#define SYNTHAEA_PORT_NAME          L"\\SynthaeaPort"
#define SYNTHAEA_CONNECT_MAGIC      0x544E5953UL    // 'SYNT', little-endian
#define SYNTHAEA_PROTOCOL_VERSION   3UL

#define SYNTHAEA_EVENT_HEARTBEAT            0
#define SYNTHAEA_EVENT_DELETE               1
#define SYNTHAEA_EVENT_RENAME               2
#define SYNTHAEA_EVENT_FLAG_DELETE_ON_CLOSE 0x0001
#define SYNTHAEA_EVENT_FLAG_OLD_TRUNCATED   0x0002
#define SYNTHAEA_EVENT_FLAG_NEW_TRUNCATED   0x0004
#define SYNTHAEA_MAX_PATH_CHARS             4096
#define SYNTHAEA_MAX_QUEUE_RECORDS          8192
#define SYNTHAEA_MAX_QUEUE_BYTES            (16 * 1024 * 1024)
#define SYNTHAEA_SEND_TIMEOUT_100NS         (-1000000LL) // 100 ms
#define SYNTHAEA_HEARTBEAT_TIMEOUT_100NS    (-50000000LL) // 5 s
#define SYNTHAEA_POOL_TAG                   'aeyS'

// The wire header is fixed-width little-endian. Do not change its layout
// without changing the Rust decoder in lockstep.
#pragma pack(push, 1)
typedef struct _SYNTHAEA_EVENT_HEADER {
    USHORT Kind;
    USHORT Flags;
    ULONGLONG Sequence;
    LONGLONG Timestamp;
    ULONGLONG ProcessId;
    ULONGLONG ThreadId;
    ULONGLONG DroppedQueueFull;
    ULONGLONG DroppedSendFailed;
    ULONGLONG NotConnected;
    USHORT OldPathLength;
    USHORT NewPathLength;
    ULONGLONG DroppedCaptureFailed;
} SYNTHAEA_EVENT_HEADER, *PSYNTHAEA_EVENT_HEADER;
#pragma pack(pop)

C_ASSERT(FIELD_OFFSET(SYNTHAEA_EVENT_HEADER, Kind) == 0);
C_ASSERT(FIELD_OFFSET(SYNTHAEA_EVENT_HEADER, Flags) == 2);
C_ASSERT(FIELD_OFFSET(SYNTHAEA_EVENT_HEADER, Sequence) == 4);
C_ASSERT(FIELD_OFFSET(SYNTHAEA_EVENT_HEADER, Timestamp) == 12);
C_ASSERT(FIELD_OFFSET(SYNTHAEA_EVENT_HEADER, ProcessId) == 20);
C_ASSERT(FIELD_OFFSET(SYNTHAEA_EVENT_HEADER, ThreadId) == 28);
C_ASSERT(FIELD_OFFSET(SYNTHAEA_EVENT_HEADER, DroppedQueueFull) == 36);
C_ASSERT(FIELD_OFFSET(SYNTHAEA_EVENT_HEADER, DroppedSendFailed) == 44);
C_ASSERT(FIELD_OFFSET(SYNTHAEA_EVENT_HEADER, NotConnected) == 52);
C_ASSERT(FIELD_OFFSET(SYNTHAEA_EVENT_HEADER, OldPathLength) == 60);
C_ASSERT(FIELD_OFFSET(SYNTHAEA_EVENT_HEADER, NewPathLength) == 62);
C_ASSERT(FIELD_OFFSET(SYNTHAEA_EVENT_HEADER, DroppedCaptureFailed) == 64);
C_ASSERT(sizeof(SYNTHAEA_EVENT_HEADER) == 72);

typedef struct _SYNTHAEA_QUEUED_EVENT {
    LIST_ENTRY Link;
    SIZE_T AllocationSize;
    BOOLEAN ReservationHeld;
    UCHAR Reserved[3];
    SYNTHAEA_EVENT_HEADER Header;
    WCHAR Paths[ANYSIZE_ARRAY];
} SYNTHAEA_QUEUED_EVENT, *PSYNTHAEA_QUEUED_EVENT;

typedef struct _SYNTHAEA_RENAME_INFORMATION {
    union {
        BOOLEAN ReplaceIfExists;
        ULONG Flags;
    } RenameFlags;
    HANDLE RootDirectory;
    ULONG FileNameLength;
    WCHAR FileName[ANYSIZE_ARRAY];
} SYNTHAEA_RENAME_INFORMATION, *PSYNTHAEA_RENAME_INFORMATION;

typedef struct _SYNTHAEA_DISPOSITION_INFORMATION_EX {
    ULONG Flags;
} SYNTHAEA_DISPOSITION_INFORMATION_EX, *PSYNTHAEA_DISPOSITION_INFORMATION_EX;

#define SYNTHAEA_FILE_DISPOSITION_DELETE 0x00000001

//
//  What a client must pass as the connection context of
//  FilterConnectCommunicationPort. Anything else is refused.
//

typedef struct _SYNTHAEA_CONNECT_CONTEXT {

    ULONG Magic;
    ULONG Version;

} SYNTHAEA_CONNECT_CONTEXT, *PSYNTHAEA_CONNECT_CONTEXT;

//
//  Guardrail 5, "only the agent may connect": the caller's primary token
//  must hold NT SERVICE\SynthaEDR, the service SID of the watchdog service
//  that spawns the agent (the agent inherits the watchdog's token). A
//  service SID is derived from the service name alone, so it is a constant:
//  `sc showsid SynthaEDR` gives
//  S-1-5-80-3000362003-865703788-3960528645-4228801270-24284304.
//  Windows only puts it in the token when the service is configured with
//  `sc sidtype SynthaEDR unrestricted`, which `watchdog install` does.
//

//
//  TOKEN_GROUPS attribute; the kernel headers don't define it (um/winnt.h does).
//

#ifndef SE_GROUP_ENABLED
#define SE_GROUP_ENABLED    (0x00000004L)
#endif

typedef struct _SYNTHAEA_SERVICE_SID {

    UCHAR Revision;
    UCHAR SubAuthorityCount;
    SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
    ULONG SubAuthority[6];

} SYNTHAEA_SERVICE_SID;

static const SYNTHAEA_SERVICE_SID SynthaeaAgentServiceSid = {
    SID_REVISION,
    6,
    SECURITY_NT_AUTHORITY,
    { SECURITY_SERVICE_ID_BASE_RID,
      3000362003UL, 865703788UL, 3960528645UL, 4228801270UL, 24284304UL }
};

//---------------------------------------------------------------------------
//      Global variables
//---------------------------------------------------------------------------


typedef struct _SYNTHAEA_FILTER_DATA {

    //
    //  The filter handle that results from a call to
    //  FltRegisterFilter.
    //

    PFLT_FILTER FilterHandle;

    //
    //  The server port the agent connects to, and the single client
    //  port once connected (NULL otherwise).
    //

    PFLT_PORT ServerPort;
    PFLT_PORT ClientPort;

    //
    //  Event channel state. QueueLock protects Queue, queue capacity,
    //  connection wakeups, and each record's reservation ownership.
    //

    KSPIN_LOCK QueueLock;
    LIST_ENTRY Queue;
    ULONG QueueRecords;
    SIZE_T QueueBytes;
    KEVENT QueueEvent;
    KEVENT StopEvent;
    PETHREAD SenderThread;
    volatile LONG Stopping;

    EX_RUNDOWN_REF ClientRundown;
    volatile LONG Connected;
    volatile LONG AgentProcessId;
    volatile LONG64 Sequence;
    volatile LONG64 DroppedQueueFull;
    volatile LONG64 DroppedSendFailed;
    volatile LONG64 NotConnected;
    volatile LONG64 DroppedCaptureFailed;

} SYNTHAEA_FILTER_DATA, *PSYNTHAEA_FILTER_DATA;


/*************************************************************************
    Prototypes for the startup and unload routines used for
    this Filter.

    Implementation in SynthaeaFilter.c
*************************************************************************/

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

NTSTATUS
SynthaeaUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

NTSTATUS
SynthaeaQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );

NTSTATUS
SynthaeaPortConnect (
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie
    );

VOID
SynthaeaPortDisconnect (
    _In_opt_ PVOID ConnectionCookie
    );

NTSTATUS
SynthaeaCreatePort (
    VOID
    );

BOOLEAN
SynthaeaCallerIsAgent (
    VOID
    );

FLT_PREOP_CALLBACK_STATUS
SynthaeaPreCreate (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID *CompletionContext
    );

FLT_PREOP_CALLBACK_STATUS
SynthaeaPreSetInformation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID *CompletionContext
    );

FLT_POSTOP_CALLBACK_STATUS
SynthaeaPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

VOID
SynthaeaSenderThread (
    _In_opt_ PVOID StartContext
    );

PSYNTHAEA_QUEUED_EVENT
SynthaeaAllocateEvent (
    _In_ USHORT Kind,
    _In_ USHORT Flags,
    _In_opt_ PFLT_FILE_NAME_INFORMATION OldName,
    _In_opt_ PFLT_FILE_NAME_INFORMATION NewName,
    _In_ ULONG ProcessId,
    _In_ ULONGLONG ThreadId
    );

VOID
SynthaeaReleaseReservation (
    _Inout_ PSYNTHAEA_QUEUED_EVENT Event
    );

VOID
SynthaeaFreeEvent (
    _In_opt_ PSYNTHAEA_QUEUED_EVENT Event
    );

BOOLEAN
SynthaeaShouldSkip (
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    );

VOID
SynthaeaSetEventCounters (
    _Inout_ PSYNTHAEA_EVENT_HEADER Header
    );

NTSTATUS
SynthaeaSendBuffer (
    _In_reads_bytes_(BufferLength) PVOID Buffer,
    _In_ ULONG BufferLength
    );

VOID
SynthaeaStopSender (
    VOID
    );

BOOLEAN
SynthaeaReserveQueue (
    _In_ SIZE_T AllocationSize
    );

VOID
SynthaeaReleaseReservationLocked (
    _Inout_ PSYNTHAEA_QUEUED_EVENT Event
    );

NTSTATUS
SynthaeaStartSender (
    VOID
    );

VOID
SynthaeaFreeQueuedEvents (
    VOID
    );

VOID
SynthaeaActivateClient (
    _In_ PFLT_PORT ClientPort
    );

VOID
SynthaeaDeactivateClient (
    VOID
    );

//
//  Structure that contains all the global data structures
//  used throughout SynthaeaFilter.
//

SYNTHAEA_FILTER_DATA SynthaeaFilterData;
static UCHAR SynthaeaQueueFullSentinel;
static UCHAR SynthaeaCaptureFailedSentinel;

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, SynthaeaUnload)
#pragma alloc_text(PAGE, SynthaeaQueryTeardown)
#pragma alloc_text(PAGE, SynthaeaPortConnect)
#pragma alloc_text(PAGE, SynthaeaPortDisconnect)
#pragma alloc_text(PAGE, SynthaeaCreatePort)
#pragma alloc_text(PAGE, SynthaeaCallerIsAgent)
#endif

CONST FLT_OPERATION_REGISTRATION SynthaeaCallbacks[] = {
    { IRP_MJ_CREATE, 0, SynthaeaPreCreate, SynthaeaPostOperation },
    { IRP_MJ_SET_INFORMATION, 0, SynthaeaPreSetInformation, SynthaeaPostOperation },
    { IRP_MJ_OPERATION_END }
};


//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

    NULL,                               //  Context
    SynthaeaCallbacks,                  //  Operation callbacks

    SynthaeaUnload,                         //  FilterUnload

    NULL,                               //  InstanceSetup
    SynthaeaQueryTeardown,                  //  InstanceQueryTeardown
    NULL,                               //  InstanceTeardownStart
    NULL,                               //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};


/*************************************************************************
    Filter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    This is the initialization routine for this miniFilter driver. This
    registers the miniFilter with FltMgr and initializes all
    its global data structures.

Arguments:

    DriverObject - Pointer to driver object created by the system to
        represent this driver.
    RegistryPath - Unicode string identifying where the parameters for this
        driver are located in the registry.

Return Value:

    Returns STATUS_SUCCESS.

--*/
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( RegistryPath );

    KeInitializeSpinLock( &SynthaeaFilterData.QueueLock );
    InitializeListHead( &SynthaeaFilterData.Queue );
    KeInitializeEvent( &SynthaeaFilterData.QueueEvent, NotificationEvent, FALSE );
    KeInitializeEvent( &SynthaeaFilterData.StopEvent, NotificationEvent, FALSE );
    ExInitializeRundownProtection( &SynthaeaFilterData.ClientRundown );

    status = SynthaeaStartSender();
    if (!NT_SUCCESS( status )) {
        return status;
    }

    //
    //  Register with FltMgr
    //

    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &SynthaeaFilterData.FilterHandle );

    //
    //  No FLT_ASSERT on the status: it is NT_ASSERT, which bugchecks a Debug
    //  build with no kernel debugger attached before the failure is traced
    //  below (reachable when the service has no Instances key).
    //

    if (NT_SUCCESS( status )) {

        //
        //  Create the agent's communication port before filtering starts,
        //  so there is never a window where the filter runs without it.
        //

        status = SynthaeaCreatePort();

        if (!NT_SUCCESS( status )) {
            SynthaeaStopSender();
            FltUnregisterFilter( SynthaeaFilterData.FilterHandle );
            SynthaeaFreeQueuedEvents();
            return status;
        }

        //
        //  Start filtering i/o
        //

        status = FltStartFiltering( SynthaeaFilterData.FilterHandle );

        if (!NT_SUCCESS( status )) {
            DbgPrintEx( DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                        "SynthaeaFilter: FltStartFiltering failed 0x%08X\n", status );
            FltCloseCommunicationPort( SynthaeaFilterData.ServerPort );
            SynthaeaFilterData.ServerPort = NULL;
            SynthaeaStopSender();
            FltUnregisterFilter( SynthaeaFilterData.FilterHandle );
            SynthaeaFreeQueuedEvents();
        } else {
            DbgPrintEx( DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                        "SynthaeaFilter: loaded, filtering started\n" );
        }
    } else {
        SynthaeaStopSender();
        DbgPrintEx( DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "SynthaeaFilter: FltRegisterFilter failed 0x%08X\n", status );
    }
    return status;
}

NTSTATUS
SynthaeaUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
/*++

Routine Description:

    This is the unload routine for this miniFilter driver. This is called
    when the minifilter is about to be unloaded. We can fail this unload
    request if this is not a mandatory unloaded indicated by the Flags
    parameter.

Arguments:

    Flags - Indicating if this is a mandatory unload.

Return Value:

    Returns the final status of this operation.

--*/
{
    PAGED_CODE();

    DbgPrintEx( DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "SynthaeaFilter: unloading (flags 0x%08X)\n", Flags );

    //
    //  Closing the server port refuses new connections. Stop the sender
    //  before unregistering, then let FltUnregisterFilter unregister callbacks
    //  and tear down instances before freeing callback-visible queue state.
    //  Filter Manager's "Unregistering the Minifilter" and
    //  "Loading and Unloading a Minifilter" contracts make unregister the
    //  synchronization point for callback/instance teardown and outstanding I/O.
    //

    FltCloseCommunicationPort( SynthaeaFilterData.ServerPort );
    SynthaeaFilterData.ServerPort = NULL;
    SynthaeaStopSender();
    FltUnregisterFilter( SynthaeaFilterData.FilterHandle );
    SynthaeaFilterData.FilterHandle = NULL;
    SynthaeaFreeQueuedEvents();

    return STATUS_SUCCESS;
}

NTSTATUS
SynthaeaQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
/*++

Routine Description:

    This is the instance detach routine for this miniFilter driver.
    This is called when an instance is being manually deleted by a
    call to FltDetachVolume or FilterDetach thereby giving us a
    chance to fail that detach request.

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance and its associated volume.

    Flags - Indicating where this detach request came from.

Return Value:

    Returns the status of this operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    return STATUS_SUCCESS;
}


/*************************************************************************
    Kernel-to-agent event channel (milestone 2c, issue #136).
*************************************************************************/

BOOLEAN
SynthaeaShouldSkip (
    _In_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects
    )
{
    ULONG requestorPid;
    LONG agentPid;

    if (Data == NULL || FltObjects == NULL || FltObjects->FileObject == NULL ||
        FlagOn( Data->Iopb->IrpFlags, IRP_PAGING_IO ) ||
        InterlockedCompareExchange( &SynthaeaFilterData.Stopping, 0, 0 ) != 0) {
        return TRUE;
    }

    requestorPid = FltGetRequestorProcessId( Data );
    agentPid = InterlockedCompareExchange( &SynthaeaFilterData.AgentProcessId, 0, 0 );
    return agentPid != 0 && requestorPid == (ULONG)agentPid;
}

VOID
SynthaeaActivateClient (
    _In_ PFLT_PORT ClientPort
    )
{
    KIRQL oldIrql;

    KeAcquireSpinLock( &SynthaeaFilterData.QueueLock, &oldIrql );
    ExReInitializeRundownProtection( &SynthaeaFilterData.ClientRundown );
    SynthaeaFilterData.ClientPort = ClientPort;
    InterlockedExchange( &SynthaeaFilterData.AgentProcessId,
                         (LONG)(ULONG_PTR)PsGetCurrentProcessId() );
    InterlockedExchange64( &SynthaeaFilterData.Sequence, 0 );
    InterlockedExchange( &SynthaeaFilterData.Connected, 1 );
    KeSetEvent( &SynthaeaFilterData.QueueEvent, IO_NO_INCREMENT, FALSE );
    KeReleaseSpinLock( &SynthaeaFilterData.QueueLock, oldIrql );
}

VOID
SynthaeaDeactivateClient (
    VOID
    )
{
    KIRQL oldIrql;

    KeAcquireSpinLock( &SynthaeaFilterData.QueueLock, &oldIrql );
    InterlockedExchange( &SynthaeaFilterData.Connected, 0 );
    InterlockedExchange( &SynthaeaFilterData.AgentProcessId, 0 );
    KeResetEvent( &SynthaeaFilterData.QueueEvent );
    KeReleaseSpinLock( &SynthaeaFilterData.QueueLock, oldIrql );
}

BOOLEAN
SynthaeaReserveQueue (
    _In_ SIZE_T AllocationSize
    )
{
    KIRQL oldIrql;
    BOOLEAN reserved = FALSE;

    KeAcquireSpinLock( &SynthaeaFilterData.QueueLock, &oldIrql );
    if (InterlockedCompareExchange( &SynthaeaFilterData.Stopping, 0, 0 ) == 0 &&
        SynthaeaFilterData.QueueRecords < SYNTHAEA_MAX_QUEUE_RECORDS &&
        AllocationSize <= (SIZE_T)SYNTHAEA_MAX_QUEUE_BYTES &&
        SynthaeaFilterData.QueueBytes <= SYNTHAEA_MAX_QUEUE_BYTES - AllocationSize) {
        SynthaeaFilterData.QueueRecords++;
        SynthaeaFilterData.QueueBytes += AllocationSize;
        reserved = TRUE;
    }
    KeReleaseSpinLock( &SynthaeaFilterData.QueueLock, oldIrql );

    return reserved;
}

VOID
SynthaeaReleaseReservationLocked (
    _Inout_ PSYNTHAEA_QUEUED_EVENT Event
    )
{
    if (Event->ReservationHeld) {
        Event->ReservationHeld = FALSE;
        if (SynthaeaFilterData.QueueRecords != 0) {
            SynthaeaFilterData.QueueRecords--;
        }
        if (SynthaeaFilterData.QueueBytes >= Event->AllocationSize) {
            SynthaeaFilterData.QueueBytes -= Event->AllocationSize;
        } else {
            SynthaeaFilterData.QueueBytes = 0;
        }
    }
}

VOID
SynthaeaReleaseReservation (
    _Inout_ PSYNTHAEA_QUEUED_EVENT Event
    )
{
    KIRQL oldIrql;
    KeAcquireSpinLock( &SynthaeaFilterData.QueueLock, &oldIrql );
    SynthaeaReleaseReservationLocked( Event );
    KeReleaseSpinLock( &SynthaeaFilterData.QueueLock, oldIrql );
}

VOID
SynthaeaFreeEvent (
    _In_opt_ PSYNTHAEA_QUEUED_EVENT Event
    )
{
    if (Event != NULL) {
        SynthaeaReleaseReservation( Event );
        ExFreePoolWithTag( Event, SYNTHAEA_POOL_TAG );
    }
}

PSYNTHAEA_QUEUED_EVENT
SynthaeaAllocateEvent (
    _In_ USHORT Kind,
    _In_ USHORT Flags,
    _In_opt_ PFLT_FILE_NAME_INFORMATION OldName,
    _In_opt_ PFLT_FILE_NAME_INFORMATION NewName,
    _In_ ULONG ProcessId,
    _In_ ULONGLONG ThreadId
    )
{
    ULONG oldChars = 0;
    ULONG newChars = 0;
    SIZE_T pathBytes;
    SIZE_T allocationSize;
    SIZE_T oldPathBytes;
    SIZE_T newPathBytes;
    PSYNTHAEA_QUEUED_EVENT event;
    LARGE_INTEGER timestamp;
    NTSTATUS sizeStatus;

    if (OldName != NULL) {
        oldChars = OldName->Name.Length / sizeof(WCHAR);
        if (oldChars > SYNTHAEA_MAX_PATH_CHARS) {
            oldChars = SYNTHAEA_MAX_PATH_CHARS;
            Flags |= SYNTHAEA_EVENT_FLAG_OLD_TRUNCATED;
        }
    }
    if (NewName != NULL) {
        newChars = NewName->Name.Length / sizeof(WCHAR);
        if (newChars > SYNTHAEA_MAX_PATH_CHARS) {
            newChars = SYNTHAEA_MAX_PATH_CHARS;
            Flags |= SYNTHAEA_EVENT_FLAG_NEW_TRUNCATED;
        }
    }

    // Keep the allocation arithmetic explicitly bounded for both pool safety
    // and the static analyzer; each wire path is limited to 4096 WCHARs.
    if (oldChars > SYNTHAEA_MAX_PATH_CHARS ||
        newChars > SYNTHAEA_MAX_PATH_CHARS) {
        return (PSYNTHAEA_QUEUED_EVENT)&SynthaeaQueueFullSentinel;
    }

    oldPathBytes = (SIZE_T)oldChars * sizeof(WCHAR);
    newPathBytes = (SIZE_T)newChars * sizeof(WCHAR);
    if (oldPathBytes > (SIZE_T)(SYNTHAEA_MAX_PATH_CHARS * sizeof(WCHAR)) ||
        newPathBytes > (SIZE_T)(SYNTHAEA_MAX_PATH_CHARS * sizeof(WCHAR))) {
        return (PSYNTHAEA_QUEUED_EVENT)&SynthaeaQueueFullSentinel;
    }

    sizeStatus = RtlSizeTAdd( oldPathBytes, newPathBytes, &pathBytes );
    if (!NT_SUCCESS( sizeStatus ) ||
        pathBytes > (SIZE_T)(2 * SYNTHAEA_MAX_PATH_CHARS * sizeof(WCHAR))) {
        return (PSYNTHAEA_QUEUED_EVENT)&SynthaeaQueueFullSentinel;
    }

    // Include the declared one-WCHAR tail in sizeof; a zero-path event still
    // needs a complete SYNTHAEA_QUEUED_EVENT object.
    allocationSize = sizeof( SYNTHAEA_QUEUED_EVENT );
    sizeStatus = RtlSizeTAdd( allocationSize, pathBytes, &allocationSize );
    if (!NT_SUCCESS( sizeStatus ) ||
        allocationSize < sizeof( SYNTHAEA_QUEUED_EVENT )) {
        return (PSYNTHAEA_QUEUED_EVENT)&SynthaeaQueueFullSentinel;
    }

    if (!SynthaeaReserveQueue( allocationSize )) {
        return (PSYNTHAEA_QUEUED_EVENT)&SynthaeaQueueFullSentinel;
    }

    event = (PSYNTHAEA_QUEUED_EVENT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, allocationSize, SYNTHAEA_POOL_TAG );
    if (event == NULL) {
        KIRQL oldIrql;
        KeAcquireSpinLock( &SynthaeaFilterData.QueueLock, &oldIrql );
        // The reservation was made before allocation, so release it without
        // requiring a partially initialized record.
        SynthaeaFilterData.QueueRecords--;
        SynthaeaFilterData.QueueBytes -= allocationSize;
        KeReleaseSpinLock( &SynthaeaFilterData.QueueLock, oldIrql );
        return (PSYNTHAEA_QUEUED_EVENT)&SynthaeaQueueFullSentinel;
    }

    RtlZeroMemory( event, sizeof( SYNTHAEA_QUEUED_EVENT ) );
    event->AllocationSize = allocationSize;
    event->ReservationHeld = TRUE;
    event->Header.Kind = Kind;
    event->Header.Flags = Flags;
    event->Header.ProcessId = ProcessId;
    event->Header.ThreadId = ThreadId;
    event->Header.OldPathLength = (USHORT)oldChars;
    event->Header.NewPathLength = (USHORT)newChars;
    KeQuerySystemTimePrecise( &timestamp );
    event->Header.Timestamp = timestamp.QuadPart;

    if (oldPathBytes != 0) {
        RtlCopyMemory( event->Paths, OldName->Name.Buffer, oldPathBytes );
    }
    if (newPathBytes != 0) {
        RtlCopyMemory( (PUCHAR)event->Paths + oldPathBytes,
                       NewName->Name.Buffer, newPathBytes );
    }
    return event;
}

FLT_PREOP_CALLBACK_STATUS
SynthaeaPreCreate (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID *CompletionContext
    )
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PSYNTHAEA_QUEUED_EVENT event;
    NTSTATUS status;

    *CompletionContext = NULL;
    if (SynthaeaShouldSkip( Data, FltObjects )) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (!FlagOn( Data->Iopb->Parameters.Create.Options, FILE_DELETE_ON_CLOSE )) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    // This records a successful delete-on-close request, not the later final
    // removal that occurs when the last handle is closed.
    if (InterlockedCompareExchange( &SynthaeaFilterData.Connected, 0, 0 ) == 0) {
        InterlockedIncrement64( &SynthaeaFilterData.NotConnected );
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetFileNameInformation(
        Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo );
    if (!NT_SUCCESS( status )) {
        *CompletionContext = &SynthaeaCaptureFailedSentinel;
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    event = SynthaeaAllocateEvent( SYNTHAEA_EVENT_DELETE,
                                   SYNTHAEA_EVENT_FLAG_DELETE_ON_CLOSE,
                                   nameInfo, NULL,
                                   FltGetRequestorProcessId( Data ),
                                   (ULONGLONG)(ULONG_PTR)PsGetCurrentThreadId() );
    FltReleaseFileNameInformation( nameInfo );
    if (event == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    *CompletionContext = event;
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
SynthaeaPreSetInformation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID *CompletionContext
    )
{
    FILE_INFORMATION_CLASS informationClass;
    PVOID infoBuffer;
    ULONG infoLength;
    PFLT_FILE_NAME_INFORMATION oldName = NULL;
    PFLT_FILE_NAME_INFORMATION newName = NULL;
    PSYNTHAEA_QUEUED_EVENT event = NULL;
    USHORT kind = 0;
    USHORT eventFlags = 0;
    NTSTATUS status;

    *CompletionContext = NULL;
    if (SynthaeaShouldSkip( Data, FltObjects )) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (InterlockedCompareExchange( &SynthaeaFilterData.Connected, 0, 0 ) == 0) {
        InterlockedIncrement64( &SynthaeaFilterData.NotConnected );
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    informationClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
    infoBuffer = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
    infoLength = Data->Iopb->Parameters.SetFileInformation.Length;
    if (infoBuffer == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (informationClass == FileDispositionInformation) {
        if (infoLength < sizeof( FILE_DISPOSITION_INFORMATION ) ||
            !((PFILE_DISPOSITION_INFORMATION)infoBuffer)->DeleteFile) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        kind = SYNTHAEA_EVENT_DELETE;
    } else if (informationClass == FileDispositionInformationEx) {
        if (infoLength < sizeof( SYNTHAEA_DISPOSITION_INFORMATION_EX ) ||
            !FlagOn( ((PSYNTHAEA_DISPOSITION_INFORMATION_EX)infoBuffer)->Flags,
                     SYNTHAEA_FILE_DISPOSITION_DELETE )) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }
        kind = SYNTHAEA_EVENT_DELETE;
    } else if (informationClass == FileRenameInformation ||
               informationClass == FileRenameInformationEx) {
        PSYNTHAEA_RENAME_INFORMATION renameInfo =
            (PSYNTHAEA_RENAME_INFORMATION)infoBuffer;
        ULONG headerLength = FIELD_OFFSET( SYNTHAEA_RENAME_INFORMATION, FileName );

        if (infoLength < headerLength || renameInfo->FileNameLength == 0 ||
            (renameInfo->FileNameLength % sizeof(WCHAR)) != 0 ||
            renameInfo->FileNameLength > infoLength - headerLength) {
            return FLT_PREOP_SUCCESS_NO_CALLBACK;
        }

        kind = SYNTHAEA_EVENT_RENAME;
        status = FltGetFileNameInformation(
            Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &oldName );
        if (!NT_SUCCESS( status )) {
            *CompletionContext = &SynthaeaCaptureFailedSentinel;
            return FLT_PREOP_SUCCESS_WITH_CALLBACK;
        }

        status = FltGetDestinationFileNameInformation(
            FltObjects->Instance, FltObjects->FileObject,
            renameInfo->RootDirectory, renameInfo->FileName,
            renameInfo->FileNameLength,
            FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &newName );
        if (!NT_SUCCESS( status )) {
            FltReleaseFileNameInformation( oldName );
            *CompletionContext = &SynthaeaCaptureFailedSentinel;
            return FLT_PREOP_SUCCESS_WITH_CALLBACK;
        }
    } else {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (kind == SYNTHAEA_EVENT_DELETE) {
        status = FltGetFileNameInformation(
            Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &oldName );
        if (!NT_SUCCESS( status )) {
            *CompletionContext = &SynthaeaCaptureFailedSentinel;
            return FLT_PREOP_SUCCESS_WITH_CALLBACK;
        }
    }

    event = SynthaeaAllocateEvent( kind, eventFlags, oldName, newName,
                                   FltGetRequestorProcessId( Data ),
                                   (ULONGLONG)(ULONG_PTR)PsGetCurrentThreadId() );
    if (newName != NULL) {
        FltReleaseFileNameInformation( newName );
    }
    if (oldName != NULL) {
        FltReleaseFileNameInformation( oldName );
    }
    if (event == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    *CompletionContext = event;
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS
SynthaeaPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
{
    PSYNTHAEA_QUEUED_EVENT event = (PSYNTHAEA_QUEUED_EVENT)CompletionContext;
    KIRQL oldIrql;

    UNREFERENCED_PARAMETER( FltObjects );
    // The sentinels let pre-op defer loss accounting until this operation's
    // result is known; failed file operations were never expected telemetry.
    if (CompletionContext == &SynthaeaCaptureFailedSentinel) {
        if (NT_SUCCESS( Data->IoStatus.Status )) {
            InterlockedIncrement64( &SynthaeaFilterData.DroppedCaptureFailed );
        }
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (CompletionContext == &SynthaeaQueueFullSentinel) {
        if (NT_SUCCESS( Data->IoStatus.Status )) {
            InterlockedIncrement64( &SynthaeaFilterData.DroppedQueueFull );
        }
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (event == NULL) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    // Post-op can run at DISPATCH_LEVEL: only spin-lock and nonpaged memory
    // operations are allowed here. DRAINING owns cleanup, never delivery.
    if (FlagOn( Flags, FLTFL_POST_OPERATION_DRAINING ) ||
        InterlockedCompareExchange( &SynthaeaFilterData.Stopping, 0, 0 ) != 0 ||
        !NT_SUCCESS( Data->IoStatus.Status )) {
        SynthaeaFreeEvent( event );
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    KeAcquireSpinLock( &SynthaeaFilterData.QueueLock, &oldIrql );
    if (InterlockedCompareExchange( &SynthaeaFilterData.Connected, 0, 0 ) != 0 &&
        InterlockedCompareExchange( &SynthaeaFilterData.Stopping, 0, 0 ) == 0) {
        InsertTailList( &SynthaeaFilterData.Queue, &event->Link );
        KeSetEvent( &SynthaeaFilterData.QueueEvent, IO_NO_INCREMENT, FALSE );
        event = NULL; // Queue owns the record and its reservation.
    } else {
        InterlockedIncrement64( &SynthaeaFilterData.NotConnected );
    }
    KeReleaseSpinLock( &SynthaeaFilterData.QueueLock, oldIrql );

    if (event != NULL) {
        SynthaeaFreeEvent( event );
    }
    return FLT_POSTOP_FINISHED_PROCESSING;
}

VOID
SynthaeaSetEventCounters (
    _Inout_ PSYNTHAEA_EVENT_HEADER Header
    )
{
    Header->Sequence = (ULONGLONG)InterlockedIncrement64( &SynthaeaFilterData.Sequence );
    Header->DroppedQueueFull = (ULONGLONG)InterlockedCompareExchange64(
        &SynthaeaFilterData.DroppedQueueFull, 0, 0 );
    Header->DroppedSendFailed = (ULONGLONG)InterlockedCompareExchange64(
        &SynthaeaFilterData.DroppedSendFailed, 0, 0 );
    Header->NotConnected = (ULONGLONG)InterlockedCompareExchange64(
        &SynthaeaFilterData.NotConnected, 0, 0 );
    Header->DroppedCaptureFailed = (ULONGLONG)InterlockedCompareExchange64(
        &SynthaeaFilterData.DroppedCaptureFailed, 0, 0 );
}

NTSTATUS
SynthaeaSendBuffer (
    _In_reads_bytes_(BufferLength) PVOID Buffer,
    _In_ ULONG BufferLength
    )
{
    PFLT_PORT port;
    LARGE_INTEGER timeout;
    NTSTATUS status;

    if (!ExAcquireRundownProtection( &SynthaeaFilterData.ClientRundown )) {
        return STATUS_PORT_DISCONNECTED;
    }

    port = SynthaeaFilterData.ClientPort;
    if (port == NULL || InterlockedCompareExchange(
            &SynthaeaFilterData.Connected, 0, 0 ) == 0) {
        ExReleaseRundownProtection( &SynthaeaFilterData.ClientRundown );
        return STATUS_PORT_DISCONNECTED;
    }

    timeout.QuadPart = SYNTHAEA_SEND_TIMEOUT_100NS;
    status = FltSendMessage( SynthaeaFilterData.FilterHandle, &port,
                             Buffer, BufferLength, NULL, NULL, &timeout );
    ExReleaseRundownProtection( &SynthaeaFilterData.ClientRundown );

    // STATUS_TIMEOUT is informational in the DDI contract, but means this
    // event was not delivered to a waiting FilterGetMessage caller.
    return status == STATUS_TIMEOUT ? STATUS_UNSUCCESSFUL : status;
}

VOID
SynthaeaSenderThread (
    _In_opt_ PVOID StartContext
    )
{
    PVOID waitObjects[2];
    LARGE_INTEGER heartbeatTimeout;
    NTSTATUS waitStatus;

    UNREFERENCED_PARAMETER( StartContext );
    waitObjects[0] = &SynthaeaFilterData.StopEvent;
    waitObjects[1] = &SynthaeaFilterData.QueueEvent;
    heartbeatTimeout.QuadPart = SYNTHAEA_HEARTBEAT_TIMEOUT_100NS;

    for (;;) {
        PSYNTHAEA_QUEUED_EVENT event = NULL;
        KIRQL oldIrql;
        BOOLEAN connected;

        if (InterlockedCompareExchange( &SynthaeaFilterData.Stopping, 0, 0 ) != 0) {
            break;
        }

        KeAcquireSpinLock( &SynthaeaFilterData.QueueLock, &oldIrql );
        connected = InterlockedCompareExchange(
            &SynthaeaFilterData.Connected, 0, 0 ) != 0;
        if (connected && !IsListEmpty( &SynthaeaFilterData.Queue )) {
            PLIST_ENTRY entry = RemoveHeadList( &SynthaeaFilterData.Queue );
            event = CONTAINING_RECORD( entry, SYNTHAEA_QUEUED_EVENT, Link );
            InitializeListHead( &event->Link );
            SynthaeaReleaseReservationLocked( event );
        } else {
            KeResetEvent( &SynthaeaFilterData.QueueEvent );
        }
        KeReleaseSpinLock( &SynthaeaFilterData.QueueLock, oldIrql );

        if (event != NULL) {
            ULONG wireLength = sizeof( SYNTHAEA_EVENT_HEADER ) +
                ((ULONG)event->Header.OldPathLength + event->Header.NewPathLength) * sizeof(WCHAR);
            SynthaeaSetEventCounters( &event->Header );
            if (!NT_SUCCESS( SynthaeaSendBuffer( &event->Header, wireLength ) )) {
                InterlockedIncrement64( &SynthaeaFilterData.DroppedSendFailed );
            }
            ExFreePoolWithTag( event, SYNTHAEA_POOL_TAG );
            continue;
        }

        waitStatus = KeWaitForMultipleObjects(
            RTL_NUMBER_OF( waitObjects ), waitObjects, WaitAny, Executive,
            KernelMode, FALSE, connected ? &heartbeatTimeout : NULL, NULL );
        if (waitStatus == STATUS_WAIT_0) {
            break;
        }
        if (waitStatus == STATUS_TIMEOUT && connected &&
            InterlockedCompareExchange( &SynthaeaFilterData.Connected, 0, 0 ) != 0) {
            SYNTHAEA_EVENT_HEADER heartbeat;
            LARGE_INTEGER now;
            RtlZeroMemory( &heartbeat, sizeof( heartbeat ) );
            heartbeat.Kind = SYNTHAEA_EVENT_HEARTBEAT;
            KeQuerySystemTimePrecise( &now );
            heartbeat.Timestamp = now.QuadPart;
            SynthaeaSetEventCounters( &heartbeat );
            if (!NT_SUCCESS( SynthaeaSendBuffer( &heartbeat, sizeof( heartbeat ) ) )) {
                InterlockedIncrement64( &SynthaeaFilterData.DroppedSendFailed );
            }
        }
    }

    PsTerminateSystemThread( STATUS_SUCCESS );
}

NTSTATUS
SynthaeaStartSender (
    VOID
    )
{
    NTSTATUS status;
    HANDLE threadHandle = NULL;
    PETHREAD threadObject = NULL;

    status = PsCreateSystemThread( &threadHandle, THREAD_ALL_ACCESS, NULL,
                                   NULL, NULL, SynthaeaSenderThread, NULL );
    if (!NT_SUCCESS( status )) {
        return status;
    }

    status = ObReferenceObjectByHandle( threadHandle, SYNCHRONIZE,
                                        *PsThreadType, KernelMode,
                                        (PVOID *)&threadObject, NULL );
    if (!NT_SUCCESS( status )) {
        KeSetEvent( &SynthaeaFilterData.StopEvent, IO_NO_INCREMENT, FALSE );
        ZwWaitForSingleObject( threadHandle, FALSE, NULL );
        ZwClose( threadHandle );
        return status;
    }

    ZwClose( threadHandle );
    SynthaeaFilterData.SenderThread = threadObject;
    return STATUS_SUCCESS;
}

VOID
SynthaeaStopSender (
    VOID
    )
{
    InterlockedExchange( &SynthaeaFilterData.Stopping, 1 );
    KeSetEvent( &SynthaeaFilterData.StopEvent, IO_NO_INCREMENT, FALSE );
    if (SynthaeaFilterData.SenderThread != NULL) {
        KeWaitForSingleObject( SynthaeaFilterData.SenderThread, Executive,
                               KernelMode, FALSE, NULL );
        ObDereferenceObject( SynthaeaFilterData.SenderThread );
        SynthaeaFilterData.SenderThread = NULL;
    }
}

VOID
SynthaeaFreeQueuedEvents (
    VOID
    )
{
    LIST_ENTRY localQueue;
    KIRQL oldIrql;

    InitializeListHead( &localQueue );
    KeAcquireSpinLock( &SynthaeaFilterData.QueueLock, &oldIrql );
    while (!IsListEmpty( &SynthaeaFilterData.Queue )) {
        PLIST_ENTRY entry = RemoveHeadList( &SynthaeaFilterData.Queue );
        PSYNTHAEA_QUEUED_EVENT event = CONTAINING_RECORD(
            entry, SYNTHAEA_QUEUED_EVENT, Link );
        SynthaeaReleaseReservationLocked( event );
        InsertTailList( &localQueue, &event->Link );
    }
    KeReleaseSpinLock( &SynthaeaFilterData.QueueLock, oldIrql );

    while (!IsListEmpty( &localQueue )) {
        PLIST_ENTRY entry = RemoveHeadList( &localQueue );
        PSYNTHAEA_QUEUED_EVENT event = CONTAINING_RECORD(
            entry, SYNTHAEA_QUEUED_EVENT, Link );
        ExFreePoolWithTag( event, SYNTHAEA_POOL_TAG );
    }
}


/*************************************************************************
    Communication port (milestone 2a, ADR-0012 guardrails 2 and 5).
*************************************************************************/

NTSTATUS
SynthaeaCreatePort (
    VOID
    )
/*++

Routine Description:

    Creates the server port the agent connects to. The security descriptor
    from FltBuildDefaultSecurityDescriptor only grants access to SYSTEM and
    Administrators, and MaxConnections = 1: whoever is connected blocks any
    other client until it disconnects.

Return Value:

    Status of the port creation.

--*/
{
    NTSTATUS status;
    PSECURITY_DESCRIPTOR sd = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING portName = RTL_CONSTANT_STRING( SYNTHAEA_PORT_NAME );

    PAGED_CODE();

    status = FltBuildDefaultSecurityDescriptor( &sd, FLT_PORT_ALL_ACCESS );

    if (!NT_SUCCESS( status )) {
        DbgPrintEx( DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "SynthaeaFilter: FltBuildDefaultSecurityDescriptor failed 0x%08X\n", status );
        return status;
    }

    InitializeObjectAttributes( &oa,
                                &portName,
                                OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                                NULL,
                                sd );

    status = FltCreateCommunicationPort( SynthaeaFilterData.FilterHandle,
                                         &SynthaeaFilterData.ServerPort,
                                         &oa,
                                         NULL,
                                         SynthaeaPortConnect,
                                         SynthaeaPortDisconnect,
                                         NULL,      // no MessageNotify: user mode cannot send to the driver
                                         1 );       // a single client, the agent

    FltFreeSecurityDescriptor( sd );

    if (!NT_SUCCESS( status )) {
        DbgPrintEx( DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "SynthaeaFilter: FltCreateCommunicationPort failed 0x%08X\n", status );
    }

    return status;
}

NTSTATUS
SynthaeaPortConnect (
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie
    )
/*++

Routine Description:

    Called by FltMgr when a client that passed the port's security check
    (SYSTEM/Administrators) connects, in that client's process context.

    Guardrail 5: the caller must be the agent, i.e. its primary token holds
    NT SERVICE\SynthaEDR (see SynthaeaCallerIsAgent). Any other elevated
    process is refused, so it cannot take the single connection slot.

    Guardrail 2: the connection context comes from user mode and is hostile
    until validated. It must be exactly one SYNTHAEA_CONNECT_CONTEXT with
    the expected magic and version. The magic is not authentication, only a
    protocol version check.

Return Value:

    STATUS_SUCCESS to accept; STATUS_ACCESS_DENIED for a caller that is not
    the agent; STATUS_INVALID_PARAMETER for a bad connection context.

--*/
{
    SYNTHAEA_CONNECT_CONTEXT context;

    UNREFERENCED_PARAMETER( ServerPortCookie );

    PAGED_CODE();

    *ConnectionPortCookie = NULL;

    if (!SynthaeaCallerIsAgent()) {

        DbgPrintEx( DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                    "SynthaeaFilter: connect refused, pid %p: not the agent (no NT SERVICE\\SynthaEDR in its token)\n",
                    PsGetCurrentProcessId() );
        return STATUS_ACCESS_DENIED;
    }

    if (ConnectionContext == NULL ||
        SizeOfContext != sizeof( SYNTHAEA_CONNECT_CONTEXT )) {

        DbgPrintEx( DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                    "SynthaeaFilter: connect refused, pid %p: bad context size %lu\n",
                    PsGetCurrentProcessId(), SizeOfContext );
        return STATUS_INVALID_PARAMETER;
    }

    //
    //  Copy once, then only read the local copy: no double fetch.
    //

    RtlCopyMemory( &context, ConnectionContext, sizeof( context ) );

    if (context.Magic != SYNTHAEA_CONNECT_MAGIC ||
        context.Version != SYNTHAEA_PROTOCOL_VERSION) {

        DbgPrintEx( DPFLTR_IHVDRIVER_ID, DPFLTR_WARNING_LEVEL,
                    "SynthaeaFilter: connect refused, pid %p: magic 0x%08lX version %lu\n",
                    PsGetCurrentProcessId(), context.Magic, context.Version );
        return STATUS_INVALID_PARAMETER;
    }

    SynthaeaActivateClient( ClientPort );

    DbgPrintEx( DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "SynthaeaFilter: client connected, pid %p\n",
                PsGetCurrentProcessId() );

    return STATUS_SUCCESS;
}

VOID
SynthaeaPortDisconnect (
    _In_opt_ PVOID ConnectionCookie
    )
/*++

Routine Description:

    Called by FltMgr when the client's handle count drops to zero or the
    filter unloads. Closes the client port so a new client can connect.

--*/
{
    UNREFERENCED_PARAMETER( ConnectionCookie );

    PAGED_CODE();

    SynthaeaDeactivateClient();

    // Keep queued records for a reconnect; only pending completions that race
    // this disconnect are dropped and counted by the post-operation callback.
    // Stop new sends and wait for the sender's bounded FltSendMessage call
    // before FltCloseClientPort clears the shared port pointer.
    ExWaitForRundownProtectionRelease( &SynthaeaFilterData.ClientRundown );

    DbgPrintEx( DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "SynthaeaFilter: client disconnected\n" );

    FltCloseClientPort( SynthaeaFilterData.FilterHandle,
                        &SynthaeaFilterData.ClientPort );
}

BOOLEAN
SynthaeaCallerIsAgent (
    VOID
    )
/*++

Routine Description:

    Whether the current process's primary token holds the agent's service
    SID as an enabled group. The primary token, not the thread's effective
    token: a thread impersonating the agent from another process does not
    count.

    This raises the bar, it is not a hard boundary: an administrator can
    still reconfigure or replace the SynthaEDR service, or take the agent's
    token with SeDebugPrivilege. Closing that needs a protected (PPL) agent.

Return Value:

    TRUE if the caller is the agent, FALSE otherwise (including when the
    token cannot be queried).

--*/
{
    PACCESS_TOKEN token;
    PTOKEN_GROUPS groups = NULL;
    NTSTATUS status;
    BOOLEAN isAgent = FALSE;
    ULONG i;

    PAGED_CODE();

    token = PsReferencePrimaryToken( PsGetCurrentProcess() );
    status = SeQueryInformationToken( token, TokenGroups, (PVOID *)&groups );
    PsDereferencePrimaryToken( token );

    if (!NT_SUCCESS( status )) {
        DbgPrintEx( DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "SynthaeaFilter: SeQueryInformationToken failed 0x%08X\n", status );
        return FALSE;
    }

    for (i = 0; i < groups->GroupCount; i++) {

        if (FlagOn( groups->Groups[i].Attributes, SE_GROUP_ENABLED ) &&
            RtlEqualSid( groups->Groups[i].Sid, (PSID)&SynthaeaAgentServiceSid )) {

            isAgent = TRUE;
            break;
        }
    }

    //
    //  SeQueryInformationToken allocates the buffer; the caller frees it.
    //

    ExFreePool( groups );

    return isAgent;
}
