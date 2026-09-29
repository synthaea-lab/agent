/*++

Copyright (c) 1999 - 2002  Microsoft Corporation

    Adapted for Synthaea from microsoft/Windows-driver-samples
    (filesys/miniFilter/nullFilter), Microsoft Public License (MS-PL): see
    LICENSE.windows-driver-samples next to this file.

Module Name:

    SynthaeaFilter.c

Abstract:

    This is the main module of the SynthaeaFilter mini filter driver.
    Milestone 2a (#136): it registers with FltMgr for no I/O callbacks yet
    and exposes one communication port for the Synthaea agent. The port
    follows ADR-0012 guardrails 2 and 5: SYSTEM/Administrators-only
    security descriptor, a single connection, and a connect callback that
    validates the client's connection context before accepting it. No
    message callback is registered, so user mode cannot send anything to
    the driver; the channel is kernel -> user only.

Environment:

    Kernel mode

--*/

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")

//---------------------------------------------------------------------------
//      Port protocol (mirrored by the user-mode client, keep in sync)
//---------------------------------------------------------------------------

#define SYNTHAEA_PORT_NAME          L"\\SynthaeaPort"
#define SYNTHAEA_CONNECT_MAGIC      0x544E5953UL    // 'SYNT', little-endian
#define SYNTHAEA_PROTOCOL_VERSION   1UL

//
//  What a client must pass as the connection context of
//  FilterConnectCommunicationPort. Anything else is refused.
//

typedef struct _SYNTHAEA_CONNECT_CONTEXT {

    ULONG Magic;
    ULONG Version;

} SYNTHAEA_CONNECT_CONTEXT, *PSYNTHAEA_CONNECT_CONTEXT;

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

//
//  Structure that contains all the global data structures
//  used throughout SynthaeaFilter.
//

SYNTHAEA_FILTER_DATA SynthaeaFilterData;

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
#endif


//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

    NULL,                               //  Context
    NULL,                               //  Operation callbacks

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

    //
    //  Register with FltMgr
    //

    status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &SynthaeaFilterData.FilterHandle );

    FLT_ASSERT( NT_SUCCESS( status ) );

    if (NT_SUCCESS( status )) {

        //
        //  Create the agent's communication port before filtering starts,
        //  so there is never a window where the filter runs without it.
        //

        status = SynthaeaCreatePort();

        if (!NT_SUCCESS( status )) {
            FltUnregisterFilter( SynthaeaFilterData.FilterHandle );
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
            FltUnregisterFilter( SynthaeaFilterData.FilterHandle );
        } else {
            DbgPrintEx( DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                        "SynthaeaFilter: loaded, filtering started\n" );
        }
    } else {
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
    //  Closing the server port refuses new connections; FltUnregisterFilter
    //  then disconnects any remaining client (DisconnectNotify runs).
    //

    FltCloseCommunicationPort( SynthaeaFilterData.ServerPort );
    FltUnregisterFilter( SynthaeaFilterData.FilterHandle );

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
    connects. Guardrail 2: the connection context comes from user mode and
    is hostile until validated. It must be exactly one
    SYNTHAEA_CONNECT_CONTEXT with the expected magic and version; anything
    else is refused before the client port is kept.

    The magic is not authentication (any administrator can send it); the
    security descriptor is the access control. The check only refuses
    clients that do not speak this protocol version.

Return Value:

    STATUS_SUCCESS to accept, STATUS_INVALID_PARAMETER to refuse.

--*/
{
    SYNTHAEA_CONNECT_CONTEXT context;

    UNREFERENCED_PARAMETER( ServerPortCookie );

    PAGED_CODE();

    *ConnectionPortCookie = NULL;

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

    SynthaeaFilterData.ClientPort = ClientPort;

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

    DbgPrintEx( DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                "SynthaeaFilter: client disconnected\n" );

    FltCloseClientPort( SynthaeaFilterData.FilterHandle,
                        &SynthaeaFilterData.ClientPort );
}
