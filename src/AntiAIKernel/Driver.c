/*
 * AntiAIKernel — minimal KMDF driver (Windows 10 x64, C).
 * Educational: IOCTL policy + optional process_guard (PsSetCreateProcessNotifyRoutineEx).
 * No stealth, no injection, no security bypass.
 */

#define POOL_NX_OPTIN 1

#include <ntddk.h>
#include <wdf.h>

#include "antiai_ioctl.h"
#include "process_guard.h"

/* Must match ANTIAI_GET_VERSION_OUT reported to user mode. */
#define ANTIAI_DRIVER_VERSION_MAJOR 1u
#define ANTIAI_DRIVER_VERSION_MINOR 0u
#define ANTIAI_DRIVER_VERSION_BUILD 1u

typedef struct _DEVICE_CONTEXT
{
    ANTIAI_POLICY_MODE Mode;
} DEVICE_CONTEXT, *PDEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_CONTEXT, DeviceGetContext)

EVT_WDF_DRIVER_DEVICE_ADD AntiAIEvtDeviceAdd;
EVT_WDF_DRIVER_UNLOAD AntiAIEvtDriverUnload;
EVT_WDF_IO_QUEUE_IO_DEFAULT AntiAIEvtIoDefault;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL AntiAIEvtIoDeviceControl;

static NTSTATUS AntiAIValidateMode(_In_ ANTIAI_POLICY_MODE mode)
{
    switch (mode)
    {
    case ANTIAI_MODE_OFF:
    case ANTIAI_MODE_AUDIT_ONLY:
    case ANTIAI_MODE_BLOCK_NETWORK:
    case ANTIAI_MODE_BLOCK_PROCESS:
    case ANTIAI_MODE_BLOCK_ALL:
        return STATUS_SUCCESS;
    default:
        return STATUS_INVALID_PARAMETER;
    }
}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    WDF_DRIVER_CONFIG config;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "AntiAIKernel: DriverEntry\n"));

    WDF_DRIVER_CONFIG_INIT(&config, AntiAIEvtDeviceAdd);
    config.EvtDriverUnload = AntiAIEvtDriverUnload;

    status = WdfDriverCreate(
        DriverObject,
        RegistryPath,
        WDF_NO_OBJECT_ATTRIBUTES,
        &config,
        WDF_NO_HANDLE);

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = ProcessGuardInitialize();
    if (!NT_SUCCESS(status))
    {
        KdPrintEx((
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "AntiAIKernel: ProcessGuardInitialize failed %08X\n",
            status));
        return status;
    }

    return STATUS_SUCCESS;
}

VOID
AntiAIEvtDriverUnload(_In_ WDFDRIVER Driver)
{
    UNREFERENCED_PARAMETER(Driver);

    KdPrintEx((DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "AntiAIKernel: EvtDriverUnload\n"));
    ProcessGuardShutdown();
}

NTSTATUS
AntiAIEvtDeviceAdd(
    _In_ WDFDRIVER Driver,
    _Inout_ PWDFDEVICE_INIT DeviceInit
)
{
    NTSTATUS status;
    WDF_OBJECT_ATTRIBUTES deviceAttributes;
    WDFDEVICE device;
    WDF_IO_QUEUE_CONFIG queueConfig;
    PDEVICE_CONTEXT ctx;
    UNICODE_STRING ntName;

    /*
     * Symbolic link exposes the device as \\.\AntiAIKernel in user mode.
     * Alternative (PnP-friendly): WdfDeviceCreateDeviceInterface + SetupAPI —
     * not required for this minimal root\ software device.
     */
    DECLARE_CONST_UNICODE_STRING(symLink, L"\\DosDevices\\AntiAIKernel");

    UNREFERENCED_PARAMETER(Driver);

    RtlInitUnicodeString(&ntName, L"\\Device\\AntiAIKernel");

    status = WdfDeviceInitAssignName(DeviceInit, &ntName);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, DEVICE_CONTEXT);
    status = WdfDeviceCreate(&DeviceInit, &deviceAttributes, &device);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = WdfDeviceCreateSymbolicLink(device, &symLink);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    ctx = DeviceGetContext(device);
    ctx->Mode = ANTIAI_MODE_OFF;

    /*
     * Sequential queue: serializes IOCTL handling so DEVICE_CONTEXT.Mode
     * updates do not race without an explicit lock (good enough for this MVP).
     */
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = AntiAIEvtIoDeviceControl;
    queueConfig.EvtIoDefault = AntiAIEvtIoDefault;

    status = WdfIoQueueCreate(
        device,
        &queueConfig,
        WDF_NO_OBJECT_ATTRIBUTES,
        WDF_NO_HANDLE);

    if (!NT_SUCCESS(status))
    {
        return status;
    }

    return STATUS_SUCCESS;
}

VOID
AntiAIEvtIoDefault(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request
)
{
    UNREFERENCED_PARAMETER(Queue);
    WdfRequestComplete(Request, STATUS_INVALID_DEVICE_REQUEST);
}

VOID
AntiAIEvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
)
{
    NTSTATUS status;
    WDFDEVICE device;
    PDEVICE_CONTEXT ctx;
    size_t bufferLength = 0;

    device = WdfIoQueueGetDevice(Queue);
    ctx = DeviceGetContext(device);

    switch (IoControlCode)
    {
    case IOCTL_ANTIAI_PING:
        /*
         * No payload. Ignore buffer sizes; complete successfully.
         */
        WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, 0);
        return;

    case IOCTL_ANTIAI_GET_VERSION:
    {
        PANTIAI_GET_VERSION_OUT out = NULL;

        if (OutputBufferLength < sizeof(ANTIAI_GET_VERSION_OUT))
        {
            WdfRequestComplete(Request, STATUS_BUFFER_TOO_SMALL);
            return;
        }

        status = WdfRequestRetrieveOutputBuffer(
            Request,
            sizeof(ANTIAI_GET_VERSION_OUT),
            (PVOID *)&out,
            &bufferLength);

        if (!NT_SUCCESS(status))
        {
            WdfRequestComplete(Request, status);
            return;
        }

        if (bufferLength < sizeof(ANTIAI_GET_VERSION_OUT))
        {
            WdfRequestComplete(Request, STATUS_BUFFER_TOO_SMALL);
            return;
        }

        RtlZeroMemory(out, sizeof(*out));
        out->Major = (UINT16)ANTIAI_DRIVER_VERSION_MAJOR;
        out->Minor = (UINT16)ANTIAI_DRIVER_VERSION_MINOR;
        out->Build = ANTIAI_DRIVER_VERSION_BUILD;

        WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(ANTIAI_GET_VERSION_OUT));
        return;
    }

    case IOCTL_ANTIAI_GET_STATUS:
    {
        PANTIAI_GET_STATUS_OUT out = NULL;

        if (OutputBufferLength < sizeof(ANTIAI_GET_STATUS_OUT))
        {
            WdfRequestComplete(Request, STATUS_BUFFER_TOO_SMALL);
            return;
        }

        status = WdfRequestRetrieveOutputBuffer(
            Request,
            sizeof(ANTIAI_GET_STATUS_OUT),
            (PVOID *)&out,
            &bufferLength);

        if (!NT_SUCCESS(status))
        {
            WdfRequestComplete(Request, status);
            return;
        }

        if (bufferLength < sizeof(ANTIAI_GET_STATUS_OUT))
        {
            WdfRequestComplete(Request, STATUS_BUFFER_TOO_SMALL);
            return;
        }

        RtlZeroMemory(out, sizeof(*out));
        out->PolicyMode = ctx->Mode;
        out->Flags = 0;
        out->Reserved0 = 0;
        out->Reserved1 = 0;

        /*
         * FUTURE (BLOCK_NETWORK): set capability bits in out->Flags when a
         * Windows Filtering Platform (WFP) callout / sublayer is registered.
         *   Typical integration: FWPM* / Fwps* in a dedicated module; start/stop
         *   when PolicyMode transitions into/out of modes that require network
         *   enforcement. Keep audit-only vs block semantics explicit.
         */

        /*
         * FUTURE (BLOCK_PROCESS): set capability bits when a process guard is
         * active (for example ObRegisterCallbacks for handle restrictions, or
         * documented process-create notifications if appropriate to your design).
         *   Place initialization/teardown next to mode transitions, not inside
         *   this IOCTL fast-path, to keep IRQL / reentrancy predictable.
         */

        WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(ANTIAI_GET_STATUS_OUT));
        return;
    }

    case IOCTL_ANTIAI_SET_MODE:
    {
        PANTIAI_SET_MODE_IN in = NULL;

        if (InputBufferLength < sizeof(ANTIAI_SET_MODE_IN))
        {
            WdfRequestComplete(Request, STATUS_INVALID_PARAMETER);
            return;
        }

        status = WdfRequestRetrieveInputBuffer(
            Request,
            sizeof(ANTIAI_SET_MODE_IN),
            (PVOID *)&in,
            &bufferLength);

        if (!NT_SUCCESS(status))
        {
            WdfRequestComplete(Request, status);
            return;
        }

        if (bufferLength < sizeof(ANTIAI_SET_MODE_IN))
        {
            WdfRequestComplete(Request, STATUS_BUFFER_TOO_SMALL);
            return;
        }

        status = AntiAIValidateMode(in->Mode);
        if (!NT_SUCCESS(status))
        {
            WdfRequestComplete(Request, status);
            return;
        }

        ctx->Mode = in->Mode;
        ProcessGuardSetPolicyMode(ctx->Mode);

        /*
         * FUTURE (BLOCK_NETWORK): if transitioning into a mode that requires
         * network enforcement, enable the WFP module here (or schedule a passive
         * worker). If leaving those modes, tear down callouts and filters.
         *   Do not add stealth filtering; keep explicit policy and logging.
         */

        /* Process creation policy is applied in process_guard.c (notify routine). */

        if (ctx->Mode != ANTIAI_MODE_OFF)
        {
            KdPrintEx((
                DPFLTR_IHVDRIVER_ID,
                DPFLTR_INFO_LEVEL,
                "AntiAIKernel: PolicyMode=%lu\n",
                (ULONG)ctx->Mode));
        }

        WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, 0);
        return;
    }

    case IOCTL_ANTIAI_GET_MODE:
    {
        PANTIAI_GET_MODE_OUT out = NULL;

        if (OutputBufferLength < sizeof(ANTIAI_GET_MODE_OUT))
        {
            WdfRequestComplete(Request, STATUS_BUFFER_TOO_SMALL);
            return;
        }

        status = WdfRequestRetrieveOutputBuffer(
            Request,
            sizeof(ANTIAI_GET_MODE_OUT),
            (PVOID *)&out,
            &bufferLength);

        if (!NT_SUCCESS(status))
        {
            WdfRequestComplete(Request, status);
            return;
        }

        if (bufferLength < sizeof(ANTIAI_GET_MODE_OUT))
        {
            WdfRequestComplete(Request, STATUS_BUFFER_TOO_SMALL);
            return;
        }

        out->Mode = ctx->Mode;

        WdfRequestCompleteWithInformation(Request, STATUS_SUCCESS, sizeof(ANTIAI_GET_MODE_OUT));
        return;
    }

    default:
        WdfRequestComplete(Request, STATUS_INVALID_DEVICE_REQUEST);
        return;
    }
}
