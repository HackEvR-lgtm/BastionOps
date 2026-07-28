/*
 * Capability Denial System (CDS) - Kernel Mode Protection Driver
 * Module: Process Protection (ObRegisterCallbacks) with IOCTL Communication
 * 
 * PURPOSE:
 * Protects the CDS User-Mode Daemon from termination or memory manipulation
 * by stripping specific access rights from handle creation operations.
 * Receives the CDS PID via IOCTL from user-mode application.
 * 
 * REQUIREMENTS:
 * - Windows Driver Kit (WDK)
 * - Test Signing Mode (bcdedit /set testsigning on) OR EV Code Signing Certificate
 * 
 * COMPILATION:
 * msbuild CdsProtectDriver.vcxproj
 */

#include <ntifs.h>
#include <ntddk.h>
#include <wdf.h>

// Driver Tag
#define CDS_POOL_TAG 'sdC'

// Device Name and Symbolic Link
#define DEVICE_NAME L"\\Device\\CdsProtect"
#define SYMBOLIC_LINK_NAME L"\\DosDevices\\CdsProtect"

// IOCTL Definition
#define IOCTL_CDS_REGISTER_PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Global Variables
static PVOID g_RegistrationHandle = NULL;
static HANDLE g_CDS_PID = NULL;
static PDEVICE_OBJECT g_DeviceObject = NULL;

// Function Prototypes
DRIVER_INITIALIZE DriverEntry;
VOID DriverUnload(PDRIVER_OBJECT DriverObject);
OB_PREOP_CALLBACK_STATUS PreOperationCallback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
);
NTSTATUS CdsDispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS CdsDispatchCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS CdsDispatchClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);

/*
 * Callback Routine: PreOperationCallback
 * Called before a handle is created for a process/thread.
 * We strip dangerous access rights if the target is the CDS Daemon.
 */
OB_PREOP_CALLBACK_STATUS PreOperationCallback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    // Ensure we are dealing with a process
    if (OperationInformation->ObjectType != *PsProcessType)
    {
        return OB_PREOP_SUCCESS;
    }

    // Check if the target process is our protected CDS Daemon
    HANDLE targetPid = PsGetProcessId((PEPROCESS)OperationInformation->Object);
    if (targetPid != g_CDS_PID || g_CDS_PID == NULL)
    {
        return OB_PREOP_SUCCESS;
    }

    // ACCESS MASKS TO STRIP
    // Prevent Termination, VM Write, VM Operation, and Suspend/Resume
    const ACCESS_MASK DENY_MASK = PROCESS_TERMINATE | 
                                  PROCESS_VM_WRITE | 
                                  PROCESS_VM_OPERATION |
                                  PROCESS_SUSPEND_RESUME;

    // Strip rights from CreateHandleAccess
    OperationInformation->Parameters->CreateHandleAccess.DesiredAccess &= ~DENY_MASK;

    // Strip rights from DuplicateHandleAccess
    OperationInformation->Parameters->DuplicateHandleAccess.DesiredAccess &= ~DENY_MASK;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, 
               "CDS: Protected handle access stripped for PID %lu\n", targetPid);

    return OB_PREOP_SUCCESS;
}

/*
 * Dispatch Routine: Device Control
 * Handles IOCTL calls from user-mode applications.
 */
NTSTATUS CdsDispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG bytesReturned = 0;

    switch (irpStack->Parameters.DeviceIoControl.IoControlCode)
    {
        case IOCTL_CDS_REGISTER_PID:
        {
            // Validate input buffer size
            if (irpStack->Parameters.DeviceIoControl.InputBufferLength < sizeof(HANDLE))
            {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }

            // Extract PID from input buffer
            HANDLE receivedPid = *(HANDLE*)(Irp->AssociatedIrp.SystemBuffer);
            
            // Validate PID (must be a valid process ID)
            PEPROCESS targetProcess;
            if (NT_SUCCESS(PsLookupProcessByProcessId(receivedPid, &targetProcess)))
            {
                // Store the PID globally
                g_CDS_PID = receivedPid;
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, 
                           "CDS: Registered CDS PID: %lu\n", g_CDS_PID);
                bytesReturned = sizeof(HANDLE);
            }
            else
            {
                status = STATUS_INVALID_PARAMETER;
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
                           "CDS: Invalid PID received: %lu\n", receivedPid);
            }
            break;
        }

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

    // Complete the IRP
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

/*
 * Dispatch Routine: Create
 * Handles file open requests.
 */
NTSTATUS CdsDispatchCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    
    return STATUS_SUCCESS;
}

/*
 * Dispatch Routine: Close
 * Handles file close requests.
 */
NTSTATUS CdsDispatchClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    
    return STATUS_SUCCESS;
}

/*
 * Driver Entry Point
 */
NTSTATUS DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status;
    OB_CALLBACK_REGISTRATION obReg;
    OB_OPERATION_REGISTRATION opReg;
    UNICODE_STRING deviceName, symbolicLinkName;

    // Set Dispatch Routines
    DriverObject->MajorFunction[IRP_MJ_CREATE] = CdsDispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CdsDispatchClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = CdsDispatchDeviceControl;
    DriverObject->DriverUnload = DriverUnload;

    // Initialize global PID to NULL (no protection until registered)
    g_CDS_PID = NULL;

    // Create Device Object
    RtlInitUnicodeString(&deviceName, DEVICE_NAME);
    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_DeviceObject
    );

    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
                   "CDS: Failed to create device object. Status: 0x%X\n", status);
        return status;
    }

    // Create Symbolic Link
    RtlInitUnicodeString(&symbolicLinkName, SYMBOLIC_LINK_NAME);
    status = IoCreateSymbolicLink(&symbolicLinkName, &deviceName);

    if (!NT_SUCCESS(status))
    {
        IoDeleteDevice(g_DeviceObject);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
                   "CDS: Failed to create symbolic link. Status: 0x%X\n", status);
        return status;
    }

    // Configure Operation Registration
    RtlZeroMemory(&opReg, sizeof(OB_OPERATION_REGISTRATION));
    opReg.Version = ObGetFilterVersion();
    opReg.OperationType = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg.ObjectType = PsProcessType;
    opReg.PreOperation = PreOperationCallback;

    // Configure Callback Registration
    RtlZeroMemory(&obReg, sizeof(OB_CALLBACK_REGISTRATION));
    obReg.Version = ObGetFilterVersion();
    obReg.OperationRegistrationCount = 1;
    obReg.RegistrationContext = NULL;
    obReg.OperationRegistration = &opReg;

    // Register the callback
    status = ObRegisterCallbacks(&obReg, &g_RegistrationHandle);

    if (!NT_SUCCESS(status))
    {
        IoDeleteSymbolicLink(&symbolicLinkName);
        IoDeleteDevice(g_DeviceObject);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
                   "CDS: Failed to register callbacks. Status: 0x%X\n", status);
        return status;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, 
               "CDS: Driver Loaded Successfully. Waiting for PID registration...\n");
    
    return STATUS_SUCCESS;
}

/*
 * Driver Unload Routine
 * Cleans up resources and unregisters callbacks.
 */
VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    UNICODE_STRING symbolicLinkName;

    if (g_RegistrationHandle != NULL)
    {
        ObUnRegisterCallbacks(g_RegistrationHandle);
        g_RegistrationHandle = NULL;
    }

    if (g_DeviceObject != NULL)
    {
        RtlInitUnicodeString(&symbolicLinkName, SYMBOLIC_LINK_NAME);
        IoDeleteSymbolicLink(&symbolicLinkName);
        IoDeleteDevice(g_DeviceObject);
    }

    g_CDS_PID = NULL;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "CDS: Driver Unloaded.\n");
}
