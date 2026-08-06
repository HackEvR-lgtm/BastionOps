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

#define CDS_POOL_TAG 'sdC'
#define IOCTL_CDS_REGISTER_PID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

static PVOID g_RegistrationHandle = NULL;
static HANDLE g_CDS_PID = NULL;
static PDEVICE_OBJECT g_DeviceObject = NULL;

OB_PREOP_CALLBACK_STATUS PreOperationCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInformation->ObjectType != *PsProcessType) {
        return OB_PREOP_SUCCESS;
    }

    HANDLE targetPid = PsGetProcessId((PEPROCESS)OperationInformation->Object);
    if (targetPid != g_CDS_PID || g_CDS_PID == NULL) {
        return OB_PREOP_SUCCESS;
    }

    const ACCESS_MASK DENY_MASK = PROCESS_TERMINATE | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_SUSPEND_RESUME;
    
    OperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~DENY_MASK;
    OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= ~DENY_MASK;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "CDS: Protected handle access stripped for PID %lu\n", (ULONG)(ULONG_PTR)targetPid);
    return OB_PREOP_SUCCESS;
}

NTSTATUS CdsDispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

    if (irpSp->MajorFunction == IRP_MJ_DEVICE_CONTROL) {
        if (irpSp->Parameters.DeviceIoControl.IoControlCode == IOCTL_CDS_REGISTER_PID) {
            if (irpSp->Parameters.DeviceIoControl.InputBufferLength >= sizeof(HANDLE)) {
                HANDLE* pidBuffer = (HANDLE*)Irp->AssociatedIrp.SystemBuffer;
                g_CDS_PID = *pidBuffer;
                status = STATUS_SUCCESS;
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "CDS: Registered protected PID %lu\n", (ULONG)(ULONG_PTR)g_CDS_PID);
            } else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
        }
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = (status == STATUS_SUCCESS) ? sizeof(HANDLE) : 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

VOID CdsDriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symLink;
    RtlInitUnicodeString(&symLink, L"\\DosDevices\\CdsProtect");
    IoDeleteSymbolicLink(&symLink);
    
    if (g_DeviceObject) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }
    
    if (g_RegistrationHandle) {
        ObUnRegisterCallbacks(g_RegistrationHandle);
        g_RegistrationHandle = NULL;
    }
    
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "CDS: Driver Unloaded Successfully.\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;
    UNICODE_STRING deviceName, symLink;
    
    RtlInitUnicodeString(&deviceName, L"\\Device\\CdsProtect");
    RtlInitUnicodeString(&symLink, L"\\DosDevices\\CdsProtect");

    status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &g_DeviceObject);
    if (!NT_SUCCESS(status)) return status;

    status = IoCreateSymbolicLink(&symLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = CdsDispatchDeviceControl;
    DriverObject->DriverUnload = CdsDriverUnload;

    OB_OPERATION_REGISTRATION opReg = {0};
    opReg.Version = ObGetFilterVersion();
    opReg.OperationType = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg.ObjectType = PsProcessType;
    opReg.PreOperation = PreOperationCallback;

    OB_CALLBACK_REGISTRATION obReg = {0};
    obReg.Version = ObGetFilterVersion();
    obReg.OperationRegistrationCount = 1;
    obReg.RegistrationContext = NULL;
    obReg.OperationRegistration = &opReg;

    status = ObRegisterCallbacks(&obReg, &g_RegistrationHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "CDS: Failed to register callbacks. Status: 0x%X\n", status);
        return status;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "CDS: Driver Loaded Successfully.\n");
    return STATUS_SUCCESS;
}
