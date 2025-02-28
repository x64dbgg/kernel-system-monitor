// driver/KernelMonitor.h
#pragma once

#include <ntddk.h>
#include <wdf.h>

// Driver device name and symbolic link
#define DEVICE_NAME     L"\\Device\\KernelMonitor"
#define SYMBOLIC_LINK   L"\\DosDevices\\KernelMonitor"

// IOCTLs
#define IOCTL_MONITOR_PROCESS_CREATE   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MONITOR_PROCESS_TERMINATE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_KERNEL_MEMORY        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MONITOR_REGISTRY         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MONITOR_FILE_IO          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Structures for communication with user mode
typedef struct _KERNEL_MEMORY_REQUEST {
    ULONG_PTR Address;
    SIZE_T Size;
} KERNEL_MEMORY_REQUEST, *PKERNEL_MEMORY_REQUEST;

typedef struct _PROCESS_CALLBACK_INFO {
    HANDLE ProcessId;
    HANDLE ParentProcessId;
    WCHAR ImageFileName[260];
} PROCESS_CALLBACK_INFO, *PPROCESS_CALLBACK_INFO;

// Function prototypes
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_UNLOAD DriverUnload;
EVT_WDF_DEVICE_FILE_CREATE DeviceFileCreate;
EVT_WDF_FILE_CLOSE DeviceFileClose;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL DeviceIoControl;

// Callback functions
VOID ProcessCreateCallback(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
);

// Helper functions
NTSTATUS RegisterProcessCallbacks();
VOID UnregisterProcessCallbacks();
NTSTATUS ReadKernelMemory(PKERNEL_MEMORY_REQUEST Request, PVOID OutputBuffer, ULONG OutputBufferLength);
