// driver/KernelMonitor.c
#include "KernelMonitor.h"

WDFDEVICE   DeviceObject = NULL;
PVOID       ProcessCallbackHandle = NULL;

// Driver entry point
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;
    WDFDRIVER driver;
    WDF_DRIVER_CONFIG config;
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicLink;
    PWDFDEVICE_INIT deviceInit;
    WDF_OBJECT_ATTRIBUTES deviceAttributes;
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDFQUEUE queue;
    
    // Initialize WDF driver
    WDF_DRIVER_CONFIG_INIT(&config, NULL);
    config.DriverInitFlags |= WdfDriverInitNonPnpDriver;
    config.EvtDriverUnload = DriverUnload;
    
    status = WdfDriverCreate(
        DriverObject,
        RegistryPath,
        WDF_NO_OBJECT_ATTRIBUTES,
        &config,
        &driver
    );
    
    if (!NT_SUCCESS(status)) {
        DbgPrint("KernelMonitor: WdfDriverCreate failed with status 0x%08x\n", status);
        return status;
    }
    
    // Create device object
    RtlInitUnicodeString(&deviceName, DEVICE_NAME);
    deviceInit = WdfControlDeviceInitAllocate(driver, &SDDL_DEVOBJ_SYS_ALL_ADM_ALL);
    
    if (deviceInit == NULL) {
        DbgPrint("KernelMonitor: WdfControlDeviceInitAllocate failed\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    WdfDeviceInitSetDeviceType(deviceInit, FILE_DEVICE_UNKNOWN);
    WdfDeviceInitSetIoType(deviceInit, WdfDeviceIoBuffered);
    WdfDeviceInitSetCharacteristics(deviceInit, FILE_DEVICE_SECURE_OPEN, FALSE);
    WdfDeviceInitSetDeviceClass(deviceInit, &GUID_DEVCLASS_MONITOR);
    
    status = WdfDeviceInitAssignName(deviceInit, &deviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("KernelMonitor: WdfDeviceInitAssignName failed with status 0x%08x\n", status);
        WdfDeviceInitFree(deviceInit);
        return status;
    }
    
    // Set file-create callback
    WdfDeviceInitSetFileObjectConfig(
        deviceInit,
        WDF_NO_OBJECT_ATTRIBUTES,
        WDF_NO_OBJECT_ATTRIBUTES,
        DeviceFileCreate,
        DeviceFileClose
    );
    
    // Create device
    WDF_OBJECT_ATTRIBUTES_INIT(&deviceAttributes);
    
    status = WdfDeviceCreate(
        &deviceInit,
        &deviceAttributes,
        &DeviceObject
    );
    
    if (!NT_SUCCESS(status)) {
        DbgPrint("KernelMonitor: WdfDeviceCreate failed with status 0x%08x\n", status);
        WdfDeviceInitFree(deviceInit);
        return status;
    }
    
    // Create symbolic link
    RtlInitUnicodeString(&symbolicLink, SYMBOLIC_LINK);
    status = WdfDeviceCreateSymbolicLink(DeviceObject, &symbolicLink);
    
    if (!NT_SUCCESS(status)) {
        DbgPrint("KernelMonitor: WdfDeviceCreateSymbolicLink failed with status 0x%08x\n", status);
        return status;
    }
    
    // Configure I/O queue
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = DeviceIoControl;
    
    status = WdfIoQueueCreate(
        DeviceObject,
        &queueConfig,
        WDF_NO_OBJECT_ATTRIBUTES,
        &queue
    );
    
    if (!NT_SUCCESS(status)) {
        DbgPrint("KernelMonitor: WdfIoQueueCreate failed with status 0x%08x\n", status);
        return status;
    }
    
    // Register process callbacks
    status = RegisterProcessCallbacks();
    if (!NT_SUCCESS(status)) {
        DbgPrint("KernelMonitor: RegisterProcessCallbacks failed with status 0x%08x\n", status);
        return status;
    }
    
    WdfControlFinishInitializing(DeviceObject);
    
    DbgPrint("KernelMonitor: Driver loaded successfully\n");
    return STATUS_SUCCESS;
}

// Driver unload callback
VOID DriverUnload(
    _In_ WDFDRIVER Driver
)
{
    UNREFERENCED_PARAMETER(Driver);
    
    // Unregister callbacks
    UnregisterProcessCallbacks();
    
    DbgPrint("KernelMonitor: Driver unloaded\n");
}

// Device file create callback
VOID DeviceFileCreate(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ WDFFILEOBJECT FileObject
)
{
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(FileObject);
    
    DbgPrint("KernelMonitor: Device file opened\n");
    WdfRequestComplete(Request, STATUS_SUCCESS);
}

// Device file close callback
VOID DeviceFileClose(
    _In_ WDFFILEOBJECT FileObject
)
{
    UNREFERENCED_PARAMETER(FileObject);
    
    DbgPrint("KernelMonitor: Device file closed\n");
}

// I/O control handler
VOID DeviceIoControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    
    UNREFERENCED_PARAMETER(Queue);
    
    switch (IoControlCode) {
        case IOCTL_GET_KERNEL_MEMORY:
            // Get input buffer
            if (InputBufferLength < sizeof(KERNEL_MEMORY_REQUEST)) {
                status = STATUS_BUFFER_TOO_SMALL;
                break;
            }
            
            status = WdfRequestRetrieveInputBuffer(Request, sizeof(KERNEL_MEMORY_REQUEST), &inputBuffer, NULL);
            if (!NT_SUCCESS(status)) {
                DbgPrint("KernelMonitor: WdfRequestRetrieveInputBuffer failed with status 0x%08x\n", status);
                break;
            }
            
            // Get output buffer
            status = WdfRequestRetrieveOutputBuffer(Request, 1, &outputBuffer, NULL);
            if (!NT_SUCCESS(status)) {
                DbgPrint("KernelMonitor: WdfRequestRetrieveOutputBuffer failed with status 0x%08x\n", status);
                break;
            }
            
            // Read kernel memory
            status = ReadKernelMemory((PKERNEL_MEMORY_REQUEST)inputBuffer, outputBuffer, (ULONG)OutputBufferLength);
            break;
            
        case IOCTL_MONITOR_PROCESS_CREATE:
            // Process monitoring is handled by callbacks, just return success
            DbgPrint("KernelMonitor: Process monitoring enabled\n");
            break;
            
        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }
    
    WdfRequestCompleteWithInformation(Request, status, (status == STATUS_SUCCESS) ? OutputBufferLength : 0);
}

// Process creation callback
VOID ProcessCreateCallback(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
    UNREFERENCED_PARAMETER(Process);
    
    if (CreateInfo) {
        // Process created
        DbgPrint("KernelMonitor: Process created - PID: %llu, Parent PID: %llu\n", 
                (ULONG64)ProcessId, (ULONG64)CreateInfo->ParentProcessId);
        
        if (CreateInfo->ImageFileName) {
            DbgPrint("KernelMonitor: Process image: %wZ\n", CreateInfo->ImageFileName);
        }
    } else {
        // Process terminated
        DbgPrint("KernelMonitor: Process terminated - PID: %llu\n", (ULONG64)ProcessId);
    }
}

// Register process callbacks
NTSTATUS RegisterProcessCallbacks()
{
    NTSTATUS status;
    
    status = PsSetCreateProcessNotifyRoutineEx(ProcessCreateCallback, FALSE);
    if (!NT_SUCCESS(status)) {
        DbgPrint("KernelMonitor: Failed to register process callback with status 0x%08x\n", status);
        return status;
    }
    
    ProcessCallbackHandle = (PVOID)1; // Mark as registered
    return STATUS_SUCCESS;
}

// Unregister process callbacks
VOID UnregisterProcessCallbacks()
{
    if (ProcessCallbackHandle) {
        PsSetCreateProcessNotifyRoutineEx(ProcessCreateCallback, TRUE);
        ProcessCallbackHandle = NULL;
    }
}

// Read kernel memory (dangerous operation!)
NTSTATUS ReadKernelMemory(
    PKERNEL_MEMORY_REQUEST Request,
    PVOID OutputBuffer,
    ULONG OutputBufferLength
)
{
    SIZE_T bytesToCopy;
    
    // Validate request
    if (Request->Address == 0 || Request->Size == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Limit size to output buffer size
    bytesToCopy = min(Request->Size, OutputBufferLength);
    
    // Use try/except to safely probe memory
    __try {
        // This is a security risk and should never be done in production code!
        // Only for educational purposes
        ProbeForRead((PVOID)Request->Address, bytesToCopy, 1);
        RtlCopyMemory(OutputBuffer, (PVOID)Request->Address, bytesToCopy);
        
        DbgPrint("KernelMonitor: Read %llu bytes from address 0x%p\n", 
                 (ULONG64)bytesToCopy, (PVOID)Request->Address);
        
        return STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("KernelMonitor: Exception reading memory at address 0x%p\n", 
                 (PVOID)Request->Address);
        return GetExceptionCode();
    }
}
