#pragma once
#include <string>
#include <vector>
#include <Windows.h>

class KernelDriver {
public:
    KernelDriver();
    ~KernelDriver();
    
    bool loadDriver();
    bool unloadDriver();
    bool isDriverLoaded() const;
    
    bool sendIoctl(DWORD controlCode, LPVOID inBuffer, DWORD inBufferSize, 
                  LPVOID outBuffer, DWORD outBufferSize, LPDWORD bytesReturned);
    
    std::vector<BYTE> getKernelMemoryData(ULONG_PTR address, SIZE_T size);
    
private:
    bool createAndStartService();
    bool stopAndDeleteService();
    
    HANDLE m_driverHandle;
    bool m_isLoaded;
    std::wstring m_driverPath;
    std::wstring m_serviceName;
    
    static const DWORD IOCTL_GET_KERNEL_MEMORY = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS);
};
