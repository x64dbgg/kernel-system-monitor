#include "KernelDriver.h"
#include <iostream>
#include <filesystem>
#include <stdexcept>

KernelDriver::KernelDriver() 
    : m_driverHandle(INVALID_HANDLE_VALUE), m_isLoaded(false) {
    // Set driver path to current directory
    wchar_t currentDir[MAX_PATH];
    GetCurrentDirectoryW(MAX_PATH, currentDir);
    m_driverPath = std::wstring(currentDir) + L"\\KernelMonitor.sys";
    m_serviceName = L"KernelMonitor";
}

KernelDriver::~KernelDriver() {
    unloadDriver();
}

bool KernelDriver::loadDriver() {
    if (m_isLoaded) {
        return true;
    }
    
    // Check if driver file exists
    if (!std::filesystem::exists(m_driverPath)) {
        std::cerr << "Driver file not found: " << std::string(m_driverPath.begin(), m_driverPath.end()) << std::endl;
        return false;
    }
    
    // Load driver via service
    if (!createAndStartService()) {
        std::cerr << "Failed to create and start driver service" << std::endl;
        return false;
    }
    
    // Open handle to the driver
    m_driverHandle = CreateFileW(
        L"\\\\.\\KernelMonitor",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (m_driverHandle == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        std::cerr << "Failed to open handle to driver. Error code: " << error << std::endl;
        stopAndDeleteService();
        return false;
    }
    
    m_isLoaded = true;
    return true;
}

bool KernelDriver::unloadDriver() {
    if (!m_isLoaded) {
        return true;
    }
    
    if (m_driverHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(m_driverHandle);
        m_driverHandle = INVALID_HANDLE_VALUE;
    }
    
    if (!stopAndDeleteService()) {
        std::cerr << "Failed to stop and delete driver service" << std::endl;
        return false;
    }
    
    m_isLoaded = false;
    return true;
}

bool KernelDriver::isDriverLoaded() const {
    return m_isLoaded;
}

bool KernelDriver::sendIoctl(DWORD controlCode, LPVOID inBuffer, DWORD inBufferSize, 
                           LPVOID outBuffer, DWORD outBufferSize, LPDWORD bytesReturned) {
    if (!m_isLoaded || m_driverHandle == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    return DeviceIoControl(
        m_driverHandle,
        controlCode,
        inBuffer,
        inBufferSize,
        outBuffer,
        outBufferSize,
        bytesReturned,
        NULL
    );
}

std::vector<BYTE> KernelDriver::getKernelMemoryData(ULONG_PTR address, SIZE_T size) {
    std::vector<BYTE> result(size);
    
    struct {
        ULONG_PTR Address;
        SIZE_T Size;
    } inputBuffer = { address, size };
    
    DWORD bytesReturned = 0;
    if (!sendIoctl(IOCTL_GET_KERNEL_MEMORY, &inputBuffer, sizeof(inputBuffer), 
                  result.data(), static_cast<DWORD>(result.size()), &bytesReturned)) {
        throw std::runtime_error("Failed to read kernel memory data");
    }
    
    if (bytesReturned != size) {
        result.resize(bytesReturned);
    }
    
    return result;
}

bool KernelDriver::createAndStartService() {
    SC_HANDLE scManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scManager == NULL) {
        DWORD error = GetLastError();
        std::cerr << "Failed to open service control manager. Error code: " << error << std::endl;
        return false;
    }
    
    // Create service
    SC_HANDLE service = CreateServiceW(
        scManager,
        m_serviceName.c_str(),
        m_serviceName.c_str(),
        SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        m_driverPath.c_str(),
        NULL,
        NULL,
        NULL,
        NULL,
        NULL
    );
    
    DWORD lastError = GetLastError();
    if (service == NULL) {
        if (lastError == ERROR_SERVICE_EXISTS) {
            // Service already exists, try to open it
            service = OpenServiceW(scManager, m_serviceName.c_str(), SERVICE_ALL_ACCESS);
            if (service == NULL) {
                CloseServiceHandle(scManager);
                std::cerr << "Service exists but could not be opened. Error code: " << GetLastError() << std::endl;
                return false;
            }
        } else {
            CloseServiceHandle(scManager);
            std::cerr << "Failed to create service. Error code: " << lastError << std::endl;
            return false;
        }
    }
    
    // Start service
    if (!StartServiceW(service, 0, NULL)) {
        lastError = GetLastError();
        if (lastError != ERROR_SERVICE_ALREADY_RUNNING) {
            CloseServiceHandle(service);
            CloseServiceHandle(scManager);
            std::cerr << "Failed to start service. Error code: " << lastError << std::endl;
            return false;
        }
    }
    
    CloseServiceHandle(service);
    CloseServiceHandle(scManager);
    return true;
}

bool KernelDriver::stopAndDeleteService() {
    SC_HANDLE scManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scManager == NULL) {
        return false;
    }
    
    SC_HANDLE service = OpenServiceW(scManager, m_serviceName.c_str(), SERVICE_ALL_ACCESS);
    if (service == NULL) {
        CloseServiceHandle(scManager);
        return false;
    }
    
    SERVICE_STATUS serviceStatus;
    if (ControlService(service, SERVICE_CONTROL_STOP, &serviceStatus)) {
        // Wait for service to stop
        Sleep(1000);
    }
    
    BOOL result = DeleteService(service);
    
    CloseServiceHandle(service);
    CloseServiceHandle(scManager);
    
    return result != FALSE;
}
