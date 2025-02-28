
#pragma once

#include <Windows.h>
#include <vector>
#include <string>
#include <atomic>
#include <mutex>
#include <thread>
#include <functional>
#include <map>

struct ProcessInfo {
    DWORD processId;
    std::wstring name;
    std::wstring path;
    DWORD parentProcessId;
    FILETIME creationTime;
    HANDLE processHandle;
    bool is64Bit;
};

class ProcessMonitor {
public:
    ProcessMonitor();
    ~ProcessMonitor();
    
    void startMonitoring();
    void stopMonitoring();
    bool isMonitoring() const;
    
    std::vector<ProcessInfo> getRunningProcesses();
    ProcessInfo getProcessInfo(DWORD processId);
    
    void setProcessCreateCallback(std::function<void(const ProcessInfo&)> callback);
    void setProcessTerminateCallback(std::function<void(DWORD)> callback);

private:
    void monitorThread();
    bool getProcessPath(HANDLE processHandle, std::wstring& path);
    bool isProcess64Bit(HANDLE processHandle);
    
    std::atomic<bool> m_running;
    std::thread m_monitorThread;
    std::mutex m_processesMutex;
    std::map<DWORD, ProcessInfo> m_processes;
    
    std::function<void(const ProcessInfo&)> m_createCallback;
    std::function<void(DWORD)> m_terminateCallback;
};
