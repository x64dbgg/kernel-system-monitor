
#include "ProcessMonitor.h"
#include <Psapi.h>
#include <TlHelp32.h>
#include <iostream>

ProcessMonitor::ProcessMonitor() : m_running(false) {
    m_createCallback = [](const ProcessInfo&) {};
    m_terminateCallback = [](DWORD) {};
}

ProcessMonitor::~ProcessMonitor() {
    stopMonitoring();
}

void ProcessMonitor::startMonitoring() {
    if (m_running) {
        return;
    }
    
    m_running = true;
    m_monitorThread = std::thread(&ProcessMonitor::monitorThread, this);
}

void ProcessMonitor::stopMonitoring() {
    if (!m_running) {
        return;
    }
    
    m_running = false;
    if (m_monitorThread.joinable()) {
        m_monitorThread.join();
    }
}

bool ProcessMonitor::isMonitoring() const {
    return m_running;
}

std::vector<ProcessInfo> ProcessMonitor::getRunningProcesses() {
    std::vector<ProcessInfo> result;
    
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return result;
    }
    
    PROCESSENTRY32W processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32W);
    
    if (Process32FirstW(snapshot, &processEntry)) {
        do {
            ProcessInfo info;
            info.processId = processEntry.th32ProcessID;
            info.name = processEntry.szExeFile;
            info.parentProcessId = processEntry.th32ParentProcessID;
            
            // Open process to get more info
            HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, info.processId);
            if (processHandle != NULL) {
                getProcessPath(processHandle, info.path);
                info.is64Bit = isProcess64Bit(processHandle);
                info.processHandle = processHandle;
                
                FILETIME creationTime, exitTime, kernelTime, userTime;
                if (GetProcessTimes(processHandle, &creationTime, &exitTime, &kernelTime, &userTime)) {
                    info.creationTime = creationTime;
                }
            }
            
            result.push_back(info);
            
            if (processHandle != NULL) {
                CloseHandle(processHandle);
            }
            
        } while (Process32NextW(snapshot, &processEntry));
    }
    
    CloseHandle(snapshot);
    return result;
}

ProcessInfo ProcessMonitor::getProcessInfo(DWORD processId) {
    ProcessInfo info = {};
    info.processId = processId;
    
    HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (processHandle != NULL) {
        wchar_t buffer[MAX_PATH];
        if (GetModuleFileNameExW(processHandle, NULL, buffer, MAX_PATH)) {
            info.path = buffer;
            
            // Extract filename from path
            size_t pos = info.path.find_last_of(L"\\");
            if (pos != std::wstring::npos) {
                info.name = info.path.substr(pos + 1);
            } else {
                info.name = info.path;
            }
        }
        
        info.is64Bit = isProcess64Bit(processHandle);
        
        FILETIME creationTime, exitTime, kernelTime, userTime;
        if (GetProcessTimes(processHandle, &creationTime, &exitTime, &kernelTime, &userTime)) {
            info.creationTime = creationTime;
        }
        
        // Get parent process ID
        PROCESS_BASIC_INFORMATION pbi;
        typedef NTSTATUS (WINAPI *PFN_NT_QUERY_INFORMATION_PROCESS)(
            HANDLE ProcessHandle,
            ULONG ProcessInformationClass,
            PVOID ProcessInformation,
            ULONG ProcessInformationLength,
            PULONG ReturnLength
        );
        
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll) {
            PFN_NT_QUERY_INFORMATION_PROCESS NtQueryInformationProcess = 
                (PFN_NT_QUERY_INFORMATION_PROCESS)GetProcAddress(ntdll, "NtQueryInformationProcess");
                
            if (NtQueryInformationProcess) {
                ULONG returnLength;
                if (NtQueryInformationProcess(processHandle, 0, &pbi, sizeof(pbi), &returnLength) >= 0) {
                    info.parentProcessId = (DWORD)(ULONG_PTR)pbi.Reserved3;
                }
            }
        }
        
        CloseHandle(processHandle);
    }
    
    return info;
}

void ProcessMonitor::setProcessCreateCallback(std::function<void(const ProcessInfo&)> callback) {
    m_createCallback = callback;
}

void ProcessMonitor::setProcessTerminateCallback(std::function<void(DWORD)> callback) {
    m_terminateCallback = callback;
}

void ProcessMonitor::monitorThread() {
    // Initial snapshot of running processes
    auto processes = getRunningProcesses();
    
    {
        std::lock_guard<std::mutex> lock(m_processesMutex);
        for (const auto& proc : processes) {
            m_processes[proc.processId] = proc;
        }
    }
    
    while (m_running) {
        // Get current process list
        auto currentProcesses = getRunningProcesses();
        std::map<DWORD, ProcessInfo> currentProcessMap;
        
        for (const auto& proc : currentProcesses) {
            currentProcessMap[proc.processId] = proc;
        }
        
        // Check for new processes
        for (const auto& pair : currentProcessMap) {
            std::lock_guard<std::mutex> lock(m_processesMutex);
            if (m_processes.find(pair.first) == m_processes.end()) {
                // New process
                m_processes[pair.first] = pair.second;
                m_createCallback(pair.second);
            }
        }
        
        // Check for terminated processes
        std::vector<DWORD> terminatedProcesses;
        {
            std::lock_guard<std::mutex> lock(m_processesMutex);
            for (const auto& pair : m_processes) {
                if (currentProcessMap.find(pair.first) == currentProcessMap.end()) {
                    // Process terminated
                    terminatedProcesses.push_back(pair.first);
                }
            }
            
            // Remove terminated processes from our map
            for (DWORD pid : terminatedProcesses) {
                m_processes.erase(pid);
                m_terminateCallback(pid);
            }
        }
        
        // Sleep to avoid excessive CPU usage
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

bool ProcessMonitor::getProcessPath(HANDLE processHandle, std::wstring& path) {
    wchar_t buffer[MAX_PATH];
    if (GetModuleFileNameExW(processHandle, NULL, buffer, MAX_PATH)) {
        path = buffer;
        return true;
    }
    return false;
}

bool ProcessMonitor::isProcess64Bit(HANDLE processHandle) {
    BOOL isWow64 = FALSE;
    if (IsWow64Process(processHandle, &isWow64)) {
        // On 64-bit Windows, if the process is not running under WOW64, 
        // then it's a native 64-bit process
        #ifdef _WIN64
            return !isWow64;
        #else
            // On 32-bit Windows, all processes are 32-bit
            return false;
        #endif
    }
    // If we can't determine, assume it matches the architecture of the current process
    #ifdef _WIN64
        return true;
    #else
        return false;
    #endif
}
