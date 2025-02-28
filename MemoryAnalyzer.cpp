// MemoryAnalyzer.cpp
#include "MemoryAnalyzer.h"
#include <Psapi.h>
#include <TlHelp32.h>
#include <iomanip>
#include <iostream>
#include <sstream>

MemoryAnalyzer::MemoryAnalyzer() {
    enableDebugPrivilege();
}

MemoryAnalyzer::~MemoryAnalyzer() {
}

MemoryStats MemoryAnalyzer::getSystemMemoryStats() {
    MemoryStats stats = {};
    
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    if (GlobalMemoryStatusEx(&memInfo)) {
        stats.totalPhysical = memInfo.ullTotalPhys;
        stats.availablePhysical = memInfo.ullAvailPhys;
        stats.totalPageFile = memInfo.ullTotalPageFile;
        stats.availablePageFile = memInfo.ullAvailPageFile;
        stats.totalVirtual = memInfo.ullTotalVirtual;
        stats.availableVirtual = memInfo.ullAvailVirtual;
        stats.memoryLoad = memInfo.dwMemoryLoad;
        stats.systemCache = getSystemCacheSize();
    }
    
    return stats;
}

std::vector<ProcessMemoryInfo> MemoryAnalyzer::getProcessesMemoryInfo() {
    std::vector<ProcessMemoryInfo> result;
    
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return result;
    }
    
    PROCESSENTRY32W processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32W);
    
    if (Process32FirstW(snapshot, &processEntry)) {
        do {
            ProcessMemoryInfo info = {};
            info.processId = processEntry.th32ProcessID;
            info.processName = processEntry.szExeFile;
            
            HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, info.processId);
            if (processHandle != NULL) {
                PROCESS_MEMORY_COUNTERS_EX pmc;
                if (GetProcessMemoryInfo(processHandle, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
                    info.workingSetSize = pmc.WorkingSetSize;
                    info.privateUsage = pmc.PrivateUsage;
                    info.peakWorkingSetSize = pmc.PeakWorkingSetSize;
                    info.pageFaultCount = pmc.PageFaultCount;
                    info.pagefileUsage = pmc.PagefileUsage;
                    info.peakPagefileUsage = pmc.PeakPagefileUsage;
                    
                    NTSTATUS status;
                    PVOID addresses[1] = { 0 };
                    MEMORY_BASIC_INFORMATION memInfo;
                    SIZE_T virtualSize = 0;
                    
                    while (VirtualQueryEx(processHandle, addresses[0], &memInfo, sizeof(memInfo))) {
                        addresses[0] = (PVOID)((LPBYTE)memInfo.BaseAddress + memInfo.RegionSize);
                        virtualSize += memInfo.RegionSize;
                    }
                    
                    info.virtualSize = virtualSize;
                }
                
                CloseHandle(processHandle);
            }
            
            result.push_back(info);
            
        } while (Process32NextW(snapshot, &processEntry));
    }
    
    CloseHandle(snapshot);
    return result;
}

std::map<std::wstring, SIZE_T> MemoryAnalyzer::analyzeSystemMemory() {
    std::map<std::wstring, SIZE_T> result;
    
    // Get system memory stats
    MemoryStats stats = getSystemMemoryStats();
    result[L"TotalPhysical"] = stats.totalPhysical;
    result[L"AvailablePhysical"] = stats.availablePhysical;
    result[L"UsedPhysical"] = stats.totalPhysical - stats.availablePhysical;
    result[L"MemoryLoad"] = stats.memoryLoad;
    result[L"SystemCache"] = stats.systemCache;
    
    // Analyze process memory usage
    auto processInfo = getProcessesMemoryInfo();
    
    SIZE_T totalProcessPrivate = 0;
    SIZE_T totalProcessWorking = 0;
    
    for (const auto& proc : processInfo) {
        totalProcessPrivate += proc.privateUsage;
        totalProcessWorking += proc.workingSetSize;
    }
    
    result[L"TotalProcessPrivate"] = totalProcessPrivate;
    result[L"TotalProcessWorking"] = totalProcessWorking;
    
    // Find top memory consumers
    std::sort(processInfo.begin(), processInfo.end(), [](const ProcessMemoryInfo& a, const ProcessMemoryInfo& b) {
        return a.workingSetSize > b.workingSetSize;
    });
    
    for (size_t i = 0; i < std::min(size_t(5), processInfo.size()); i++) {
        std::wstringstream ss;
        ss << L"Top" << (i + 1) << L"_" << processInfo[i].processName;
        result[ss.str()] = processInfo[i].workingSetSize;
    }
    
    return result;
}

void MemoryAnalyzer::displayResults(const std::map<std::wstring, SIZE_T>& results) {
    std::cout << "===== Memory Analysis Results =====" << std::endl;
    
    for (const auto& pair : results) {
        std::wcout << std::left << std::setw(30) << pair.first << L": ";
        
        // Format size in human-readable form
        if (pair.first == L"MemoryLoad") {
            std::cout << pair.second << "%" << std::endl;
        } else {
            double size = static_cast<double>(pair.second);
            const char* units[] = {"B", "KB", "MB", "GB", "TB"};
            int unitIndex = 0;
            
            while (size >= 1024.0 && unitIndex < 4) {
                size /= 1024.0;
                unitIndex++;
            }
            
            std::cout << std::fixed << std::setprecision(2) << size << " " << units[unitIndex] << std::endl;
        }
    }
    
    std::cout << "=================================" << std::endl;
}

bool MemoryAnalyzer::enableDebugPrivilege() {
    HANDLE token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return false;
    }
    
    TOKEN_PRIVILEGES tp;
    LUID luid;
    
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(token);
        return false;
    }
    
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    BOOL result = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    DWORD error = GetLastError();
    
    CloseHandle(token);
    
    return (result && error != ERROR_NOT_ALL_ASSIGNED);
}

SIZE_T MemoryAnalyzer::getSystemCacheSize() {
    typedef BOOL (WINAPI *PGET_PERFORMANCE_INFO)(PERFORMANCE_INFORMATION*, DWORD);
    
    PERFORMANCE_INFORMATION perfInfo = { sizeof(PERFORMANCE_INFORMATION) };
    HMODULE psapi = LoadLibraryW(L"psapi.dll");
    
    if (psapi) {
        PGET_PERFORMANCE_INFO pGetPerformanceInfo = 
            (PGET_PERFORMANCE_INFO)GetProcAddress(psapi, "GetPerformanceInfo");
            
        if (pGetPerformanceInfo && pGetPerformanceInfo(&perfInfo, sizeof(perfInfo))) {
            FreeLibrary(psapi);
            return perfInfo.SystemCache * perfInfo.PageSize;
        }
        
        FreeLibrary(psapi);
    }
    
    return 0;
}
