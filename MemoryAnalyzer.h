// MemoryAnalyzer.h
#pragma once

#include <Windows.h>
#include <vector>
#include <string>
#include <map>

struct MemoryStats {
    SIZE_T totalPhysical;
    SIZE_T availablePhysical;
    SIZE_T totalPageFile;
    SIZE_T availablePageFile;
    SIZE_T totalVirtual;
    SIZE_T availableVirtual;
    SIZE_T systemCache;
    DWORD memoryLoad;
};

struct ProcessMemoryInfo {
    DWORD processId;
    std::wstring processName;
    SIZE_T workingSetSize;
    SIZE_T privateUsage;
    SIZE_T peakWorkingSetSize;
    SIZE_T pageFaultCount;
    SIZE_T pagefileUsage;
    SIZE_T peakPagefileUsage;
    SIZE_T virtualSize;
};

class MemoryAnalyzer {
public:
    MemoryAnalyzer();
    ~MemoryAnalyzer();
    
    MemoryStats getSystemMemoryStats();
    std::vector<ProcessMemoryInfo> getProcessesMemoryInfo();
    std::map<std::wstring, SIZE_T> analyzeSystemMemory();
    
    void displayResults(const std::map<std::wstring, SIZE_T>& results);
    
private:
    bool enableDebugPrivilege();
    SIZE_T getSystemCacheSize();
};
