// SystemInfo.h
#pragma once

#include <Windows.h>
#include <string>
#include <vector>
#include <map>

struct CPUInfo {
    std::string vendor;
    std::string brand;
    int numCores;
    int numLogicalProcessors;
    std::string architecture;
    bool hyperThreading;
    double frequencyMHz;
};

struct GPUInfo {
    std::string name;
    SIZE_T dedicatedMemory;
    SIZE_T sharedMemory;
    std::string driverVersion;
};

struct OSInfo {
    std::string name;
    std::string version;
    std::string buildNumber;
    std::string architecture;
    DWORD majorVersion;
    DWORD minorVersion;
};

struct DiskInfo {
    std::string driveLetter;
    std::string volumeName;
    std::string fileSystem;
    ULONGLONG totalSize;
    ULONGLONG freeSpace;
};

struct NetworkAdapterInfo {
    std::string name;
    std::string description;
    std::string macAddress;
    std::vector<std::string> ipAddresses;
    bool isConnected;
};

class SystemInfo {
public:
    SystemInfo();
    ~SystemInfo();
    
    CPUInfo getCPUInfo();
    std::vector<GPUInfo> getGPUInfo();
    OSInfo getOSInfo();
    std::vector<DiskInfo> getDiskInfo();
    std::vector<NetworkAdapterInfo> getNetworkAdapters();
    
    std::map<std::string, std::string> getEnvironmentVariables();
    
    void displaySystemInfo();
    
private:
    bool isElevated();
    std::string getWMIProperty(const std::string& wmiClass, const std::string& property);
    std::vector<std::map<std::string, std::string>> getWMIData(const std::string& wmiClass, const std::vector<std::string>& properties);
};
