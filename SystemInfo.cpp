// SystemInfo.cpp
#include "SystemInfo.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <comdef.h>
#include <Wbemidl.h>
#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

SystemInfo::SystemInfo() {
    // Initialize COM
    CoInitializeEx(0, COINIT_MULTITHREADED);
}

SystemInfo::~SystemInfo() {
    // Uninitialize COM
    CoUninitialize();
}

CPUInfo SystemInfo::getCPUInfo() {
    CPUInfo info = {};
    
    // Use WMI to get CPU information
    auto cpuData = getWMIData("Win32_Processor", { "Name", "Manufacturer", "NumberOfCores", "NumberOfLogicalProcessors", "MaxClockSpeed" });
    
    if (!cpuData.empty()) {
        info.brand = cpuData[0]["Name"];
        info.vendor = cpuData[0]["Manufacturer"];
        info.numCores = std::stoi(cpuData[0]["NumberOfCores"]);
        info.numLogicalProcessors = std::stoi(cpuData[0]["NumberOfLogicalProcessors"]);
        info.frequencyMHz = std::stod(cpuData[0]["MaxClockSpeed"]);
        info.hyperThreading = (info.numLogicalProcessors > info.numCores);
    }
    
    // Get architecture
    SYSTEM_INFO sysInfo;
    GetNativeSystemInfo(&sysInfo);
    
    switch (sysInfo.wProcessorArchitecture) {
        case PROCESSOR_ARCHITECTURE_AMD64:
            info.architecture = "x64";
            break;
        case PROCESSOR_ARCHITECTURE_INTEL:
            info.architecture = "x86";
            break;
        case PROCESSOR_ARCHITECTURE_ARM:
            info.architecture = "ARM";
            break;
        case PROCESSOR_ARCHITECTURE_ARM64:
            info.architecture = "ARM64";
            break;
        default:
            info.architecture = "Unknown";
            break;
    }
    
    return info;
}

std::vector<GPUInfo> SystemInfo::getGPUInfo() {
    std::vector<GPUInfo> result;
    
    // Use WMI to get GPU information
    auto gpuData = getWMIData("Win32_VideoController", 
                             { "Name", "AdapterRAM", "DriverVersion", "VideoMemoryType" });
    
    for (const auto& gpu : gpuData) {
        GPUInfo info = {};
        
        auto it = gpu.find("Name");
        if (it != gpu.end()) {
            info.name = it->second;
        }
        
        it = gpu.find("AdapterRAM");
        if (it != gpu.end()) {
            try {
                info.dedicatedMemory = std::stoull(it->second);
            } catch (...) {
                info.dedicatedMemory = 0;
            }
        }
        
        it = gpu.find("DriverVersion");
        if (it != gpu.end()) {
            info.driverVersion = it->second;
        }
        
        result.push_back(info);
    }
    
    return result;
}

OSInfo SystemInfo::getOSInfo() {
    OSInfo info = {};
    
    // Get OS version information
    auto osData = getWMIData("Win32_OperatingSystem", 
                            { "Caption", "Version", "BuildNumber", "OSArchitecture" });
    
    if (!osData.empty()) {
        info.name = osData[0]["Caption"];
        info.version = osData[0]["Version"];
        info.buildNumber = osData[0]["BuildNumber"];
        info.architecture = osData[0]["OSArchitecture"];
        
        // Parse version string
        std::istringstream versionStream(info.version);
        std::string majorStr, minorStr;
        
        if (std::getline(versionStream, majorStr, '.') && 
            std::getline(versionStream, minorStr, '.')) {
            try {
                info.majorVersion = std::stoul(majorStr);
                info.minorVersion = std::stoul(minorStr);
            } catch (...) {
                info.majorVersion = 0;
                info.minorVersion = 0;
            }
        }
    }
    
    return info;
}

std::vector<DiskInfo> SystemInfo::getDiskInfo() {
    std::vector<DiskInfo> result;
    
    // Get logical drives
    DWORD drives = GetLogicalDrives();
    char driveLetter = 'A';
    
    for (int i = 0; i < 26; i++, driveLetter++) {
        if (drives & (1 << i)) {
            std::string rootPath = std::string(1, driveLetter) + ":\\";
            
            UINT driveType = GetDriveTypeA(rootPath.c_str());
            if (driveType == DRIVE_FIXED || driveType == DRIVE_REMOVABLE) {
                DiskInfo info = {};
                info.driveLetter = driveLetter;
                
                char volumeName[MAX_PATH + 1] = { 0 };
                char fileSystemName[MAX_PATH + 1] = { 0 };
                DWORD serialNumber = 0;
                DWORD maxComponentLength = 0;
                DWORD fileSystemFlags = 0;
                
                if (GetVolumeInformationA(
                    rootPath.c_str(),
                    volumeName,
                    sizeof(volumeName),
                    &serialNumber,
                    &maxComponentLength,
                    &fileSystemFlags,
                    fileSystemName,
                    sizeof(fileSystemName))) {
                    
                    info.volumeName = volumeName;
                    info.fileSystem = fileSystemName;
                }
                
                ULARGE_INTEGER freeBytesAvailable;
                ULARGE_INTEGER totalNumberOfBytes;
                ULARGE_INTEGER totalNumberOfFreeBytes;
                
                if (GetDiskFreeSpaceExA(
                    rootPath.c_str(),
                    &freeBytesAvailable,
                    &totalNumberOfBytes,
                    &totalNumberOfFreeBytes)) {
                    
                    info.totalSize = totalNumberOfBytes.QuadPart;
                    info.freeSpace = freeBytesAvailable.QuadPart;
                }
                
                result.push_back(info);
            }
        }
    }
    
    return result;
}

std::vector<NetworkAdapterInfo> SystemInfo::getNetworkAdapters() {
    std::vector<NetworkAdapterInfo> result;
    
    // Initialize Winsock
    WSADATA wsaData;
    int wsaResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsaResult != 0) {
        return result;
    }
    
    // Get adapter info
    ULONG bufferSize = sizeof(IP_ADAPTER_ADDRESSES) * 16; // Start with 16 adapters
    PIP_ADAPTER_ADDRESSES pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(bufferSize);
    
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
    ULONG retVal = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, pAddresses, &bufferSize);
    
    if (retVal == ERROR_BUFFER_OVERFLOW) {
        free(pAddresses);
        pAddresses = (PIP_ADAPTER_ADDRESSES)malloc(bufferSize);
        retVal = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, pAddresses, &bufferSize);
    }
    
    if (retVal == NO_ERROR) {
        PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses;
        while (pCurrAddresses) {
            NetworkAdapterInfo adapter = {};
            
            // Convert adapter name from wide char
            std::wstring wideName(pCurrAddresses->FriendlyName);
            adapter.name = std::string(wideName.begin(), wideName.end());
            
            // Convert description from wide char
            std::wstring wideDesc(pCurrAddresses->Description);
            adapter.description = std::string(wideDesc.begin(), wideDesc.end());
            
            // Get MAC address
            if (pCurrAddresses->PhysicalAddressLength != 0) {
                std::stringstream macStream;
                for (ULONG i = 0; i < pCurrAddresses->PhysicalAddressLength; i++) {
                    if (i > 0) macStream << "-";
                    macStream << std::uppercase << std::hex << std::setfill('0') << std::setw(2) 
                              << (int)pCurrAddresses->PhysicalAddress[i];
                }
                adapter.macAddress = macStream.str();
            }
            
            // Connection status
            adapter.isConnected = (pCurrAddresses->OperStatus == IfOperStatusUp);
            
            // Get IP addresses
            PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurrAddresses->FirstUnicastAddress;
            while (pUnicast) {
                SOCKET_ADDRESS sockAddr = pUnicast->Address;
                sockaddr* pSockAddr = sockAddr.lpSockaddr;
                
                char ipStr[INET6_ADDRSTRLEN];
                
                if (pSockAddr->sa_family == AF_INET) {
                    // IPv4
                    sockaddr_in* pIPv4 = (sockaddr_in*)pSockAddr;
                    inet_ntop(AF_INET, &(pIPv4->sin_addr), ipStr, INET_ADDRSTRLEN);
                    adapter.ipAddresses.push_back(ipStr);
                } else if (pSockAddr->sa_family == AF_INET6) {
                    // IPv6
                    sockaddr_in6* pIPv6 = (sockaddr_in6*)pSockAddr;
                    inet_ntop(AF_INET6, &(pIPv6->sin6_addr), ipStr, INET6_ADDRSTRLEN);
                    adapter.ipAddresses.push_back(ipStr);
                }
                
                pUnicast = pUnicast->Next;
            }
            
            result.push_back(adapter);
            pCurrAddresses = pCurrAddresses->Next;
        }
    }
    
    free(pAddresses);
    WSACleanup();
    
    return result;
}

std::map<std::string, std::string> SystemInfo::getEnvironmentVariables() {
    std::map<std::string, std::string> result;
    
    // Get environment variables
    LPCH envBlock = GetEnvironmentStrings();
    if (envBlock) {
        LPCH current = envBlock;
        while (*current) {
            std::string envVar(current);
            
            // Skip environment variables with no name (like "=C:=C:\Windows")
            if (envVar[0] != '=') {
                size_t pos = envVar.find('=');
                if (pos != std::string::npos) {
                    std::string name = envVar.substr(0, pos);
                    std::string value = envVar.substr(pos + 1);
                    result[name] = value;
                }
            }
            
            current += strlen(current) + 1;
        }
        
        FreeEnvironmentStrings(envBlock);
    }
    
    return result;
}

void SystemInfo::displaySystemInfo() {
    std::cout << "===== System Information =====" << std::endl;
    
    // OS Info
    OSInfo os = getOSInfo();
    std::cout << "OS: " << os.name << std::endl;
    std::cout << "Version: " << os.version << " (Build " << os.buildNumber << ")" << std::endl;
    std::cout << "Architecture: " << os.architecture << std::endl;
    std::cout << std::endl;
    
    // CPU Info
    CPUInfo cpu = getCPUInfo();
    std::cout << "CPU: " << cpu.brand << std::endl;
    std::cout << "Vendor: " << cpu.vendor << std::endl;
    std::cout << "Cores: " << cpu.numCores << " (Logical processors: " << cpu.numLogicalProcessors << ")" << std::endl;
    std::cout << "Architecture: " << cpu.architecture << std::endl;
    std::cout << "Frequency: " << cpu.frequencyMHz << " MHz" << std::endl;
    std::cout << "Hyper-Threading: " << (cpu.hyperThreading ? "Yes" : "No") << std::endl;
    std::cout << std::endl;
    
    // GPU Info
    auto gpus = getGPUInfo();
    std::cout << "GPUs: " << gpus.size() << std::endl;
    for (size_t i = 0; i < gpus.size(); i++) {
        std::cout << "  " << (i + 1) << ". " << gpus[i].name << std::endl;
        std::cout << "     VRAM: " << (gpus[i].dedicatedMemory / (1024 * 1024)) << " MB" << std::endl;
        std::cout << "     Driver: " << gpus[i].driverVersion << std::endl;
    }
    std::cout << std::endl;
    
    // Disk Info
    auto disks = getDiskInfo();
    std::cout << "Disks: " << disks.size() << std::endl;
    for (const auto& disk : disks) {
        std::cout << "  " << disk.driveLetter << ": (" << disk.volumeName << ") - " << disk.fileSystem << std::endl;
        std::cout << "     Total: " << (disk.totalSize / (1024 * 1024 * 1024)) << " GB, Free: " 
                  << (disk.freeSpace / (1024 * 1024 * 1024)) << " GB" << std::endl;
    }
    std::cout << std::endl;
    
    // Network Adapters
    auto adapters = getNetworkAdapters();
    std::cout << "Network Adapters: " << adapters.size() << std::endl;
    for (const auto& adapter : adapters) {
        std::cout << "  " << adapter.name << (adapter.isConnected ? " (Connected)" : " (Disconnected)") << std::endl;
        std::cout << "     MAC: " << adapter.macAddress << std::endl;
        
        if (!adapter.ipAddresses.empty()) {
            std::cout << "     IP Addresses:" << std::endl;
            for (const auto& ip : adapter.ipAddresses) {
                std::cout << "       " << ip << std::endl;
            }
        }
    }
    
    std::cout << "=============================" << std::endl;
}

bool SystemInfo::isElevated() {
    BOOL fRet = FALSE;
    HANDLE hToken = NULL;
    
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        
        if (GetTokenInformation(hToken, TokenElevation, &elevation, cbSize, &cbSize)) {
            fRet = elevation.TokenIsElevated;
        }
    }
    
    if (hToken) {
        CloseHandle(hToken);
    }
    
    return fRet;
}

std::string SystemInfo::getWMIProperty(const std::string& wmiClass, const std::string& property) {
    std::string result;
    
    IWbemLocator* pLoc = nullptr;
    IWbemServices* pSvc = nullptr;
    IEnumWbemClassObject* pEnumerator = nullptr;
    IWbemClassObject* pclsObj = nullptr;
    VARIANT vtProp;
    
    try {
        // Initialize COM
        HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (FAILED(hr)) throw std::runtime_error("Failed to initialize COM library");
        
        // Initialize WMI
        hr = CoCreateInstance(
            CLSID_WbemLocator,
            0,
            CLSCTX_INPROC_SERVER,
            IID_IWbemLocator,
            (LPVOID*)&pLoc
        );
        if (FAILED(hr)) throw std::runtime_error("Failed to create IWbemLocator");
        
        // Connect to WMI
        hr = pLoc->ConnectServer(
            _bstr_t(L"ROOT\\CIMV2"),  // WMI namespace
            NULL,                      // User name
            NULL,                      // User password
            0,                         // Locale
            NULL,                      // Security flags
            0,                         // Authority
            0,                         // Context
            &pSvc                      // IWbemServices proxy
        );
        if (FAILED(hr)) throw std::runtime_error("Failed to connect to WMI");
        
        // Set security levels
        hr = CoSetProxyBlanket(
            pSvc,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            NULL,
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL,
            EOAC_NONE
        );
        if (FAILED(hr)) throw std::runtime_error("Failed to set proxy blanket");
        
        // Create WMI query
        std::string query = "SELECT " + property + " FROM " + wmiClass;
        hr = pSvc->ExecQuery(
            bstr_t("WQL"),
            bstr_t(query.c_str()),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL,
            &pEnumerator
        );
        if (FAILED(hr)) throw std::runtime_error("Failed to execute WMI query");
        
        // Get first result
        ULONG uReturn = 0;
        hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (FAILED(hr) || uReturn == 0) throw std::runtime_error("No WMI objects found");
        
        // Get property value
        hr = pclsObj->Get(bstr_t(property.c_str()), 0, &vtProp, 0, 0);
        if (FAILED(hr)) throw std::runtime_error("Failed to get property value");
        
        // Convert to string
        if (vtProp.vt == VT_BSTR) {
            std::wstring wstrValue(vtProp.bstrVal);
            result = std::string(wstrValue.begin(), wstrValue.end());
        } else if (vtProp.vt == VT_I4) {
            result = std::to_string(vtProp.lVal);
        } else if (vtProp.vt == VT_UI4) {
            result = std::to_string(vtProp.ulVal);
        } else if (vtProp.vt == VT_BOOL) {
            result = vtProp.boolVal ? "True" : "False";
        }
        
        // Clean up variant
        VariantClear(&vtProp);
    }
    catch (const std::exception& e) {
        // Handle exception
        result = "";
    }
    
    // Clean up
    if (pclsObj) pclsObj->Release();
    if (pEnumerator) pEnumerator->Release();
    if (pSvc) pSvc->Release();
    if (pLoc) pLoc->Release();
    
    return result;
}

std::vector<std::map<std::string, std::string>> SystemInfo::getWMIData(
    const std::string& wmiClass, const std::vector<std::string>& properties) {
    
    std::vector<std::map<std::string, std::string>> result;
    
    IWbemLocator* pLoc = nullptr;
    IWbemServices* pSvc = nullptr;
    IEnumWbemClassObject* pEnumerator = nullptr;
    
    try {
        // Initialize COM if not already initialized
        HRESULT hr = CoCreateInstance(
            CLSID_WbemLocator,
            0,
            CLSCTX_INPROC_SERVER,
            IID_IWbemLocator,
            (LPVOID*)&pLoc
        );
        if (FAILED(hr)) throw std::runtime_error("Failed to create IWbemLocator");
        
        // Connect to WMI
        hr = pLoc->ConnectServer(
            _bstr_t(L"ROOT\\CIMV2"),  // WMI namespace
            NULL,                      // User name
            NULL,                      // User password
            0,                         // Locale
            NULL,                      // Security flags
            0,                         // Authority
            0,                         // Context
            &pSvc                      // IWbemServices proxy
        );
        if (FAILED(hr)) throw std::runtime_error("Failed to connect to WMI");
        
        // Set security levels
        hr = CoSetProxyBlanket(
            pSvc,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            NULL,
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            NULL,
            EOAC_NONE
        );
        if (FAILED(hr)) throw std::runtime_error("Failed to set proxy blanket");
        
        // Create property list for query
        std::string propList;
        for (size_t i = 0; i < properties.size(); i++) {
            if (i > 0) propList += ", ";
            propList += properties[i];
        }
        
        // Create WMI query
        std::string query = "SELECT " + propList + " FROM " + wmiClass;
        hr = pSvc->ExecQuery(
            bstr_t("WQL"),
            bstr_t(query.c_str()),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL,
            &pEnumerator
        );
        if (FAILED(hr)) throw std::runtime_error("Failed to execute WMI query");
        
        // Enumerate results
        IWbemClassObject* pclsObj = nullptr;
        ULONG uReturn = 0;
        
        while (pEnumerator) {
            hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
            
            if (uReturn == 0) break;
            
            std::map<std::string, std::string> row;
            
            // Get properties for this object
            for (const auto& prop : properties) {
                VARIANT vtProp;
                hr = pclsObj->Get(bstr_t(prop.c_str()), 0, &vtProp, 0, 0);
                
                if (SUCCEEDED(hr)) {
                    std::string strValue;
                    
                    // Convert variant to string based on type
                    if (vtProp.vt == VT_BSTR) {
                        std::wstring wstrValue(vtProp.bstrVal, SysStringLen(vtProp.bstrVal));
                        strValue = std::string(wstrValue.begin(), wstrValue.end());
                    } else if (vtProp.vt == VT_I4) {
                        strValue = std::to_string(vtProp.lVal);
                    } else if (vtProp.vt == VT_UI4) {
                        strValue = std::to_string(vtProp.ulVal);
                    } else if (vtProp.vt == VT_BOOL) {
                        strValue = vtProp.boolVal ? "True" : "False";
                    } else if (vtProp.vt == VT_I8) {
                        strValue = std::to_string(vtProp.llVal);
                    } else if (vtProp.vt == VT_UI8) {
                        strValue = std::to_string(vtProp.ullVal);
                    } else if (vtProp.vt == VT_R4) {
                        strValue = std::to_string(vtProp.fltVal);
                    } else if (vtProp.vt == VT_R8) {
                        strValue = std::to_string(vtProp.dblVal);
                    } else if (vtProp.vt == VT_NULL) {
                        strValue = "";
                    }
                    
                    row[prop] = strValue;
                    VariantClear(&vtProp);
                }
            }
            
            result.push_back(row);
            pclsObj->Release();
        }
    }
    catch (const std::exception& e) {
        // Handle exception
    }
    
    // Clean up
    if (pEnumerator) pEnumerator->Release();
    if (pSvc) pSvc->Release();
    if (pLoc) pLoc->Release();
    
    return result;
}
