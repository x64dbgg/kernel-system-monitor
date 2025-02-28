// APIHook.h
#pragma once

#include <Windows.h>
#include <vector>
#include <string>
#include <functional>
#include <map>

// Hook callback function type
typedef std::function<void(const std::wstring&, const std::vector<DWORD_PTR>&)> HookCallback;

struct HookInfo {
    void* originalFunction;
    void* hookFunction;
    void* trampolineFunction;
    std::wstring functionName;
    std::wstring moduleName;
    bool isHooked;
};

class APIHook {
public:
    APIHook();
    ~APIHook();
    
    bool installHooks();
    bool removeHooks();
    bool isHooked() const;
    
    // Set callback for when hooked functions are called
    void setHookCallback(HookCallback callback);
    
    // Manual hook function
    bool hookFunction(const std::wstring& moduleName, const std::string& functionName, void* hookFunction, void** originalFunction);
    
private:
    bool createTrampoline(void* originalFunction, void* hookFunction, void** trampolineFunction);
    void reportHookCall(const std::wstring& functionName, const std::vector<DWORD_PTR>& params);
    
    std::vector<HookInfo> m_hooks;
    bool m_isHooked;
    HookCallback m_callback;
    
    // Common Windows API hooks
    static BOOL WINAPI HookCreateProcessW(
        LPCWSTR lpApplicationName,
        LPWSTR lpCommandLine,
        LPSECURITY_ATTRIBUTES lpProcessAttributes,
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        BOOL bInheritHandles,
        DWORD dwCreationFlags,
        LPVOID lpEnvironment,
        LPCWSTR lpCurrentDirectory,
        LPSTARTUPINFOW lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation
    );
    
    static BOOL WINAPI HookCreateProcessA(
        LPCSTR lpApplicationName,
        LPSTR lpCommandLine,
        LPSECURITY_ATTRIBUTES lpProcessAttributes,
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        BOOL bInheritHandles,
        DWORD dwCreationFlags,
        LPVOID lpEnvironment,
        LPCSTR lpCurrentDirectory,
        LPSTARTUPINFOA lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation
    );
    
    static BOOL WINAPI HookReadFile(
        HANDLE hFile,
        LPVOID lpBuffer,
        DWORD nNumberOfBytesToRead,
        LPDWORD lpNumberOfBytesRead,
        LPOVERLAPPED lpOverlapped
    );
    
    static BOOL WINAPI HookWriteFile(
        HANDLE hFile,
        LPCVOID lpBuffer,
        DWORD nNumberOfBytesToWrite,
        LPDWORD lpNumberOfBytesWritten,
        LPOVERLAPPED lpOverlapped
    );
    
    static HANDLE WINAPI HookCreateFileW(
        LPCWSTR lpFileName,
        DWORD dwDesiredAccess,
        DWORD dwShareMode,
        LPSECURITY_ATTRIBUTES lpSecurityAttributes,
        DWORD dwCreationDisposition,
        DWORD dwFlagsAndAttributes,
        HANDLE hTemplateFile
    );
    
    static HMODULE WINAPI HookLoadLibraryW(
        LPCWSTR lpLibFileName
    );
    
    // Original function pointers
    static decltype(&CreateProcessW) OriginalCreateProcessW;
    static decltype(&CreateProcessA) OriginalCreateProcessA;
    static decltype(&ReadFile) OriginalReadFile;
    static decltype(&WriteFile) OriginalWriteFile;
    static decltype(&CreateFileW) OriginalCreateFileW;
    static decltype(&LoadLibraryW) OriginalLoadLibraryW;
    
    // Singleton instance for callback access from static functions
    static APIHook* s_instance;
};
