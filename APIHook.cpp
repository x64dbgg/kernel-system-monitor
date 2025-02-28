// APIHook.cpp
#include "APIHook.h"
#include <iostream>
#include <detours/detours.h>

// Static member initialization
APIHook* APIHook::s_instance = nullptr;
decltype(&CreateProcessW) APIHook::OriginalCreateProcessW = CreateProcessW;
decltype(&CreateProcessA) APIHook::OriginalCreateProcessA = CreateProcessA;
decltype(&ReadFile) APIHook::OriginalReadFile = ReadFile;
decltype(&WriteFile) APIHook::OriginalWriteFile = WriteFile;
decltype(&CreateFileW) APIHook::OriginalCreateFileW = CreateFileW;
decltype(&LoadLibraryW) APIHook::OriginalLoadLibraryW = LoadLibraryW;

APIHook::APIHook() : m_isHooked(false) {
    s_instance = this;
    
    // Default callback (does nothing)
    m_callback = [](const std::wstring&, const std::vector<DWORD_PTR>&) {};
}

APIHook::~APIHook() {
    removeHooks();
    s_instance = nullptr;
}

bool APIHook::installHooks() {
    if (m_isHooked) {
        return true;
    }
    
    // Initialize Detours
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    
    // Hook CreateProcessW
    DetourAttach(&(PVOID&)OriginalCreateProcessW, HookCreateProcessW);
    m_hooks.push_back({ (void*)OriginalCreateProcessW, (void*)HookCreateProcessW, nullptr, L"CreateProcessW", L"kernel32.dll", true });
    
    // Hook CreateProcessA
    DetourAttach(&(PVOID&)OriginalCreateProcessA, HookCreateProcessA);
    m_hooks.push_back({ (void*)OriginalCreateProcessA, (void*)HookCreateProcessA, nullptr, L"CreateProcessA", L"kernel32.dll", true });
    
    // Hook ReadFile
    DetourAttach(&(PVOID&)OriginalReadFile, HookReadFile);
    m_hooks.push_back({ (void*)OriginalReadFile, (void*)HookReadFile, nullptr, L"ReadFile", L"kernel32.dll", true });
    
    // Hook WriteFile
    DetourAttach(&(PVOID&)OriginalWriteFile, HookWriteFile);
    m_hooks.push_back({ (void*)OriginalWriteFile, (void*)HookWriteFile, nullptr, L"WriteFile", L"kernel32.dll", true });
    
    // Hook CreateFileW
    DetourAttach(&(PVOID&)OriginalCreateFileW, HookCreateFileW);
    m_hooks.push_back({ (void*)OriginalCreateFileW, (void*)HookCreateFileW, nullptr, L"CreateFileW", L"kernel32.dll", true });
    
    // Hook LoadLibraryW
    DetourAttach(&(PVOID&)OriginalLoadLibraryW, HookLoadLibraryW);
    m_hooks.push_back({ (void*)OriginalLoadLibraryW, (void*)HookLoadLibraryW, nullptr, L"LoadLibraryW", L"kernel32.dll", true });
    
    // Commit the transaction
    LONG error = DetourTransactionCommit();
    if (error != NO_ERROR) {
        std::cerr << "Error installing hooks: " << error << std::endl;
        return false;
    }
    
    m_isHooked = true;
    std::cout << "Installed " << m_hooks.size() << " API hooks successfully." << std::endl;
    
    return true;
}

bool APIHook::removeHooks() {
    if (!m_isHooked) {
        return true;
    }
    
    // Initialize Detours
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    
    // Detach all hooks
    DetourDetach(&(PVOID&)OriginalCreateProcessW, HookCreateProcessW);
    DetourDetach(&(PVOID&)OriginalCreateProcessA, HookCreateProcessA);
    DetourDetach(&(PVOID&)OriginalReadFile, HookReadFile);
    DetourDetach(&(PVOID&)OriginalWriteFile, HookWriteFile);
    DetourDetach(&(PVOID&)OriginalCreateFileW, HookCreateFileW);
    DetourDetach(&(PVOID&)OriginalLoadLibraryW, HookLoadLibraryW);
    
    // Commit the transaction
    LONG error = DetourTransactionCommit();
    if (error != NO_ERROR) {
        std::cerr << "Error removing hooks: " << error << std::endl;
        return false;
    }
    
    m_hooks.clear();
    m_isHooked = false;
    std::cout << "Removed all API hooks successfully." << std::endl;
    
    return true;
}

bool APIHook::isHooked() const {
    return m_isHooked;
}

void APIHook::setHookCallback(HookCallback callback) {
    m_callback = callback;
}

bool APIHook::hookFunction(const std::wstring& moduleName, const std::string& functionName, void* hookFunction, void** originalFunction) {
    if (m_isHooked) {
        std::cerr << "Cannot add individual hooks while global hooks are active." << std::endl;
        return false;
    }
    
    HMODULE module = GetModuleHandleW(moduleName.c_str());
    if (module == NULL) {
        module = LoadLibraryW(moduleName.c_str());
        if (module == NULL) {
            std::cerr << "Failed to load module: " << std::string(moduleName.begin(), moduleName.end()) << std::endl;
            return false;
        }
    }
    
    void* originalFunc = GetProcAddress(module, functionName.c_str());
    if (originalFunc == NULL) {
        std::cerr << "Failed to find function: " << functionName << std::endl;
        return false;
    }
    
    *originalFunction = originalFunc;
    
    // Initialize Detours
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    
    // Attach the hook
    DetourAttach(&(PVOID&)*originalFunction, hookFunction);
    
    // Commit the transaction
    LONG error = DetourTransactionCommit();
    if (error != NO_ERROR) {
        std::cerr << "Error installing hook for " << functionName << ": " << error << std::endl;
        return false;
    }
    
    m_hooks.push_back({ originalFunc, hookFunction, nullptr, 
                      std::wstring(functionName.begin(), functionName.end()), 
                      moduleName, true });
    
    return true;
}

bool APIHook::createTrampoline(void* originalFunction, void* hookFunction, void** trampolineFunction) {
    // Note: This is a simplified implementation - a real one would need to handle
    // various instruction types and sizes properly
    
    // Allocate memory for the trampoline
    *trampolineFunction = VirtualAlloc(NULL, 20, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (*trampolineFunction == NULL) {
        return false;
    }
    
    // Copy the first bytes of the original function
    memcpy(*trampolineFunction, originalFunction, 5);
    
    // Add a jump back to the original function after our copied bytes
    BYTE* trampolineBytes = (BYTE*)*trampolineFunction;
    trampolineBytes[5] = 0xE9; // JMP instruction
    
    // Calculate the relative address for the jump
    *(DWORD*)(&trampolineBytes[6]) = (DWORD)((BYTE*)originalFunction + 5) - ((DWORD)((BYTE*)*trampolineFunction + 10));
    
    return true;
}

void APIHook::reportHookCall(const std::wstring& functionName, const std::vector<DWORD_PTR>& params) {
    if (m_callback) {
        m_callback(functionName, params);
    }
}

// Hook implementations

BOOL WINAPI APIHook::HookCreateProcessW(
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
) {
    if (s_instance) {
        std::vector<DWORD_PTR> params = {
            (DWORD_PTR)lpApplicationName,
            (DWORD_PTR)lpCommandLine,
            (DWORD_PTR)lpProcessAttributes,
            (DWORD_PTR)lpThreadAttributes,
            (DWORD_PTR)bInheritHandles,
            (DWORD_PTR)dwCreationFlags,
            (DWORD_PTR)lpEnvironment,
            (DWORD_PTR)lpCurrentDirectory,
            (DWORD_PTR)lpStartupInfo,
            (DWORD_PTR)lpProcessInformation
        };
        
        s_instance->reportHookCall(L"CreateProcessW", params);
        
        std::wcout << L"CreateProcessW: " << (lpApplicationName ? lpApplicationName : L"NULL") << 
            L" CommandLine: " << (lpCommandLine ? lpCommandLine : L"NULL") << std::endl;
    }
    
    return OriginalCreateProcessW(
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation
    );
}

BOOL WINAPI APIHook::HookCreateProcessA(
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
) {
    if (s_instance) {
        std::vector<DWORD_PTR> params = {
            (DWORD_PTR)lpApplicationName,
            (DWORD_PTR)lpCommandLine,
            (DWORD_PTR)lpProcessAttributes,
            (DWORD_PTR)lpThreadAttributes,
            (DWORD_PTR)bInheritHandles,
            (DWORD_PTR)dwCreationFlags,
            (DWORD_PTR)lpEnvironment,
            (DWORD_PTR)lpCurrentDirectory,
            (DWORD_PTR)lpStartupInfo,
            (DWORD_PTR)lpProcessInformation
        };
        
        s_instance->reportHookCall(L"CreateProcessA", params);
        
        std::cout << "CreateProcessA: " << (lpApplicationName ? lpApplicationName : "NULL") << 
            " CommandLine: " << (lpCommandLine ? lpCommandLine : "NULL") << std::endl;
    }
    
    return OriginalCreateProcessA(
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation
    );
}

BOOL WINAPI APIHook::HookReadFile(
    HANDLE hFile,
    LPVOID lpBuffer,
    DWORD nNumberOfBytesToRead,
    LPDWORD lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped
) {
    if (s_instance) {
        std::vector<DWORD_PTR> params = {
            (DWORD_PTR)hFile,
            (DWORD_PTR)lpBuffer,
            (DWORD_PTR)nNumberOfBytesToRead,
            (DWORD_PTR)lpNumberOfBytesRead,
            (DWORD_PTR)lpOverlapped
        };
        
        s_instance->reportHookCall(L"ReadFile", params);
    }
    
    return OriginalReadFile(
        hFile,
        lpBuffer,
        nNumberOfBytesToRead,
        lpNumberOfBytesRead,
        lpOverlapped
    );
}

BOOL WINAPI APIHook::HookWriteFile(
    HANDLE hFile,
    LPCVOID lpBuffer,
    DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
) {
    if (s_instance) {
        std::vector<DWORD_PTR> params = {
            (DWORD_PTR)hFile,
            (DWORD_PTR)lpBuffer,
            (DWORD_PTR)nNumberOfBytesToWrite,
            (DWORD_PTR)lpNumberOfBytesWritten,
            (DWORD_PTR)lpOverlapped
        };
        
        s_instance->reportHookCall(L"WriteFile", params);
    }
    
    return OriginalWriteFile(
        hFile,
        lpBuffer,
        nNumberOfBytesToWrite,
        lpNumberOfBytesWritten,
        lpOverlapped
    );
}

HANDLE WINAPI APIHook::HookCreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile
) {
    if (s_instance) {
        std::vector<DWORD_PTR> params = {
            (DWORD_PTR)lpFileName,
            (DWORD_PTR)dwDesiredAccess,
            (DWORD_PTR)dwShareMode,
            (DWORD_PTR)lpSecurityAttributes,
            (DWORD_PTR)dwCreationDisposition,
            (DWORD_PTR)dwFlagsAndAttributes,
            (DWORD_PTR)hTemplateFile
        };
        
        s_instance->reportHookCall(L"CreateFileW", params);
        
        std::wcout << L"CreateFileW: " << lpFileName << std::endl;
    }
    
    return OriginalCreateFileW(
        lpFileName,
        dwDesiredAccess,
        dwShareMode,
        lpSecurityAttributes,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        hTemplateFile
    );
}

HMODULE WINAPI APIHook::HookLoadLibraryW(
    LPCWSTR lpLibFileName
) {
    if (s_instance) {
        std::vector<DWORD_PTR> params = {
            (DWORD_PTR)lpLibFileName
        };
        
        s_instance->reportHookCall(L"LoadLibraryW", params);
        
        std::wcout << L"LoadLibraryW: " << lpLibFileName << std::endl;
    }
    
    return OriginalLoadLibraryW(
        lpLibFileName
    );
}
