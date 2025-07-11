#include "HookManager.h"
#include "Logger.h"
#include "Syscalls.h"
#include <Windows.h>
#include <vector>
#include <string>
#include <cstring>

struct HookEntry {
    const char* functionName;
    void* detourFunc;
    void** originalFunc;
};

bool HookFunction(void* targetFunc, void* detourFunc, void** originalFunc) {
    DWORD oldProtect;
    BYTE jmpInstruction[14] = {
        0x49, 0xBB,
        0,0,0,0,0,0,0,0,
        0x41, 0xFF, 0xE3
    };

    memcpy(&jmpInstruction[2], &detourFunc, sizeof(void*));
    if (!VirtualProtect(targetFunc, sizeof(jmpInstruction), PAGE_EXECUTE_READWRITE, &oldProtect))
        return false;

    memcpy(targetFunc, jmpInstruction, sizeof(jmpInstruction));
    VirtualProtect(targetFunc, sizeof(jmpInstruction), oldProtect, &oldProtect);

    *originalFunc = targetFunc;
    return true;
}

bool InitializeHooks() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        Log("{\"error\":\"failed to load ntdll.dll\"}");
        return false;
    }

    HookEntry hooks[] = {
        { "NtOpenProcess", DetourNtOpenProcess, (void**)&OriginalNtOpenProcess },
        { "NtCreateThreadEx", DetourNtCreateThreadEx, (void**)&OriginalNtCreateThreadEx },
        { "NtWriteVirtualMemory", DetourNtWriteVirtualMemory, (void**)&OriginalNtWriteVirtualMemory },
        { "NtReadVirtualMemory", DetourNtReadVirtualMemory, (void**)&OriginalNtReadVirtualMemory },
        { "NtAllocateVirtualMemory", DetourNtAllocateVirtualMemory, (void**)&OriginalNtAllocateVirtualMemory },
        { "NtMapViewOfSection", DetourNtMapViewOfSection, (void**)&OriginalNtMapViewOfSection },
    };

    for (auto& hook : hooks) {
        void* target = GetProcAddress(ntdll, hook.functionName);
        if (!target) {
            Log(std::string("{\"warn\":\"GetProcAddress failed for ") + hook.functionName + "\"}");
            continue;
        }

        if (!HookFunction(target, hook.detourFunc, hook.originalFunc)) {
            Log(std::string("{\"warn\":\"HookFunction failed for ") + hook.functionName + "\"}");
            continue;
        }

        Log(std::string("{\"hooked\":\"") + hook.functionName + "\"}");
    }

    return true;
}
