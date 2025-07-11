#include "pch.h"
#include "HookManager.h"
#include "Logger.h"

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        SetLogMode(STDOUT); // ou FILE
        InitializeHooks();
    }
    return TRUE;
}
