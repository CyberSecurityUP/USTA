#include "pch.h"
#include "Syscalls.h"
#include "Logger.h"
#include <sstream>

// ---------- ORIGINAL FUNCTION POINTERS ----------

LONG(NTAPI* OriginalNtOpenProcess)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, CLIENT_ID*) = nullptr;
LONG(NTAPI* OriginalNtCreateThreadEx)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID) = nullptr;
LONG(NTAPI* OriginalNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG) = nullptr;
LONG(NTAPI* OriginalNtReadVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG) = nullptr;
LONG(NTAPI* OriginalNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG, PSIZE_T, ULONG, ULONG) = nullptr;
LONG(NTAPI* OriginalNtMapViewOfSection)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG) = nullptr;

// ---------- DETOUR FUNCTIONS ----------

LONG NTAPI DetourNtOpenProcess(PHANDLE h, ACCESS_MASK a, POBJECT_ATTRIBUTES oa, CLIENT_ID* cid) {
    DWORD caller = GetCurrentProcessId();
    DWORD target = cid ? (DWORD)(ULONG_PTR)cid->UniqueProcess : 0;

    std::ostringstream oss;
    oss << "{\"event\":\"NtOpenProcess\",\"caller_pid\":" << caller
        << ",\"target_pid\":" << target << "}";

    Log(oss.str());
    return OriginalNtOpenProcess ? OriginalNtOpenProcess(h, a, oa, cid) : -1;
}

LONG NTAPI DetourNtCreateThreadEx(PHANDLE h, ACCESS_MASK a, POBJECT_ATTRIBUTES oa, HANDLE ph, PVOID sr, PVOID arg, ULONG f, SIZE_T z, SIZE_T ss, SIZE_T mss, PVOID al) {
    DWORD caller = GetCurrentProcessId();

    std::ostringstream oss;
    oss << "{\"event\":\"NtCreateThreadEx\",\"caller_pid\":" << caller
        << ",\"start_routine\":\"0x" << std::hex << sr << "\"}";

    Log(oss.str());
    return OriginalNtCreateThreadEx ? OriginalNtCreateThreadEx(h, a, oa, ph, sr, arg, f, z, ss, mss, al) : -1;
}

LONG NTAPI DetourNtWriteVirtualMemory(HANDLE ph, PVOID base, PVOID buf, ULONG size, PULONG written) {
    std::ostringstream oss;
    oss << "{\"event\":\"NtWriteVirtualMemory\",\"process\":\"0x" << std::hex << ph
        << "\",\"size\":" << std::dec << size << "}";

    Log(oss.str());
    return OriginalNtWriteVirtualMemory ? OriginalNtWriteVirtualMemory(ph, base, buf, size, written) : -1;
}

LONG NTAPI DetourNtReadVirtualMemory(HANDLE ph, PVOID base, PVOID buf, ULONG size, PULONG read) {
    std::ostringstream oss;
    oss << "{\"event\":\"NtReadVirtualMemory\",\"process\":\"0x" << std::hex << ph
        << "\",\"size\":" << std::dec << size << "}";

    Log(oss.str());
    return OriginalNtReadVirtualMemory ? OriginalNtReadVirtualMemory(ph, base, buf, size, read) : -1;
}

LONG NTAPI DetourNtAllocateVirtualMemory(HANDLE ph, PVOID* base, ULONG zero, PSIZE_T size, ULONG type, ULONG prot) {
    std::ostringstream oss;
    oss << "{\"event\":\"NtAllocateVirtualMemory\",\"process\":\"0x" << std::hex << ph
        << "\",\"size\":" << std::dec << (size ? *size : 0) << "}";

    Log(oss.str());
    return OriginalNtAllocateVirtualMemory ? OriginalNtAllocateVirtualMemory(ph, base, zero, size, type, prot) : -1;
}

LONG NTAPI DetourNtMapViewOfSection(HANDLE sh, HANDLE ph, PVOID* base, ULONG_PTR zero, SIZE_T commit, PLARGE_INTEGER offset, PSIZE_T viewSize, DWORD disp, ULONG type, ULONG prot) {
    std::ostringstream oss;
    oss << "{\"event\":\"NtMapViewOfSection\",\"process\":\"0x" << std::hex << ph
        << "\",\"view_size\":" << std::dec << (viewSize ? *viewSize : 0) << "}";

    Log(oss.str());
    return OriginalNtMapViewOfSection ? OriginalNtMapViewOfSection(sh, ph, base, zero, commit, offset, viewSize, disp, type, prot) : -1;
}
