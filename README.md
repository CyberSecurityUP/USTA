# 🛡️ USTA_DLL - Userland Syscall Tracing Agent

**USTA_DLL** is a Windows x64 DLL that hooks native system calls (`ntdll.dll`) to trace and log key userland API calls. It's designed for malware analysis, red team tooling, and behavioral monitoring.

## 🔧 Features

- Inline hooking of native syscalls:
  - `NtOpenProcess`
  - `NtCreateThreadEx`
  - `NtWriteVirtualMemory`
  - `NtReadVirtualMemory`
  - `NtAllocateVirtualMemory`
  - `NtMapViewOfSection`
- Logs events in JSON format
- Supports stdout or file-based logging
- Easy to inject into any target process (e.g., using Extreme Injector)

## 🧪 Usage

1. Compile the project as a `x64 DLL` (Debug or Release)
2. Inject `USTA_DLL.dll` into a target process (e.g., `mimikatz.exe`)
3. View logs in:
   - Console (stdout)
   - Log file (e.g., `C:\Temp\usta_hooks.log`)
   - Or attach DebugView for OutputDebugString monitoring

## 📁 Project Structure

```
USTA\_DLL/
├── dllmain.cpp
├── HookManager.cpp/.h
├── Syscalls.cpp/.h
├── Logger.cpp/.h
├── pch.h / pch.cpp
```

## ⚠️ Disclaimer

This project is for educational and research purposes only. Use it responsibly.

## 📜 License

MIT License

Let me know if you want a version with screenshots or GIFs (e.g. showing `mimikatz` being hooked).
