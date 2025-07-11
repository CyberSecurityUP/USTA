#include <Windows.h>
#include <iostream>
#include <string>
#include "Logger.h"
#include "HookManager.h"

bool shouldTraceNtOpenProcess = true;

void ParseArgs(int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--stdout") {
            SetLogMode(true);
        }
        else if (arg.rfind("--trace", 0) == 0) {
            if (arg.find("NtOpenProcess") == std::string::npos)
                shouldTraceNtOpenProcess = false;
        }
    }
}

int main(int argc, char* argv[]) {
    ParseArgs(argc, argv);

    Log("{\"status\":\"starting\",\"component\":\"USTA\"}");

    if (!InitializeHooks()) {
        Log("{\"status\":\"error\",\"message\":\"Failed to initialize hooks\"}");
        return -1;
    }

    Log("{\"status\":\"ok\",\"message\":\"Hooks initialized\"}");

    while (true)
        Sleep(1000);

    return 0;
}
