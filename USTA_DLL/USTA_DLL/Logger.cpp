#include "pch.h"
#include "Logger.h"
#include <iostream>
#include <fstream>

static LogOutputMode logMode = STDOUT;

void SetLogMode(LogOutputMode mode) {
    logMode = mode;
}

void Log(const std::string& msg) {
    if (logMode == STDOUT) {
        std::cout << msg << std::endl;
    }
    else {
        std::ofstream logFile("syscall_log.json", std::ios::app);
        logFile << msg << std::endl;
    }
}

void LogJson(const std::string& json) {
    Log(json);
}
