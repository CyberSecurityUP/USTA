#include "Logger.h"
#include <fstream>
#include <iostream>

bool g_LogToStdout = false;

void SetLogMode(bool toStdout) {
    g_LogToStdout = toStdout;
}

void Log(const std::string& msg) {
    if (g_LogToStdout) {
        std::cout << msg << std::endl;
    }
    else {
        std::ofstream logFile("syscall_log.json", std::ios::app);
        logFile << msg << std::endl;
    }
}
