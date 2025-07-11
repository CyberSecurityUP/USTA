#pragma once
#include <string>

enum LogOutputMode {
    STDOUT,
    FILEOUT
};

void SetLogMode(LogOutputMode mode);
void Log(const std::string& msg);
void LogJson(const std::string& json);
