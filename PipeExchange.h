#pragma once
#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>

// Helper function to safely read available data from the pipe without blocking
std::string ReadFromPipe(HANDLE hPipeRead) {
    DWORD bytesAvailable = 0;
    if (!PeekNamedPipe(hPipeRead, NULL, 0, NULL, &bytesAvailable, NULL) || bytesAvailable == 0) {
        return "";
    }

    std::vector<char> buffer(bytesAvailable + 1, 0);
    DWORD bytesRead = 0;
    if (ReadFile(hPipeRead, buffer.data(), bytesAvailable, &bytesRead, NULL) && bytesRead > 0) {
        return std::string(buffer.data(), bytesRead);
    }
    return "";
}

// Helper function to send interactive commands to the child process
bool WriteToPipe(HANDLE hPipeWrite, const std::string& command) {
    DWORD bytesWritten = 0;
    return WriteFile(hPipeWrite, command.c_str(), static_cast<DWORD>(command.length()), &bytesWritten, NULL);
}

bool WriteToPipeBin(HANDLE hPipeWrite, BYTE* buff, DWORD size)
{
    DWORD bytesWritten = 0;
    return WriteFile(hPipeWrite, buff, size, &bytesWritten, NULL);
}