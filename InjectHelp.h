#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <vector>
#include <optional>
#include <iostream>

extern "C" NTSTATUS NTAPI NtSetContextThread(HANDLE, PCONTEXT);
//extern "C" NTSTATUS NTAPI NtQueryInformationThread(HANDLE, ULONG, PVOID, ULONG, PULONG);
#pragma comment(lib, "ntdll.lib")

#ifndef ThreadQuerySetWin32StartAddress
#define ThreadQuerySetWin32StartAddress ((THREADINFOCLASS)9)
#endif

// ---------- helpers ----------
static void PrintLastError(const char* fn) {
    DWORD err = GetLastError();
    LPSTR buf = nullptr;
    FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&buf, 0, nullptr);
    std::printf("[!] %s failed (err %lu): %s\n", fn, err, buf ? buf : "unknown");
    if (buf) LocalFree(buf);
}

static bool ParseU64(const char* s, uint64_t& out) {
    if (!s || !*s) return false;
    char* end = nullptr;
    unsigned long long v = _strtoui64(s, &end, 0);
    if (end == s || *end != '\0') return false;
    out = v;
    return true;
}

static void HexDump(const uint8_t* data, size_t size, uintptr_t base) {
    constexpr size_t BPL = 16;
    for (size_t i = 0; i < size; i += BPL) {
        std::printf("%016llX  ", (unsigned long long)(base + i));
        for (size_t j = 0; j < BPL; ++j) {
            if (i + j < size) std::printf("%02X ", data[i + j]);
            else              std::printf("   ");
            if (j == 7) std::printf(" ");
        }
        std::printf(" |");
        for (size_t j = 0; j < BPL && i + j < size; ++j) {
            uint8_t c = data[i + j];
            std::printf("%c", (c >= 0x20 && c < 0x7F) ? c : '.');
        }
        std::printf("|\n");
    }
}

std::optional<uintptr_t> FindPatternInRemoteProcess(
    HANDLE hProcess,
    const std::vector<uint8_t>& pattern)
{
    if (pattern.empty())
        return std::nullopt;

    SYSTEM_INFO sysInfo{};
    GetNativeSystemInfo(&sysInfo);

    uintptr_t address = reinterpret_cast<uintptr_t>(sysInfo.lpMinimumApplicationAddress);
    uintptr_t maxAddr = reinterpret_cast<uintptr_t>(sysInfo.lpMaximumApplicationAddress);

    MEMORY_BASIC_INFORMATION mbi{};
    std::vector<uint8_t> buffer;

    const size_t patternSize = pattern.size();

    while (address < maxAddr) {
        // 2. Query the next region.
        if (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(address),
            &mbi, sizeof(mbi)) == 0)
        {
            // Cannot query here — advance one page to avoid infinite loop.
            address += sysInfo.dwPageSize;
            continue;
        }

        // 3. Filter: only private, committed, readable (not guarded) memory.
        const bool isPrivate = (mbi.Type == MEM_PRIVATE);
        const bool isCommitted = (mbi.State == MEM_COMMIT);
        const bool isReadable = (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE |
            PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
            PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) != 0;
        const bool isGuarded = (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0;

        if (isPrivate && isCommitted && isReadable && !isGuarded) {
            SIZE_T regionSize = mbi.RegionSize;

            // Skip regions smaller than the pattern.
            if (regionSize >= patternSize) {
                buffer.resize(regionSize);
                SIZE_T bytesRead = 0;

                // 4. Read the whole region in one shot.
                if (ReadProcessMemory(hProcess, mbi.BaseAddress,
                    buffer.data(), regionSize, &bytesRead) && bytesRead > 0)
                {
                    // 5. Search inside this chunk.
                    const size_t limit = bytesRead - patternSize;
                    for (size_t i = 0; i <= limit; ++i) {
                        if (memcmp(buffer.data() + i, pattern.data(), patternSize) == 0) {
                            uintptr_t found = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + i;
                            //CloseHandle(hProcess);
                            return found;
                        }
                    }
                }
                // If ReadProcessMemory fails partially, we still advance below.
            }
        }

        // Advance to next region.
        address = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    }

    //CloseHandle(hProcess);
    return std::nullopt;
}
// ---------- main thread discovery ----------
// Picks the thread whose Win32 start address falls inside the main module
// image. Falls back to the first thread of the process.
static DWORD GetMainThreadId(DWORD pid) {
    uintptr_t imageBase = 0, imageEnd = 0;
    {
        HANDLE snap = CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32W me{}; me.dwSize = sizeof(me);
            if (Module32FirstW(snap, &me)) {
                imageBase = (uintptr_t)me.modBaseAddr;
                imageEnd = imageBase + me.modBaseSize;
            }
            CloseHandle(snap);
        }
    }

    DWORD best = 0, firstAny = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te{}; te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            if (!firstAny) firstAny = te.th32ThreadID;

            HANDLE hT = OpenThread(
                THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION,
                FALSE, te.th32ThreadID);
            if (!hT) continue;

            void* startAddr = nullptr;
            NtQueryInformationThread(hT, ThreadQuerySetWin32StartAddress,
                &startAddr, sizeof(startAddr), nullptr);
            CloseHandle(hT);

            if (startAddr && imageBase && imageEnd &&
                (uintptr_t)startAddr >= imageBase &&
                (uintptr_t)startAddr < imageEnd) {
                best = te.th32ThreadID;
                break;
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return best ? best : firstAny;
}

// ---------- thread pause + RIP hijack ----------
static bool HijackThreadRip(DWORD tid, uint64_t newRip, bool resumeAfter = true) {
    HANDLE hT = OpenThread(
        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
        FALSE, tid);
    if (!hT) { PrintLastError("OpenThread"); return false; }

    if (SuspendThread(hT) == (DWORD)-1) {
        PrintLastError("SuspendThread"); CloseHandle(hT); return false;
    }

    alignas(16) CONTEXT ctx {};
    ctx.ContextFlags = CONTEXT_CONTROL;      // RIP + RSP + RBP + flags + segs
    if (!GetThreadContext(hT, &ctx)) {
        PrintLastError("GetThreadContext");
        ResumeThread(hT); CloseHandle(hT); return false;
    }

    std::printf("[+] Thread %lu: old RIP = 0x%llX, RSP = 0x%llX\n",
        tid, (unsigned long long)ctx.Rip, (unsigned long long)ctx.Rsp);

    ctx.Rip = newRip;

    NTSTATUS st = NtSetContextThread(hT, &ctx);
    if (st != 0) {
        std::printf("[!] NtSetContextThread failed: NTSTATUS = 0x%08lX\n", (unsigned long)st);
        ResumeThread(hT); CloseHandle(hT); return false;
    }
    std::printf("[+] Thread %lu: new RIP = 0x%llX\n",
        tid, (unsigned long long)newRip);

    if (resumeAfter) {
        if (ResumeThread(hT) == (DWORD)-1) PrintLastError("ResumeThread");
        else std::printf("[+] Thread %lu resumed\n", tid);
    }
    CloseHandle(hT);
    return true;
}