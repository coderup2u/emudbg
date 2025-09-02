#include <windows.h>
#include <iostream>
#include <string>
#include <algorithm>

int main() {
    STARTUPINFOW si{ sizeof(si) };
    PROCESS_INFORMATION pi;

    std::wstring exePath = L"C:\\Program Files (x86)\\Steam\\steamapps\\common\\SHINOBI_AOV\\SHINOBI_AOV.exe";
    std::wstring targetDll = L"GameAssembly.dll";

    if (!CreateProcessW(exePath.c_str(), NULL, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi)) {
        std::wcerr << L"Failed to start process. Error: " << GetLastError() << std::endl;
        return 1;
    }

    std::wcout << L"Process started in debug mode. PID: " << pi.dwProcessId << std::endl;

    DEBUG_EVENT dbgEvent{};
    while (WaitForDebugEvent(&dbgEvent, INFINITE)) {
        DWORD continueStatus = DBG_CONTINUE;

        switch (dbgEvent.dwDebugEventCode) {
        case LOAD_DLL_DEBUG_EVENT: {
            auto& ld = dbgEvent.u.LoadDll;
            if (ld.lpImageName && ld.fUnicode) {
                ULONGLONG ptr = 0;
                wchar_t buffer[MAX_PATH]{};
                if (ReadProcessMemory(pi.hProcess, ld.lpImageName, &ptr, sizeof(ptr), nullptr) && ptr &&
                    ReadProcessMemory(pi.hProcess, (LPCVOID)ptr, buffer, sizeof(buffer) - sizeof(wchar_t), nullptr)) {

                    std::wstring loadedName(buffer);
                    std::wstring lowerLoaded = loadedName;
                    std::transform(lowerLoaded.begin(), lowerLoaded.end(), lowerLoaded.begin(), ::towlower);

                    std::wstring lowerTarget = targetDll;
                    std::transform(lowerTarget.begin(), lowerTarget.end(), lowerTarget.begin(), ::towlower);

                    if (lowerLoaded.find(lowerTarget) != std::wstring::npos) {
                        std::wcout << targetDll << L" loaded at: 0x" << std::hex << (uint64_t)ld.lpBaseOfDll << std::endl;
                    }
                }
            }
            if (ld.hFile) CloseHandle(ld.hFile);
            break;
        }

        case EXCEPTION_DEBUG_EVENT: {
            auto& exc = dbgEvent.u.Exception;
            if (exc.ExceptionRecord.ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
                std::wcout << L"[!] EXCEPTION_ACCESS_VIOLATION at 0x"
                    << std::hex << (uint64_t)exc.ExceptionRecord.ExceptionAddress
                    << L", Flags: " << exc.ExceptionRecord.ExceptionInformation[0]
                    << L", Address: 0x" << exc.ExceptionRecord.ExceptionInformation[1]
                    << std::endl;
            }
            else {
                std::wcout << L"[!] Other exception: 0x"
                    << std::hex << exc.ExceptionRecord.ExceptionCode
                    << L" at 0x" << exc.ExceptionRecord.ExceptionAddress
                    << std::endl;
            }
            continueStatus = DBG_EXCEPTION_NOT_HANDLED; // یا DBG_CONTINUE بسته به رفتار مورد نظر
            break;
        }

        case EXIT_PROCESS_DEBUG_EVENT:
            std::wcout << L"Process exited." << std::endl;
            goto endDebugLoop;
        }

        ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, continueStatus);
    }

endDebugLoop:
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0;
}
