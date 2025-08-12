#include "cpu.hpp"
#include <thread>

using namespace std;

std::unordered_map<DWORD, CPU> cpuThreads;

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        wprintf(L"Usage: %s <exe_path> [-m target.dll] [-b software|hardware]\n", argv[0]);
        return 1;
    }

    std::wstring exePath;
    std::wstring targetModuleName;
    bool waitForModule = false;

    for (int i = 1; i < argc; ++i) {
        std::wstring arg = argv[i];
        if (arg == L"-m" && i + 1 < argc) {
            targetModuleName = argv[++i];
            waitForModule = true;
        }
        else if (arg == L"-b" && i + 1 < argc) {
            std::wstring type = argv[++i];
            std::transform(type.begin(), type.end(), type.begin(), ::towlower);
            if (type == L"hardware") bpType = BreakpointType::Hardware;
            else if (type == L"software") bpType = BreakpointType::Software;
            else {
                wprintf(L"[-] Invalid breakpoint type: %s\n", type.c_str());
                return 1;
            }
        }
        else {
            exePath = arg;
        }
    }

    if (exePath.empty()) {
        wprintf(L"Usage: %s <exe_path> [-m target.dll] [-b software|hardware]\n", argv[0]);
        return 1;
    }


    DWORD64 FeatureMask;

    // If this function was called before and we were not running on 
    // at least Windows 7 SP1, then bail.
    if (pfnGetEnabledXStateFeatures == (PGETENABLEDXSTATEFEATURES)-1)
    {
        _tprintf(_T("This needs to run on Windows 7 SP1 or greater.\n"));
    }

    // Get the addresses of the AVX XState functions.
    if (pfnGetEnabledXStateFeatures == NULL)
    {
        HMODULE hm = GetModuleHandle(_T("kernel32.dll"));
        if (hm == NULL)
        {
            pfnGetEnabledXStateFeatures = (PGETENABLEDXSTATEFEATURES)-1;
            _tprintf(_T("GetModuleHandle failed (error == %d).\n"), GetLastError());
        }

        pfnGetEnabledXStateFeatures = (PGETENABLEDXSTATEFEATURES)GetProcAddress(hm, "GetEnabledXStateFeatures");
        pfnInitializeContext = (PINITIALIZECONTEXT)GetProcAddress(hm, "InitializeContext");
        pfnGetXStateFeaturesMask = (PGETXSTATEFEATURESMASK)GetProcAddress(hm, "GetXStateFeaturesMask");
        pfnLocateXStateFeature = (LOCATEXSTATEFEATURE)GetProcAddress(hm, "LocateXStateFeature");
        pfnSetXStateFeaturesMask = (SETXSTATEFEATURESMASK)GetProcAddress(hm, "SetXStateFeaturesMask");

        if (pfnGetEnabledXStateFeatures == NULL
            || pfnInitializeContext == NULL
            || pfnGetXStateFeaturesMask == NULL
            || pfnLocateXStateFeature == NULL
            || pfnSetXStateFeaturesMask == NULL)
        {
            pfnGetEnabledXStateFeatures = (PGETENABLEDXSTATEFEATURES)-1;
            _tprintf(_T("This needs to run on Windows 7 SP1 or greater.\n"));
 
        }
    }

    FeatureMask = pfnGetEnabledXStateFeatures();
    if ((FeatureMask & XSTATE_MASK_AVX) == 0)
    {
        _tprintf(_T("The AVX feature is not enabled.\n"));

    }

    STARTUPINFOW si = { sizeof(si) };
    uint32_t entryRVA = GetEntryPointRVA(exePath);
    std::vector<uint32_t> tlsRVAs = GetTLSCallbackRVAs(exePath);

    if (!CreateProcessW(exePath.c_str(), NULL, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi)) return 1;

    DEBUG_EVENT dbgEvent = {};
    uint64_t baseAddress = 0;
    uint64_t moduleBase = 0;
    std::unordered_map<uint64_t, BreakpointInfo> breakpoints;

    while (true) {
        if (!WaitForDebugEvent(&dbgEvent, INFINITE)) break;
        DWORD continueStatus = DBG_CONTINUE;

        switch (dbgEvent.dwDebugEventCode) {
        case LOAD_DLL_DEBUG_EVENT: {
            auto& ld = dbgEvent.u.LoadDll;
            if (ld.lpImageName && ld.fUnicode) {
                ULONGLONG ptr = 0;
                wchar_t buffer[MAX_PATH] = {};
                if (ReadProcessMemory(pi.hProcess, (LPCVOID)ld.lpImageName, &ptr, sizeof(ptr), nullptr) && ptr &&
                    ReadProcessMemory(pi.hProcess, (LPCVOID)ptr, buffer, sizeof(buffer) - sizeof(wchar_t), nullptr)) {

                    std::wstring loadedName(buffer);
                    std::wstring lowerLoaded = loadedName;
                    std::transform(lowerLoaded.begin(), lowerLoaded.end(), lowerLoaded.begin(), ::towlower);
                    std::wstring lowerTarget = targetModuleName;
                    std::transform(lowerTarget.begin(), lowerTarget.end(), lowerTarget.begin(), ::towlower);
#if Stealth_Mode_ENABLED

                    if (lowerLoaded.find(L"kernelbase.dll") != std::wstring::npos) {
                        kernelBase_address = reinterpret_cast<uint64_t>(ld.lpBaseOfDll);
                        Patch_CheckRemoteDebuggerPresent();
                        LOG(L"[+] kernelbase.dll loaded at 0x" << std::hex << kernelBase_address);
                    }
#endif
#if analyze_ENABLED
                    LOG_analyze(GREEN,"DLL LOADED : "<< lowerLoaded.c_str());
                    if (lowerLoaded.find(L"ntdll.dll") != std::wstring::npos) {
                        ntdllBase = reinterpret_cast<uint64_t>(ld.lpBaseOfDll);
                        LOG(L"[+] ntdll.dll loaded at 0x" << std::hex << ntdllBase);
                    }
#endif
#if FUll_user_MODE
                    if (lowerLoaded.find(L"system32") == std::wstring::npos &&
                        lowerLoaded.find(L"ntdll.dll") == std::wstring::npos) {
                        IMAGE_DOS_HEADER dosHeader{};
                        IMAGE_NT_HEADERS64 ntHeaders{};
                        if (ReadProcessMemory(pi.hProcess, ld.lpBaseOfDll, &dosHeader, sizeof(dosHeader), nullptr) &&
                            dosHeader.e_magic == IMAGE_DOS_SIGNATURE &&
                            ReadProcessMemory(pi.hProcess, (BYTE*)ld.lpBaseOfDll + dosHeader.e_lfanew, &ntHeaders, sizeof(ntHeaders), nullptr) &&
                            ntHeaders.Signature == IMAGE_NT_SIGNATURE) {

                            uint64_t dllBase = reinterpret_cast<uint64_t>(ld.lpBaseOfDll);
                            uint64_t dllSize = ntHeaders.OptionalHeader.SizeOfImage;
                            valid_ranges.emplace_back(dllBase, dllBase + dllSize);

                            LOG(L"[+] User-mode DLL added to valid_ranges: " << lowerLoaded.c_str()
                                << L" at 0x" << std::hex << dllBase
                                << L" - size: 0x" << dllSize);

                            // --- TLS & EntryPoint Breakpoints ---
                            auto modEntryRVA = GetEntryPointRVA(buffer);
                            auto modTLSRVAs = GetTLSCallbackRVAs(buffer);

                            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dbgEvent.dwThreadId);
                            if (modEntryRVA)
                                modTLSRVAs.push_back(modEntryRVA);

                            for (auto& rva : modTLSRVAs) {
                                uint64_t addr = dllBase + rva;
                                if (bpType == BreakpointType::Hardware)
                                    SetHardwareBreakpointAuto(hThread, addr);
                                else {
                                    BYTE orig;
                                    if (SetBreakpoint(pi.hProcess, addr, orig))
                                        breakpoints[addr] = { orig, 1 };
                                }
                            }
                            if (hThread) CloseHandle(hThread);
                        }
                    }
#endif

                    if (waitForModule && lowerLoaded.find(lowerTarget) != std::wstring::npos) {
                        moduleBase = (uint64_t)ld.lpBaseOfDll;
                        auto modEntryRVA = GetEntryPointRVA(buffer);
                        auto modTLSRVAs = GetTLSCallbackRVAs(buffer);
                        valid_ranges.emplace_back(moduleBase, moduleBase + optionalHeader.SizeOfImage);
                        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dbgEvent.dwThreadId);
                        if (modEntryRVA) modTLSRVAs.push_back(modEntryRVA);

                        for (auto &rva : modTLSRVAs) {
                            uint64_t addr = moduleBase + rva;
                            if (bpType == BreakpointType::Hardware)
                                SetHardwareBreakpointAuto(hThread, addr);
                            else {
                                BYTE orig;
                                if (SetBreakpoint(pi.hProcess, addr, orig)) breakpoints[addr] = { orig, 1 };
                            }
                        }
                        if (hThread) CloseHandle(hThread);
                    }
                }
            }
            if (ld.hFile) CloseHandle(ld.hFile);
            break;
        }

        case CREATE_THREAD_DEBUG_EVENT: {
            CONTEXT ctx = { 0 };
            ctx.ContextFlags = CONTEXT_FULL;
            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dbgEvent.dwThreadId);

            if (hThread && GetThreadContext(hThread, &ctx)) {
#if Stealth_Mode_ENABLED

                EnableStealthMode(hThread);

#endif
                uint64_t entryAddress = (uint64_t)dbgEvent.u.CreateThread.lpStartAddress;
                if (IsInEmulationRange(entryAddress)) {
#if analyze_ENABLED
                    LOG_analyze(GREEN, "New THREAD CREATED! Entry point : " << std::hex << entryAddress);

#endif

                    CPU cpu(hThread);
                    cpu.CPUThreadState = ThreadState::Unknown;
                    cpuThreads.emplace(dbgEvent.dwThreadId, std::move(cpu));

                    if (bpType == BreakpointType::Hardware)
                        SetHardwareBreakpointAuto(hThread, ctx.Rip);
                    else {
                        BYTE orig;
                        if (breakpoints.find(ctx.Rip) == breakpoints.end()) {
                            if (SetBreakpoint(pi.hProcess, ctx.Rip, orig)) breakpoints[ctx.Rip] = { orig, 1 };
                        }
                    }
                }
                if (IsInEmulationRange(ctx.Rip)) {
#if analyze_ENABLED
                    LOG_analyze(GREEN, "New THREAD CREATED! Rip : " << std::hex << ctx.Rip);

#endif
          
                    CPU cpu(hThread);
                    cpu.CPUThreadState = ThreadState::Unknown;
                    cpuThreads.emplace(dbgEvent.dwThreadId, std::move(cpu));

                    if (bpType == BreakpointType::Hardware)
                        SetHardwareBreakpointAuto(hThread, ctx.Rip);
                    else {
                        BYTE orig;
                        if (breakpoints.find(ctx.Rip) == breakpoints.end()) {
                            if (SetBreakpoint(pi.hProcess, ctx.Rip, orig)) breakpoints[ctx.Rip] = { orig, 1 };
                        }
                    }
                }

                uint64_t pointer = ctx.Rdx, address = 0;
            if (ReadProcessMemory(pi.hProcess, (LPCVOID)pointer, &address, sizeof(address), nullptr) && IsInEmulationRange(address)) {
#if analyze_ENABLED
                    LOG_analyze(GREEN, "New THREAD CREATED! RDX address : " << std::hex << address);

#endif


                    CPU cpu(hThread);
                    cpu.CPUThreadState = ThreadState::Unknown;
                    cpuThreads.emplace(dbgEvent.dwThreadId, std::move(cpu));

                    if (bpType == BreakpointType::Hardware)
                        SetHardwareBreakpointAuto(hThread, address);
                    else {
                        BYTE orig;
                        if (breakpoints.find(address) == breakpoints.end()) {
                            if (SetBreakpoint(pi.hProcess, address, orig)) breakpoints[address] = { orig, 1 };
                        }
                    }
                }
            }
            if (hThread) CloseHandle(hThread);
            break;
        }

        case CREATE_PROCESS_DEBUG_EVENT: {
            auto& procInfo = dbgEvent.u.CreateProcessInfo;
            baseAddress = reinterpret_cast<uint64_t>(procInfo.lpBaseOfImage);
            valid_ranges.emplace_back(baseAddress, baseAddress + optionalHeader.SizeOfImage);

            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dbgEvent.dwThreadId);
#if Stealth_Mode_ENABLED
            EnableStealthMode(hThread);
#endif
            if (hThread) {
                cpuThreads.emplace(dbgEvent.dwThreadId, CPU(hThread));
            }

            if (!waitForModule) {
                if (entryRVA) tlsRVAs.push_back(entryRVA);
               
                for (auto &rva : tlsRVAs) {
                    uint64_t addr = baseAddress + rva;
                    if (bpType == BreakpointType::Hardware)
                        SetHardwareBreakpointAuto(hThread, addr);
                    else {
                        BYTE orig;
                        if (SetBreakpoint(pi.hProcess, addr, orig)) breakpoints[addr] = { orig, 1 };
                    }
                }
            }
            break;
        }

        case EXCEPTION_DEBUG_EVENT: {
            auto& er = dbgEvent.u.Exception.ExceptionRecord;
            DWORD exceptionCode = er.ExceptionCode;
            uint64_t exAddr = reinterpret_cast<uint64_t>(er.ExceptionAddress);

            switch (exceptionCode) {
#if Multithread_the_MultiThread
            case EXCEPTION_BREAKPOINT:
                if (bpType == BreakpointType::Software && breakpoints.count(exAddr)) {
                    auto& bp = breakpoints[exAddr];
                    RemoveBreakpoint(pi.hProcess, exAddr, bp.originalByte);
                    bp.remainingHits--;

                    CONTEXT ctx = { 0 };
                    ctx.ContextFlags = CONTEXT_FULL;
                    HANDLE hThreadTrigger = OpenThread(THREAD_ALL_ACCESS, FALSE, dbgEvent.dwThreadId);
                    if (hThreadTrigger && GetThreadContext(hThreadTrigger, &ctx)) {
                        ctx.Rip -= 1;
                        SetThreadContext(hThreadTrigger, &ctx);
                    }

                    RemoveAllBreakpoints(pi.hProcess, breakpoints);

                    std::vector<CPU*> cpus;
                    for (auto& p : cpuThreads) {
                        cpus.push_back(&p.second);
                    }

                    std::vector<uint64_t> returnedAddrs(cpus.size(), 0);

     
                    for (auto* cpu : cpus) {
                        cpu->CPUThreadState = ThreadState::Running;
                        cpu->UpdateRegistersFromContext();
                    }


                    std::vector<std::thread> workers;
                    for (size_t i = 0; i < cpus.size(); ++i) {
                        CPU* cpu = cpus[i];
                        workers.emplace_back([cpu, &returnedAddrs, i]() {
                            returnedAddrs[i] = cpu->start_emulation();
                            LOG( "  returnedAddrs["<< i<<"] " << returnedAddrs[i]);
                            });
                    }
                    for (auto& t : workers) {
                        if (t.joinable()) t.join();
                    }

                    for (auto* cpu : cpus) {
                        if (!cpu->ApplyRegistersToContext()) {
            
                            DWORD tid = GetThreadId(cpu->hThread);
                            if (tid != 0) {
                                LOG(L"[!] Removing CPU for dead thread ID: " << tid);
                                cpuThreads.erase(tid);
                            }
                        }
                    }


                    for (auto addr : returnedAddrs) {
                        if (addr == 0) continue;
                        if (breakpoints.find(addr) == breakpoints.end()) {
                            BYTE orig;
                            if (SetBreakpoint(pi.hProcess, addr, orig)) {
                                breakpoints[addr] = { orig, 1 };
                                LOG(L"[+] Breakpoint set at new address: 0x" << std::hex << addr);
                            }
                        }
                        else {
                            breakpoints[addr].remainingHits++;
                        }
                    }

                    if (bp.remainingHits > 0) {
                        SetBreakpoint(pi.hProcess, exAddr, bp.originalByte);
                    }
                    else {
                        breakpoints.erase(exAddr);
                        LOG(L"[*] Breakpoint at 0x" << std::hex << exAddr << L" removed permanently");
                    }

                    if (hThreadTrigger) CloseHandle(hThreadTrigger);
                }
                break;

#else

            case EXCEPTION_BREAKPOINT:
                if (bpType == BreakpointType::Software && breakpoints.count(exAddr)) {
                    auto& bp = breakpoints[exAddr];
                    RemoveBreakpoint(pi.hProcess, exAddr, bp.originalByte);
                    bp.remainingHits--;

                    CONTEXT ctx = { 0 };
                    ctx.ContextFlags = CONTEXT_FULL;
                    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dbgEvent.dwThreadId);
                    if (hThread && GetThreadContext(hThread, &ctx)) {
                        ctx.Rip -= 1;
                        SetThreadContext(hThread, &ctx);
                    }

                    RemoveAllBreakpoints(pi.hProcess, breakpoints);

                    auto it = cpuThreads.find(dbgEvent.dwThreadId);
                    if (it == cpuThreads.end()) {
     
                        if (hThread) {
                            CPU cpu(hThread);
                            cpu.CPUThreadState = ThreadState::Unknown;
                            cpuThreads.emplace(dbgEvent.dwThreadId, std::move(cpu));
                            LOG(L"[+] Created new CPU object for missing thread: " << dbgEvent.dwThreadId);
                            it = cpuThreads.find(dbgEvent.dwThreadId);
                        }
                    }

                    if (it != cpuThreads.end()) {
                        CPU& cpu = it->second;
                        cpu.CPUThreadState = ThreadState::Running;
                        cpu.UpdateRegistersFromContext();

                        uint64_t addr = cpu.start_emulation();
                        LOG(L"[+] Emulation returned address: 0x" << std::hex << addr);

                        cpu.ApplyRegistersToContext();

                        if (bp.remainingHits > 0) {
                            SetBreakpoint(pi.hProcess, exAddr, bp.originalByte);
                        }
                        else {
                            breakpoints.erase(exAddr);
                            LOG(L"[*] Breakpoint at 0x" << std::hex << exAddr << L" removed permanently");
                        }

                        if (breakpoints.find(addr) == breakpoints.end()) {
                            BYTE orig;
                            if (SetBreakpoint(pi.hProcess, addr, orig)) {
                                breakpoints[addr] = { orig, 1 };
                                LOG(L"[+] Breakpoint set at new address: 0x" << std::hex << addr);
                            }
                        }
                        else {
                            breakpoints[addr].remainingHits++;
                        }
                    }

                    if (hThread) CloseHandle(hThread);
                }
                break;


#endif

            case EXCEPTION_SINGLE_STEP: {



                HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dbgEvent.dwThreadId);
                RemoveHardwareBreakpointByAddress(hThread, exAddr);
                auto it = cpuThreads.find(dbgEvent.dwThreadId);
                if (it != cpuThreads.end()) {
                    CPU& cpu = it->second;
                    cpu.CPUThreadState = ThreadState::Running;
                    cpu.UpdateRegistersFromContext();

                    uint64_t addr = cpu.start_emulation();
                    LOG(L"[+] Emulation returned address: 0x" << std::hex << addr);

                    cpu.ApplyRegistersToContext();

                    if (bpType == BreakpointType::Hardware)
                        if (SetHardwareBreakpointAuto(hThread, addr)) {
                            LOG(L"[+] Breakpoint set at new address: 0x" << std::hex << addr);
                        }
                        else {
                            BYTE orig;
                            if (breakpoints.find(addr) == breakpoints.end()) {
                                if (SetBreakpoint(pi.hProcess, addr, orig)) breakpoints[addr] = { orig, 1 };
                            }
                        }
                }

                if (hThread) CloseHandle(hThread);
                break;
            }

            case EXCEPTION_ACCESS_VIOLATION:
                LOG(L"[!] Access Violation at 0x" << std::hex << exAddr);
                exit(0);
                break;

            case EXCEPTION_ILLEGAL_INSTRUCTION:
                LOG(L"[!] Illegal instruction at 0x" << std::hex << exAddr);
                exit(0);
                break;

            case EXCEPTION_STACK_OVERFLOW:
                LOG(L"[!] Stack overflow at 0x" << std::hex << exAddr);
                exit(0);
                break;

            case EXCEPTION_INT_DIVIDE_BY_ZERO:
                LOG(L"[!] Divide by zero at 0x" << std::hex << exAddr);
                exit(0);
                break;

            case EXCEPTION_PRIV_INSTRUCTION:
                LOG(L"[!] Privileged instruction exception at 0x" << std::hex << exAddr);
                break;

            case 0x406d1388:  // DBG_PRINTEXCEPTION_C
                LOG(L"[i] Debug string output exception at 0x" << std::hex << exAddr);
                break;

            default:
                LOG(L"[!] Unhandled exception 0x" << std::hex << exceptionCode << L" at 0x" << exAddr);
                break;
            }

            break;
        }

        case EXIT_THREAD_DEBUG_EVENT:
            cpuThreads.erase(dbgEvent.dwThreadId);
            LOG(dbgEvent.dwThreadId<< "  EXIT");
            break;

        case EXIT_PROCESS_DEBUG_EVENT:
            goto cleanup;

        default:
            break;
        }
        ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, continueStatus);
    }

cleanup:
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
