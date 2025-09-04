#include "cpu.hpp"
#include <thread>

using namespace std;

std::unordered_map<DWORD, CPU> cpuThreads;

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        wprintf(L"Usage: %s <exe_path> [-m target.dll] [-r <hex_rva>] [-b software|hardware]\n", argv[0]);
        wprintf(L"  Example:\n");
        wprintf(L"    %s program.exe -r 0x1234\n", argv[0]);
        wprintf(L"    %s program.exe -m ntdll.dll -r 0x500 -b hardware\n", argv[0]);
        return 1;
    }


    std::wstring targetModuleName;
    bool waitForModule = false;
    uint64_t targetRVA = 0;
    bool hasRVA = false;
    ReadGDTR(&gdtr);
#if AUTO_PATCH_HW
    std::wstring patchSection;      // -section <section_name>
#endif

    for (int i = 1; i < argc; ++i) {
        std::wstring arg = argv[i];

#if AUTO_PATCH_HW
        if (arg == L"-p" && i + 1 < argc) {
            patchModule = argv[++i];
        }
        else if (arg == L"-section" && i + 1 < argc) {
            patchSection = argv[++i];

        }
        else
#endif
            if (arg == L"-m" && i + 1 < argc) {
                targetModuleName = argv[++i];
                waitForModule = true;
            }
            else if (arg == L"-b" && i + 1 < argc) {
                std::wstring type = argv[++i];
                std::transform(type.begin(), type.end(), type.begin(), ::towlower);
                if (type == L"hardware") bpType = BreakpointType::Hardware;
                else if (type == L"software") bpType = BreakpointType::Software;
                else if (type == L"noexec") bpType = BreakpointType::ExecGuard;
                else {
                    wprintf(L"[-] Invalid breakpoint type: %s\n", type.c_str());
                    return 1;
                }
            }
            else if ((arg == L"-r" || arg == L"-rva") && i + 1 < argc) {
                std::wistringstream iss(argv[++i]);
                iss >> std::hex >> targetRVA;
                if (iss.fail()) {
                    wprintf(L"[-] Invalid hex value for RVA: %s\n", argv[i]);
                    return 1;
                }
                hasRVA = true;
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
#if AUTO_PATCH_HW
                    std::wstring lowerPatchTarget = patchModule;
                    std::transform(lowerPatchTarget.begin(), lowerPatchTarget.end(), lowerPatchTarget.begin(), ::towlower);
                    if ((lowerLoaded.find(lowerPatchTarget) != std::wstring::npos) && patchSectionAddress == 0 && !patchSection.empty()) {
                        uint64_t dllBase = reinterpret_cast<uint64_t>(ld.lpBaseOfDll);
                        patchModule_File_Path = lowerLoaded;

                        IMAGE_DOS_HEADER dosHdr{};
                        ReadProcessMemory(pi.hProcess, ld.lpBaseOfDll, &dosHdr, sizeof(dosHdr), nullptr);

                        IMAGE_NT_HEADERS64 ntHdr{};
                        ReadProcessMemory(pi.hProcess, (LPCVOID)((uint64_t)ld.lpBaseOfDll + dosHdr.e_lfanew), &ntHdr, sizeof(ntHdr), nullptr);

                        DWORD numberOfSections = ntHdr.FileHeader.NumberOfSections;
                        DWORD sectionOffset = dosHdr.e_lfanew +
                            offsetof(IMAGE_NT_HEADERS64, OptionalHeader) +
                            ntHdr.FileHeader.SizeOfOptionalHeader;

                        std::string patchSections(patchSection.begin(), patchSection.end());

                        for (DWORD i = 0; i < numberOfSections; i++) {
                            IMAGE_SECTION_HEADER secHdr{};
                            ReadProcessMemory(pi.hProcess,
                                (LPCVOID)((uint64_t)ld.lpBaseOfDll + sectionOffset + i * sizeof(secHdr)),
                                &secHdr, sizeof(secHdr), nullptr);

                            size_t cmpLen = min(patchSections.size(), (size_t)IMAGE_SIZEOF_SHORT_NAME);
                            sections.push_back(secHdr);
                            if (strncmp((char*)secHdr.Name, patchSections.c_str(), cmpLen) == 0) {
                                patch_modules_ranges.first = dllBase;
                                patch_modules_ranges.second = dllBase + ntHdr.OptionalHeader.SizeOfImage;

                                patchSectionAddress = (uint64_t)ld.lpBaseOfDll + secHdr.VirtualAddress;
                                patch_section_ranges.first = patchSectionAddress;
                                patch_section_ranges.second = patchSectionAddress + secHdr.Misc.VirtualSize;
                                printf("%s section at: 0x%llx (size: 0x%x)\n",
                                    patchSections.c_str(), patchSectionAddress, secHdr.Misc.VirtualSize);
                                break;
                            }
                        }
                    }


#endif

                    if (hasRVA && waitForModule && lowerLoaded.find(lowerTarget) != std::wstring::npos) {
                        moduleBase = (uint64_t)ld.lpBaseOfDll;
                        uint64_t targetAddr = moduleBase + targetRVA;

                        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dbgEvent.dwThreadId);
                        if (hThread) {
                            if (bpType == BreakpointType::Hardware)
                                SetHardwareBreakpointAuto(hThread, targetAddr);
                            else {
                                BYTE orig;
                                if (SetBreakpoint(pi.hProcess, targetAddr, orig))
                                    breakpoints[targetAddr] = { orig, 1 };
                            }
                            CloseHandle(hThread);
                        }
                        LOG(L"[+] Breakpoint set on module '%s' at RVA 0x%llX -> 0x%llX",
                            lowerTarget.c_str(), targetRVA, targetAddr);
                    }

#if Stealth_Mode_ENABLED

                    if (lowerLoaded.find(L"kernelbase.dll") != std::wstring::npos) {
                        kernelBase_address = reinterpret_cast<uint64_t>(ld.lpBaseOfDll);
                        Patch_CheckRemoteDebuggerPresent();
                        LOG(L"[+] kernelbase.dll loaded at 0x" << std::hex << kernelBase_address);
                    }
#endif
#if analyze_ENABLED
                    LOG_analyze(GREEN, "DLL LOADED : " << lowerLoaded.c_str());
                    if (lowerLoaded.find(L"ntdll.dll") != std::wstring::npos) {
                        ntdllBase = reinterpret_cast<uint64_t>(ld.lpBaseOfDll);
                        LOG(L"[+] ntdll.dll loaded at 0x" << std::hex << ntdllBase);
                    }
#endif
#if FUll_user_MODE

                    bool isSystemModule = (
                        lowerLoaded.find(L"system32") != std::wstring::npos ||
                        lowerLoaded.find(L"ntdll.dll") != std::wstring::npos
                        );

                    IMAGE_DOS_HEADER dosHeader{};
                    IMAGE_NT_HEADERS64 ntHeaders{};
                    if (ReadProcessMemory(pi.hProcess, ld.lpBaseOfDll, &dosHeader, sizeof(dosHeader), nullptr) &&
                        dosHeader.e_magic == IMAGE_DOS_SIGNATURE &&
                        ReadProcessMemory(pi.hProcess, (BYTE*)ld.lpBaseOfDll + dosHeader.e_lfanew, &ntHeaders, sizeof(ntHeaders), nullptr) &&
                        ntHeaders.Signature == IMAGE_NT_SIGNATURE)
                    {
                        uint64_t dllBase = reinterpret_cast<uint64_t>(ld.lpBaseOfDll);
                        uint64_t dllSize = ntHeaders.OptionalHeader.SizeOfImage;
                        std::wstring fileName = std::filesystem::path(lowerLoaded).filename().wstring();
                        if (isSystemModule) {
                            system_modules_ranges.emplace_back(dllBase, dllBase + dllSize);
                            system_modules_names.push_back(fileName);
                            LOG(L"[+] System DLL added to system_modules_ranges: " << lowerLoaded.c_str()
                                << L" at 0x" << std::hex << dllBase
                                << L" - size: 0x" << dllSize);
                        }
                        else {
                            valid_ranges.emplace_back(dllBase, dllBase + dllSize);

                            LOG(L"[+] User-mode DLL added to valid_ranges: " << lowerLoaded.c_str()
                                << L" at 0x" << std::hex << dllBase
                                << L" - size: 0x" << dllSize);

                            // --- TLS & EntryPoint Breakpoints ---
                            if (!hasRVA && !waitForModule && bpType != BreakpointType::ExecGuard) {
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
                            else if (!hasRVA && !waitForModule && bpType == BreakpointType::ExecGuard) {

                                RemoveExecutionEx((LPVOID)dllBase, dllSize);
                            }
                        }
                    }
#endif
#if Save_Rva
                    if (lowerLoaded.find(L"ntdll.dll") != std::wstring::npos) {
                        ntdll_rang.first = reinterpret_cast<uint64_t>(ld.lpBaseOfDll);
                        ntdll_rang.second = moduleBase + optionalHeader.SizeOfImage;
                    }
#endif

                    if (waitForModule && !hasRVA && lowerLoaded.find(lowerTarget) != std::wstring::npos) {
                        moduleBase = (uint64_t)ld.lpBaseOfDll;
                        auto modEntryRVA = GetEntryPointRVA(buffer);
                        auto modTLSRVAs = GetTLSCallbackRVAs(buffer);
                        valid_ranges.emplace_back(moduleBase, moduleBase + optionalHeader.SizeOfImage);
                        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dbgEvent.dwThreadId);
                        if (modEntryRVA) modTLSRVAs.push_back(modEntryRVA);

                        if (bpType == BreakpointType::ExecGuard) {
                            RemoveExecutionEx((LPVOID)moduleBase, optionalHeader.SizeOfImage);
                        }
                        else {
                            for (auto& rva : modTLSRVAs) {
                                uint64_t addr = moduleBase + rva;
                                if (bpType == BreakpointType::Hardware)
                                    SetHardwareBreakpointAuto(hThread, addr);
                                else {
                                    BYTE orig;
                                    if (SetBreakpoint(pi.hProcess, addr, orig)) breakpoints[addr] = { orig, 1 };
                                }
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
            if (bpType != BreakpointType::ExecGuard) {
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
            }

            break;
        }

        case CREATE_PROCESS_DEBUG_EVENT: {
            auto& procInfo = dbgEvent.u.CreateProcessInfo;
            baseAddress = reinterpret_cast<uint64_t>(procInfo.lpBaseOfImage);
#if AUTO_PATCH_HW
            if (patchModule.empty() && !patchSection.empty() && patchSectionAddress == 0) {

                IMAGE_DOS_HEADER dosHdr{};
                ReadProcessMemory(pi.hProcess, (LPCVOID)baseAddress, &dosHdr, sizeof(dosHdr), nullptr);

                IMAGE_NT_HEADERS64 ntHdr{};
                ReadProcessMemory(pi.hProcess, (LPCVOID)(baseAddress + dosHdr.e_lfanew), &ntHdr, sizeof(ntHdr), nullptr);

                DWORD numberOfSections = ntHdr.FileHeader.NumberOfSections;
                DWORD sectionOffset = dosHdr.e_lfanew +
                    offsetof(IMAGE_NT_HEADERS64, OptionalHeader) +
                    ntHdr.FileHeader.SizeOfOptionalHeader;
                std::string patchSections(patchSection.begin(), patchSection.end());
                for (DWORD i = 0; i < numberOfSections; i++) {
                    IMAGE_SECTION_HEADER secHdr{};
                    ReadProcessMemory(pi.hProcess, (LPCVOID)(baseAddress + sectionOffset + i * sizeof(secHdr)), &secHdr, sizeof(secHdr), nullptr);
                    sections.push_back(secHdr);
                    if (strncmp((char*)secHdr.Name, (char*)patchSections.c_str(), patchSection.size()) == 0) {
                        patch_modules_ranges.first = baseAddress;
                        patch_modules_ranges.second = baseAddress + ntHdr.OptionalHeader.SizeOfImage;

                        patchSectionAddress = baseAddress + secHdr.VirtualAddress;
                        patch_section_ranges.first = patchSectionAddress;
                        patch_section_ranges.second = patchSectionAddress + secHdr.Misc.VirtualSize;
                        printf("%s section at: 0x%llx (size: 0x%x)\n", patchSections.c_str(), patchSectionAddress, secHdr.Misc.VirtualSize);
                        break;
                    }
                }
            }


#endif



            valid_ranges.emplace_back(baseAddress, baseAddress + optionalHeader.SizeOfImage);

            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dbgEvent.dwThreadId);
#if Stealth_Mode_ENABLED
            EnableStealthMode(hThread);
#endif
            if (hThread) {
                cpuThreads.emplace(dbgEvent.dwThreadId, CPU(hThread));
            }


   
                if (hasRVA && !waitForModule) {
                    uint64_t targetAddr = baseAddress + targetRVA;
                    if (bpType == BreakpointType::Hardware)
                        SetHardwareBreakpointAuto(hThread, targetAddr);
                    else {
                        BYTE orig;
                        if (SetBreakpoint(pi.hProcess, targetAddr, orig)) breakpoints[targetAddr] = { orig, 1 };
                    }
                    LOG(L"[+] Breakpoint set on main executable at RVA 0x%llX -> 0x%llX", targetRVA, targetAddr);
                }


                if (!waitForModule && !hasRVA) {
                    if (entryRVA) tlsRVAs.push_back(entryRVA);

                    for (auto& rva : tlsRVAs) {
                        uint64_t addr = baseAddress + rva;
                        if (bpType == BreakpointType::ExecGuard) {
                            RemoveExecutionEx((LPVOID)baseAddress, optionalHeader.SizeOfImage);
                        }
                        else if (bpType == BreakpointType::Hardware)
                            SetHardwareBreakpointAuto(hThread, addr);
                        else {
                            BYTE orig;
                            if (SetBreakpoint(pi.hProcess, addr, orig)) breakpoints[addr] = { orig, 1 };
                        }
                    }
                }


            }

            break;
        

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
                            LOG("  returnedAddrs[" << i << "] " << returnedAddrs[i]);
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
                    //some time work better with this 
                    //RemoveAllBreakpoints(pi.hProcess, breakpoints);

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
                if (bpType == BreakpointType::ExecGuard) {
                    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dbgEvent.dwThreadId);
                    if (!hThread) {
                        printf("OpenThread failed: %lu\n", GetLastError());

                    }

                    auto it = cpuThreads.find(dbgEvent.dwThreadId);
                    if (it == cpuThreads.end()) {
                        CPU cpu(hThread);
                        cpu.CPUThreadState = ThreadState::Unknown;
                        auto [newIt, inserted] = cpuThreads.emplace(dbgEvent.dwThreadId, std::move(cpu));
                        it = newIt;
                    }
                    CPU& cpu = it->second;
                    cpu.CPUThreadState = ThreadState::Running;

                    cpu.UpdateRegistersFromContext();

                    cpu.start_emulation();

                    cpu.ApplyRegistersToContext();
                }

                else {
                    std::cout << "[!] Access Violation at 0x" << std::hex << exAddr;
                    if (bpType == BreakpointType::Software) {
                        std::cout << " (Writing INT3 on code integrity protected program can cause this. Use hardware breakpoints: emudbg my.exe -b hardware)";
                    }
                    std::cout << std::endl;
                }

                // exit(0);
                break;

            case EXCEPTION_ILLEGAL_INSTRUCTION:
                std::cout << "[!] Illegal instruction at 0x" << std::hex << exAddr << std::endl;
                //exit(0);
                break;


            case 0xC0000409: // STATUS_STACK_BUFFER_OVERRUN
                std::cout << "[!] Stack buffer overrun detected at 0x" << std::hex << exAddr << std::endl;
                //exit(0);
                break;

            case EXCEPTION_STACK_OVERFLOW:
                std::cout << "[!] Stack overflow at 0x" << std::hex << exAddr << std::endl;
                //exit(0);
                break;

            case EXCEPTION_INT_DIVIDE_BY_ZERO:
                std::cout << "[!] Divide by zero at 0x" << std::hex << exAddr << std::endl;
                //exit(0);
                break;

            case EXCEPTION_PRIV_INSTRUCTION:
                std::cout << "[!] Privileged instruction exception at 0x" << std::hex << std::endl;
                break;

            case 0x406d1388:  // DBG_PRINTEXCEPTION_C
                std::cout << "[i] Debug string output exception at 0x" << std::hex << exAddr << std::endl;
                break;

            default:
                std::cout << "[!] Unhandled exception 0x" << std::hex << exceptionCode << " at 0x" << exAddr << std::endl;
                break;
            }

            break;
        }

        case EXIT_THREAD_DEBUG_EVENT:
            cpuThreads.erase(dbgEvent.dwThreadId);
            LOG(dbgEvent.dwThreadId << "  EXIT");
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
