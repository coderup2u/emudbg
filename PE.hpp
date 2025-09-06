typedef struct _THREAD_BASIC_INFORMATION {
  NTSTATUS ExitStatus;
  PVOID TebBaseAddress;
  CLIENT_ID ClientId;
  KAFFINITY AffinityMask;
  LONG Priority;
  LONG BasePriority;
} THREAD_BASIC_INFORMATION;

typedef NTSTATUS(NTAPI *NtQueryInformationThreadPtr)(
    HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation, ULONG ThreadInformationLength,
    PULONG ReturnLength);

extern "C" NTSTATUS NTAPI NtQueryInformationThread(
    HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation, ULONG ThreadInformationLength,
    PULONG ReturnLength);

struct memory_mange {
  uint64_t address;
  SIZE_T size;
  char buffer[1024];
  bool is_write;
};

std::vector<std::pair<uint64_t, uint64_t>> valid_ranges;
std::vector<std::pair<uint64_t, uint64_t>> system_modules_ranges;
std::vector<std::wstring> system_modules_names;
std::wstring GetSystemModuleNameFromAddress(uint64_t addr) {
  for (size_t i = 0; i < system_modules_ranges.size(); ++i) {
    auto [start, end] = system_modules_ranges[i];
    if (addr >= start && addr < end) {
      return system_modules_names[i];
    }
  }
  return L"";
}
PROCESS_INFORMATION pi;
IMAGE_OPTIONAL_HEADER64 optionalHeader;
uint64_t kernelBase_address;

bool IsInEmulationRange(uint64_t addr) {
  for (const auto &range : valid_ranges) {
    if (addr >= range.first && addr <= range.second)
      return true;
  }
  return false;
}

bool IsInSystemRange(uint64_t addr) {
  for (const auto &range : system_modules_ranges) {
    if (addr >= range.first && addr <= range.second)
      return true;
  }
  return false;
}

uint64_t GetTEBAddress(HANDLE hThread) {
  HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  if (!ntdll)
    return 0;

  auto NtQueryInformationThread = reinterpret_cast<NtQueryInformationThreadPtr>(
      GetProcAddress(ntdll, "NtQueryInformationThread"));

  if (!NtQueryInformationThread)
    return 0;

  THREAD_BASIC_INFORMATION tbi = {};
  if (NtQueryInformationThread(hThread, static_cast<THREADINFOCLASS>(0), &tbi,
                               sizeof(tbi), nullptr) != 0)
    return 0;

  return reinterpret_cast<uint64_t>(tbi.TebBaseAddress);
}

std::vector<uint32_t> GetTLSCallbackRVAs(const std::wstring &exePath) {
  std::vector<uint32_t> tlsCallbacks;
  std::ifstream file(exePath, std::ios::binary);
  if (!file)
    return tlsCallbacks;

  IMAGE_DOS_HEADER dosHeader;
  file.read(reinterpret_cast<char *>(&dosHeader), sizeof(dosHeader));
  if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
    return tlsCallbacks;

  file.seekg(dosHeader.e_lfanew, std::ios::beg);
  DWORD ntSignature;
  file.read(reinterpret_cast<char *>(&ntSignature), sizeof(ntSignature));
  if (ntSignature != IMAGE_NT_SIGNATURE)
    return tlsCallbacks;

  IMAGE_FILE_HEADER fileHeader;
  file.read(reinterpret_cast<char *>(&fileHeader), sizeof(fileHeader));
  IMAGE_OPTIONAL_HEADER64 optionalHeader;
  file.read(reinterpret_cast<char *>(&optionalHeader), sizeof(optionalHeader));
  DWORD tlsDirRVA =
      optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
  if (tlsDirRVA == 0)
    return tlsCallbacks;

  std::vector<IMAGE_SECTION_HEADER> sections(fileHeader.NumberOfSections);
  file.seekg(dosHeader.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
             fileHeader.SizeOfOptionalHeader);
  file.read(reinterpret_cast<char *>(sections.data()),
            sizeof(IMAGE_SECTION_HEADER) * fileHeader.NumberOfSections);
  DWORD tlsOffset = 0;

  for (const auto &sec : sections) {
    if (tlsDirRVA >= sec.VirtualAddress &&
        tlsDirRVA < sec.VirtualAddress + sec.Misc.VirtualSize) {
      tlsOffset = tlsDirRVA - sec.VirtualAddress + sec.PointerToRawData;
      break;
    }
  }

  if (tlsOffset == 0)
    return tlsCallbacks;

  file.seekg(tlsOffset, std::ios::beg);
  IMAGE_TLS_DIRECTORY64 tlsDir;
  file.read(reinterpret_cast<char *>(&tlsDir), sizeof(tlsDir));
  uint64_t callbackVA = tlsDir.AddressOfCallBacks;

  if (callbackVA == 0)
    return tlsCallbacks;

  uint64_t fileOffset = 0;

  for (const auto &sec : sections) {
    if (callbackVA >= optionalHeader.ImageBase + sec.VirtualAddress &&
        callbackVA < optionalHeader.ImageBase + sec.VirtualAddress +
                         sec.Misc.VirtualSize) {
      fileOffset = callbackVA - optionalHeader.ImageBase - sec.VirtualAddress +
                   sec.PointerToRawData;
      break;
    }
  }
  if (fileOffset == 0)
    return tlsCallbacks;

  file.seekg(fileOffset, std::ios::beg);
  uint64_t callback = 0;
  file.read(reinterpret_cast<char *>(&callback), sizeof(callback));
  if (callback)
    tlsCallbacks.push_back(
        static_cast<uint32_t>(callback - optionalHeader.ImageBase));

  return tlsCallbacks;
}

uint32_t GetEntryPointRVA(const std::wstring &exePath) {
  std::ifstream file(exePath, std::ios::binary);
  if (!file)
    return 0;

  IMAGE_DOS_HEADER dosHeader;
  file.read(reinterpret_cast<char *>(&dosHeader), sizeof(dosHeader));
  if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
    return 0;

  file.seekg(dosHeader.e_lfanew, std::ios::beg);
  DWORD ntSignature;
  file.read(reinterpret_cast<char *>(&ntSignature), sizeof(ntSignature));
  if (ntSignature != IMAGE_NT_SIGNATURE)
    return 0;

  IMAGE_FILE_HEADER fileHeader;
  file.read(reinterpret_cast<char *>(&fileHeader), sizeof(fileHeader));
  file.read(reinterpret_cast<char *>(&optionalHeader), sizeof(optionalHeader));

  return optionalHeader.AddressOfEntryPoint;
}

bool EnableStealthMode(HANDLE hThread) {
  uint64_t tebAddr = GetTEBAddress(hThread);
  if (tebAddr == 0)
    return false;

  uint64_t pebAddr = 0;
  if (!ReadProcessMemory(pi.hProcess, (LPCVOID)(tebAddr + 0x60), &pebAddr,
                         sizeof(pebAddr), nullptr)) {
    return false;
  }

  BYTE zero = 0;

  // 1. Clear BeingDebugged (PEB+0x2)
  if (!WriteProcessMemory(pi.hProcess, (LPVOID)(pebAddr + 0x2), &zero,
                          sizeof(zero), nullptr)) {
    return false;
  }

  // 2. Clear NtGlobalFlag (PEB+0xBC)
  if (!WriteProcessMemory(pi.hProcess, (LPVOID)(pebAddr + 0xBC), &zero,
                          sizeof(zero), nullptr)) {
    return false;
  }

  // 3. Clear HeapFlags and HeapForceFlags
  uint64_t processHeapAddr = 0;
  if (!ReadProcessMemory(pi.hProcess, (LPCVOID)(pebAddr + 0x30),
                         &processHeapAddr, sizeof(processHeapAddr), nullptr)) {
    return false;
  }

  DWORD heapFlags = 0;
  DWORD heapForceFlags = 0;

  return true;
}

bool PatchKernelBaseFunction(HANDLE hProcess, uintptr_t kernelBase_address,
                             const std::string &funcName,
                             const BYTE *patchBytes, size_t patchSize) {
  if (!kernelBase_address)
    return false;

  HMODULE hLocalKernelBase = GetModuleHandleW(L"kernelbase.dll");
  if (!hLocalKernelBase)
    return false;

  FARPROC localFunc = GetProcAddress(hLocalKernelBase, funcName.c_str());
  if (!localFunc)
    return false;

  uintptr_t offset = (uintptr_t)localFunc - (uintptr_t)hLocalKernelBase;
  LPVOID remoteFuncAddr = (LPVOID)(kernelBase_address + offset);

  DWORD oldProtect;
  if (!VirtualProtectEx(hProcess, remoteFuncAddr, patchSize,
                        PAGE_EXECUTE_READWRITE, &oldProtect))
    return false;

  bool success = WriteProcessMemory(hProcess, remoteFuncAddr, patchBytes,
                                    patchSize, nullptr) != 0;

  VirtualProtectEx(hProcess, remoteFuncAddr, patchSize, oldProtect,
                   &oldProtect);

  return success;
}

bool Patch_CheckRemoteDebuggerPresent() {
  BYTE patch[] = {
      0x48, 0x31,
      0xC0, // xor rax, rax
      0xC3  // ret
  };

  return PatchKernelBaseFunction(pi.hProcess, kernelBase_address,
                                 "CheckRemoteDebuggerPresent", patch,
                                 sizeof(patch));
}

static const std::map<uint64_t, std::string> ntdll_directory_offsets = {
    {0x00000070, "Export Directory RVA"},
    {0x00000078, "Export Directory Size"},

    {0x00000080, "Import Directory RVA"},
    {0x00000088, "Import Directory Size"},

    {0x00000090, "Resource Directory RVA"},
    {0x00000098, "Resource Directory Size"},

    {0x000000A0, "Exception Directory RVA"},
    {0x000000A8, "Exception Directory Size"},

    {0x000000B0, "Security Directory RVA"},
    {0x000000B8, "Security Directory Size"},

    {0x000000C0, "Relocation Directory RVA"},
    {0x000000C8, "Relocation Directory Size"},

    {0x000000D0, "Debug Directory RVA"},
    {0x000000D8, "Debug Directory Size"},

    {0x000000E0, "Architecture Directory RVA"},
    {0x000000E8, "Architecture Directory Size"},

    {0x000000F0, "Global Ptr RVA"},
    {0x000000F8, "Global Ptr Size"},

    {0x00000100, "TLS Directory RVA"},
    {0x00000108, "TLS Directory Size"},

    {0x00000110, "Load Config Directory RVA"},
    {0x00000118, "Load Config Directory Size"},

    {0x00000120, "Bound Import Directory RVA"},
    {0x00000128, "Bound Import Directory Size"},

    {0x00000130, "IAT Directory RVA"},
    {0x00000138, "IAT Directory Size"},

    {0x00000140, "Delay Import Descriptor RVA"},
    {0x00000148, "Delay Import Descriptor Size"},

    {0x00000150, "CLR Runtime Header RVA"},
    {0x00000158, "CLR Runtime Header Size"},

    {0x00000160, "Reserved (Zero) RVA"},
    {0x00000168, "Reserved (Zero) Size"},
};

struct ExportedFunctionInfo {
  std::unordered_map<uint64_t, std::string> addrToName;
};
std::unordered_map<uint64_t, ExportedFunctionInfo> exportsCache_;

DWORD RvaToOffset(LPVOID fileBase, DWORD rva) {
  auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(fileBase);
  auto nt =
      reinterpret_cast<PIMAGE_NT_HEADERS>((BYTE *)fileBase + dos->e_lfanew);
  auto section = IMAGE_FIRST_SECTION(nt);

  for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
    DWORD start = section->VirtualAddress;
    DWORD size = section->Misc.VirtualSize;
    if (rva >= start && rva < start + size) {
      return section->PointerToRawData + (rva - start);
    }
  }
  return 0;
}

std::string GetExportedFunctionNameByAddress(uint64_t addr) {
  HMODULE hMods[1024];
  DWORD cbNeeded;

  if (!EnumProcessModules(pi.hProcess, hMods, sizeof(hMods), &cbNeeded))
    return "";

  for (DWORD i = 0; i < cbNeeded / sizeof(HMODULE); ++i) {
    MODULEINFO modInfo;
    if (!GetModuleInformation(pi.hProcess, hMods[i], &modInfo, sizeof(modInfo)))
      continue;

    uint64_t base = reinterpret_cast<uint64_t>(modInfo.lpBaseOfDll);
    uint64_t end = base + modInfo.SizeOfImage;
    if (addr < base || addr >= end)
      continue;

    // Check if cache exists
    auto it = exportsCache_.find(base);
    if (it != exportsCache_.end()) {
      const auto &map = it->second.addrToName;
      auto found = map.find(addr);
      if (found != map.end())
        return found->second;
    }

    // Load the module from disk
    char path[MAX_PATH];
    if (!GetModuleFileNameExA(pi.hProcess, hMods[i], path, MAX_PATH))
      continue;

    HANDLE hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
      continue;

    HANDLE hMap =
        CreateFileMappingA(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMap) {
      CloseHandle(hFile);
      continue;
    }

    LPVOID baseMap = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!baseMap) {
      CloseHandle(hMap);
      CloseHandle(hFile);
      continue;
    }

    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(baseMap);
    auto nt =
        reinterpret_cast<PIMAGE_NT_HEADERS>((BYTE *)baseMap + dos->e_lfanew);

    DWORD exportRVA =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
            .VirtualAddress;
    if (!exportRVA) {
      UnmapViewOfFile(baseMap);
      CloseHandle(hMap);
      CloseHandle(hFile);
      continue;
    }

    auto exportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
        (BYTE *)baseMap + RvaToOffset(baseMap, exportRVA));
    DWORD *functions =
        (DWORD *)((BYTE *)baseMap +
                  RvaToOffset(baseMap, exportDir->AddressOfFunctions));
    DWORD *names = (DWORD *)((BYTE *)baseMap +
                             RvaToOffset(baseMap, exportDir->AddressOfNames));
    WORD *ordinals =
        (WORD *)((BYTE *)baseMap +
                 RvaToOffset(baseMap, exportDir->AddressOfNameOrdinals));

    ExportedFunctionInfo info;

    for (DWORD j = 0; j < exportDir->NumberOfFunctions; ++j) {
      uint64_t funcAddr = base + functions[j];
      std::string funcName;

      for (DWORD k = 0; k < exportDir->NumberOfNames; ++k) {
        if (ordinals[k] == j) {
          const char *name =
              (const char *)baseMap + RvaToOffset(baseMap, names[k]);
          funcName = name;
          break;
        }
      }

      info.addrToName[funcAddr] = funcName;
    }

    // Clean up
    UnmapViewOfFile(baseMap);
    CloseHandle(hMap);
    CloseHandle(hFile);

    exportsCache_[base] = std::move(info);

    auto found = exportsCache_[base].addrToName.find(addr);
    if (found != exportsCache_[base].addrToName.end())
      return found->second;

    return "";
  }

  return "";
}