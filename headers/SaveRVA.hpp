std::pair<uint64_t, uint64_t> ntdll_rang;
std::string filename = "rva_list.txt";

enum class RVAType {
  CPUID,
  KUSER_SHARED_DATA,
  SYSCALL,
  NTDLL,
  XGETBV,
  RCPSS,
  CMPXCHG,
  UNKNOWN
};

std::string typeToString(RVAType type) {
  switch (type) {
  case RVAType::CPUID:
    return "CPUID";
  case RVAType::KUSER_SHARED_DATA:
    return "KUSER_SHARED_DATA";
  case RVAType::SYSCALL:
    return "SYSCALL";
  case RVAType::NTDLL:
    return "NTDLL";
  case RVAType::XGETBV:
    return "XGETBV";
  case RVAType::RCPSS:
    return "RCPSS";
  case RVAType::CMPXCHG:
    return "CMPXCHG";
  default:
    return "UNKNOWN";
  }
}

RVAType stringToType(const std::string &s) {
  if (s == "CPUID")
    return RVAType::CPUID;
  if (s == "KUSER_SHARED_DATA")
    return RVAType::KUSER_SHARED_DATA;
  if (s == "SYSCALL")
    return RVAType::SYSCALL;
  if (s == "NTDLL")
    return RVAType::NTDLL;
  if (s == "XGETBV")
    return RVAType::XGETBV;
  if (s == "RCPSS")
    return RVAType::RCPSS;
  if (s == "CMPXCHG")
    return RVAType::CMPXCHG;
  return RVAType::UNKNOWN;
}

struct RVAEntry {
  uint64_t rva;
  uint64_t size;
  RVAType type;

  void save(std::ofstream &out) const {
    out << std::hex << rva << " " << size << " " << typeToString(type) << "\n";
  }

  static RVAEntry load(std::ifstream &in) {
    RVAEntry entry;
    std::string typeStr;
    in >> std::hex >> entry.rva >> entry.size >> typeStr;
    entry.type = stringToType(typeStr);
    return entry;
  }
};

bool addRVA(std::vector<RVAEntry> &entries, uint64_t rva, uint64_t size,
            RVAType type, const std::string &filename) {
  for (const auto &e : entries) {
    if (e.rva == rva) {
      return false;
    }
  }

  RVAEntry newEntry{rva, size, type};
  entries.push_back(newEntry);

  std::ofstream out(filename, std::ios::app);
  if (out.is_open()) {
    newEntry.save(out);
  }

  return true;
}

std::vector<RVAEntry> entries;
