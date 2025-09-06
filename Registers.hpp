union GPR {
  uint64_t q;
  uint32_t d;
  uint16_t w;
  struct {
    uint8_t l, h;
  };
};

union YMM {
  struct {
    uint8_t xmm[16];
    uint8_t ymmh[16];
  };
  uint8_t full[32];
};

struct Flags {
  uint64_t CF : 1; // bit 0
  uint64_t always1 : 1;
  uint64_t PF : 1; // bit 2
  uint64_t reserved3 : 1;
  uint64_t AF : 1; // bit 4
  uint64_t reserved5 : 1;
  uint64_t ZF : 1;   // bit 6
  uint64_t SF : 1;   // bit 7
  uint64_t TF : 1;   // bit 8
  uint64_t IF : 1;   // bit 9
  uint64_t DF : 1;   // bit 10
  uint64_t OF : 1;   // bit 11
  uint64_t IOPL : 2; // bits 12-13
  uint64_t NT : 1;   // bit 14
  uint64_t reserved15 : 1;
  uint64_t RF : 1;  // bit 16
  uint64_t VM : 1;  // bit 17
  uint64_t AC : 1;  // bit 18
  uint64_t VIF : 1; // bit 19
  uint64_t VIP : 1; // bit 20
  uint64_t ID : 1;  // bit 21
  uint64_t reserved22 : 42;
};

union RFlags {
  uint64_t value;
  Flags flags;
};

struct RegState {
  GPR rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp;
  GPR r8, r9, r10, r11, r12, r13, r14, r15;
  uint64_t rip;
  RFlags rflags;
  YMM ymm[16];
  uint64_t gs_base;
  uint64_t fs_base;
  uint64_t peb_address;
  uint64_t peb_ldr;
};

#pragma pack(push, 1)

#ifdef _WIN64
using GDTRStruct = struct {
  uint16_t limit;
  uint64_t base;
};
#else
using GDTRStruct = struct {
  uint16_t limit;
  uint32_t base;
};
#endif

#pragma pack(pop)

GDTRStruct gdtr = {};

extern "C" void read_mxcsr_asm(uint32_t *dest);
extern "C" void fnstcw_asm(void *dest);
extern "C" uint64_t __cdecl xgetbv_asm(uint32_t ecx);
extern "C" uint64_t rdtsc_asm();
extern "C" void ReadGDTR(GDTRStruct *gdtr);

bool compareGPR(const GPR &a, const GPR &b) { return a.q == b.q; }
bool compareRegState(const RegState &a, const RegState &b) {
  const GPR *gprs_a[] = {&a.rbx, &a.rcx, &a.rdx, &a.rsi, &a.rdi,
                         &a.rbp, &a.r8,  &a.r9,  &a.r10, &a.r11,
                         &a.r12, &a.r13, &a.r14, &a.r15};
  const GPR *gprs_b[] = {&b.rbx, &b.rcx, &b.rdx, &b.rsi, &b.rdi,
                         &b.rbp, &b.r8,  &b.r9,  &b.r10, &b.r11,
                         &b.r12, &b.r13, &b.r14, &b.r15};

  for (int i = 0; i < 14; ++i) {
    if (!compareGPR(*gprs_a[i], *gprs_b[i]))
      return false;
  }

  return true;
}