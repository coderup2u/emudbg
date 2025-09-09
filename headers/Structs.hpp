uint64_t ntdllBase = 0;
bool is_first_time = 1;

typedef enum _NT_PRODUCT_TYPE {
  NtProductWinNt = 1,
  NtProductLanManNt,
  NtProductServer
} NT_PRODUCT_TYPE,
    *PNT_PRODUCT_TYPE;

typedef struct _KSYSTEM_TIME {
  ULONG LowPart;
  LONG High1Time;
  LONG High2Time;
} KSYSTEM_TIME, *PKSYSTEM_TIME;

typedef enum _ALTERNATIVE_ARCHITECTURE_TYPE {
  StandardDesign,
  NEC98x86,
  EndAlternatives
} ALTERNATIVE_ARCHITECTURE_TYPE;
#define PROCESSOR_FEATURE_MAX 64

typedef struct _KUSER_SHARED_DATA {
  ULONG TickCountLowDeprecated;
  ULONG TickCountMultiplier;
  KSYSTEM_TIME InterruptTime;
  KSYSTEM_TIME SystemTime;
  KSYSTEM_TIME TimeZoneBias;
  USHORT ImageNumberLow;
  USHORT ImageNumberHigh;
  WCHAR NtSystemRoot[260];
  ULONG MaxStackTraceDepth;
  ULONG CryptoExponent;
  ULONG TimeZoneId;
  ULONG LargePageMinimum;
  ULONG AitSamplingValue;
  ULONG AppCompatFlag;
  ULONGLONG RNGSeedVersion;
  ULONG GlobalValidationRunlevel;
  LONG TimeZoneBiasStamp;
  ULONG NtBuildNumber;
  NT_PRODUCT_TYPE NtProductType;
  BOOLEAN ProductTypeIsValid;
  BOOLEAN Reserved0[1];
  USHORT NativeProcessorArchitecture;
  ULONG NtMajorVersion;
  ULONG NtMinorVersion;
  BOOLEAN ProcessorFeatures[PROCESSOR_FEATURE_MAX];
  ULONG Reserved1;
  ULONG Reserved3;
  ULONG TimeSlip;
  ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;
  ULONG BootId;
  LARGE_INTEGER SystemExpirationDate;
  ULONG SuiteMask;
  BOOLEAN KdDebuggerEnabled;
  union {
    UCHAR MitigationPolicies;
    struct {
      UCHAR NXSupportPolicy : 2;
      UCHAR SEHValidationPolicy : 2;
      UCHAR CurDirDevicesSkippedForDlls : 2;
      UCHAR Reserved : 2;
    };
  };
  USHORT CyclesPerYield;
  ULONG ActiveConsoleId;
  ULONG DismountCount;
  ULONG ComPlusPackage;
  ULONG LastSystemRITEventTickCount;
  ULONG NumberOfPhysicalPages;
  BOOLEAN SafeBootMode;
  union {
    UCHAR VirtualizationFlags;
    struct {
      UCHAR ArchStartedInEl2 : 1;
      UCHAR QcSlIsSupported : 1;
    };
  };
  UCHAR Reserved12[2];
  union {
    ULONG SharedDataFlags;
    struct {
      ULONG DbgErrorPortPresent : 1;
      ULONG DbgElevationEnabled : 1;
      ULONG DbgVirtEnabled : 1;
      ULONG DbgInstallerDetectEnabled : 1;
      ULONG DbgLkgEnabled : 1;
      ULONG DbgDynProcessorEnabled : 1;
      ULONG DbgConsoleBrokerEnabled : 1;
      ULONG DbgSecureBootEnabled : 1;
      ULONG DbgMultiSessionSku : 1;
      ULONG DbgMultiUsersInSessionSku : 1;
      ULONG DbgStateSeparationEnabled : 1;
      ULONG SpareBits : 21;
    } DUMMYSTRUCTNAME2;
  } DUMMYUNIONNAME2;
  ULONG DataFlagsPad[1];
  ULONGLONG TestRetInstruction;
  LONGLONG QpcFrequency;
  ULONG SystemCall;
  ULONG Reserved2;
  ULONGLONG FullNumberOfPhysicalPages;
  ULONGLONG SystemCallPad[1];
  union {
    KSYSTEM_TIME TickCount;
    ULONG64 TickCountQuad;
    struct {
      ULONG ReservedTickCountOverlay[3];
      ULONG TickCountPad[1];
    } DUMMYSTRUCTNAME;
  } DUMMYUNIONNAME3;
  ULONG Cookie;
  ULONG CookiePad[1];
  LONGLONG ConsoleSessionForegroundProcessId;
  ULONGLONG TimeUpdateLock;
  ULONGLONG BaselineSystemTimeQpc;
  ULONGLONG BaselineInterruptTimeQpc;
  ULONGLONG QpcSystemTimeIncrement;
  ULONGLONG QpcInterruptTimeIncrement;
  UCHAR QpcSystemTimeIncrementShift;
  UCHAR QpcInterruptTimeIncrementShift;
  USHORT UnparkedProcessorCount;
  ULONG EnclaveFeatureMask[4];
  ULONG TelemetryCoverageRound;
  USHORT UserModeGlobalLogger[16];
  ULONG ImageFileExecutionOptions;
  ULONG LangGenerationCount;
  ULONGLONG Reserved4;
  ULONGLONG InterruptTimeBias;
  ULONGLONG QpcBias;
  ULONG ActiveProcessorCount;
  UCHAR ActiveGroupCount;
  UCHAR Reserved9;
  union {
    USHORT QpcData;
    struct {
      UCHAR QpcBypassEnabled;
      UCHAR QpcReserved;
    };
  };
  LARGE_INTEGER TimeZoneBiasEffectiveStart;
  LARGE_INTEGER TimeZoneBiasEffectiveEnd;
  XSTATE_CONFIGURATION XState;
  KSYSTEM_TIME FeatureConfigurationChangeStamp;
  ULONG Spare;
  ULONG64 UserPointerAuthMask;
  XSTATE_CONFIGURATION XStateArm64;
  ULONG Reserved10[210];
} KUSER_SHARED_DATA, *PKUSER_SHARED_DATA;

extern KUSER_SHARED_DATA g_kuser_shared_data;

struct OffsetName {
  size_t offset;
  const char *name;
};

#define FIELD_INFO(field) {offsetof(KUSER_SHARED_DATA, field), #field}

OffsetName kuser_offsets[] = {
    FIELD_INFO(TickCountLowDeprecated),
    FIELD_INFO(TickCountMultiplier),
    FIELD_INFO(InterruptTime),
    FIELD_INFO(SystemTime),
    FIELD_INFO(TimeZoneBias),
    FIELD_INFO(ImageNumberLow),
    FIELD_INFO(ImageNumberHigh),
    FIELD_INFO(NtSystemRoot),
    FIELD_INFO(MaxStackTraceDepth),
    FIELD_INFO(CryptoExponent),
    FIELD_INFO(TimeZoneId),
    FIELD_INFO(LargePageMinimum),
    FIELD_INFO(AitSamplingValue),
    FIELD_INFO(AppCompatFlag),
    FIELD_INFO(RNGSeedVersion),
    FIELD_INFO(GlobalValidationRunlevel),
    FIELD_INFO(TimeZoneBiasStamp),
    FIELD_INFO(NtBuildNumber),
    FIELD_INFO(NtProductType),
    FIELD_INFO(ProductTypeIsValid),
    FIELD_INFO(NativeProcessorArchitecture),
    FIELD_INFO(NtMajorVersion),
    FIELD_INFO(NtMinorVersion),
    FIELD_INFO(ProcessorFeatures),
    FIELD_INFO(Reserved1),
    FIELD_INFO(Reserved3),
    FIELD_INFO(TimeSlip),
    FIELD_INFO(AlternativeArchitecture),
    FIELD_INFO(BootId),
    FIELD_INFO(SystemExpirationDate),
    FIELD_INFO(SuiteMask),
    FIELD_INFO(KdDebuggerEnabled),
    FIELD_INFO(MitigationPolicies),
    FIELD_INFO(CyclesPerYield),
    FIELD_INFO(ActiveConsoleId),
    FIELD_INFO(DismountCount),
    FIELD_INFO(ComPlusPackage),
    FIELD_INFO(LastSystemRITEventTickCount),
    FIELD_INFO(NumberOfPhysicalPages),
    FIELD_INFO(SafeBootMode),
    FIELD_INFO(VirtualizationFlags),
    FIELD_INFO(Reserved12),
    FIELD_INFO(SharedDataFlags),
    FIELD_INFO(DataFlagsPad),
    FIELD_INFO(TestRetInstruction),
    FIELD_INFO(QpcFrequency),
    FIELD_INFO(SystemCall),
    FIELD_INFO(Reserved2),
    FIELD_INFO(FullNumberOfPhysicalPages),
    FIELD_INFO(SystemCallPad),
    FIELD_INFO(TickCount),
    FIELD_INFO(Cookie),
    FIELD_INFO(CookiePad),
    FIELD_INFO(ConsoleSessionForegroundProcessId),
    FIELD_INFO(TimeUpdateLock),
    FIELD_INFO(BaselineSystemTimeQpc),
    FIELD_INFO(BaselineInterruptTimeQpc),
    FIELD_INFO(QpcSystemTimeIncrement),
    FIELD_INFO(QpcInterruptTimeIncrement),
    FIELD_INFO(QpcSystemTimeIncrementShift),
    FIELD_INFO(QpcInterruptTimeIncrementShift),
    FIELD_INFO(UnparkedProcessorCount),
    FIELD_INFO(EnclaveFeatureMask),
    FIELD_INFO(TelemetryCoverageRound),
    FIELD_INFO(UserModeGlobalLogger),
    FIELD_INFO(ImageFileExecutionOptions),
    FIELD_INFO(LangGenerationCount),
    FIELD_INFO(Reserved4),
    FIELD_INFO(InterruptTimeBias),
    FIELD_INFO(QpcBias),
    FIELD_INFO(ActiveProcessorCount),
    FIELD_INFO(ActiveGroupCount),
    FIELD_INFO(Reserved9),
    FIELD_INFO(QpcData),
    FIELD_INFO(TimeZoneBiasEffectiveStart),
    FIELD_INFO(TimeZoneBiasEffectiveEnd),
    FIELD_INFO(XState),
    FIELD_INFO(FeatureConfigurationChangeStamp),
    FIELD_INFO(Spare),
    FIELD_INFO(UserPointerAuthMask),
    FIELD_INFO(XStateArm64),
    FIELD_INFO(Reserved10),
};

std::string get_kuser_field_name(uint64_t offset) {
  std::string result = "Unknown";
  for (size_t i = 0; i < sizeof(kuser_offsets) / sizeof(kuser_offsets[0]);
       ++i) {
    if (offset == kuser_offsets[i].offset) {
      return kuser_offsets[i].name;
    } else if (offset > kuser_offsets[i].offset) {
      std::stringstream ss;
      ss << kuser_offsets[i].name << " + 0x" << std::hex
         << (offset - kuser_offsets[i].offset);
      result = ss.str();
    }
  }
  return result;
}

typedef struct _ACTIVATION_CONTEXT *PACTIVATION_CONTEXT;
typedef struct _ACTIVATION_CONTEXT_DATA *PACTIVATION_CONTEXT_DATA;
typedef struct _ACTIVATION_CONTEXT_DATA {
  ULONG Magic;
  ULONG HeaderSize;
  ULONG FormatVersion;
  ULONG TotalSize;
  ULONG DefaultTocOffset;  // to ACTIVATION_CONTEXT_DATA_TOC_HEADER
  ULONG ExtendedTocOffset; // to ACTIVATION_CONTEXT_DATA_EXTENDED_TOC_HEADER
  ULONG
  AssemblyRosterOffset; // to ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_HEADER
  ULONG Flags;          // ACTIVATION_CONTEXT_FLAG_*
} ACTIVATION_CONTEXT_DATA, *PACTIVATION_CONTEXT_DATA;
typedef VOID(NTAPI *PACTIVATION_CONTEXT_NOTIFY_ROUTINE)(
    _In_ ULONG NotificationType, // ACTIVATION_CONTEXT_NOTIFICATION_*
    _In_ PACTIVATION_CONTEXT ActivationContext,
    _In_ PACTIVATION_CONTEXT_DATA ActivationContextData,
    _In_opt_ PVOID NotificationContext, _In_opt_ PVOID NotificationData,
    _Inout_ PBOOLEAN DisableThisNotification);
typedef struct _ASSEMBLY_STORAGE_MAP_ENTRY {
  ULONG Flags;
  UNICODE_STRING DosPath;
  HANDLE Handle;
} ASSEMBLY_STORAGE_MAP_ENTRY, *PASSEMBLY_STORAGE_MAP_ENTRY;
typedef struct _ASSEMBLY_STORAGE_MAP {
  ULONG Flags;
  ULONG AssemblyCount;
  PASSEMBLY_STORAGE_MAP_ENTRY *AssemblyArray;
} ASSEMBLY_STORAGE_MAP, *PASSEMBLY_STORAGE_MAP;
typedef struct _ACTIVATION_CONTEXT {
  LONG RefCount;
  ULONG Flags;
  PACTIVATION_CONTEXT_DATA ActivationContextData;
  PACTIVATION_CONTEXT_NOTIFY_ROUTINE NotificationRoutine;
  PVOID NotificationContext;
  ULONG SentNotifications[8];
  ULONG DisabledNotifications[8];
  ASSEMBLY_STORAGE_MAP StorageMap;
  PASSEMBLY_STORAGE_MAP_ENTRY InlineStorageMapEntries[32];
} ACTIVATION_CONTEXT, *PACTIVATION_CONTEXT;
typedef struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME {
  struct _RTL_ACTIVATION_CONTEXT_STACK_FRAME *Previous;
  PACTIVATION_CONTEXT ActivationContext;
  ULONG Flags; // RTL_ACTIVATION_CONTEXT_STACK_FRAME_FLAG_*
} RTL_ACTIVATION_CONTEXT_STACK_FRAME, *PRTL_ACTIVATION_CONTEXT_STACK_FRAME;
typedef struct _ACTIVATION_CONTEXT_STACK {
  PRTL_ACTIVATION_CONTEXT_STACK_FRAME ActiveFrame;
  LIST_ENTRY FrameListCache;
  ULONG Flags; // ACTIVATION_CONTEXT_STACK_FLAG_*
  ULONG NextCookieSequenceNumber;
  ULONG StackId;
} ACTIVATION_CONTEXT_STACK, *PACTIVATION_CONTEXT_STACK;
#define GDI_BATCH_BUFFER_SIZE 310
typedef struct _GDI_TEB_BATCH {
  ULONG Offset;
  ULONG_PTR HDC;
  ULONG Buffer[GDI_BATCH_BUFFER_SIZE];
} GDI_TEB_BATCH, *PGDI_TEB_BATCH;
#define WIN32_CLIENT_INFO_LENGTH 62
#define STATIC_UNICODE_BUFFER_LENGTH 261
typedef struct _TEB_ACTIVE_FRAME_CONTEXT {
  ULONG Flags;
  PCSTR FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, *PTEB64_ACTIVE_FRAME_CONTEXT;
typedef struct _TEB_ACTIVE_FRAME {
  ULONG Flags;
  struct _TEB_ACTIVE_FRAME *Previous;
  PTEB64_ACTIVE_FRAME_CONTEXT Context;
} TEB_ACTIVE_FRAME, *PTEB64_ACTIVE_FRAME;
typedef struct tagSOleTlsData {
  PVOID ThreadBase;
  PVOID SmAllocator;
  DWORD dwApartmentID; // Per thread "process ID"
  DWORD dwFlags;       // see OLETLSFLAGS above

  // counters
  DWORD cComInits; // number of per-thread inits
  DWORD cOleInits; // number of per-thread OLE inits
#if DBG == 1
  LONG cTraceNestingLevel; // call nesting level for OLETRACE
#endif

  // Object RPC data
  UUID LogicalThreadId;   // current logical thread id
  DWORD dwTIDCaller;      // TID of current calling app
  ULONG fault;            // fault value
  LONG cORPCNestingLevel; // call nesting level (DBG only)
#ifdef DCOM
  CChannelCallInfo *pCallInfo; // channel call info
  DWORD cDebugData;            // count of bytes of debug data in call
  void *pOXIDEntry;            // ptr to OXIDEntry for this thread.
  CObjServer *pObjServer;      // Activation Server Object.
  CRemoteUnknown *pRemoteUnk;  // CRemUnknown for this thread.
  CAptCallCtrl *pCallCtrl;     // new call control for RPC
  CSrvCallState *pTopSCS;      // top server-side callctrl state
  IMessageFilter *pMsgFilter;  // temp storage for App MsgFilter
  ULONG cPreRegOidsAvail;      // count of server-side OIDs avail
  unsigned hyper *pPreRegOids; // ptr to array of pre-reg OIDs
  IUnknown *pCallContext;      // call context object
  DWORD dwAuthnLevel;          // security level of current call
#else
  void *pChanCtrl; // channel control
  void *pService;  // per-thread service object
  void *pServiceList;
  void *pCallCont;    // call control
  void *pDdeCallCont; // dde call control
  void *pCALLINFO;    // callinfo
  DWORD dwEndPoint;   // endpoint id
#ifdef _CHICAGO_
  HWND hwndOleRpcNotify;
#endif
#endif // DCOM

  // DDE data
  HWND hwndDdeServer; // Per thread Common DDE server
  HWND hwndDdeClient; // Per thread Common DDE client

  // upper layer data
  HWND hwndClip;       // Clipboard window
  IUnknown *punkState; // Per thread "state" object
#ifdef WX86OLE
  IUnknown *punkStateWx86; // Per thread "state" object for Wx86
#endif
  void *pDragCursors; // Per thread drag cursor table.

#ifdef _CHICAGO_
  LPVOID pWcstokContext; // Scan context for wcstok
#endif

  IUnknown *punkError; // Per thread error object.
  ULONG cbErrorData;   // Maximum size of error data.
} SOleTlsData, *PSOleTlsData;
typedef struct _TEB64 {
  NT_TIB NtTib;
  PVOID EnvironmentPointer;
  CLIENT_ID ClientId;
  PVOID ActiveRpcHandle;
  PVOID ThreadLocalStoragePointer;
  PPEB ProcessEnvironmentBlock;
  ULONG LastErrorValue;
  ULONG CountOfOwnedCriticalSections;
  PVOID CsrClientThread;
  PVOID Win32ThreadInfo;
  ULONG User32Reserved[26];
  ULONG UserReserved[5];
  PVOID WOW32Reserved;
  LCID CurrentLocale;
  ULONG FpSoftwareStatusRegister;
  PVOID ReservedForDebuggerInstrumentation[16];
#ifdef _WIN64
  PVOID SystemReserved1[25];
  PVOID HeapFlsData;
  ULONG_PTR RngState[4];
#else
  PVOID SystemReserved1[26];
#endif
  CHAR PlaceholderCompatibilityMode;
  BOOLEAN PlaceholderHydrationAlwaysExplicit;
  CHAR PlaceholderReserved[10];
  ULONG ProxiedProcessId;
  ACTIVATION_CONTEXT_STACK ActivationStack;
  UCHAR WorkingOnBehalfTicket[8];
  NTSTATUS ExceptionCode;
  PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;
  ULONG_PTR InstrumentationCallbackSp;
  ULONG_PTR InstrumentationCallbackPreviousPc;
  ULONG_PTR InstrumentationCallbackPreviousSp;
#ifdef _WIN64
  ULONG TxFsContext;
#endif
  BOOLEAN InstrumentationCallbackDisabled;
#ifdef _WIN64
  BOOLEAN UnalignedLoadStoreExceptions;
#endif
#ifndef _WIN64
  UCHAR SpareBytes[23];
  ULONG TxFsContext;
#endif
  GDI_TEB_BATCH GdiTebBatch;
  CLIENT_ID RealClientId;
  HANDLE GdiCachedProcessHandle;
  ULONG GdiClientPID;
  ULONG GdiClientTID;
  PVOID GdiThreadLocalInfo;
  ULONG_PTR Win32ClientInfo[WIN32_CLIENT_INFO_LENGTH];
  PVOID glDispatchTable[233];
  ULONG_PTR glReserved1[29];
  PVOID glReserved2;
  PVOID glSectionInfo;
  PVOID glSection;
  PVOID glTable;
  PVOID glCurrentRC;
  PVOID glContext;
  NTSTATUS LastStatusValue;
  UNICODE_STRING StaticUnicodeString;
  WCHAR StaticUnicodeBuffer[STATIC_UNICODE_BUFFER_LENGTH];
  PVOID DeallocationStack;
  PVOID TlsSlots[TLS_MINIMUM_AVAILABLE];
  LIST_ENTRY TlsLinks;
  PVOID Vdm;
  PVOID ReservedForNtRpc;
  PVOID DbgSsReserved[2];
  ULONG HardErrorMode;
#ifdef _WIN64
  PVOID Instrumentation[11];
#else
  PVOID Instrumentation[9];
#endif
  GUID ActivityId;
  PVOID SubProcessTag;
  PVOID PerflibData;
  PVOID EtwTraceData;
  HANDLE WinSockData;
  ULONG GdiBatchCount;
  union {
    PROCESSOR_NUMBER CurrentIdealProcessor;
    ULONG IdealProcessorValue;
    struct {
      UCHAR ReservedPad0;
      UCHAR ReservedPad1;
      UCHAR ReservedPad2;
      UCHAR IdealProcessor;
    };
  };
  ULONG GuaranteedStackBytes;
  PVOID ReservedForPerf;
  PSOleTlsData ReservedForOle;
  ULONG WaitingOnLoaderLock;
  PVOID SavedPriorityState;
  ULONG_PTR ReservedForCodeCoverage;
  PVOID ThreadPoolData;
  PVOID *TlsExpansionSlots;
#ifdef _WIN64
  PVOID ChpeV2CpuAreaInfo;
  PVOID Unused;
#endif
  ULONG MuiGeneration;
  ULONG IsImpersonating;
  PVOID NlsCache;
  PVOID pShimData;
  ULONG HeapData;
  HANDLE CurrentTransactionHandle;
  PTEB64_ACTIVE_FRAME ActiveFrame;
  PVOID FlsData;
  PVOID PreferredLanguages;
  PVOID UserPrefLanguages;
  PVOID MergedPrefLanguages;
  ULONG MuiImpersonation;
  union {
    USHORT CrossTebFlags;
    USHORT SpareCrossTebBits : 16;
  };
  union {
    USHORT SameTebFlags;
    struct {
      USHORT SafeThunkCall : 1;
      USHORT InDebugPrint : 1; // Indicates if the thread is currently in a
      // debug print routine.
      USHORT HasFiberData : 1; // Indicates if the thread has local fiber-local
      // storage (FLS).
      USHORT SkipThreadAttach : 1; // Indicates if the thread should suppress
      // DLL_THREAD_ATTACH notifications.
      USHORT WerInShipAssertCode : 1;
      USHORT RanProcessInit : 1; // Indicates if the thread has run process
      // initialization code.
      USHORT ClonedThread : 1; // Indicates if the thread is a clone of a
      // different thread.
      USHORT SuppressDebugMsg : 1; // Indicates if the thread should suppress
      // LOAD_DLL_DEBUG_INFO notifications.
      USHORT DisableUserStackWalk : 1;
      USHORT RtlExceptionAttached : 1;
      USHORT
      InitialThread : 1; // Indicates if the thread is the initial thread
      // of the process.
      USHORT SessionAware : 1;
      USHORT LoadOwner : 1; // Indicates if the thread is the owner of the
      // process loader lock.
      USHORT LoaderWorker : 1;
      USHORT SkipLoaderInit : 1;
      USHORT SkipFileAPIBrokering : 1;
    };
  };
  PVOID TxnScopeEnterCallback;
  PVOID TxnScopeExitCallback;
  PVOID TxnScopeContext;
  ULONG LockCount;
  LONG WowTebOffset;
  PVOID ResourceRetValue;
  PVOID ReservedForWdf;
  ULONGLONG ReservedForCrt;
  GUID EffectiveContainerId;
  ULONGLONG LastSleepCounter; // since Win11
  ULONG SpinCallCount;
  ULONGLONG ExtendedFeatureDisableMask;
  PVOID SchedulerSharedDataSlot; // since 24H2
  PVOID HeapWalkContext;
  GROUP_AFFINITY PrimaryGroupAffinity;
  ULONG Rcu[2];
} _TEB64, *PTEB64;
#define FIELD_INFO_TEB64(field) {offsetof(_TEB64, field), #field}

struct Teb64FieldMapper {
  std::vector<std::pair<size_t, std::string_view>> members_ = {
      FIELD_INFO_TEB64(NtTib),
      FIELD_INFO_TEB64(EnvironmentPointer),
      FIELD_INFO_TEB64(ClientId),
      FIELD_INFO_TEB64(ActiveRpcHandle),
      FIELD_INFO_TEB64(ThreadLocalStoragePointer),
      FIELD_INFO_TEB64(ProcessEnvironmentBlock),
      FIELD_INFO_TEB64(LastErrorValue),
      FIELD_INFO_TEB64(CountOfOwnedCriticalSections),
      FIELD_INFO_TEB64(CsrClientThread),
      FIELD_INFO_TEB64(Win32ThreadInfo),
      FIELD_INFO_TEB64(User32Reserved),
      FIELD_INFO_TEB64(UserReserved),
      FIELD_INFO_TEB64(WOW32Reserved),
      FIELD_INFO_TEB64(CurrentLocale),
      FIELD_INFO_TEB64(FpSoftwareStatusRegister),
      FIELD_INFO_TEB64(ReservedForDebuggerInstrumentation),
      FIELD_INFO_TEB64(SystemReserved1),
      FIELD_INFO_TEB64(HeapFlsData),
      FIELD_INFO_TEB64(RngState),
      FIELD_INFO_TEB64(PlaceholderCompatibilityMode),
      FIELD_INFO_TEB64(PlaceholderHydrationAlwaysExplicit),
      FIELD_INFO_TEB64(PlaceholderReserved),
      FIELD_INFO_TEB64(ProxiedProcessId),
      FIELD_INFO_TEB64(ActivationStack),
      FIELD_INFO_TEB64(WorkingOnBehalfTicket),
      FIELD_INFO_TEB64(ExceptionCode),
      FIELD_INFO_TEB64(ActivationContextStackPointer),
      FIELD_INFO_TEB64(InstrumentationCallbackSp),
      FIELD_INFO_TEB64(InstrumentationCallbackPreviousPc),
      FIELD_INFO_TEB64(InstrumentationCallbackPreviousSp),
      FIELD_INFO_TEB64(TxFsContext),
      FIELD_INFO_TEB64(InstrumentationCallbackDisabled),
      FIELD_INFO_TEB64(UnalignedLoadStoreExceptions),
      FIELD_INFO_TEB64(GdiTebBatch),
      FIELD_INFO_TEB64(RealClientId),
      FIELD_INFO_TEB64(GdiCachedProcessHandle),
      FIELD_INFO_TEB64(GdiClientPID),
      FIELD_INFO_TEB64(GdiClientTID),
      FIELD_INFO_TEB64(GdiThreadLocalInfo),
      FIELD_INFO_TEB64(Win32ClientInfo),
      FIELD_INFO_TEB64(glDispatchTable),
      FIELD_INFO_TEB64(glReserved1),
      FIELD_INFO_TEB64(glReserved2),
      FIELD_INFO_TEB64(glSectionInfo),
      FIELD_INFO_TEB64(glSection),
      FIELD_INFO_TEB64(glTable),
      FIELD_INFO_TEB64(glCurrentRC),
      FIELD_INFO_TEB64(glContext),
      FIELD_INFO_TEB64(LastStatusValue),
      FIELD_INFO_TEB64(StaticUnicodeString),
      FIELD_INFO_TEB64(StaticUnicodeBuffer),
      FIELD_INFO_TEB64(DeallocationStack),
      FIELD_INFO_TEB64(TlsSlots),
      FIELD_INFO_TEB64(TlsLinks),
      FIELD_INFO_TEB64(Vdm),
      FIELD_INFO_TEB64(ReservedForNtRpc),
      FIELD_INFO_TEB64(DbgSsReserved),
      FIELD_INFO_TEB64(HardErrorMode),
      FIELD_INFO_TEB64(Instrumentation),
      FIELD_INFO_TEB64(ActivityId),
      FIELD_INFO_TEB64(SubProcessTag),
      FIELD_INFO_TEB64(PerflibData),
      FIELD_INFO_TEB64(EtwTraceData),
      FIELD_INFO_TEB64(WinSockData),
      FIELD_INFO_TEB64(GdiBatchCount),
      FIELD_INFO_TEB64(CurrentIdealProcessor),
      FIELD_INFO_TEB64(GuaranteedStackBytes),
      FIELD_INFO_TEB64(ReservedForPerf),
      FIELD_INFO_TEB64(ReservedForOle),
      FIELD_INFO_TEB64(WaitingOnLoaderLock),
      FIELD_INFO_TEB64(SavedPriorityState),
      FIELD_INFO_TEB64(ReservedForCodeCoverage),
      FIELD_INFO_TEB64(ThreadPoolData),
      FIELD_INFO_TEB64(TlsExpansionSlots),
      FIELD_INFO_TEB64(ChpeV2CpuAreaInfo),
      FIELD_INFO_TEB64(Unused),
      FIELD_INFO_TEB64(MuiGeneration),
      FIELD_INFO_TEB64(IsImpersonating),
      FIELD_INFO_TEB64(NlsCache),
      FIELD_INFO_TEB64(pShimData),
      FIELD_INFO_TEB64(HeapData),
      FIELD_INFO_TEB64(CurrentTransactionHandle),
      FIELD_INFO_TEB64(ActiveFrame),
      FIELD_INFO_TEB64(FlsData),
      FIELD_INFO_TEB64(PreferredLanguages),
      FIELD_INFO_TEB64(UserPrefLanguages),
      FIELD_INFO_TEB64(MergedPrefLanguages),
      FIELD_INFO_TEB64(MuiImpersonation),
      FIELD_INFO_TEB64(CrossTebFlags),
      FIELD_INFO_TEB64(SameTebFlags),
      FIELD_INFO_TEB64(TxnScopeEnterCallback),
      FIELD_INFO_TEB64(TxnScopeExitCallback),
      FIELD_INFO_TEB64(TxnScopeContext),
      FIELD_INFO_TEB64(LockCount),
      FIELD_INFO_TEB64(WowTebOffset),
      FIELD_INFO_TEB64(ResourceRetValue),
      FIELD_INFO_TEB64(ReservedForWdf),
      FIELD_INFO_TEB64(ReservedForCrt),
      FIELD_INFO_TEB64(EffectiveContainerId),
      FIELD_INFO_TEB64(LastSleepCounter),
      FIELD_INFO_TEB64(SpinCallCount),
      FIELD_INFO_TEB64(ExtendedFeatureDisableMask),
      FIELD_INFO_TEB64(SchedulerSharedDataSlot),
      FIELD_INFO_TEB64(HeapWalkContext),
      FIELD_INFO_TEB64(PrimaryGroupAffinity),
      FIELD_INFO_TEB64(Rcu),
  };

  std::string get_member_name(size_t offset) const {
    size_t last_offset{};
    std::string_view last_member{};

    for (const auto &member : members_) {
      if (offset == member.first)
        return std::string(member.second);

      if (offset < member.first) {
        size_t diff = offset - last_offset;
        std::stringstream ss;
        ss << last_member << " + 0x" << std::hex << diff;
        return ss.str();
      }

      last_offset = member.first;
      last_member = member.second;
    }

    if (!members_.empty()) {
      size_t diff = offset - members_.back().first;
      std::stringstream ss;
      ss << members_.back().second << " + 0x" << std::hex << diff;
      return ss.str();
    }

    return "<N/A>";
  }
};

// LDR
#define FIELD_INFO_LDR(field) {offsetof(_PEB_LDR_DATA, field), #field}

struct PebLdrFieldMapper {
  std::vector<std::pair<size_t, std::string_view>> members_ = {
      FIELD_INFO_LDR(Reserved1),
      FIELD_INFO_LDR(Reserved2),
      FIELD_INFO_LDR(InMemoryOrderModuleList),
  };

  std::string get_member_name(size_t offset) const {
    size_t last_offset{};
    std::string_view last_member{};

    for (const auto &member : members_) {
      if (offset == member.first)
        return std::string(member.second);

      if (offset < member.first) {
        size_t diff = offset - last_offset;
        std::stringstream ss;
        ss << last_member << " + 0x" << std::hex << diff;
        return ss.str();
      }

      last_offset = member.first;
      last_member = member.second;
    }

    if (!members_.empty()) {
      size_t diff = offset - members_.back().first;
      std::stringstream ss;
      ss << members_.back().second << " + 0x" << std::hex << diff;
      return ss.str();
    }

    return "<N/A>";
  }
};

#define FIELD_INFO_PEB(field) {offsetof(_PEB, field), #field}

struct PebFieldMapper {
  std::vector<std::pair<size_t, std::string_view>> members_ = {
      FIELD_INFO_PEB(Reserved1),
      FIELD_INFO_PEB(BeingDebugged),
      FIELD_INFO_PEB(Reserved2),
      FIELD_INFO_PEB(Reserved3),
      FIELD_INFO_PEB(Ldr),
      FIELD_INFO_PEB(ProcessParameters),
      FIELD_INFO_PEB(Reserved4),
      FIELD_INFO_PEB(AtlThunkSListPtr),
      FIELD_INFO_PEB(Reserved5),
      FIELD_INFO_PEB(Reserved6),
      FIELD_INFO_PEB(Reserved7),
      FIELD_INFO_PEB(Reserved8),
      FIELD_INFO_PEB(AtlThunkSListPtr32),
      FIELD_INFO_PEB(Reserved9),
      FIELD_INFO_PEB(Reserved10),
      FIELD_INFO_PEB(PostProcessInitRoutine),
      FIELD_INFO_PEB(Reserved11),
      FIELD_INFO_PEB(Reserved12),
      FIELD_INFO_PEB(SessionId),
  };

  std::string get_member_name(size_t offset) const {
    size_t last_offset{};
    std::string_view last_member{};

    for (const auto &member : members_) {
      if (offset == member.first)
        return std::string(member.second);

      if (offset < member.first) {
        size_t diff = offset - last_offset;
        std::stringstream ss;
        ss << last_member << " + 0x" << std::hex << diff;
        return ss.str();
      }

      last_offset = member.first;
      last_member = member.second;
    }

    if (!members_.empty()) {
      size_t diff = offset - members_.back().first;
      std::stringstream ss;
      ss << members_.back().second << " + 0x" << std::hex << diff;
      return ss.str();
    }

    return "<N/A>";
  }
};
