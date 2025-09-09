#define XSTATE_AVX (XSTATE_GSSE)
#define XSTATE_MASK_AVX (XSTATE_MASK_GSSE)

typedef DWORD64(WINAPI *PGETENABLEDXSTATEFEATURES)();
PGETENABLEDXSTATEFEATURES pfnGetEnabledXStateFeatures = NULL;

typedef BOOL(WINAPI *PINITIALIZECONTEXT)(PVOID Buffer, DWORD ContextFlags,
                                         PCONTEXT *Context,
                                         PDWORD ContextLength);
PINITIALIZECONTEXT pfnInitializeContext = NULL;

typedef BOOL(WINAPI *PGETXSTATEFEATURESMASK)(PCONTEXT Context,
                                             PDWORD64 FeatureMask);
PGETXSTATEFEATURESMASK pfnGetXStateFeaturesMask = NULL;

typedef PVOID(WINAPI *LOCATEXSTATEFEATURE)(PCONTEXT Context, DWORD FeatureId,
                                           PDWORD Length);
LOCATEXSTATEFEATURE pfnLocateXStateFeature = NULL;

typedef BOOL(WINAPI *SETXSTATEFEATURESMASK)(PCONTEXT Context,
                                            DWORD64 FeatureMask);
SETXSTATEFEATURESMASK pfnSetXStateFeaturesMask = NULL;