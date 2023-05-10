// (c) FFRI Security, Inc., 2023 / Author: FFRI Security, Inc.
#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>

#include "HelperMacros.h"

#define DEFINE_FOR_32_AND_64(T)\
	PP_CONCAT(T, _T)(DWORD, 32);\
	PP_CONCAT(T, _T)(DWORD64, 64);\
	PP_DEFINE_POINTER(PP_CONCAT(T, 32));\
	PP_DEFINE_POINTER(PP_CONCAT(T, 64))

#define ANSI_STRING_T(T, BITS)\
	typedef struct {\
		union {\
			struct {\
				USHORT Length;\
				USHORT MaximumLength;\
			};\
			T dummy;\
		};\
		T Buffer;\
	} PP_CONCAT(ANSI_STRING, BITS)

DEFINE_FOR_32_AND_64(ANSI_STRING);

#define UNICODE_STRING_T(T, BITS)\
	typedef struct {\
		union {\
			struct {\
				WORD Length;\
				WORD MaximumLength;\
			};\
			T dummy;\
		};\
		T Buffer;\
	} PP_CONCAT(UNICODE_STRING, BITS)

DEFINE_FOR_32_AND_64(UNICODE_STRING);

#define PEB_LDR_DATA_T(T, BITS)\
	typedef struct {\
		ULONG Length;\
		BOOLEAN Initialized;\
		T SsHandle;\
		PP_CONCAT(LIST_ENTRY, BITS) InLoadOrderModuleList;\
		PP_CONCAT(LIST_ENTRY, BITS) InMemoryOrderModuleList;\
		PP_CONCAT(LIST_ENTRY, BITS) InInitializationOrderModuleList;\
	} PP_CONCAT(PEB_LDR_DATA, BITS)

DEFINE_FOR_32_AND_64(PEB_LDR_DATA);

#define LDR_DATA_TABLE_ENTRY_T(T, BITS)\
    typedef struct {\
		PP_CONCAT(LIST_ENTRY, BITS) InLoadOrderLinks;\
		PP_CONCAT(LIST_ENTRY, BITS) InMemoryOrderLinks;\
		PP_CONCAT(LIST_ENTRY, BITS) InInitializationOrderLinks;\
		T DllBase;\
		T EntryPoint;\
		ULONG SizeOfImage;\
		PP_CONCAT(UNICODE_STRING, BITS) FullDllName;\
		PP_CONCAT(UNICODE_STRING, BITS) BaseDllName;\
	} PP_CONCAT(LDR_DATA_TABLE_ENTRY, BITS)

DEFINE_FOR_32_AND_64(LDR_DATA_TABLE_ENTRY);

#define PEB_T(T, NGF, A, BITS)\
    typedef struct {\
		union {\
			struct {\
				BYTE InheritedAddressSpace;\
				BYTE ReadImageFileExecOptions;\
				BYTE BeingDebugged;\
				BYTE BitField;\
			};\
			T dummy01;\
		};\
		T Mutant;\
		T ImageBaseAddress;\
		T Ldr;\
		T ProcessParameters;\
		T SubSystemData;\
		T ProcessHeap;\
		T FastPebLock;\
		T AtlThunkSListPtr;\
		T IFEOKey;\
		T CrossProcessFlags;\
		T UserSharedInfoPtr;\
		DWORD SystemReserved;\
		DWORD AtlThunkSListPtr32;\
		T ApiSetMap;\
		T TlsExpansionCounter;\
		T TlsBitmap;\
		DWORD TlsBitmapBits[2];\
		T ReadOnlySharedMemoryBase;\
		T HotpatchInformation;\
		T ReadOnlyStaticServerData;\
		T AnsiCodePageData;\
		T OemCodePageData;\
		T UnicodeCaseTableData;\
		DWORD NumberOfProcessors;\
		union {\
			DWORD NtGlobalFlag;\
			NGF dummy02;\
		};\
		LARGE_INTEGER CriticalSectionTimeout;\
		T HeapSegmentReserve;\
		T HeapSegmentCommit;\
		T HeapDeCommitTotalFreeThreshold;\
		T HeapDeCommitFreeBlockThreshold;\
		DWORD NumberOfHeaps;\
		DWORD MaximumNumberOfHeaps;\
		T ProcessHeaps;\
		T GdiSharedHandleTable;\
		T ProcessStarterHelper;\
		T GdiDCAttributeList;\
		T LoaderLock;\
		DWORD OSMajorVersion;\
		DWORD OSMinorVersion;\
		WORD OSBuildNumber;\
		WORD OSCSDVersion;\
		DWORD OSPlatformId;\
		DWORD ImageSubsystem;\
		DWORD ImageSubsystemMajorVersion;\
		T ImageSubsystemMinorVersion;\
		T ActiveProcessAffinityMask;\
		T GdiHandleBuffer[A];\
		T PostProcessInitRoutine;\
		T TlsExpansionBitmap;\
		DWORD TlsExpansionBitmapBits[32];\
		T SessionId;\
		ULARGE_INTEGER AppCompatFlags;\
		ULARGE_INTEGER AppCompatFlagsUser;\
		T pShimData;\
		T AppCompatInfo;\
		PP_CONCAT(UNICODE_STRING, BITS) CSDVersion;\
		T ActivationContextData;\
		T ProcessAssemblyStorageMap;\
		T SystemDefaultActivationContextData;\
		T SystemAssemblyStorageMap;\
		T MinimumStackCommit;\
		T FlsCallback;\
		PP_CONCAT(LIST_ENTRY, BITS) FlsListHead;\
		T FlsBitmap;\
		DWORD FlsBitmapBits[4];\
		T FlsHighIndex;\
		T WerRegistrationData;\
		T WerShipAssertPtr;\
		T pContextData;\
		T pImageHeaderHash;\
		T TracingFlags;\
	} PP_CONCAT(PEB, BITS)

PEB_T(DWORD, DWORD64, 34, 32);
PEB_T(DWORD64, DWORD, 30, 64);
PP_DEFINE_POINTER(PEB32);
PP_DEFINE_POINTER(PEB64);

#define TEB_T(T, BITS)\
	typedef struct {\
		T Reserved1[12];\
		T ProcessEnvironmentBlock;\
		T Reserved2[399];\
		BYTE Reserved3[1952];\
		T TlsSlots[64];\
		BYTE Reserved4[8];\
		T Reserved5[26];\
		T ReservedForOle;\
		T Reserved6[4];\
		T TlsExpansionSlots;\
	} PP_CONCAT(TEB, BITS)

DEFINE_FOR_32_AND_64(TEB);

#define CLIENT_ID_T(T, BITS) \
	typedef struct {\
		T UniqueProcess;\
		T UniqueThread;\
	} PP_CONCAT(CLIENT_ID, BITS)

DEFINE_FOR_32_AND_64(CLIENT_ID);

#ifdef _WIN64
#define PROG_BITS 64
#else
#define PROG_BITS 32
#endif

#define TYPEDEF(T) \
	typedef PP_CONCAT(T, PROG_BITS) T;\
	typedef PP_CONCAT(PP_CONCAT(P, T), PROG_BITS) PP_CONCAT(P, T)

TYPEDEF(ANSI_STRING);
TYPEDEF(UNICODE_STRING);
TYPEDEF(PEB_LDR_DATA);
TYPEDEF(LDR_DATA_TABLE_ENTRY);
TYPEDEF(PEB);
TYPEDEF(CLIENT_ID);
TYPEDEF(TEB);

#undef TYPEDEF
#undef PROG_BITS
#undef DEFINE_FOR_32_AND_64

