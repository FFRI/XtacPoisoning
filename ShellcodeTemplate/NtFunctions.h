// (c) FFRI Security, Inc., 2023 / Author: FFRI Security, Inc.
#pragma once

#include "NtStructs.h"
#include <stdint.h>

typedef NTSTATUS(NTAPI* NTALLOCATEVIRTUALMEMORY)(
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T   RegionSize,
	ULONG     AllocationType,
	ULONG     Protect
);

typedef NTSTATUS(NTAPI* NTFLUSHINSTRUCTIONCACHE)(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	ULONG NumberOfBytesToFlush
);

typedef NTSTATUS(NTAPI* RTLCREATEUSERTHREAD)(
	IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits OPTIONAL,
	IN SIZE_T StackReserve OPTIONAL,
	IN SIZE_T StackCommit OPTIONAL,
	IN PTHREAD_START_ROUTINE StartAddress,
	IN PVOID Parameter OPTIONAL,
	OUT PHANDLE ThreadHandle OPTIONAL,
	OUT PCLIENT_ID ClientId OPTIONAL
);

typedef NTSTATUS(NTAPI* LDRLOADDLL)(
	ULONGLONG PathToFile,
	PULONG Flags,
	PUNICODE_STRING ModuleFileName,
	PHANDLE ModuleHandle
);

typedef NTSTATUS(NTAPI* RTLUNICODESTRINGTOANSISTRING)(
	PANSI_STRING     DestinationString,
	PUNICODE_STRING SourceString,
	BOOLEAN          AllocateDestinationString
);

typedef NTSTATUS(NTAPI* RTLANSISTRINGTOUNICODESTRING)(
	PUNICODE_STRING DestinationString,
	PANSI_STRING   SourceString,
	BOOLEAN         AllocateDestinationString
);

typedef void(NTAPI* RTLINITANSISTRING)(
	PANSI_STRING DestinationString,
	PSZ SourceString OPTIONAL
);

typedef void(NTAPI* RTLFREEANSISTRING)(
	PANSI_STRING AnsiString
);

typedef void(NTAPI* RTLFREEUNICODESTRING)(
	PUNICODE_STRING UnicodeString
);

typedef NTSTATUS (NTAPI* LDRGETPROCEDUREADDRESSFORCALLER)(
	HMODULE       ModuleHandle,
	PANSI_STRING  FunctionName,
	WORD          Ordinal,
	PVOID        *FunctionAddress,
	BOOL          bValue,
	PVOID         CallbackAddress
);

typedef NTSTATUS(NTAPI* LDRPINITIALIZETLS)(VOID);

typedef HANDLE (WINAPI *CREATETHREAD)(
	LPSECURITY_ATTRIBUTES   lpThreadAttributes,
	SIZE_T                  dwStackSize,
	LPTHREAD_START_ROUTINE  lpStartAddress,
	__drv_aliasesMem LPVOID lpParameter,
	DWORD                   dwCreationFlags,
	LPDWORD                 lpThreadId
);

typedef DWORD (WINAPI *WAITFORSINGLEOBJECT)(
	HANDLE hHandle,
	DWORD  dwMilliseconds
);

typedef struct _USER_STACK {
	PVOID FixedStackBase;
	PVOID FixedStackLimit;
	PVOID ExpandableStackBase;
	PVOID ExpandableStackLimit;
	PVOID ExpandableStackBottom;
} USER_STACK, *PUSER_STACK;

typedef struct _NTDLL_FUNCS {
	NTALLOCATEVIRTUALMEMORY pNtAllocateVirtualMemory;
	NTFLUSHINSTRUCTIONCACHE pNtFlushInstructionCache;
	RTLINITANSISTRING pRtlInitAnsiString;
	RTLUNICODESTRINGTOANSISTRING pRtlUnicodeStringToAnsiString;
	RTLFREEANSISTRING pRtlFreeAnsiString;
	RTLANSISTRINGTOUNICODESTRING pRtlAnsiStringToUnicodeString;
	RTLFREEUNICODESTRING pRtlFreeUnicodeString;
	RTLCREATEUSERTHREAD pRtlCreateUserThread;
	LDRLOADDLL pLdrLoadDll;
	LDRGETPROCEDUREADDRESSFORCALLER pLdrGetProcedureAddressForCaller;
} NTDLL_FUNCS;

// NOTE: this value depends on Windows Build version
#define RVA_TO_LDRPINITIALIZETLS 0x563c8

NTDLL_FUNCS GetNtDllFuncs32();
#ifdef _WIN64
NTDLL_FUNCS GetNtDllFuncs64();
NTDLL_FUNCS GetNtDllFuncsGuest();
#endif

#ifdef _WIN64
PTEB32 NtGuestTeb(void);
PPEB32 NtGuestPeb(void);
#endif

LPVOID GetApiAddressFromHash32(DWORD dwHash);
#ifdef _WIN64
LPVOID GetApiAddressFromHash64(DWORD dwHash);
LPVOID GetApiAddressFromHashGuest(DWORD dwHash);
#endif

uint32_t CalcApiHash(const char* dll, const char* api);

