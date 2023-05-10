// (c) FFRI Security, Inc., 2023 / Author: FFRI Security, Inc.
#pragma once

#include "NtFunctions.h"

typedef LPVOID (WINAPI *CustomAllocFunc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI *CustomFreeFunc)(LPVOID, SIZE_T, DWORD);
typedef HMODULE (WINAPI *CustomLoadLibraryFunc)(LPCSTR);
typedef FARPROC (WINAPI *CustomGetProcAddressFunc)(HMODULE, LPCSTR);
typedef void (*CustomFreeLibraryFunc)(HMODULE);
typedef WINBASEAPI VOID (WINAPI* CustomGetNativeSystemInfo)(_Out_ LPSYSTEM_INFO lpSystemInfo);
typedef WINBASEAPI BOOL (WINAPI* CustomVirtualProtect)(_In_ LPVOID lpAddress,
	_In_ SIZE_T dwSize, _In_ DWORD flNewProtect, _Out_ PDWORD lpflOldProtect); 
typedef WINBASEAPI BOOL (WINAPI* CustomIsBadReadPtr)(_In_opt_ CONST VOID *lp, _In_ UINT_PTR ucb);
typedef WINBASEAPI HANDLE (WINAPI* CustomCreateThread)(
	LPSECURITY_ATTRIBUTES   lpThreadAttributes,
	SIZE_T                  dwStackSize,
	LPTHREAD_START_ROUTINE  lpStartAddress,
	__drv_aliasesMem LPVOID lpParameter,
	DWORD                   dwCreationFlags,
	LPDWORD                 lpThreadId
);
typedef WINBASEAPI DWORD (WINAPI* CustomWaitForSingleObject)(HANDLE hHandle, DWORD dwMilliseconds);

typedef struct {
	CustomAllocFunc allocMemory;
	CustomFreeFunc freeMemory;
	CustomLoadLibraryFunc loadLibrary;
	CustomGetProcAddressFunc getProcAddress;
	CustomFreeLibraryFunc freeLibrary;
	CustomGetNativeSystemInfo getNativeSystemInfo;
	CustomVirtualProtect virtualProtect;
	CustomIsBadReadPtr isBadReadPtr;
	CustomCreateThread createThread;
	CustomWaitForSingleObject waitForSingleObject;
} KERNELBASE_APIS;

PVOID MyBasepMapModuleHandle(HMODULE hModule, BOOLEAN asDataFile);

FARPROC MyGetProcAddress(
	NTDLL_FUNCS* pNtDllFuncs,
	HMODULE hModule,
	LPCSTR lpProcName);

#ifdef _WIN64
FARPROC MyGetProcAddressGuest(
	NTDLL_FUNCS* pNtDllFuncs,
	HMODULE hModule,
	LPCSTR lpProcName);
#endif

HMODULE MyLoadLibraryA(
	NTDLL_FUNCS* pNtDllFuncs,
	LPCSTR lpLibFileName);

typedef NTSTATUS (NTAPI* LDRGETPROCEDUREADDRESSFORCALLER)(
	HMODULE       ModuleHandle,
	PANSI_STRING  FunctionName,
	WORD          Ordinal,
	PVOID        *FunctionAddress,
	BOOL          bValue,
	PVOID         CallbackAddress
);

typedef WINBASEAPI FARPROC (WINAPI* GETPROCADDRESS)(
	_In_ HMODULE hModule,
	_In_ LPCSTR lpProcName
);

typedef WINBASEAPI _Ret_maybenull_ HMODULE (WINAPI* LOADLIBRARYA)(
	_In_ LPCSTR lpLibFileName
);

KERNELBASE_APIS GetKernelBaseApis(NTDLL_FUNCS* ntDllFuncs, BOOL callInitializeTls);
