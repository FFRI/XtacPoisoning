// (c) FFRI Security, Inc., 2023 / Author: FFRI Security, Inc.
#include "MiniWin32Api.h"
#include "HelperMacros.h"

#pragma code_seg(".scode")

PVOID MyBasepMapModuleHandle(HMODULE hModule, BOOLEAN asDataFile) {
	if (!hModule) return (PVOID)((PPEB)(((PTEB)NtCurrentTeb())->ProcessEnvironmentBlock))->ImageBaseAddress;
	if ((((uint64_t)hModule & 0x3) != 0) && asDataFile) return NULL;
	return hModule;
}

#ifdef _WIN64
PVOID MyBasepMapModuleHandleGuest(HMODULE hModule, BOOLEAN asDataFile) {
	if (!hModule) return (PVOID)(NtGuestPeb()->ImageBaseAddress);
	if ((((uint64_t)hModule & 0x3) != 0) && asDataFile) return NULL;
	return hModule;
}
#endif

#define DEFINE_MY_GET_PROC_ADDRESS(S, PebFunc)\
	FARPROC PP_CONCAT(MyGetProcAddress, S)(NTDLL_FUNCS* pNtDllFuncs, HMODULE hModule, LPCSTR lpProcName){\
		const ULONG_PTR MAX_USHORT = 0x10000;\
		WORD ordinal = 0x0;\
		PANSI_STRING pFuncNameAnsi = NULL;\
		ANSI_STRING funcNameAnsi = {0};\
		HMODULE moduleHandle = NULL;\
		if ((ULONG_PTR)lpProcName < MAX_USHORT) {\
			ordinal = (WORD)lpProcName;\
			moduleHandle = (HMODULE) PP_CONCAT(MyBasepMapModuleHandle, S)(hModule, FALSE);\
		}\
		else {\
			pNtDllFuncs->pRtlInitAnsiString(&funcNameAnsi, (char*)lpProcName);\
			if (hModule == NULL) {\
				moduleHandle = (HMODULE)PebFunc->ImageBaseAddress;\
			}\
			else {\
				moduleHandle = hModule;\
				if (((uint64_t)hModule & 0x3) != 0x0) {\
					moduleHandle = 0x0;\
				}\
			}\
			ordinal = 0x0;\
			pFuncNameAnsi = &funcNameAnsi;\
		}\
		PVOID pFunctionAddress = NULL;\
		pNtDllFuncs->pLdrGetProcedureAddressForCaller(moduleHandle, pFuncNameAnsi, ordinal, &pFunctionAddress, 0, _ReturnAddress());\
		return (FARPROC)pFunctionAddress;\
	}

DEFINE_MY_GET_PROC_ADDRESS(PP_EMPTY, ((PPEB)((PTEB)NtCurrentTeb())->ProcessEnvironmentBlock))

#ifdef _WIN64
DEFINE_MY_GET_PROC_ADDRESS(Guest, NtGuestPeb())
#endif

__declspec(noinline)
HMODULE MyLoadLibraryA(
	NTDLL_FUNCS* pNtDllFuncs,
	LPCSTR lpLibFileName) {
	ANSI_STRING libFileNameAnsi = {0};
	UNICODE_STRING libFileNameUnicode = {0};
	pNtDllFuncs->pRtlInitAnsiString(&libFileNameAnsi, (char*)lpLibFileName);

	NTSTATUS stat;
	stat = pNtDllFuncs->pRtlAnsiStringToUnicodeString(&libFileNameUnicode, &libFileNameAnsi, TRUE);

	ULONG flags = 0;
	HANDLE ret = NULL;
	stat = pNtDllFuncs->pLdrLoadDll(1, &flags, &libFileNameUnicode, &ret);

	pNtDllFuncs->pRtlFreeUnicodeString(&libFileNameUnicode);
	return (HMODULE)ret;
}

KERNELBASE_APIS GetKernelBaseApis(NTDLL_FUNCS* ntDllFuncs, BOOL callInitializeTls) {
	const uint64_t kernel32DllStr[] = { 0x32336c656e72656b, 0x6c6c642e, };
	const uint64_t ntdllStr[] = {0x6c642e6c6c64746e, 0x6c};

	const uint64_t virtualallocApiStr[] = { 0x416c617574726956, 0x636f6c6c };
	const uint64_t virtualfreeApiStr[] = { 0x466c617574726956, 0x656572 };
	const uint64_t loadlibraryaApiStr[] = { 0x7262694c64616f4c, 0x41797261 };
	const uint64_t getprocaddressApiStr[] = {0x41636f7250746547, 0x0000737365726464 };
	const uint64_t freelibraryApiStr[] = { 0x7262694c65657246, 0x797261 };
	const uint64_t getnativesysteminfoApiStr[] = { 0x766974614e746547, 0x496d657473795365, 0x6f666e };
	const uint64_t virtualprotectApiStr[] = { 0x506c617574726956, 0x746365746f72 };
	const uint64_t isbadreadptrApiStr[] = { 0x6165526461427349, 0x72745064 };
	const uint64_t createthreadApiStr[] = {0x6854657461657243, 0x64616572};
	const uint64_t waitforsingleobjectApiStr[] = {0x53726f4674696157, 0x6a624f656c676e69, 0x746365};

#define AS_CHAR_ARRAY(v) ((char*)&(v))

	// NOTE:
	// Calling LdrpInitializeTls is ESSENTIAL because native TLS is not initialize for WOW64 process.
	// If the shellcode to be injected does not use native TLS, this function call is not needed.
	// Since LdrpInitializeTls is not exported, the address of LdrpInitializeTls is hard-coded.
	if (callInitializeTls) {
		HMODULE ntdllBaseAddr = MyLoadLibraryA(ntDllFuncs, AS_CHAR_ARRAY(ntdllStr));
		LDRPINITIALIZETLS addrLdrpInitializeTls = (LDRPINITIALIZETLS)((ULONG_PTR)ntdllBaseAddr + RVA_TO_LDRPINITIALIZETLS);
		addrLdrpInitializeTls();
	}

	HMODULE kernelBaseAddr = MyLoadLibraryA(ntDllFuncs, AS_CHAR_ARRAY(kernel32DllStr));
	GETPROCADDRESS pGetProcAddress = (GETPROCADDRESS)MyGetProcAddress(ntDllFuncs,
		kernelBaseAddr,
		AS_CHAR_ARRAY(getprocaddressApiStr));

	KERNELBASE_APIS apis = {
		.allocMemory = (CustomAllocFunc)pGetProcAddress(kernelBaseAddr, AS_CHAR_ARRAY(virtualallocApiStr)),
		.freeMemory = (CustomFreeFunc)pGetProcAddress(kernelBaseAddr, AS_CHAR_ARRAY(virtualfreeApiStr)),
		.loadLibrary = (CustomLoadLibraryFunc)pGetProcAddress(kernelBaseAddr, AS_CHAR_ARRAY(loadlibraryaApiStr)),
		.freeLibrary = (CustomFreeLibraryFunc)pGetProcAddress(kernelBaseAddr, AS_CHAR_ARRAY(freelibraryApiStr)),
		.getProcAddress = (CustomGetProcAddressFunc)pGetProcAddress,
		.getNativeSystemInfo =
			(CustomGetNativeSystemInfo)pGetProcAddress(kernelBaseAddr, AS_CHAR_ARRAY(getnativesysteminfoApiStr)),
		.virtualProtect =
			(CustomVirtualProtect)pGetProcAddress(kernelBaseAddr, AS_CHAR_ARRAY(virtualprotectApiStr)),
		.isBadReadPtr =
			(CustomIsBadReadPtr)pGetProcAddress(kernelBaseAddr, AS_CHAR_ARRAY(isbadreadptrApiStr)),
		.createThread =
			(CustomCreateThread)pGetProcAddress(kernelBaseAddr, AS_CHAR_ARRAY(createthreadApiStr)),
		.waitForSingleObject = 
			(CustomWaitForSingleObject)pGetProcAddress(kernelBaseAddr, AS_CHAR_ARRAY(waitforsingleobjectApiStr)),
	};

	return apis;
}

