// (c) FFRI Security, Inc., 2023 / Author: FFRI Security, Inc.
#include "NtFunctions.h"
#include "HelperMacros.h"

#pragma code_seg(".scode")

#define RVA2VA(type, base, rva) (type)((ULONG_PTR) base + rva)

#ifdef _WIN64

PTEB32 NtGuestTeb(void) {
	return (PTEB32)((ULONG_PTR)NtCurrentTeb() + 0x2000);
}

PPEB32 NtGuestPeb(void) {
	return NtGuestTeb()->ProcessEnvironmentBlock;
}

#endif

uint32_t CalcCrc32c(const char* s, size_t len) {
	uint32_t crc = 0;
	for (size_t i = 0; i < len; i++) {
		crc ^= (uint8_t)(*s++ | 0x20);
		for (int j = 0; j < 8; j++) {
			crc = (crc >> 1) ^ (0x82F63B78 * (crc & 1));
		}
	}
	return crc;
}

uint32_t CalcCrc32cFromUnicodeString(PUNICODE_STRING u,
	RTLUNICODESTRINGTOANSISTRING pRtlUnicodeStringToAnsiString,
	RTLFREEANSISTRING pRtlFreeAnsiString) {
	ANSI_STRING a = { 0, 0, 0 };
	pRtlUnicodeStringToAnsiString(&a, u, TRUE);
	uint32_t crc = CalcCrc32c((const char*)a.Buffer, a.Length);
	pRtlFreeAnsiString(&a);
	return crc;
}

uint32_t CalcApiHash(const char* dll,
	const char* api) {
	return CalcCrc32c(dll, strlen(dll)) + CalcCrc32c(api, strlen(api));
}

#define DEFINE_SEARCH_EXPORT_FUNCTION(S, PIMAGE_NT_HEADER_TYPE) \
	LPVOID PP_CONCAT(SearchExportFunction, S)(LPVOID base, DWORD hash) {\
		PIMAGE_DOS_HEADER       dos;\
		PIMAGE_NT_HEADER_TYPE       nt;\
		DWORD                   cnt, rva, dll_h;\
		PIMAGE_DATA_DIRECTORY   dir;\
		PIMAGE_EXPORT_DIRECTORY exp;\
		PDWORD                  adr;\
		PDWORD                  sym;\
		PWORD                   ord;\
		PCHAR                   api, dll;\
		LPVOID                  api_adr = NULL;\
		dos = (PIMAGE_DOS_HEADER)base;\
		nt = RVA2VA(PIMAGE_NT_HEADER_TYPE, base, dos->e_lfanew);\
		dir = (PIMAGE_DATA_DIRECTORY)nt->OptionalHeader.DataDirectory;\
		rva = dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;\
		if (rva == 0) return NULL;\
		exp = (PIMAGE_EXPORT_DIRECTORY) RVA2VA(ULONG_PTR, base, rva);\
		cnt = exp->NumberOfNames;\
		if (cnt == 0) return NULL;\
		adr = RVA2VA(PDWORD,base, exp->AddressOfFunctions);\
		sym = RVA2VA(PDWORD,base, exp->AddressOfNames);\
		ord = RVA2VA(PWORD, base, exp->AddressOfNameOrdinals);\
		dll = RVA2VA(PCHAR, base, exp->Name);\
		dll_h = CalcCrc32c(dll, strlen(dll));\
		do {\
			api = RVA2VA(PCHAR, base, sym[cnt-1]);\
			if (CalcCrc32c(api, strlen(api)) + dll_h == hash) {\
				api_adr = RVA2VA(LPVOID, base, adr[ord[cnt-1]]);\
				return api_adr;\
			}\
		} while (--cnt && api_adr==0);\
		return api_adr;\
	}

DEFINE_SEARCH_EXPORT_FUNCTION(64, PIMAGE_NT_HEADERS64) // 64bit version
DEFINE_SEARCH_EXPORT_FUNCTION(32, PIMAGE_NT_HEADERS32) // 32bit version

#define DEFINE_GET_API_ADDRESS_FROM_HASH_FUNCTION(S, Bits, PebFunc)\
__declspec(noinline)\
	LPVOID PP_CONCAT(GetApiAddressFromHash, S)(DWORD dwHash) {\
		LPVOID api_adr = NULL;\
		PP_CONCAT(PPEB, Bits) peb = (PP_CONCAT(PPEB, Bits))PebFunc;\
		PP_CONCAT(PPEB_LDR_DATA, Bits) ldr = (PP_CONCAT(PPEB_LDR_DATA, Bits))peb->Ldr;\
		for (PP_CONCAT(PLDR_DATA_TABLE_ENTRY, Bits) dte = (PP_CONCAT(PLDR_DATA_TABLE_ENTRY, Bits))ldr->InLoadOrderModuleList.Flink;\
			dte->DllBase != 0 && api_adr == NULL;\
			dte = (PP_CONCAT(PLDR_DATA_TABLE_ENTRY, Bits))dte->InLoadOrderLinks.Flink) {\
			api_adr = PP_CONCAT(SearchExportFunction, Bits)((LPVOID)dte->DllBase, dwHash);\
		}\
		return api_adr;\
	}

DEFINE_GET_API_ADDRESS_FROM_HASH_FUNCTION(32, 32, ((PTEB32)NtCurrentTeb())->ProcessEnvironmentBlock) // for 32bit process
#ifdef _WIN64
DEFINE_GET_API_ADDRESS_FROM_HASH_FUNCTION(64, 64, ((PTEB64)NtCurrentTeb())->ProcessEnvironmentBlock) // for 64bit native process
DEFINE_GET_API_ADDRESS_FROM_HASH_FUNCTION(Guest, 32, NtGuestPeb()) // for getting WOW64 peb
#endif

#define NTDLLDLL_HASH 0x921bf95c

#define NTALLOCATEVIRTUALMEMORY_HASH 0xb1418e6f
#define NTFLUSHINSTRUCTIONCACHE_HASH 0xa97d22c1
#define RTLINITANSISTRING_HASH 0xfc1134b2
#define RTLUNICODESTRINGTOANSISTRING_HASH 0x3ba51e0c
#define RTLFREEANSISTRING_HASH 0x5a995a7a
#define RTLANSISTRINGTOUNICODESTRING_HASH 0xe39a7b8d
#define RTLFREEUNICODESTRING_HASH 0xe231e13
#define RTLCREATEUSERTHREAD_HASH 0x5d7f1738
#define LDRLOADDLL_HASH 0x49a0a53b
#define LDRGETPROCEDUREADDRESSFORCALLER_HASH 0xbc42ab88

#define DEFINE_GET_NTDLL_FUNCS(S, GET_API_ADDRESS)\
	NTDLL_FUNCS PP_CONCAT(GetNtDllFuncs, S)() {\
		NTDLL_FUNCS funcs = {\
			.pNtAllocateVirtualMemory = (NTALLOCATEVIRTUALMEMORY)GET_API_ADDRESS(NTALLOCATEVIRTUALMEMORY_HASH),\
			.pNtFlushInstructionCache = (NTFLUSHINSTRUCTIONCACHE)GET_API_ADDRESS(NTFLUSHINSTRUCTIONCACHE_HASH),\
			.pRtlInitAnsiString = (RTLINITANSISTRING)GET_API_ADDRESS(RTLINITANSISTRING_HASH),\
			.pRtlUnicodeStringToAnsiString = (RTLUNICODESTRINGTOANSISTRING)GET_API_ADDRESS(RTLUNICODESTRINGTOANSISTRING_HASH),\
			.pRtlFreeAnsiString = (RTLFREEANSISTRING)GET_API_ADDRESS(RTLFREEANSISTRING_HASH),\
			.pRtlAnsiStringToUnicodeString = (RTLANSISTRINGTOUNICODESTRING)GET_API_ADDRESS(RTLANSISTRINGTOUNICODESTRING_HASH),\
			.pRtlFreeUnicodeString = (RTLFREEUNICODESTRING)GET_API_ADDRESS(RTLFREEUNICODESTRING_HASH),\
			.pRtlCreateUserThread = (RTLCREATEUSERTHREAD)GET_API_ADDRESS(RTLCREATEUSERTHREAD_HASH),\
			.pLdrLoadDll = (LDRLOADDLL)GET_API_ADDRESS(LDRLOADDLL_HASH),\
			.pLdrGetProcedureAddressForCaller = (LDRGETPROCEDUREADDRESSFORCALLER)GET_API_ADDRESS(LDRGETPROCEDUREADDRESSFORCALLER_HASH),\
		};\
		return funcs;\
	}\

DEFINE_GET_NTDLL_FUNCS(32, GetApiAddressFromHash32)
#ifdef _WIN64
DEFINE_GET_NTDLL_FUNCS(64, GetApiAddressFromHash64)
DEFINE_GET_NTDLL_FUNCS(Guest, GetApiAddressFromHashGuest)
#endif

#if 0
// for debug purpose
void ShowNtDllFuncs(NTDLL_FUNCS* ntdllFuncs) {
	printf("%p %p %p %p %p %p %p %p %p %p\n",
		ntdllFuncs->pNtAllocateVirtualMemory,
		ntdllFuncs->pNtFlushInstructionCache,
		ntdllFuncs->pRtlInitAnsiString,
		ntdllFuncs->pRtlUnicodeStringToAnsiString,
		ntdllFuncs->pRtlFreeAnsiString,
		ntdllFuncs->pRtlAnsiStringToUnicodeString,
		ntdllFuncs->pRtlFreeUnicodeString,
		ntdllFuncs->pRtlCreateUserThread,
		ntdllFuncs->pLdrLoadDll,
		ntdllFuncs->pLdrGetProcedureAddressForCaller
	);
}
#endif
