// (c) FFRI Security, Inc., 2023 / Author: FFRI Security, Inc.
#pragma warning(push)
#pragma warning(disable : 4005)
#include <ntstatus.h>
#include <Windows.h>
#pragma warning(pop)

#include <bcrypt.h>
#include <DbgHelp.h>
#include <iostream>
#include <iomanip>
#include <format>
#include <algorithm>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "Bcrypt.lib")

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef enum _FILE_INFORMATION_CLASS {
	FileBasicInformation = 4,
	FileStandardInformation = 5,
	FilePositionInformation = 14,
	FileEndOfFileInformation = 20,
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

typedef NTSTATUS(WINAPI *pNtQueryInformationFile)(
	HANDLE,
	PIO_STATUS_BLOCK,
	PVOID,
	ULONG,
	FILE_INFORMATION_CLASS);

std::wstring ConvertToHashString(uint32_t* hash) {
	return std::format(L"{:08x}{:08x}{:08x}{:08x}", hash[0], hash[1], hash[2], hash[3]);
}

void Capitalize(std::wstring& str) {
	std::transform(std::begin(str), std::end(str), std::begin(str), [](wchar_t c){ return toupper(c); });
}

#define SHOW_LOG(str) std::wcout << L"[+] " << str << std::endl
#define SHOW_ERR(str) std::wcerr << L"[-] " << str << std::endl

int wmain(int argc, wchar_t* argv[]) {
	if (argc != 2) {
		std::wcerr << L"Usage: " << argv[0] << L" x86/x64 executable" << std::endl;
		return EXIT_FAILURE;
	}

	const wchar_t* inputFileName = argv[1];

	auto ntdllHandle = GetModuleHandleW(L"ntdll.dll");
	if (!ntdllHandle) {
		SHOW_ERR(L"Cannot load ntdll.dll");
		return EXIT_FAILURE;
	}
	pNtQueryInformationFile NtQueryInformationFile = (pNtQueryInformationFile)GetProcAddress(ntdllHandle, "NtQueryInformationFile");
	if (!NtQueryInformationFile) {
		SHOW_ERR(L"Cannot find NtQueryInformationFile");
		return EXIT_FAILURE;
	}

	SHOW_LOG(L"Get Crypt Provider");
	BCRYPT_ALG_HANDLE algorithmHandle = nullptr;
	if (BCryptOpenAlgorithmProvider(&algorithmHandle, BCRYPT_SHA256_ALGORITHM, NULL, 0x20) != STATUS_SUCCESS) {
		SHOW_ERR(L"Failed to call BCryptOpenAlgorithmProvider");
	}

	BCRYPT_HASH_HANDLE hashHandle = nullptr;
	if (BCryptCreateHash(algorithmHandle, &hashHandle, nullptr, 0, nullptr, 0, 0x20) != STATUS_SUCCESS) {
		SHOW_ERR(L"Failed to call BCryptCreateHash");
		return EXIT_FAILURE;
	}

	SHOW_LOG(L"Open File");
	auto inputFileHandle = CreateFileW(inputFileName, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
	if (inputFileHandle == INVALID_HANDLE_VALUE) {
		SHOW_ERR(std::format(L"Cannot open file {}", inputFileName));
		return EXIT_FAILURE;
	}

	SHOW_LOG(L"Create File Mapping");
	auto mappingFileHandle = CreateFileMappingW(inputFileHandle, nullptr, PAGE_READONLY, 0, 0, nullptr);
	if (!mappingFileHandle) {
		SHOW_ERR(L"Cannot create file mapping");
		return EXIT_FAILURE;
	}
	auto imageBase = MapViewOfFile(mappingFileHandle, FILE_MAP_READ, 0, 0, 0);
	if (!imageBase) {
		SHOW_ERR(L"Failed to call MapViewOfFile");
		return EXIT_FAILURE;
	}

	auto pImageBase = (char*)imageBase;
	if (*pImageBase != 'M' || *(pImageBase + 1) != 'Z') {
		SHOW_ERR(L"This file is not PE file");
		return EXIT_FAILURE;
	}

	SHOW_LOG(L"Get Image NT Header");
	auto pImageNtHeader = ImageNtHeader(imageBase);
	auto offsetToNtHeader = (uintptr_t)pImageNtHeader - (uintptr_t)imageBase;

	if (pImageNtHeader->OptionalHeader.Magic == 0x10b) { // PE32
		// DOS header + NT header
		if (BCryptHashData(hashHandle, (PUCHAR)imageBase, (ULONG)offsetToNtHeader + 0x34, 0) != STATUS_SUCCESS) {
			SHOW_ERR(L"Failed to call BCryptHashData");
			return EXIT_FAILURE;
		}

		// NT header
		if (BCryptHashData(hashHandle, (PUCHAR)((uintptr_t)imageBase + offsetToNtHeader + 0x38), pImageNtHeader->FileHeader.SizeOfOptionalHeader - 0x20, 0) != STATUS_SUCCESS) {
			SHOW_ERR(L"Failed to call BCryptHashData");
			return EXIT_FAILURE;
		}
	}
	else { // PE32+
		// DOS header + NT header
		if (BCryptHashData(hashHandle, (PUCHAR)imageBase, (ULONG)offsetToNtHeader + 0x30, 0) != STATUS_SUCCESS) {
			SHOW_ERR(L"Failed to call BCryptHashData");
			return EXIT_FAILURE;
		}

		// NT header
		if (BCryptHashData(hashHandle, (PUCHAR)((uintptr_t)imageBase + offsetToNtHeader + 0x38), pImageNtHeader->FileHeader.SizeOfOptionalHeader - 0x20, 0) != STATUS_SUCCESS) {
			SHOW_ERR(L"Failed to call BCryptHashData");
			return EXIT_FAILURE;
		}
	}

	SHOW_LOG(L"Get LastWriteTime");
	FILE_BASIC_INFO fileBasicInfo{};
	IO_STATUS_BLOCK ioStatusBlock{};
	NtQueryInformationFile(inputFileHandle, &ioStatusBlock, &fileBasicInfo, sizeof FILE_BASIC_INFO, FileBasicInformation);
	if (BCryptHashData(hashHandle, (PUCHAR)(&fileBasicInfo.LastWriteTime), 0x8, 0) != STATUS_SUCCESS) {
		SHOW_ERR(L"Failed to call BCryptHashData");
		return EXIT_FAILURE;
	}

	uint32_t moduleHeaderHash[8]{};
	if (BCryptFinishHash(hashHandle, (UCHAR*)moduleHeaderHash, sizeof(moduleHeaderHash), 0) != STATUS_SUCCESS) {
		SHOW_ERR(L"Failed to call BCryptFinishHash");
		return EXIT_FAILURE;
	}
	auto moduleHeaderHashStr = ConvertToHashString(moduleHeaderHash);
	Capitalize(moduleHeaderHashStr);

	SHOW_LOG(L"Get full path");
	wchar_t fullPathName[MAX_PATH]{};
	if (!GetFullPathNameW(inputFileName, sizeof(fullPathName) / sizeof(wchar_t), fullPathName, nullptr))
	{
		SHOW_ERR(L"Failed go get full path name");
		return EXIT_FAILURE;
	}

	wchar_t linkName[3]{ fullPathName[0], fullPathName[1], 0};
	wchar_t devName[MAX_PATH]{};
	QueryDosDeviceW(linkName, devName, MAX_PATH);
	SHOW_LOG(std::format(L"Device name is {}", devName));

	std::wstring pathName = std::wstring(devName) + std::wstring(&fullPathName[2]);
	Capitalize(pathName);
	SHOW_LOG(std::format(L"Path name is {}", pathName));

	if (BCryptCreateHash(algorithmHandle, &hashHandle, nullptr, 0, nullptr, 0, 0x20) != STATUS_SUCCESS) {
		SHOW_ERR(L"Failed to call BCryptCreateHash");
		return EXIT_FAILURE;
	}

	if (BCryptHashData(hashHandle, (PUCHAR)pathName.data(), (ULONG)(pathName.length() * sizeof(wchar_t)), 0) != STATUS_SUCCESS) {
		SHOW_ERR(L"Failed to call BCryptHashData");
		return EXIT_FAILURE;
	}

	uint32_t modulePathHash[8]{};
	if (BCryptFinishHash(hashHandle, (UCHAR*)modulePathHash, sizeof(modulePathHash), 0) != STATUS_SUCCESS) {
		SHOW_ERR(L"Failed to call BCryptFinishHash");
		return EXIT_FAILURE;
	}
	auto modulePathHashStr = ConvertToHashString(modulePathHash);
	Capitalize(modulePathHashStr);

	std::wcout << std::endl;

	std::wcout << "Module Header Hash: " << moduleHeaderHashStr << std::endl;
	std::wcout << "Module Path Hash: " << modulePathHashStr << std::endl;

	BCryptDestroyHash(hashHandle);
}