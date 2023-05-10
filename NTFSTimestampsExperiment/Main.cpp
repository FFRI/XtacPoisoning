// (c) FFRI Security, Inc., 2023 / Author: FFRI Security, Inc.
#include <Windows.h>
#include <iomanip>
#include <iostream>
#include <optional>
#include <string>
#include <filesystem>
#include <cstdlib>

namespace fs = std::filesystem;

// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_io_status_block
typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _FILE_BOTH_DIR_INFORMATION {
	ULONG         NextEntryOffset;
	ULONG         FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG         FileAttributes;
	ULONG         FileNameLength;
	ULONG         EaSize;
	CCHAR         ShortNameLength;
	WCHAR         ShortName[12];
	WCHAR         FileName[1];
} FILE_BOTH_DIR_INFORMATION, *PFILE_BOTH_DIR_INFORMATION;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_file_information_class
typedef enum _FILE_INFORMATION_CLASS {
	FileDirectoryInformation = 1,
	FileFullDirectoryInformation,            // 2
	FileBothDirectoryInformation,            // 3
	FileBasicInformation,                    // 4
	FileStandardInformation,                 // 5
	FileInternalInformation,                 // 6
	FileEaInformation,                       // 7
	FileAccessInformation,                   // 8
	FileNameInformation,                     // 9
	FileRenameInformation,                   // 10
	FileLinkInformation,                     // 11
	FileNamesInformation,                    // 12
	FileDispositionInformation,              // 13
	FilePositionInformation,                 // 14
	FileFullEaInformation,                   // 15
	FileModeInformation,                     // 16
	FileAlignmentInformation,                // 17
	FileAllInformation,                      // 18
	FileAllocationInformation,               // 19
	FileEndOfFileInformation,                // 20
	FileAlternateNameInformation,            // 21
	FileStreamInformation,                   // 22
	FilePipeInformation,                     // 23
	FilePipeLocalInformation,                // 24
	FilePipeRemoteInformation,               // 25
	FileMailslotQueryInformation,            // 26
	FileMailslotSetInformation,              // 27
	FileCompressionInformation,              // 28
	FileObjectIdInformation,                 // 29
	FileCompletionInformation,               // 30
	FileMoveClusterInformation,              // 31
	FileQuotaInformation,                    // 32
	FileReparsePointInformation,             // 33
	FileNetworkOpenInformation,              // 34
	FileAttributeTagInformation,             // 35
	FileTrackingInformation,                 // 36
	FileIdBothDirectoryInformation,          // 37
	FileIdFullDirectoryInformation,          // 38
	FileValidDataLengthInformation,          // 39
	FileShortNameInformation,                // 40
	FileIoCompletionNotificationInformation, // 41
	FileIoStatusBlockRangeInformation,       // 42
	FileIoPriorityHintInformation,           // 43
	FileSfioReserveInformation,              // 44
	FileSfioVolumeInformation,               // 45
	FileHardLinkInformation,                 // 46
	FileProcessIdsUsingFileInformation,      // 47
	FileNormalizedNameInformation,           // 48
	FileNetworkPhysicalNameInformation,      // 49
	FileIdGlobalTxDirectoryInformation,      // 50
	FileIsRemoteDeviceInformation,           // 51
	FileUnusedInformation,                   // 52
	FileNumaNodeInformation,                 // 53
	FileStandardLinkInformation,             // 54
	FileRemoteProtocolInformation,           // 55

	//
	//  These are special versions of these operations (defined earlier)
	//  which can be used by kernel mode drivers only to bypass security
	//  access checks for Rename and HardLink operations.  These operations
	//  are only recognized by the IOManager, a file system should never
	//  receive these.
	//

	FileRenameInformationBypassAccessCheck, // 56
	FileLinkInformationBypassAccessCheck,   // 57

	//
	// End of special information classes reserved for IOManager.
	//

	FileVolumeNameInformation,                    // 58
	FileIdInformation,                            // 59
	FileIdExtdDirectoryInformation,               // 60
	FileReplaceCompletionInformation,             // 61
	FileHardLinkFullIdInformation,                // 62
	FileIdExtdBothDirectoryInformation,           // 63
	FileDispositionInformationEx,                 // 64
	FileRenameInformationEx,                      // 65
	FileRenameInformationExBypassAccessCheck,     // 66
	FileDesiredStorageClassInformation,           // 67
	FileStatInformation,                          // 68
	FileMemoryPartitionInformation,               // 69
	FileStatLxInformation,                        // 70
	FileCaseSensitiveInformation,                 // 71
	FileLinkInformationEx,                        // 72
	FileLinkInformationExBypassAccessCheck,       // 73
	FileStorageReserveIdInformation,              // 74
	FileCaseSensitiveInformationForceAccessCheck, // 75
	FileKnownFolderInformation,                   // 76

	FileMaximumInformation
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

typedef struct _FILE_BASIC_INFORMATION {
	LARGE_INTEGER CreationTime;   // Created
	LARGE_INTEGER LastAccessTime; // Accessed
	LARGE_INTEGER LastWriteTime;  // Modifed
	LARGE_INTEGER ChangeTime;     // Entry Modified
	ULONG FileAttributes;
} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;

using FuncNtQueryInformationFile = NTSYSCALLAPI NTSTATUS (NTAPI*)(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
	PVOID FileInformation,
    ULONG Length,
	FILE_INFORMATION_CLASS FileInformationClass
);
FuncNtQueryInformationFile NtQueryInformationFile = nullptr;

using FuncNtSetInformationFile = NTSTATUS (NTAPI*)(
	HANDLE FileHandle,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID FileInformation,
	ULONG Length,
	FILE_INFORMATION_CLASS FileInformationClass
);
FuncNtSetInformationFile NtSetInformationFile = nullptr;

using FuncNtQueryDirectoryFile = NTSTATUS (NTAPI*)(
	HANDLE                 FileHandle,
	HANDLE                 Event,
	PVOID				   ApcRoutine,
	PVOID                  ApcContext,
	PIO_STATUS_BLOCK       IoStatusBlock,
	PVOID                  FileInformation,
	ULONG                  Length,
	FILE_INFORMATION_CLASS FileInformationClass,
	BOOLEAN                ReturnSingleEntry,
	PUNICODE_STRING        FileName,
	BOOLEAN                RestartScan
);
FuncNtQueryDirectoryFile NtQueryDirectoryFile = nullptr;

using FuncRtlInitUnicodeString = void (NTAPI*)(
	PUNICODE_STRING DestinationString,
	PCWSTR          SourceString
);
FuncRtlInitUnicodeString RtlInitUnicodeString = nullptr;

std::optional<FILE_BASIC_INFORMATION> GetFileBasicInformation(const std::wstring fullPath) {
	auto fileHandle = CreateFileW(
		fullPath.c_str(),
		FILE_ALL_ACCESS,
		0,
		NULL,
		OPEN_EXISTING,
		0,
		NULL
	);
	if (fileHandle == INVALID_HANDLE_VALUE) {
		std::wcerr << L"Cannot Open File" << std::endl;
		return std::nullopt;
	}

	IO_STATUS_BLOCK ioStatusBlock{};
	FILE_BASIC_INFORMATION fileBasicInformation{};
	const auto status = NtQueryInformationFile(
		fileHandle,
		&ioStatusBlock,
		&fileBasicInformation,
		sizeof(FILE_BASIC_INFORMATION),
		FileBasicInformation
	);
	if (status < 0) {
		std::wcerr << "Failed to call NtQueryInformationFile (status code: " << std::hex << status << ")" << std::endl;
		CloseHandle(fileHandle);
		return std::nullopt;
	}

	CloseHandle(fileHandle);
	return fileBasicInformation;
}

void SetFileBasicInformation(const std::wstring& fullPath, FILE_BASIC_INFORMATION& fileBasicInformation) {
	auto fileHandle = CreateFileW(
		fullPath.c_str(),
		FILE_ALL_ACCESS,
		0,
		NULL,
		OPEN_EXISTING,
		0,
		NULL
	);
	if (fileHandle == INVALID_HANDLE_VALUE) {
		std::wcerr << L"Cannot Open File" << std::endl;
		return;
	}

	IO_STATUS_BLOCK ioStatusBlock{};
	const auto status = NtSetInformationFile(
		fileHandle,
		&ioStatusBlock,
		&fileBasicInformation,
		sizeof(FILE_BASIC_INFORMATION),
		FileBasicInformation
	);
	if (status < 0) {
		std::wcerr << "Failed to call NtSetInformationFile (status code: " << std::hex << status << ")" << std::endl;
	}

	CloseHandle(fileHandle);
}

void ShowFileBasicInformation(const FILE_BASIC_INFORMATION& fileBasicInformation) {
	std::wcout << "CreationTime ($SI):          " << std::hex << fileBasicInformation.CreationTime.QuadPart << std::endl;
	std::wcout << "LastAccessTime ($SI):        " << std::hex << fileBasicInformation.LastAccessTime.QuadPart << std::endl;
	std::wcout << "LastWriteTime ($SI):         " << std::hex << fileBasicInformation.LastWriteTime.QuadPart << std::endl;
	std::wcout << "ChangeTime ($SI):            " << std::hex << fileBasicInformation.ChangeTime.QuadPart << std::endl;
}

void ShowFilenameTimestamps(const FILE_BOTH_DIR_INFORMATION* fileBothDirInformation) {
	std::wcout << "CreationTime ($FN in dir):   " << std::hex << fileBothDirInformation->CreationTime.QuadPart << std::endl;
	std::wcout << "LastAccessTime ($FN in dir): " << std::hex << fileBothDirInformation->LastAccessTime.QuadPart << std::endl;
	std::wcout << "LastWriteTime ($FN in dir):  " << std::hex << fileBothDirInformation->LastWriteTime.QuadPart << std::endl;
	std::wcout << "ChangeTime ($FN in dir):     " << std::hex << fileBothDirInformation->ChangeTime.QuadPart << std::endl;
}

void Initialize(HMODULE ntdllBase) {
	NtQueryInformationFile = (FuncNtQueryInformationFile)GetProcAddress(
		ntdllBase,
		"NtQueryInformationFile"
	);
	NtSetInformationFile = (FuncNtSetInformationFile)GetProcAddress(
		ntdllBase,
		"NtSetInformationFile"
	);
	NtQueryDirectoryFile = (FuncNtQueryDirectoryFile)GetProcAddress(
		ntdllBase,
		"NtQueryDirectoryFile"
	);
	RtlInitUnicodeString = (FuncRtlInitUnicodeString)GetProcAddress(
		ntdllBase,
		"RtlInitUnicodeString"
	);
}

std::optional<FILE_BOTH_DIR_INFORMATION*> GetFileNameTimestampsInDir(const std::wstring& dirName, const std::wstring& fileName) {
	HANDLE dirHandle = CreateFileW(
		dirName.c_str(),
		GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_BACKUP_SEMANTICS,
		NULL);
	if (dirHandle == INVALID_HANDLE_VALUE) {
		std::wcerr << L"Cannot Open Directory" << std::endl;
		return std::nullopt;
	}
	IO_STATUS_BLOCK iosb;
	UNICODE_STRING fileNameUnicode{};
	RtlInitUnicodeString(&fileNameUnicode, fileName.c_str());

	BYTE* outputBuffer = (BYTE*)calloc(1, 1024);

	NTSTATUS st = NtQueryDirectoryFile(dirHandle,
		NULL,
		NULL,
		NULL,
		&iosb,
		outputBuffer,
		1024,
		FileBothDirectoryInformation,
		TRUE,
		&fileNameUnicode,
		FALSE);
	if (st < 0) {
		std::wcerr << L"Failed to call NtQueryDirectoryFile status code (" << std::hex << st << L")" << std::endl;
		CloseHandle(dirHandle);
		return std::nullopt;
	}

	CloseHandle(dirHandle);
	return (FILE_BOTH_DIR_INFORMATION*)outputBuffer;
}

int wmain(int argc, wchar_t *argv[]) {
	if (argc != 2) {
		std::wcerr << L"Usage: " << argv[0] << L" <InputFileName>" << std::endl;
		return EXIT_FAILURE;
	}

	const auto fullPath = fs::absolute(argv[1]);
	const auto dirName = fullPath.parent_path().wstring();
	const auto fileName = fullPath.filename().wstring();

	const auto ntdllBase = LoadLibraryA("ntdll.dll");
	if (!ntdllBase) {
		std::wcerr << L"Cannot get ntdll base address" << std::endl;
		return EXIT_FAILURE;
	}
	Initialize(ntdllBase);

	auto fileBasicInformationBefore = GetFileBasicInformation(fullPath);
	if (!fileBasicInformationBefore) {
		return EXIT_FAILURE;
	}
	auto fileNameTimestampsInDirBefore = GetFileNameTimestampsInDir(dirName, fileName);
	if (!fileNameTimestampsInDirBefore) {
		return EXIT_FAILURE;
	}

	std::wcout << "Initial timestamps" << std::endl;
	ShowFileBasicInformation(fileBasicInformationBefore.value());
	ShowFilenameTimestamps(fileNameTimestampsInDirBefore.value());
	std::wcout << std::endl;

#if 0
	std::wcout << "Please Modify " << fileName << std::endl;
	std::wcout << "Type \"continue\" after modifying" << std::endl;
	std::string in;
	std::cin >> in;
#endif

	std::wcout << "Modifying " << fileName << std::endl;
	auto handle = CreateFileW(fullPath.c_str(), GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (handle == INVALID_HANDLE_VALUE) {
		std::wcerr << L"Cannot open file " << fullPath << std::endl;
		return EXIT_FAILURE;
	}
	DWORD nBytes = 0;
	const char* contents = "test contents";
	if (WriteFile(handle, contents, strlen(contents), &nBytes, NULL) == 0) {
		std::wcerr << L"Cannot Write file" << fullPath << std::endl;
		return EXIT_FAILURE;
	}
	CloseHandle(handle);
	std::wcout << std::endl;

	auto fileBasicInformationAfter = GetFileBasicInformation(fullPath);
	if (!fileBasicInformationAfter) {
		return EXIT_FAILURE;
	}
	auto fileNameTimestampsInDirAfter = GetFileNameTimestampsInDir(dirName, fileName);
	if (!fileNameTimestampsInDirAfter) {
		return EXIT_FAILURE;
	}
	std::wcout << "Timestamps after modifying file" << std::endl;
	ShowFileBasicInformation(fileBasicInformationAfter.value());
	ShowFilenameTimestamps(fileNameTimestampsInDirAfter.value());
	std::wcout << std::endl;

	// 4. change the timestamp
	SetFileBasicInformation(fullPath, fileBasicInformationBefore.value());
	auto fileBasicInformationAfter2 = GetFileBasicInformation(fullPath);
	if (!fileBasicInformationAfter2) {
		return EXIT_FAILURE;
	}
	auto fileNameTimestampsInDirAfter2 = GetFileNameTimestampsInDir(dirName, fileName);
	if (!fileNameTimestampsInDirAfter2) {
		return EXIT_FAILURE;
	}
	std::wcout << "Timestamps after timestomping" << std::endl;
	ShowFileBasicInformation(fileBasicInformationAfter2.value());
	ShowFilenameTimestamps(fileNameTimestampsInDirAfter2.value());

	return EXIT_SUCCESS;
}