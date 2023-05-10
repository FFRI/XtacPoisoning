// (c) FFRI Security, Inc., 2023 / Author: FFRI Security, Inc.
#include <Windows.h>
#include <iostream>
#include <fstream>
#include <filesystem>

namespace fs = std::filesystem;

int main(int argc, char* argv[]) {
	if (argc != 2) {
		std::cout << "[-] Usage: " << argv[0] << " <path to shellcode>" << std::endl;
		return EXIT_FAILURE;
	}

	std::string inputFile = argv[1];
	const auto fsize = fs::file_size(inputFile);
	std::cout << "[+] Shellcode size is " << fsize << std::endl;

	std::vector<byte> shellcode(fsize, 0);

	std::ifstream fin(inputFile, std::ios::binary);
	fin.read((char*)shellcode.data(), fsize);

	DWORD oldProtect = 0;
	auto stat = VirtualProtect((LPVOID)shellcode.data(), shellcode.size(), PAGE_EXECUTE_READWRITE, &oldProtect);
	if (stat == 0) {
		std::cerr << "[-] VirtualProtect failed" << std::endl;
		return EXIT_FAILURE;
	}

	std::cout << "[+] Running shellcode" << std::endl;
	using func_t = void(__cdecl*)();
	((func_t)shellcode.data())();

	std::cout << "[+] Success" << std::endl;
}