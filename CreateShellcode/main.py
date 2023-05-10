# (c) FFRI Security, Inc., 2023 / Author: FFRI Security, Inc.
import glob
import os
import sys
import time
from enum import Enum
from typing import List, Optional, Tuple

import r2pipe
import typer

app = typer.Typer()


def find_target_section(r2p, sec_name: str) -> Optional[Tuple[int, int, int]]:
    base_addr = r2p.cmdj("ij")["bin"]["baddr"]
    for sect in r2p.cmdj("iSj"):
        if sect["name"] == ".scode":
            return sect["paddr"], sect["vaddr"] - base_addr, sect["size"]
    return None


def extract_address_pairs(r2p) -> List[Tuple[int, int]]:
    x86_rvas = list()
    arm64_rvas = list()
    for i in r2p.cmdj("iHj"):
        if "address_pairs" in i["name"] and "x86_rva" in i["name"]:
            x86_rvas.append(int(i["comment"], 16))
        if "address_pairs" in i["name"] and "arm64_rva" in i["name"]:
            arm64_rvas.append(int(i["comment"], 16))
    return list(zip(x86_rvas, arm64_rvas))


class Arch(str, Enum):
    x86 = "x86"
    x64 = "x64"


@app.command()
def create_shellcode(arch: Arch) -> None:
    """
    Extract shellcode from "ShellcodeTemplate.exe" and show required RVAs for translating with xtac.exe/xtac64.exe
    """

    shellcode_output = "shellcode.bin"
    shellcode_template = "ShellcodeTemplate.exe"

    if arch == Arch.x86:
        root_dir = "../Release"
    else:
        root_dir = "../x64/Release"

    copy_src = os.path.join(root_dir, shellcode_template)
    if not os.path.exists(copy_src):
        typer.secho("[-] Please compile ShellcodeTemplate.exe", file=sys.stderr, fg=typer.colors.RED)
        return
    typer.echo(f"[+] Copying {copy_src} -> {shellcode_template}")
    os.system(f"cp -f {copy_src} {shellcode_template}")

    xta_cache_dir = "/mnt/c/Windows/XtaCache"
    if not os.access(xta_cache_dir, os.R_OK):
        typer.secho("[-] Cannot access %SystemRoot%\\XtaCache directory.", file=sys.stderr, fg=typer.colors.RED)
        typer.echo(
            "[-] If you create shellcode to be injected, you need to change the ACL of XtaCache directory.",
            file=sys.stderr,
        )
        typer.echo(
            "[-] Open cmd.exe with Administrator privilege, and run the following commands",
            file=sys.stderr,
        )
        typer.echo("takeown /f C:\\Windows\\XtaCache", file=sys.stderr)
        typer.echo("icacls C:\\Windows\\XtaCache /grant Administrators:F", file=sys.stderr)
        return

    typer.echo("[+] Cleanup existing XTA cache files")
    for f in glob.glob(os.path.join(xta_cache_dir, f"SHELLCODETEMPLATE.EXE.*.*.{arch}.*")):
        os.remove(f)

    typer.echo("[+] Running ShellcodeTemplate.exe for generating an XTA cache file")
    os.system(f"cmd.exe /c {shellcode_template}")

    typer.echo("[+] Waiting for 5s")
    time.sleep(5)

    typer.echo("[+] Extracting RVAs")
    cache_file = glob.glob(os.path.join(xta_cache_dir, f"SHELLCODETEMPLATE.EXE.*.*.{arch}.*"))[
        0
    ]

    r2p_c = r2pipe.open(cache_file)
    address_pairs = extract_address_pairs(r2p_c)

    r2p_b = r2pipe.open(shellcode_template)
    r2p_b.cmd("aaa")

    result = find_target_section(r2p_b, ".scode")
    if result is None:
        typer.secho("[-] Cannot find target section.", file=sys.stderr, fg=typer.colors.RED)
        return
    sect_paddr, sect_vaddr, sect_size = result

    typer.echo(
        f"[+] .scode: paddr is {hex(sect_paddr)}, RVA is {hex(sect_vaddr)}, section size is {hex(sect_size)}"
    )

    os.system(
        f"dd if={shellcode_template} of={shellcode_output} skip={sect_paddr} bs=1 count={sect_size}"
    )
    typer.echo(f"[+] Shellcode is saved to {shellcode_output}")
    typer.secho(f"[+] Please test this shellcode using TestShellcode.exe", fg=typer.colors.RED)

    rvas = [
        x86_addr - sect_vaddr
        for x86_addr, _ in address_pairs
        if x86_addr >= sect_vaddr
    ]
    rvas_str = ",".join(hex(rva) for rva in rvas)
    typer.secho("[+] Show required RVAs used for translating with xtac.exe/xtac64.exe and save this to \"shellcode_rvas.txt\"", fg=typer.colors.GREEN)
    typer.echo(rvas_str)
    with open("shellcode_rvas.txt", "w") as fout:
        fout.write(rvas_str + "\n")


if __name__ == "__main__":
    app()
