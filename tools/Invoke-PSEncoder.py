#!/usr/bin/env python3
"""
tools/Invoke-PSEncoder.py
Generate PowerShell -EncodedCommand oneliners from PS1 files or raw strings.

The -EncodedCommand flag accepts a Base64-encoded UTF-16LE string and bypasses
the execution policy (Restricted / AllSigned) because the command is treated
as an in-memory string, not a script file read from disk.

Usage:
    # Encode a PS1 file
    python3 Invoke-PSEncoder.py scripts/Check-All.ps1

    # Encode a raw PowerShell string
    python3 Invoke-PSEncoder.py -c ".\scripts\Check-All.ps1 -OnlyReachable -Stats"

    # Encode and add extra flags
    python3 Invoke-PSEncoder.py scripts/Check-All.ps1 --hidden --bypass

    # Pipe into clipboard (Linux)
    python3 Invoke-PSEncoder.py scripts/Check-All.ps1 | xclip -selection clipboard

    # Pipe into clipboard (macOS)
    python3 Invoke-PSEncoder.py scripts/Check-All.ps1 | pbcopy

Options:
    file                   Path to a .ps1 file to encode
    -c, --command STRING   Raw PowerShell command string to encode
    --hidden               Append -WindowStyle Hidden
    --bypass               Append -ExecutionPolicy Bypass (redundant with
                           -EncodedCommand but useful when invoking powershell.exe
                           from a context that does not bypass policy automatically)
    --32                   Use 32-bit PowerShell (SysWOW64)
    --noexit               Append -NoExit (keep shell open after execution)
    -q, --quiet            Output only the oneliner, no decorative output
"""

import argparse
import base64
import sys
from pathlib import Path


def encode_command(ps_code: str) -> str:
    """Encode a PowerShell string as Base64 UTF-16LE (what -EncodedCommand expects)."""
    return base64.b64encode(ps_code.encode("utf-16-le")).decode("ascii")


def build_oneliner(
    encoded: str,
    use_hidden: bool = False,
    use_bypass: bool = False,
    use_32bit: bool = False,
    use_noexit: bool = False,
) -> str:
    if use_32bit:
        exe = r"C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
    else:
        exe = "powershell.exe"

    parts = [exe]
    parts += ["-NonInteractive", "-NoProfile", "-NoLogo"]

    if use_hidden:
        parts += ["-WindowStyle", "Hidden"]
    if use_bypass:
        parts += ["-ExecutionPolicy", "Bypass"]
    if use_noexit:
        parts.append("-NoExit")

    parts += ["-EncodedCommand", encoded]
    return " ".join(parts)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="Invoke-PSEncoder",
        description="Generate PowerShell -EncodedCommand oneliners.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    src_group = parser.add_mutually_exclusive_group(required=True)
    src_group.add_argument(
        "file",
        nargs="?",
        help="Path to a .ps1 file to encode.",
    )
    src_group.add_argument(
        "-c", "--command",
        metavar="STRING",
        help="Raw PowerShell command string to encode.",
    )

    parser.add_argument("--hidden",  action="store_true", help="Add -WindowStyle Hidden")
    parser.add_argument("--bypass",  action="store_true", help="Add -ExecutionPolicy Bypass")
    parser.add_argument("--32",      action="store_true", dest="use_32bit",
                        help="Use 32-bit PowerShell (SysWOW64)")
    parser.add_argument("--noexit",  action="store_true", help="Add -NoExit")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Output only the oneliner (no decoration)")

    args = parser.parse_args()

    # Read input
    if args.command:
        ps_code = args.command
        source_label = "<inline command>"
    else:
        path = Path(args.file)
        if not path.exists():
            print(f"[!] File not found: {path}", file=sys.stderr)
            sys.exit(1)
        ps_code = path.read_text(encoding="utf-8")
        source_label = str(path)

    encoded  = encode_command(ps_code)
    oneliner = build_oneliner(
        encoded,
        use_hidden=args.hidden,
        use_bypass=args.bypass,
        use_32bit=args.use_32bit,
        use_noexit=args.noexit,
    )

    if not args.quiet:
        print()
        print(f"  Source  : {source_label}")
        print(f"  Length  : {len(ps_code)} chars -> {len(encoded)} chars (Base64)")
        print()
        print("  --- ONELINER ---")
        print()

    print(oneliner)

    if not args.quiet:
        print()
        print("  [i] Paste the line above into any shell.")
        print("  [i] -EncodedCommand bypasses Restricted and AllSigned execution policies.")
        print()


if __name__ == "__main__":
    main()
