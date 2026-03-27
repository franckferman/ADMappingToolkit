<div align="center">

# ADMappingToolkit

**Active Directory machine inventory and network recon** - enumerate domain computers, probe reachability, scan ports, detect unconstrained delegation, flag end-of-support OS, and export results to CSV from the command line.

[![CI](https://github.com/franckferman/ADMappingToolkit/actions/workflows/ci.yml/badge.svg?branch=stable)](https://github.com/franckferman/ADMappingToolkit/actions/workflows/ci.yml)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?style=flat-square&logo=powershell&logoColor=white)](https://docs.microsoft.com/en-us/powershell/)
[![License](https://img.shields.io/badge/license-AGPL--3.0-blue?style=flat-square)](LICENSE)

**[Site](https://franckferman.github.io/ADMappingToolkit/) &nbsp;&middot;&nbsp; [Documentation](https://franckferman.github.io/ADMappingToolkit/doc.html)**

</div>

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Quick Start](#quick-start)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Scripts](#scripts)
  - [Check-All.ps1](#check-allps1)
  - [Check-Servers.ps1](#check-serversps1)
  - [Check-Clients.ps1](#check-clientsps1)
- [Parameters](#parameters)
- [Port Keywords](#port-keywords)
- [Target Formats](#target-formats)
- [Reports](#reports)
- [Examples](#examples)
- [Tools](#tools)
- [License](#license)

---

## Overview

ADMappingToolkit is a **hybrid SI mapping toolkit** - it combines Active Directory inventory with active network scanning to give a unified view of everything on the network, whether it appears in AD or not.

Classic AD-based inventory tools only see machines they already know. In any real enterprise network, AD is structurally incomplete: unmanaged devices, IoT equipment, printers, Linux servers, NAS, network appliances, and shadow IT never register in AD. ADMappingToolkit closes this visibility gap by combining AD queries with active network probes in a single report.

Three runner scripts cover the three most common scopes: all machines, servers only, or clients only. Each is a thin wrapper around the module functions and exposes the full parameter set directly from the command line. No installation required beyond the RSAT ActiveDirectory module.

---

## MITRE ATT&CK

| Technique | ID | Feature |
|---|---|---|
| Remote System Discovery | T1018 | AD enumeration, subnet/range scan via `-Targets` |
| Network Service Scanning | T1046 | `-TcpCheck`, `-CheckLDAP`, `-CheckWinRM`, `-CheckPSSession` |
| System Network Configuration Discovery | T1016 | `-ResolveDns`, IPv4Address / DNSHostName collection |
| Account Discovery: Domain Account | T1087.002 | AD computer account enumeration via `Get-ADComputer` |
| Domain Trust Discovery | T1482 | `-CheckUnconstrained` (TrustedForDelegation attribute) |
| Steal or Forge Kerberos Tickets | T1558 | Unconstrained delegation detection context |

---

## Features

| Capability | Description |
|---|---|
| AD enumeration | Query all domain computers, filter by OS family, scope to OU |
| ICMP ping | Parallel or sequential, configurable count and timeout |
| TCP port scan | Custom port list or Top5/Top10/Top20/Top50/Top100 keywords |
| WinRM / PSSession | Connectivity check via Test-WSMan and New-PSSession |
| LDAP check | Probe TCP 389 and 636 |
| Unconstrained delegation | Flag computers with TrustedForDelegation = True |
| End-of-support OS | Detect Windows XP, 7, 2003, 2008, Vista, 8, 8.1 |
| Stealth mode | Sequential scan with random delay between probes |
| Turbo mode | Parallel scan via ForEach-Object -Parallel (PS7+) |
| Target flexibility | Mix AD names, wildcards, IPs, CIDR, and IP ranges |
| Built-in reports | Inactive machines, open RDP exposure |
| CSV export | Auto-timestamped or explicit path |

---

## Quick Start

```powershell
# Clone
git clone https://github.com/franckferman/ADMappingToolkit.git
cd ADMappingToolkit

# Discover all reachable machines
.\scripts\Check-All.ps1 -OnlyReachable -Stats

# Probe servers for SMB, RDP, WinRM
.\scripts\Check-Servers.ps1 -TcpCheck -Ports 445,3389,5985 -OnlyReachable

# Flag end-of-support workstations and export
.\scripts\Check-Clients.ps1 -CheckEOS -ShowOU -AutoCsv

# Find computers with unconstrained delegation
.\scripts\Check-All.ps1 -ADOnly -CheckUnconstrained -ShowOU

# Stealth sweep with random 5-15 s delay
.\scripts\Check-All.ps1 -Stealth -StealthDelay 5,15 -OnlyReachable
```

---

## Project Structure

```
ADMappingToolkit.psm1       # Module - all inventory functions
scripts/
  Check-All.ps1             # Get-MachineInventory (all OS)
  Check-Servers.ps1         # Get-ServerInventory (Server OS)
  Check-Clients.ps1         # Get-ClientInventory (Client OS)
tools/
  Invoke-PSEncoder.py       # Base64 UTF-16LE encoder for -EncodedCommand
  Sign-Scripts.ps1          # Authenticode signing + RFC 3161 timestamp
docs/
  index.html                # Landing page
  doc.html                  # Full documentation
```

---

## Installation

**Prerequisites:** PowerShell 5.1+ and the RSAT ActiveDirectory module.

```powershell
# Clone
git clone https://github.com/franckferman/ADMappingToolkit.git

# Unblock if downloaded from the internet
Get-ChildItem -Recurse *.ps1,*.psm1 | Unblock-File

# Optional: import the module directly for use in your own scripts
Import-Module .\ADMappingToolkit.psm1 -Force
```

The runner scripts import the module automatically from their parent directory. No manual import needed when using the scripts.

---

## Scripts

### Check-All.ps1

Wrapper for `Get-MachineInventory`. Queries all AD computer accounts regardless of OS.

```powershell
.\scripts\Check-All.ps1 [parameters...]
```

### Check-Servers.ps1

Wrapper for `Get-ServerInventory`. Pre-filters to Windows Server OS accounts before scanning.

```powershell
.\scripts\Check-Servers.ps1 [parameters...]
```

### Check-Clients.ps1

Wrapper for `Get-ClientInventory`. Pre-filters to Windows client OS (Windows 10/11/7/XP) accounts before scanning.

```powershell
.\scripts\Check-Clients.ps1 [parameters...]
```

All three scripts accept the same parameter set described below.

---

## Parameters

### AD Query

| Parameter | Default | Description |
|---|---|---|
| `-SearchBase` | `""` | LDAP OU/DN to scope the AD query. Empty = entire domain. |
| `-IncludeDisabled` | off | Include disabled computer accounts. |
| `-OnlyDisabled` | off | Return only disabled accounts. |
| `-MinDaysInactive` | `0` | Filter to machines inactive for N+ days (0 = no filter). |
| `-Targets` | - | Override AD query: hostnames, IPs, CIDR, ranges, or wildcards. |

### Network Probing

| Parameter | Default | Description |
|---|---|---|
| `-NoIcmp` | off | Skip ICMP ping entirely. |
| `-PingCount` | `1` | Number of ICMP echo requests per host. |
| `-TimeoutMs` | `1200` | TCP connect timeout in milliseconds. |
| `-TcpCheck` | off | Probe TCP ports defined by `-Ports`. |
| `-Ports` | `445,3389,5985` | Comma-separated ports or Top5/Top10/Top20/Top50/Top100. |
| `-CheckLDAP` | off | Probe TCP 389 and 636. |
| `-CheckWinRM` | off | Test WinRM via Test-WSMan. |
| `-CheckPSSession` | off | Attempt New-PSSession for remote PS access check. |
| `-ResolveDns` | off | Reverse-resolve IPs to hostnames for AD correlation. |
| `-ADOnly` | off | Skip all network probes, return AD attributes only. |

### Filtering

| Parameter | Default | Description |
|---|---|---|
| `-OnlyReachable` | off | Return only responsive hosts. |
| `-OnlyUnreachable` | off | Return only non-responsive hosts. |

### Performance

| Parameter | Default | Description |
|---|---|---|
| `-Turbo` | off | Parallel scan via ForEach-Object -Parallel. Requires PS7+. Mutually exclusive with -Stealth. |
| `-Threads` | `50` | Thread count for Turbo mode (capped at 1000). |
| `-Stealth` | off | Sequential scan with random delay. Disables Turbo automatically. |
| `-StealthDelay` | `2,10` | Min/max random delay in seconds for Stealth mode. |

### AD Enrichment

| Parameter | Default | Description |
|---|---|---|
| `-CheckUnconstrained` | off | Flag machines with TrustedForDelegation = True. |
| `-CheckEOS` | off | Flag end-of-support OS versions. |
| `-ShowOU` | off | Include OU path in output. |
| `-ShowDescription` | off | Include AD computer description. |
| `-ShowEnabled` | off | Include Enabled column. |
| `-Credential` | - | PSCredential for AD and WinRM queries. |

### Output

| Parameter | Default | Description |
|---|---|---|
| `-Properties` | `*` | Select specific output columns. |
| `-RawOutput` | off | Return raw PSObject array, skip table formatting. |
| `-Stats` | off | Print total/reachable/unreachable summary. |
| `-AutoCsv` | off | Auto-generate a timestamped CSV file. |
| `-OutCsv` | `""` | Export to specified CSV path. |

### Reports

| Parameter | Default | Description |
|---|---|---|
| `-Report` | - | Named report: `Inactive` or `OpenRDP`. |
| `-ReportDays` | `30` | Lookback window in days for the Inactive report. |

---

## Port Keywords

Pass a keyword to `-Ports` instead of a manual list. Setting a Top keyword automatically enables `-TcpCheck`.

| Keyword | Ports |
|---|---|
| `Top5` | 21, 22, 80, 443, 3389 |
| `Top10` | Top5 + 25, 53, 135, 139, 445 |
| `Top20` | Top10 + 110, 143, 389, 1433, 3306, 5900, 5985, 8080, 8443 |
| `Top50` | Top20 + 23, 69, 88, 111, 119, 161, 162, 179, 199, ... |
| `Top100` | Top50 + 1025, 1194, 1521, 1723, 2000, 2049, 4444, 5432, ... |

---

## Target Formats

The `-Targets` parameter accepts mixed input and bypasses the AD query for the specified entries:

| Format | Example | Behavior |
|---|---|---|
| Hostname / AD name | `DC01` | Direct AD lookup by name. |
| Wildcard | `SRV-*` | AD filter: `Name -like 'SRV-*'`. |
| Single IP | `192.168.1.10` | Probed directly; optional PTR lookup with `-ResolveDns`. |
| CIDR | `192.168.1.0/24` | All host IPs in subnet (capped at 65536). |
| Short range | `192.168.1.1-50` | IPs from .1 through .50. |
| Full range | `10.0.0.1-10.0.0.100` | All IPs between the two addresses. |

```powershell
# Mixed: wildcard + CIDR
.\scripts\Check-All.ps1 -Targets SRV-*, 192.168.10.0/24 -TcpCheck -Ports 445,3389

# IP range with DNS reverse lookup
.\scripts\Check-All.ps1 -Targets 10.0.0.1-50 -ResolveDns -TcpCheck
```

---

## Reports

### Inactive

Returns machines whose last logon is older than `-ReportDays` days (default 30).

```powershell
.\scripts\Check-All.ps1 -Report Inactive -ReportDays 90 -ADOnly
```

### OpenRDP

Returns machines with TCP 3389 open. Automatically enables `-TcpCheck` and adds port 3389 to the probe list.

```powershell
.\scripts\Check-Clients.ps1 -Report OpenRDP
.\scripts\Check-Servers.ps1 -Report OpenRDP -OnlyReachable
```

---

## Examples

```powershell
# Full domain inventory, AD only
.\scripts\Check-All.ps1 -ADOnly -ShowOU -ShowDescription -ShowEnabled

# Top 20 port scan with Turbo (PS7+)
.\scripts\Check-All.ps1 -TcpCheck -Ports Top20 -Turbo -OnlyReachable -Stats

# Scope to a specific OU
.\scripts\Check-Servers.ps1 -SearchBase "OU=Servers,DC=corp,DC=local" -ADOnly

# WinRM + PSSession check on servers
.\scripts\Check-Servers.ps1 -CheckWinRM -CheckPSSession -OnlyReachable

# LDAP availability on all servers
.\scripts\Check-Servers.ps1 -CheckLDAP -OnlyReachable

# Stealth ping sweep
.\scripts\Check-All.ps1 -Stealth -StealthDelay 5,15 -OnlyReachable

# Export reachable servers to CSV
.\scripts\Check-Servers.ps1 -OnlyReachable -OutCsv C:\Audit\servers.csv

# Pipeline: filter by open RDP and export
$r = .\scripts\Check-All.ps1 -RawOutput -TcpCheck -Ports 3389
$r | Where-Object { $_.TCP_3389 } | Export-Csv rdp-exposed.csv -NoTypeInformation

# Use alternate credentials
$cred = Get-Credential
.\scripts\Check-All.ps1 -ADOnly -Credential $cred -CheckUnconstrained -ShowOU
```

---

## Tools

### tools/Invoke-PSEncoder.py

Generates `powershell.exe -EncodedCommand` oneliners from PS1 files or raw strings. Bypasses `Restricted` and `AllSigned` execution policies.

```bash
# Encode a script
python3 tools/Invoke-PSEncoder.py scripts/Check-All.ps1

# Encode a raw command
python3 tools/Invoke-PSEncoder.py -c ".\scripts\Check-All.ps1 -OnlyReachable -Stats"

# Add flags
python3 tools/Invoke-PSEncoder.py scripts/Check-All.ps1 --hidden --bypass

# Quiet mode (oneliner only)
python3 tools/Invoke-PSEncoder.py -q scripts/Check-All.ps1
```

### tools/Sign-Scripts.ps1

Signs all scripts in `scripts/` and `ADMappingToolkit.psm1` with Authenticode + RFC 3161 timestamp. The countersignature keeps signatures valid after certificate expiry.

Authenticode signing reduces detection surface: signed scripts bypass `AllSigned` execution policy without `-ExecutionPolicy Bypass`, and a valid signature lowers static heuristic scores in some EDRs and AV engines that weigh unsigned scripts more aggressively.

```powershell
# Auto-generate temporary self-signed cert, sign, then remove cert
.\tools\Sign-Scripts.ps1

# Use an existing cert by thumbprint
.\tools\Sign-Scripts.ps1 -CertThumbprint "AB12CD..."

# Use a different timestamp server
.\tools\Sign-Scripts.ps1 -TimestampServer "http://timestamp.sectigo.com"
```

**Self-signed vs production:**

| Cert type | Execution policy bypass | SmartScreen | EDR static score |
|---|---|---|---|
| None | Requires `-ExecutionPolicy Bypass` | Flagged | Higher risk weight |
| Self-signed | Passes `AllSigned` if cert is trusted locally | Still flagged | Slight improvement |
| OV code-signing | Passes `AllSigned` | Reduced warnings | Lower risk weight |
| EV code-signing | Passes `AllSigned` | Instant reputation | Best reduction |

For meaningful evasion improvement, use an OV or EV certificate (DigiCert, Sectigo, GlobalSign). EV certs provide instant SmartScreen reputation and the strongest reduction in static detection.

---

## Use Cases

### For security teams / RSSI

| Need | How |
|---|---|
| How many machines are actually on our network? | Subnet scan with `-Targets 10.0.0.0/24 -ResolveDns -Turbo` |
| Do we have end-of-support OS? | `-CheckEOS` flags Windows XP, 7, Vista, 2003, 2008, 2012 |
| Which servers have RDP exposed? | `-Report OpenRDP` |
| Ghost machines inactive for 90+ days? | `-MinDaysInactive 90 -ADOnly` |
| Can we remotely administer a host? | `-CheckWinRM -CheckPSSession` |
| Kerberos unconstrained delegation risk? | `-CheckUnconstrained` |
| ISO 27001 / ANSSI asset inventory? | Full subnet scan + `-AutoCsv` for timestamped evidence |
| Shadow IT / unmanaged devices? | Scan returns non-AD objects as synthetic entries |

### AD correlation chain

When scanning a raw IP, the tool does not just report "this IP responded". It runs a full correlation chain:

1. Reverse DNS lookup (`Resolve-DnsName -Type PTR`) to get the FQDN
2. AD lookup by `DNSHostName` or `Name` to find a match
3. If found: the entry is enriched with OS, OU, LastLogon, and all AD metadata
4. If not found: a synthetic object is created — the machine is flagged as non-AD

This means a single subnet scan returns both your managed Windows fleet and every unmanaged device on the same network.

## Real-World Results

Scan of a `/24` subnet (254 hosts) in a production environment:

| Category | Count | Details |
|---|---|---|
| Total responding hosts | 126 | Out of 254 scanned |
| Windows machines (AD-matched) | ~50 | Workstations and servers enriched with OS, OU, LastLogon |
| Non-AD devices | ~76 | Printers, Raspberry Pi, NAS, Linux servers, IoT, appliances, smartphones |
| EOS servers detected | 2 | Windows Server 2012 R2, Windows Server 2008 R2 |

In one command: a complete 360-degree view of the network — managed and unmanaged alike.

---

## License

This project is licensed under the [GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0).

Any use, modification, or distribution - including over a network - requires the full source code to remain open under the same license.
