<#
.SYNOPSIS
    Enumerates all Active Directory computer accounts and probes network reachability.

.DESCRIPTION
    Check-All.ps1 is a wrapper around Get-MachineInventory from ADMappingToolkit.psm1.
    It queries all domain computers regardless of OS family, then optionally probes each
    host via ICMP ping, TCP port scanning, WinRM, PSSession, and LDAP. It also supports
    pure IP/CIDR/range targets for network-based discovery beyond the AD perimeter.

    The tool combines two complementary data sources:
      - Active Directory: known managed assets (Name, OS, OU, LastLogon, Enabled)
      - Active network scan: detects any responding host, whether in AD or not

    For IP targets, a DNS PTR lookup and AD correlation chain is performed to enrich
    non-AD devices with domain metadata when a match is found.

.PARAMETER SearchBase
    LDAP distinguished name of the OU to scope the AD query. Empty string targets the
    entire domain.

.PARAMETER Targets
    Override AD query with explicit targets. Accepts: hostnames, wildcards (SRV-*),
    single IPs, CIDR notation (10.0.0.0/24), IP ranges (10.0.0.1-50), or any mix.

.PARAMETER TcpCheck
    Probe TCP ports defined by -Ports on each host.

.PARAMETER Ports
    Comma-separated list of TCP ports to probe, or a keyword: Top5, Top10, Top20,
    Top50, Top100. Setting a Top keyword automatically enables -TcpCheck.

.PARAMETER NoIcmp
    Skip ICMP echo requests. Use in conjunction with -TcpCheck for TCP-only probing.

.PARAMETER PingCount
    Number of ICMP echo requests per host. Default: 1.

.PARAMETER TimeoutMs
    TCP connection timeout in milliseconds. Default: 1200.

.PARAMETER OnlyReachable
    Return only hosts that responded to ICMP or TCP.

.PARAMETER OnlyUnreachable
    Return only hosts that did not respond to any probe.

.PARAMETER IncludeDisabled
    Include disabled AD computer accounts in the query results.

.PARAMETER OnlyDisabled
    Return only disabled AD computer accounts.

.PARAMETER MinDaysInactive
    Filter to computers whose LastLogonDate is older than N days. 0 disables the filter.

.PARAMETER ADOnly
    Skip all network probes. Return AD attributes only.

.PARAMETER Stealth
    Enable stealth mode: sequential scan with random inter-host delay. Randomizes scan
    order to avoid sequential patterns detectable by IDS/SIEM. Disables Turbo.

.PARAMETER StealthDelay
    Two-element array defining the min/max random delay in seconds between hosts in
    Stealth mode. Default: @(2, 10).

.PARAMETER Turbo
    Enable parallel scanning via ForEach-Object -Parallel. Requires PowerShell 7+.
    Automatically falls back to sequential mode on PowerShell 5.1. Mutually exclusive
    with -Stealth.

.PARAMETER Threads
    Maximum number of parallel threads in Turbo mode. Default: 50. Capped at 1000.

.PARAMETER CheckWinRM
    Test WinRM availability via Test-WSMan on each reachable host.

.PARAMETER CheckPSSession
    Attempt New-PSSession to verify remote PowerShell execution capability.

.PARAMETER CheckLDAP
    Probe TCP 389 (LDAP) and TCP 636 (LDAPS) to identify directory services.

.PARAMETER CheckUnconstrained
    Retrieve TrustedForDelegation from AD. Flag machines configured with unconstrained
    Kerberos delegation — a critical attack vector allowing TGT theft.

.PARAMETER CheckEOS
    Flag machines running end-of-support operating systems (Windows XP, Vista, 7, 8,
    Server 2003, 2008, 2012) that no longer receive security patches.

.PARAMETER ResolveDns
    Perform reverse DNS (PTR) lookups on IP targets for AD correlation.

.PARAMETER ShowOU
    Include the Organizational Unit path in output.

.PARAMETER ShowDescription
    Include the AD computer description field in output.

.PARAMETER ShowEnabled
    Include the Enabled status column in output.

.PARAMETER Credential
    PSCredential for AD queries and WinRM/PSSession checks.

.PARAMETER Properties
    Array of property names to include in output. Default: * (all).

.PARAMETER RawOutput
    Return raw PSObject array. Suppresses table formatting for pipeline use.

.PARAMETER Stats
    Print a summary line: total / reachable / unreachable / reachability percentage.

.PARAMETER AutoCsv
    Export results to an auto-generated timestamped CSV file.

.PARAMETER OutCsv
    Export results to the specified CSV file path.

.PARAMETER Report
    Generate a named report. Accepted values: Inactive, OpenRDP.

.PARAMETER ReportDays
    Lookback window in days for the Inactive report. Default: 30.

.EXAMPLE
    .\scripts\Check-All.ps1 -OnlyReachable -Stats
    Enumerate all AD computers, ICMP-ping each one, return reachable hosts with stats.

.EXAMPLE
    .\scripts\Check-All.ps1 -Targets "10.0.0.0/24" -ResolveDns -Turbo -AutoCsv
    Full subnet scan with AD correlation, parallel mode, export to timestamped CSV.

.EXAMPLE
    .\scripts\Check-All.ps1 -ADOnly -CheckUnconstrained -ShowOU
    List all AD computers with unconstrained delegation flag and OU path. No network probes.

.EXAMPLE
    .\scripts\Check-All.ps1 -TcpCheck -Ports Top20 -Turbo -OnlyReachable -Stats
    Top 20 port scan across all domain computers in parallel.

.EXAMPLE
    .\scripts\Check-All.ps1 -Stealth -StealthDelay 5,15 -TcpCheck -Ports 445,3389
    Low-noise sweep with 5-15 s random delay between probes.

.NOTES
    Requires the RSAT ActiveDirectory module for AD queries.
    Turbo mode requires PowerShell 7+. Stealth and Turbo are mutually exclusive.
    MITRE ATT&CK: T1018 (Remote System Discovery), T1046 (Network Service Scanning),
                  T1482 (Domain Trust Discovery).
#>
Param(
  [string]$SearchBase = "",
  [switch]$TcpCheck,
  [string]$Ports = "445,3389,5985",
  [switch]$NoIcmp,
  [int]$PingCount = 1,
  [int]$TimeoutMs = 1200,
  [switch]$OnlyReachable,
  [switch]$OnlyUnreachable,
  [switch]$IncludeDisabled,
  [switch]$OnlyDisabled,
  [switch]$Stats,
  [string[]]$Properties = "*",
  [switch]$RawOutput,
  [switch]$AutoCsv,
  [string]$OutCsv = "",
  [int]$MinDaysInactive = 0,
  [switch]$ADOnly,
  [switch]$Stealth,
  [switch]$CheckWinRM,
  [switch]$Turbo,
  [int[]]$StealthDelay = @(2, 10),
  [int]$Threads = 50,
  [string[]]$Targets,
  [switch]$ResolveDns,
  [switch]$CheckUnconstrained,
  [switch]$CheckPSSession,
  [switch]$ShowDescription,
  [switch]$ShowOU,
  [switch]$ShowEnabled,
  [PSCredential]$Credential,
  [switch]$CheckLDAP,
  [switch]$CheckEOS,
  [ValidateSet('Inactive', 'OpenRDP')]
  [string]$Report,
  [int]$ReportDays = 30
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modPath = Join-Path (Split-Path $PSScriptRoot -Parent) 'ADMappingToolkit.psm1'
if (-not (Test-Path $modPath)) { throw "Module not found at: $modPath" }
Import-Module $modPath -Force -ErrorAction Stop

# --- Port Keyword Expansion & Logic (Duplicated from Module for Display/Param Consistency) ---
$top5 = "21,22,80,443,3389"
$top10 = "$top5,25,53,135,139,445"
$top20 = "$top10,110,143,389,1433,3306,5900,5985,8080,8443"
$top50 = "$top20,23,69,88,111,119,161,162,179,199,381,382,383,464,444,513,514,515,543,544,548,554,587,631,636,873,989,990,993,995"
$top100 = "$top50,1025,1194,1521,1701,1723,2000,2049,2082,2083,2121,2222,2375,2376,2483,2484,3268,3269,3388,4000,4444,4500,4848,5000,5060,5432,5555,5631,5632,5800,5901,5902,5938,6000,6001,6667,7000,7001,8000,8008,8081,8088,8090,8222,8444,8500,8888,9000,9090,9418,9999"

if ($Ports -match '^Top(\d+)$') {
  switch ($Ports) {
    "Top5" { $Ports = $top5; break }
    "Top10" { $Ports = $top10; break }
    "Top20" { $Ports = $top20; break }
    "Top50" { $Ports = $top50; break }
    "Top100" { $Ports = $top100; break }
    Default { Write-Warning "Unknown Top list '$Ports'. Using default."; $Ports = "445,3389,5985" }
  }
  # Auto-enable TcpCheck for Top lists
  $TcpCheck = $true
}

if ($Report -eq 'OpenRDP') {
  $TcpCheck = $true
  $p = $Ports -split '[,; ]+'
  if ('3389' -notin $p) { $Ports += ",3389" }
}

# Call generic inventory without specific OS filter (default is *)
$view = Get-MachineInventory `
  -SearchBase $SearchBase -TcpCheck:$TcpCheck -Ports $Ports -NoIcmp:$NoIcmp `
  -PingCount $PingCount -TimeoutMs $TimeoutMs `
  -OnlyReachable:$OnlyReachable -OnlyUnreachable:$OnlyUnreachable `
  -IncludeDisabled:$IncludeDisabled -OnlyDisabled:$OnlyDisabled `
  -MinDaysInactive $MinDaysInactive -ADOnly:$ADOnly -Stealth:$Stealth -CheckWinRM:$CheckWinRM -Turbo:$Turbo `
  -StealthDelay $StealthDelay -Threads $Threads `
  -Targets $Targets -ResolveDns:$ResolveDns `
  -CheckUnconstrained:$CheckUnconstrained `
  -CheckPSSession:$CheckPSSession `
  -ShowDescription:$ShowDescription -ShowOU:$ShowOU `
  -Credential $Credential `
  -CheckLDAP:$CheckLDAP `
  -CheckEOS:$CheckEOS `
  -Report $Report `
  -ReportDays $ReportDays

# Properties selection
if ($Properties -and $Properties -ne "*") {
  $view = $view | Select-Object -Property $Properties
}

# Export CSV
if ($AutoCsv) {
  $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
  $autoName = "Cartographie-Global_$timestamp.csv"
  if ($OutCsv) {
    if (-not $OutCsv) { $OutCsv = $autoName }
  }
  else {
    $OutCsv = $autoName
  }
}

if ($OutCsv) {
  if ($OutCsv -notmatch '\.csv$') { $OutCsv = "$OutCsv.csv" }
  $dir = Split-Path -Path $OutCsv -Parent
  if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  $view | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8
  if (-not $RawOutput) { "CSV written to: $OutCsv" | Write-Host }
}

# Output
if ($RawOutput) {
  return $view
}

if ($Properties -and $Properties -eq "*") {
  # Optimize default view for console width dynamically
  $displayCols = @("Name")

  if (-not $ADOnly) {
    if ($CheckWinRM) { $displayCols += "WinRM" }
    if ($CheckPSSession) { $displayCols += "PSSession" }
    $displayCols += "Reachable"
    if (-not $NoIcmp) { $displayCols += "PingICMP" }
    
    if ($TcpCheck -or $CheckLDAP) {
      if ($CheckLDAP) {
        if (-not $TcpCheck) {
          # Standalone LDAP check: Show ONLY LDAP ports
          $Ports = "389,636"
        }
        else {
          # Combined: Add LDAP ports if missing (checking properly)
          $p = $Ports -split '[,; ]+'
          if ('389' -notin $p) { $Ports += ",389" }
          if ('636' -notin $p) { $Ports += ",636" }
        }
      }
      $portList = $Ports -split '[,; ]+' | Where-Object { $_ -match '^\d+$' }
      foreach ($p in $portList) { $displayCols += "TCP_$p" }
    }
  }

  $displayCols += @("DaysSince", "LastLogon")
  if ($CheckUnconstrained) { $displayCols += "Unconstrained" }
  if ($ShowOU) { $displayCols += "OU" }
  if ($ShowDescription) { $displayCols += "Description" }
  if ($ShowEnabled) { $displayCols += "Enabled" }
  if ($CheckEOS) { $displayCols += "EOS" }

  $displayCols += @("OS", "TargetUsed")

  # --- Dynamic Column Hiding (Network Scan Mode) ---
  # Force array to avoid "Property Count not found" on single object
  if ($view -isnot [array]) { $view = @($view) }

  $isPureNetwork = $true
  if ($view.Count -gt 0) {
    foreach ($row in $view) {
      if ($row.OU -ne "Network/IP") { $isPureNetwork = $false; break }
    }
  }
  else {
    $isPureNetwork = $false
  }

  if ($isPureNetwork) {
    # Remove AD specific columns
    $displayCols = $displayCols | Where-Object { $_ -notin @("DaysSince", "LastLogon", "OS", "OU", "Description", "Enabled") }
    # Ensure useful network columns are present
    if ("IPv4Address" -notin $displayCols) { $displayCols += "IPv4Address" }
  }

  $view | Sort-Object Name | Select-Object $displayCols | Format-Table -AutoSize
}
else {
  $view | Sort-Object Name | Format-Table -AutoSize
}

if ($Stats) {
  $total = $view.Count
  if ($view | Get-Member -Name "Reachable" -ErrorAction SilentlyContinue) {
    $up = ($view | Where-Object { $_.Reachable }).Count
  }
  else {
    $up = $null
  }
  
  if ($null -ne $up) {
    $down = $total - $up
    "{0} total machines found, {1} reachable, {2} unreachable, {3:p1} reachability" -f $total, $up, $down, ($up / [double]([math]::Max($total, 1))) | Write-Host
  }
  else {
    "{0} total machines found" -f $total | Write-Host
  }
}
