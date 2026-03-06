# Check-Servers.ps1
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

$modPath = Join-Path $PSScriptRoot 'ADMappingToolkit.psm1'
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

$view = Get-ServerInventory `
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

if ($AutoCsv) {
  $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
  $autoName = "Cartographie-Servers_$timestamp.csv"
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
    $displayCols = $displayCols | Where-Object { $_ -notin @("DaysSince", "LastLogon", "OS", "OU", "Description", "Enabled") }
    if ("IPv4Address" -notin $displayCols) { $displayCols += "IPv4Address" }
  }

  $view | Sort-Object Name | Select-Object $displayCols | Format-Table -AutoSize
}
else {
  $view | Sort-Object Name | Format-Table -AutoSize
}

if ($Stats) {
  $total = $view.Count
  # Need to check if Reachable property exists in case it was filtered out
  if ($view | Get-Member -Name "Reachable" -ErrorAction SilentlyContinue) {
    $up = ($view | Where-Object { $_.Reachable }).Count
  }
  else {
    # Fallback if 'Reachable' isn't selected but we want stats,
    # likely we can't compute up/down accurately if stripped.
    # Re-calculate reachable from source if possible? 
    # Actually $view is already filtered.
    # Let's just output total count.
    $up = $null
  }
  
  if ($up -ne $null) {
    $down = $total - $up
    "{0} total, {1} reachable, {2} unreachable, {3:p1} reachability" -f $total, $up, $down, ($up / [double]([math]::Max($total, 1))) | Write-Host
  }
  else {
    "{0} total servers found" -f $total | Write-Host
  }
}
