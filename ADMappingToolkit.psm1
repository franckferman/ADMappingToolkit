# ADMappingToolkit.psm1
Set-StrictMode -Version Latest

# ---------- Utils ----------
function Resolve-ToIP {
  param([Parameter(Mandatory)][string]$Target)
  if ($Target -match '^\d{1,3}(\.\d{1,3}){3}$') { return $Target }
  try {
    $a = Resolve-DnsName -Name $Target -Type A -ErrorAction Stop | Select-Object -First 1 -ExpandProperty IPAddress
    if ($a) { return $a }
  } catch {}
  try {
    $addr = [System.Net.Dns]::GetHostAddresses($Target) |
            Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
            Select-Object -First 1
    if ($addr) { return $addr.IPAddressToString }
  } catch {}
  return $null
}

function Test-Icmp {
  param([Parameter(Mandatory)][string]$Computer, [int]$Count = 1)
  try {
    return (Test-Connection -ComputerName $Computer -Count $Count -Quiet -ErrorAction SilentlyContinue)
  } catch { return $false }
}

function Test-TcpPort {
  param([Parameter(Mandatory)][string]$Computer, [Parameter(Mandatory)][int]$Port, [int]$TimeoutMs = 1200)
  $client = New-Object System.Net.Sockets.TcpClient
  try {
    $iar = $client.BeginConnect($Computer, $Port, $null, $null)
    if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { $client.Close(); return $false }
    $client.EndConnect($iar)
    $client.Close()
    return $true
  } catch {
    try { $client.Close() } catch {}
    return $false
  }
}

# ---------- Inventory ----------
# --- Helper Functions for Target Parsing ---
function Get-IpsFromCidr {
    param([string]$Cidr)
    try {
        $ipStr, $maskBits = $Cidr.Split('/')
        [int]$mask = $maskBits
        $ipAddr = [System.Net.IPAddress]::Parse($ipStr)
        $bytes = $ipAddr.GetAddressBytes()
        if ([System.BitConverter]::IsLittleEndian) { [Array]::Reverse($bytes) }
        [uint32]$ipInt = [System.BitConverter]::ToUInt32($bytes, 0)
        
        [uint32]$maskInt = [uint32]::MaxValue -shl (32 - $mask)
        [uint32]$network = $ipInt -band $maskInt
        [uint32]$broadcast = $network -bor (-bnot $maskInt)
        
        $start = $network + 1
        $end = $broadcast - 1
        
        $results = @()
        # Cap large ranges to avoid infinite loops if user scans /8
        if (($end - $start) -gt 65536) { Write-Warning "CIDR $Cidr is too large. Scanning first 65536 IPs only."; $end = $start + 65536 }

        for ($i = $start; $i -le $end; $i++) {
            $b = [System.BitConverter]::GetBytes([uint32]$i)
            if ([System.BitConverter]::IsLittleEndian) { [Array]::Reverse($b) }
            $results += ([System.Net.IPAddress]::new($b)).IPAddressToString
        }
        return $results
    } catch {
        Write-Warning "Failed to parse CIDR: $Cidr"
        return @()
    }
}

function Get-IpsFromRange {
    param([string]$Range)
    # Supports: 192.168.1.1-192.168.1.50 OR 192.168.1.1-50
    try {
        $startStr, $endStr = $Range.Split('-')
        $startIP = [System.Net.IPAddress]::Parse($startStr)
        
        $endIP = $null
        if ($endStr -match '^\d+$') {
            # Format: 192.168.1.1-50
            $base = $startStr.Substring(0, $startStr.LastIndexOf('.'))
            $endIP = [System.Net.IPAddress]::Parse("$base.$endStr")
        } else {
            # Format: 192.168.1.1-192.168.1.50
            $endIP = [System.Net.IPAddress]::Parse($endStr)
        }

        # Simple conversion to Int for loop
        $bytesS = $startIP.GetAddressBytes(); if ([System.BitConverter]::IsLittleEndian) { [Array]::Reverse($bytesS) }
        [uint32]$s = [System.BitConverter]::ToUInt32($bytesS, 0)

        $bytesE = $endIP.GetAddressBytes(); if ([System.BitConverter]::IsLittleEndian) { [Array]::Reverse($bytesE) }
        [uint32]$e = [System.BitConverter]::ToUInt32($bytesE, 0)

        $results = @()
        if ($e -lt $s) { return @() }
        if (($e - $s) -gt 65536) { Write-Warning "Range $Range is too large. Scanning first 65536 IPs only."; $e = $s + 65536 }

        for ($i = $s; $i -le $e; $i++) {
            $b = [System.BitConverter]::GetBytes([uint32]$i)
            if ([System.BitConverter]::IsLittleEndian) { [Array]::Reverse($b) }
            $results += ([System.Net.IPAddress]::new($b)).IPAddressToString
        }
        return $results
    } catch {
        Write-Warning "Failed to parse Range: $Range"
        return @()
    }
}

function Get-MachineInventory {
  [CmdletBinding()]
  param(
    [string]$SearchBase = "",
    [string]$ADFilter = '*',
    [switch]$IncludeDisabled,
    [switch]$OnlyDisabled,
    [switch]$TcpCheck,
    [string]$Ports = "445,3389,5985",
    [switch]$NoIcmp,
    [int]$PingCount = 1,
    [int]$TimeoutMs = 1200,
    [switch]$OnlyReachable,
    [switch]$OnlyUnreachable,
    [int]$MinDaysInactive = 0,
    [switch]$ADOnly,
    [switch]$Stealth,
    [switch]$CheckWinRM,
    [switch]$ResolveDns,
    [switch]$CheckUnconstrained,
    [switch]$CheckPSSession,
    [switch]$ShowDescription,
    [switch]$ShowOU,
    [switch]$Turbo,
    [int[]]$StealthDelay = @(2,10),
    [int]$Threads = 50,
    [string[]]$Targets,
    [PSCredential]$Credential,
    [switch]$CheckLDAP,
    [switch]$CheckEOS,

    [string]$Report,
    [int]$ReportDays = 30

  )

  # Turbo Mode Safety Check
  if ($Turbo -and $PSVersionTable.PSVersion.Major -lt 7) {
    Write-Warning "Turbo mode requires PowerShell 7+. Falling back to sequential mode."
    $Turbo = $false
  }
  
  if ($Turbo -and $Stealth) {
    Write-Warning "Turbo mode and Stealth mode are mutually exclusive. Disabling Turbo to prioritize Stealth safety."
    $Turbo = $false
  }


  if ($Turbo) {
    if ($Threads -lt 1) {
        $Threads = 1
    } elseif ($Threads -gt 1000) {
        Write-Warning "Thread count $Threads exceeds safe limit of 1000. Capping at 1000 to prevent network stack exhaustion."
        $Threads = 1000
    }
  }

  $machines = @()

  # --- Target Processing Logic ---
  if ($Targets) {
      $adFilters = @()
      $ipTargets = @()

      foreach ($t in $Targets) {
          if ($t -match '[*?]') {
              # Wildcard -> AD Filter pattern
              Write-Verbose "Target '$t' identified as Wildcard/AD Filter."
              $adFilters += $t
          } elseif ($t -match '/') {
              # CIDR
              Write-Verbose "Target '$t' identified as CIDR."
              $ipTargets += Get-IpsFromCidr $t
          } elseif ($t -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*-.*') {
              # IP Range
              Write-Verbose "Target '$t' identified as IP Range."
              $ipTargets += Get-IpsFromRange $t
          } elseif ($t -as [System.Net.IPAddress]) {
              # IP
              Write-Verbose "Target '$t' identified as Single IP."
              $ipTargets += $t
          } else {
              # Fallback
              Write-Verbose "Target '$t' identified as Hostname/AD Name."
              $adFilters += $t
          }
      }

      Write-Verbose "Found $($ipTargets.Count) IP targets and $($adFilters.Count) AD Filters."

      # Dependency Logic Update
      $needAd = $CheckUnconstrained -or $ShowDescription -or $ShowOU
      if ($ipTargets.Count -gt 0 -and $needAd -and -not $ResolveDns) {
          Write-Warning "Creating a dependency: Options ($CheckUnconstrained/$ShowDescription/$ShowOU) require '-ResolveDns' for IP targets. Enabling automatically."
          $ResolveDns = $true
      }

      # Fetch AD Targets
      if ($adFilters.Count -gt 0) {
          $props = @('Name','IPv4Address','DNSHostName','OperatingSystem','Enabled','CanonicalName','LastLogonDate')
          if ($CheckUnconstrained) { $props += 'TrustedForDelegation' }
          if ($ShowDescription) { $props += 'Description' }


          foreach ($f in $adFilters) {
              # Construct AD Filter. simple 'Name -like'
              # Note: Get-ADComputer -Filter "Name -like '$f'"
              $params = @{
                Filter = "Name -like '$f'"
                Properties = $props
              }
              if ($SearchBase) { $params['SearchBase'] = $SearchBase }
              try {
                  $res = Get-ADComputer @params
                  if ($res) { $machines += $res }
              } catch {
                  Write-Warning "Error querying AD for '$f': $_"
              }
          }
      }

      # Add IP Targets
      if ($Turbo -and $ipTargets.Count -gt 0) {
          Write-Verbose "Resolving $($ipTargets.Count) IP targets in parallel (Turbo Mode)..."
          
          $synMachines = $ipTargets | ForEach-Object -Parallel {
              $ip = $_
              $machineObj = $null
              $dnsName = $ip
              $foundInAd = $false
              
              # Using modifiers for outer variables
              $doResolve = $using:ResolveDns
              $doUnconst = $using:CheckUnconstrained

              if ($doResolve) {
                  try {
                      $dnsRec = Resolve-DnsName -Name $ip -Type PTR -ErrorAction Stop | Select-Object -First 1
                      if ($dnsRec -and $dnsRec.NameHost) {
                          $dnsName = $dnsRec.NameHost
                          $cleanName = $dnsName.TrimEnd('.')
                          
                          try {
                              $props = @('Name','IPv4Address','DNSHostName','OperatingSystem','Enabled','CanonicalName','LastLogonDate')
                              if ($doUnconst) { $props += 'TrustedForDelegation' }
                              if ($using:ShowDescription) { $props += 'Description' }


                              $adObj = Get-ADComputer -Filter "DNSHostName -like '$cleanName*' -or Name -eq '$cleanName'" -Properties $props -ErrorAction SilentlyContinue | Select-Object -First 1
                              if ($adObj) {
                                  $finalObj = [ordered]@{
                                      Name            = $adObj.Name
                                      IPv4Address     = $adObj.IPv4Address
                                      DNSHostName     = $adObj.DNSHostName
                                      OperatingSystem = $adObj.OperatingSystem
                                      Enabled         = $adObj.Enabled
                                      CanonicalName   = $adObj.CanonicalName
                                      LastLogonDate   = $adObj.LastLogonDate
                                      ManualTargetIP  = "$ip"
                                  }
                                  if ($doUnconst) { $finalObj['TrustedForDelegation'] = $adObj.TrustedForDelegation }
                                  if ($using:ShowDescription) { $finalObj['Description'] = $adObj.Description }
                                  return [PSCustomObject]$finalObj
                              }
                          } catch {}
                      }
                  } catch {}
              }

              # Synthetic Object
              $synObj = [ordered]@{
                  Name            = if ($doResolve -and $dnsName -ne $ip) { $dnsName.TrimEnd('.') } else { "$ip" }
                  IPv4Address     = "$ip"
                  DNSHostName     = if ($doResolve) { $dnsName } else { "$ip" }
                  OperatingSystem = "Unknown (Network Scan)"
                  Enabled         = $true
                  CanonicalName   = "Network/IP"
                  LastLogonDate   = $null
                  ManualTargetIP  = "$ip"
              }
              if ($doUnconst) { $synObj['TrustedForDelegation'] = $false }
              if ($using:ShowDescription) { $synObj['Description'] = $null }
              return [PSCustomObject]$synObj

          } -ThrottleLimit $Threads
          
          $machines += $synMachines
      } else {
          # Sequential Fallback
          foreach ($ip in $ipTargets) {
              $machineObj = $null
              $dnsName = $ip
              $foundInAd = $false

              if ($ResolveDns) {
                  try {
                      $dnsRec = Resolve-DnsName -Name $ip -Type PTR -ErrorAction Stop | Select-Object -First 1
                      if ($dnsRec -and $dnsRec.NameHost) {
                          $dnsName = $dnsRec.NameHost
                          $cleanName = $dnsName.TrimEnd('.')
                          
                          try {
                              $props = @('Name','IPv4Address','DNSHostName','OperatingSystem','Enabled','CanonicalName','LastLogonDate')
                              if ($CheckUnconstrained) { $props += 'TrustedForDelegation' }
                              if ($ShowDescription) { $props += 'Description' }


                              $adObj = Get-ADComputer -Filter "DNSHostName -like '$cleanName*' -or Name -eq '$cleanName'" -Properties $props -ErrorAction SilentlyContinue | Select-Object -First 1
                              if ($adObj) {
                                  $finalObj = [ordered]@{
                                      Name            = $adObj.Name
                                      IPv4Address     = $adObj.IPv4Address
                                      DNSHostName     = $adObj.DNSHostName
                                      OperatingSystem = $adObj.OperatingSystem
                                      Enabled         = $adObj.Enabled
                                      CanonicalName   = $adObj.CanonicalName
                                      LastLogonDate   = $adObj.LastLogonDate
                                      ManualTargetIP  = "$ip"
                                  }
                                  if ($CheckUnconstrained) { $finalObj['TrustedForDelegation'] = $adObj.TrustedForDelegation }
                                  if ($ShowDescription) { $finalObj['Description'] = $adObj.Description }
                                  $machineObj = [PSCustomObject]$finalObj
                                  $foundInAd = $true
                              }
                          } catch {}
                      }
                  } catch {}
              }

              if (-not $foundInAd) {
                  $synObj = [ordered]@{
                      Name            = if ($ResolveDns -and $dnsName -ne $ip) { $dnsName.TrimEnd('.') } else { "$ip" }
                      IPv4Address     = "$ip"
                      DNSHostName     = if ($ResolveDns) { $dnsName } else { "$ip" }
                      OperatingSystem = "Unknown (Network Scan)"
                      Enabled         = $true
                      CanonicalName   = "Network/IP"
                      LastLogonDate   = $null
                      ManualTargetIP  = "$ip"
                  }
                  if ($CheckUnconstrained) { $synObj['TrustedForDelegation'] = $false }
                  if ($ShowDescription) { $synObj['Description'] = $null }
                  $machineObj = [PSCustomObject]$synObj
              }
              
              $machines += $machineObj
          }
      }
      
      Write-Verbose "Total machines before dedupe: $(@($machines).Count)"
      # Remove duplicates
      $machines = $machines | Sort-Object Name -Unique
      Write-Verbose "Total machines after dedupe: $(@($machines).Count)"

  } else {
      # --- Standard AD Scan ---
      $props = @('Name','IPv4Address','DNSHostName','OperatingSystem','Enabled','CanonicalName','LastLogonDate')
      if ($CheckUnconstrained) { $props += 'TrustedForDelegation' }
      if ($ShowDescription) { $props += 'Description' }


      $adParams = @{
        Filter     = $ADFilter
        Properties = $props
      }
      if ($SearchBase) { $adParams['SearchBase'] = $SearchBase }

      $machines = Get-ADComputer @adParams
  }

  # Normalize Object for processing
  $selectProps = @('Name','IPv4Address','DNSHostName','OperatingSystem','Enabled','CanonicalName','LastLogonDate')
  if ($CheckUnconstrained) { $selectProps += 'TrustedForDelegation' }
  if ($ShowDescription) { $selectProps += 'Description' }

  
  $machines = $machines | Select-Object $selectProps

  if ($OnlyDisabled) {
    if ($Targets) { Write-Warning "Filtering by Disabled status may hide IP targets as they have synthetic Enabled=True." }
    $machines = @($machines | Where-Object { -not $_.Enabled })
  } elseif (-not $IncludeDisabled) {
    $machines = @($machines | Where-Object { $_.Enabled })
  }

  if ($Stealth) {
    $machines = $machines | Sort-Object { Get-Random }
  }

  $legacyServerRegex = 'Windows (2000|.*2003|.*2008|.*2012)'
  $legacyClientRegex = 'Windows (XP|Vista|7|8)'

  # --- Port Keyword Expansion ---
  $top5   = "21,22,80,443,3389"
  $top10  = "$top5,25,53,135,139,445"
  $top20  = "$top10,110,143,389,1433,3306,5900,5985,8080,8443"
  $top50  = "$top20,23,69,88,111,119,161,162,179,199,381,382,383,464,444,513,514,515,543,544,548,554,587,631,636,873,989,990,993,995"
  $top100 = "$top50,1025,1194,1521,1701,1723,2000,2049,2082,2083,2121,2222,2375,2376,2483,2484,3268,3269,3388,4000,4444,4500,4848,5000,5060,5432,5555,5631,5632,5800,5901,5902,5938,6000,6001,6667,7000,7001,8000,8008,8081,8088,8090,8222,8444,8500,8888,9000,9090,9418,9999"

  if ($Ports -match '^Top(\d+)$') {
      switch ($Ports) {
          "Top5"   { $Ports = $top5; break }
          "Top10"  { $Ports = $top10; break }
          "Top20"  { $Ports = $top20; break }
          "Top50"  { $Ports = $top50; break }
          "Top100" { $Ports = $top100; break }
          Default  { Write-Warning "Unknown Top list '$Ports'. Using default."; $Ports = "445,3389,5985" }
      }
      Write-Verbose "Expanded Ports '$Ports'"
      # Auto-enable TcpCheck if user asks for a Top list
      $TcpCheck = $true
  }


  if ($Report -eq 'OpenRDP') {
      $TcpCheck = $true
      $p = $Ports -split '[,; ]+'
      if ('3389' -notin $p) { $Ports += ",3389" }
  }
  
  $portList = @()
  if ($CheckLDAP) {
      if (-not $TcpCheck) {
          # User requested ONLY LDAP, override default ports
          $Ports = "389,636"
          $TcpCheck = $true
      } else {
          # User requested TCP Check AND LDAP, append
          $p = $Ports -split '[,; ]+'
          if ('389' -notin $p) { $Ports += ",389" }
          if ('636' -notin $p) { $Ports += ",636" }
      }
  }

  if ($TcpCheck -and -not $ADOnly) {
    # If Report=OpenRDP, ensure 3389 is checked. Moved logic up to force TcpCheck.
    $portList = @($Ports -split '[,; ]+' | Where-Object { $_ -match '^\d+$' } | ForEach-Object { [int]$_ })
  }

  # --- Execution Block ---
  if ($Turbo -and -not $ADOnly) {
    # PARALLEL MODE (PowerShell 7+)
    $rows = $machines | ForEach-Object -Parallel {
        $m = $_
        
        $daysSince = $null
        if ($m.LastLogonDate) {
            $daysSince = (New-TimeSpan -Start $m.LastLogonDate -End (Get-Date)).Days
        }
        
        # Filtering inside parallel block
        if ($using:MinDaysInactive -gt 0) {
            if ($daysSince -eq $null -or $daysSince -lt $using:MinDaysInactive) { return }
        }

        $base = if ($m.IPv4Address) { $m.IPv4Address } elseif ($m.DNSHostName) { $m.DNSHostName } else { $m.Name }
        
        # --- Inlined Network Checks for Parallel Performance ---
        
        # IP Resolution
        $ip = $null
        if ($m.ManualTargetIP) {
             # If we scanned a specific IP, ALWAYS use it. Do not resolve $base (which might be stale AD IP).
             $ip = $m.ManualTargetIP
        } else {
             try {
                  $ip = [System.Net.Dns]::GetHostAddresses($base) | Select-Object -First 1 -ExpandProperty IPAddressToString -ErrorAction SilentlyContinue
             } catch {}
        }
        $target = if ($ip) { $ip } else { $base }
        
        # Ping
        $ping = $null
        if (-not $using:NoIcmp) {
             # Test-Connection in PS7 is different, use .NET Ping
             try {
                $p = New-Object System.Net.NetworkInformation.Ping
                $reply = $p.Send($target, $using:TimeoutMs)
                $ping = ($reply.Status -eq 'Success')
             } catch {
                $ping = $false
             }
        }
        
        # Ports
        $portStates = @{}
        $portList = $using:portList
        if ($using:TcpCheck -and $portList.Count -gt 0) {
             foreach ($p in $portList) {
                $isOpen = $false
                try {
                    $tcp = New-Object System.Net.Sockets.TcpClient
                    $connect = $tcp.BeginConnect($target, $p, $null, $null)
                    $wait = $connect.AsyncWaitHandle.WaitOne($using:TimeoutMs, $false)
                    if ($wait) {
                        $isOpen = $tcp.Connected
                        $tcp.EndConnect($connect)
                    }
                    $tcp.Close()
                    $tcp.Dispose()
                } catch {}
                $portStates["TCP_$p"] = $isOpen
             }
        }
        
        # WinRM
        $winrmStatus = $null
        if ($using:CheckWinRM) {
             try {
                Test-WSMan -ComputerName $target -ErrorAction Stop | Out-Null
                $winrmStatus = $true
             } catch {
                $winrmStatus = $false
             }
        }

        # Helper function for PSSession outside? No, inside for parallel.
        $pssessionStatus = $null
        if ($using:CheckPSSession) {
             # Only try if we think it's reachable or blindly? Blindly is safer if ICMP blocked.
             try {
                if ($using:Credential) {
                    Invoke-Command -ComputerName $target -Credential $using:Credential -ScriptBlock { $true } -ErrorAction Stop | Out-Null
                } else {
                    Invoke-Command -ComputerName $target -ScriptBlock { $true } -ErrorAction Stop | Out-Null
                }
                $pssessionStatus = $true
             } catch {
                $pssessionStatus = $false
             }
        }

        $reachable = $false
        if ($ping -ne $null) { $reachable = $reachable -or $ping }
        if ($using:TcpCheck) { $reachable = $reachable -or ($portStates.Values -contains $true) }
        if ($using:CheckWinRM -and $winrmStatus -eq $true) { $reachable = $true }
        if ($using:CheckPSSession -and $pssessionStatus -eq $true) { $reachable = $true }

        $obj = [ordered]@{
            Name        = $m.Name
            IPv4Address = if ($ip) { $ip } else { $m.IPv4Address }
            OS          = $m.OperatingSystem
            Enabled     = $m.Enabled
            OU          = $m.CanonicalName
            LastLogon   = $m.LastLogonDate
            DaysSince   = $daysSince
            TargetUsed  = $target
            PingICMP    = if ($ping -ne $null) { [bool]$ping } else { $null }
            EOS         = if ($using:CheckEOS) { ($m.OperatingSystem -match $using:legacyServerRegex -or $m.OperatingSystem -match $using:legacyClientRegex) } else { $null }
        }
        if ($using:CheckUnconstrained) { $obj['Unconstrained'] = [bool]$m.TrustedForDelegation }
        if ($using:ShowDescription) { $obj['Description'] = $m.Description }
        


        foreach ($k in $portStates.Keys) { $obj[$k] = $portStates[$k] }

        if ($using:CheckWinRM) { $obj['WinRM'] = $winrmStatus }
        if ($using:CheckPSSession) { $obj['PSSession'] = $pssessionStatus }
        $obj['Reachable'] = $reachable
        [pscustomobject]$obj

    } -ThrottleLimit $Threads

  } else {
    # SEQUENTIAL MODE (Standard)
    # Validate StealthDelay
    $minDelay = 0
    $maxDelay = 0
    if ($Stealth) {
        if ($StealthDelay.Count -eq 1) {
            $minDelay = $StealthDelay[0]
            $maxDelay = $StealthDelay[0]
        } elseif ($StealthDelay.Count -ge 2) {
            $minDelay = $StealthDelay[0]
            $maxDelay = $StealthDelay[1]
        }
    }

    $rows = foreach ($m in $machines) {
        $daysSince = $null
        if ($m.LastLogonDate) {
        $daysSince = (New-TimeSpan -Start $m.LastLogonDate -End (Get-Date)).Days
        }

        if ($MinDaysInactive -gt 0) {
        if ($daysSince -eq $null -or $daysSince -lt $MinDaysInactive) { continue }
        }

        if ($Stealth -and -not $ADOnly) {
            $delay = 0
            if ($minDelay -eq $maxDelay) {
                $delay = $minDelay
            } else {
                $delay = Get-Random -Minimum $minDelay -Maximum ($maxDelay + 1)
            }
            if ($delay -gt 0) {
                Write-Verbose "[Stealth] Pausing $delay seconds before $($m.Name)..."
                Start-Sleep -Seconds $delay
            }
        }

        $base = if ($m.IPv4Address) { $m.IPv4Address } elseif ($m.DNSHostName) { $m.DNSHostName } else { $m.Name }
        
        # Initialize $ip to avoid VariableIsUndefined errors
        $ip = $null
        
        if ($ADOnly) {
        $target = $base
        $ping = $null
        $portStates = @{}
        $winrmStatus = $null
        } else {
        # Check if ManualTargetIP property exists and has a value
        if (($m.PSObject.Properties.Name -contains 'ManualTargetIP') -and $m.ManualTargetIP) {
             $ip = $m.ManualTargetIP
             $target = $m.ManualTargetIP
        } else {
             $ip   = Resolve-ToIP $base
             $target = if ($ip) { $ip } else { $base }
        }

        $ping = $null
        if (-not $NoIcmp) { $ping = Test-Icmp -Computer $target -Count $PingCount }

        $portStates = @{}
        if ($TcpCheck -and $portList.Count -gt 0) {
            foreach ($p in $portList) {
            $portStates["TCP_$p"] = Test-TcpPort -Computer $target -Port $p -TimeoutMs $TimeoutMs
            }
        }

        $winrmStatus = $null
        if ($CheckWinRM) {
            try {
                Test-WSMan -ComputerName $target -ErrorAction Stop | Out-Null
                $winrmStatus = $true
            } catch {
                $winrmStatus = $false
            }
        }
        }
        
        $pssessionStatus = $null
        if ($CheckPSSession) {
             try {
                if ($Credential) {
                    Invoke-Command -ComputerName $target -Credential $Credential -ScriptBlock { $true } -ErrorAction Stop | Out-Null
                } else {
                    Invoke-Command -ComputerName $target -ScriptBlock { $true } -ErrorAction Stop | Out-Null
                }
                $pssessionStatus = $true
             } catch {
                $pssessionStatus = $false
             }
        }
        


        $reachable = $false
        if ($ping -ne $null) { $reachable = $reachable -or $ping }
        if ($TcpCheck) { $reachable = $reachable -or ($portStates.Values -contains $true) }
        if ($CheckWinRM -and $winrmStatus -eq $true) { $reachable = $true }
        if ($CheckPSSession -and $pssessionStatus -eq $true) { $reachable = $true }

        $obj = [ordered]@{
        Name        = $m.Name
        IPv4Address = if ($ip) { $ip } else { $m.IPv4Address }
        OS          = $m.OperatingSystem
        Enabled     = $m.Enabled
        OU          = $m.CanonicalName
        LastLogon   = $m.LastLogonDate
        DaysSince   = $daysSince
        TargetUsed  = if ($target) { $target } else { "N/A" }
        PingICMP    = if ($ping -ne $null) { [bool]$ping } else { $null }
        EOS         = if ($CheckEOS) { ($m.OperatingSystem -match $legacyServerRegex -or $m.OperatingSystem -match $legacyClientRegex) } else { $null }
        }
        if ($CheckUnconstrained) { $obj['Unconstrained'] = [bool]$m.TrustedForDelegation }
        if ($ShowDescription) { $obj['Description'] = $m.Description }
        


        foreach ($k in $portStates.Keys) { $obj[$k] = $portStates[$k] }

        if ($CheckWinRM) { $obj['WinRM'] = $winrmStatus }
        if ($CheckPSSession) { $obj['PSSession'] = $pssessionStatus }
        if ($obj) { $obj['Reachable'] = $reachable }
        [pscustomobject]$obj
    }
  }

  $view = $rows
  if ($OnlyReachable)   { $view = $view | Where-Object { $_.Reachable } }
  if ($OnlyUnreachable) { $view = $view | Where-Object { -not $_.Reachable } }

  # --- Reporting Filter ---
  if ($Report -eq 'Inactive') {
      $view = $view | Where-Object { $_.DaysSince -ge $ReportDays }
  } elseif ($Report -eq 'OpenRDP') {
      # Ensure property exists before filtering to avoid errors
      if ($view | Get-Member -Name 'TCP_3389' -ErrorAction SilentlyContinue) {
         $view = $view | Where-Object { $_.TCP_3389 -eq $true }
      } else {
         Write-Warning "Report 'OpenRDP' requested but TCP_3389 property missing. Ensure -TcpCheck is enabled (it should be automatic)."
         $view = @()
      }
  }

  return $view
}

function Get-ServerInventory {
  [CmdletBinding()]
  param(
    [string]$SearchBase = "",
    [switch]$IncludeDisabled,
    [switch]$OnlyDisabled,
    [switch]$TcpCheck,
    [string]$Ports = "445,3389,5985",
    [switch]$NoIcmp,
    [int]$PingCount = 1,
    [int]$TimeoutMs = 1200,
    [switch]$OnlyReachable,
    [switch]$OnlyUnreachable,
    [int]$MinDaysInactive = 0,
    [switch]$ADOnly,
    [switch]$Stealth,
    [switch]$CheckWinRM,
    [switch]$ResolveDns,
    [switch]$CheckUnconstrained,
    [switch]$CheckPSSession,
    [switch]$ShowDescription,
    [switch]$ShowOU,
    [switch]$Turbo,
    [int[]]$StealthDelay = @(2,10),
    [int]$Threads = 50,
    [string[]]$Targets,
    [PSCredential]$Credential,
    [switch]$CheckLDAP,

    [switch]$CheckEOS,

    [string]$Report,
    [int]$ReportDays = 30
  )
  $params = @{
      ADFilter = 'OperatingSystem -like "*Server*"'
  }
  $PSBoundParameters.Keys | Where-Object { $_ -ne 'ADFilter' } | ForEach-Object { $params[$_] = $PSBoundParameters[$_] }
  Get-MachineInventory @params
}

function Get-ClientInventory {
  [CmdletBinding()]
  param(
    [string]$SearchBase = "",
    [switch]$IncludeDisabled,
    [switch]$OnlyDisabled,
    [switch]$TcpCheck,
    [string]$Ports = "445,3389,5985",
    [switch]$NoIcmp,
    [int]$PingCount = 1,
    [int]$TimeoutMs = 1200,
    [switch]$OnlyReachable,
    [switch]$OnlyUnreachable,
    [int]$MinDaysInactive = 0,
    [switch]$ADOnly,
    [switch]$Stealth,
    [switch]$CheckWinRM,
    [switch]$ResolveDns,
    [switch]$CheckUnconstrained,
    [switch]$CheckPSSession,
    [switch]$ShowDescription,
    [switch]$ShowOU,
    [switch]$Turbo,
    [int[]]$StealthDelay = @(2,10),
    [int]$Threads = 50,
    [string[]]$Targets,
    [PSCredential]$Credential,
    [switch]$CheckLDAP,

    [switch]$CheckEOS,

    [string]$Report,
    [int]$ReportDays = 30
  )
  $params = @{
      ADFilter = 'OperatingSystem -notlike "*Server*"'
  }
  $PSBoundParameters.Keys | Where-Object { $_ -ne 'ADFilter' } | ForEach-Object { $params[$_] = $PSBoundParameters[$_] }
  Get-MachineInventory @params
}



Export-ModuleMember -Function Get-MachineInventory, Get-ServerInventory, Get-ClientInventory, Get-IpsFromCidr, Get-IpsFromRange
