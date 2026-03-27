<#
.SYNOPSIS
    Signs all toolkit PS1 files with Authenticode + RFC 3161 timestamp.

.DESCRIPTION
    If -CertThumbprint is provided and the cert exists in the store, uses it directly.

    If -CertThumbprint is omitted or the cert is not found, automatically generates a
    temporary self-signed code-signing certificate, signs the scripts, then removes the
    certificate from the store.

    The RFC 3161 countersignature means the signature remains valid after certificate
    expiry — the timestamp proves the file was signed while the cert was still valid.

    Timestamp servers (choose any):
      http://timestamp.digicert.com
      http://timestamp.sectigo.com
      http://timestamp.comodoca.com
      http://tsa.starfieldtech.com

    Self-signed vs production:
      Self-signed certs sign the file but carry no publisher trust — EDRs and SmartScreen
      will still flag the script unless the cert is in the machine's trusted root store.
      For EDR bypass use an OV or EV code-signing cert (DigiCert, Sectigo, GlobalSign).
      EV certs grant instant SmartScreen reputation and are preferred for offensive use.

.PARAMETER CertThumbprint
    Optional. SHA-1 thumbprint of an existing code-signing certificate.
    If omitted or not found, a temporary self-signed cert is created and deleted after use.

.PARAMETER TimestampServer
    RFC 3161 timestamp server URL. Default: http://timestamp.digicert.com

.PARAMETER StoreLocation
    Certificate store to search. Default: CurrentUser.

.EXAMPLE
    # Use an existing cert
    .\tools\Sign-Scripts.ps1 -CertThumbprint "AB12CD..."

.EXAMPLE
    # Auto-generate a temporary self-signed cert, sign, then delete
    .\tools\Sign-Scripts.ps1

.EXAMPLE
    .\tools\Sign-Scripts.ps1 -TimestampServer "http://timestamp.sectigo.com"

.AUTHOR
    franckferman
#>

param (
    [string]$CertThumbprint,

    [string]$TimestampServer = 'http://timestamp.digicert.com',

    [ValidateSet('CurrentUser', 'LocalMachine')]
    [string]$StoreLocation = 'CurrentUser'
)

$StorePath  = "Cert:\$StoreLocation\My"
$TempCert   = $false
$Cert       = $null

# --- Locate or create certificate ---
if ($CertThumbprint) {
    $Cert = Get-ChildItem $StorePath -CodeSigningCert |
        Where-Object { $_.Thumbprint -eq $CertThumbprint }

    if (-not $Cert) {
        $Cert = Get-ChildItem $StorePath |
            Where-Object { $_.Thumbprint -eq $CertThumbprint }
    }

    if (-not $Cert) {
        Write-Host "[!] Certificate $CertThumbprint not found in $StorePath" -ForegroundColor Red
        Write-Host "[*] Available:" -ForegroundColor Yellow
        Get-ChildItem $StorePath | Select-Object Thumbprint, Subject, NotAfter | Format-Table -AutoSize
        exit 1
    }
}
else {
    Write-Host "[*] No thumbprint provided — generating temporary self-signed certificate." -ForegroundColor Yellow
    $Cert     = New-SelfSignedCertificate `
        -Subject            'CN=ADMappingToolkit (Temp)' `
        -Type               CodeSigningCert `
        -CertStoreLocation  $StorePath `
        -NotAfter           (Get-Date).AddDays(1) `
        -HashAlgorithm      SHA256
    $TempCert = $true
    Write-Host "[+] Temporary cert created: $($Cert.Thumbprint)" -ForegroundColor Green
}

Write-Host "[*] Certificate  : $($Cert.Subject)" -ForegroundColor Cyan
Write-Host "[*] Thumbprint   : $($Cert.Thumbprint)" -ForegroundColor Cyan
Write-Host "[*] Expires      : $($Cert.NotAfter)" -ForegroundColor Cyan
Write-Host "[*] Timestamp    : $TimestampServer" -ForegroundColor Cyan
Write-Host "[*] Temp cert    : $TempCert" -ForegroundColor Cyan
Write-Host ""

# --- Collect targets ---
$Root    = Join-Path $PSScriptRoot '..'
$Scripts = [System.Collections.Generic.List[string]]::new()

Get-ChildItem (Join-Path $Root 'scripts') -Filter '*.ps1' |
    ForEach-Object { $Scripts.Add($_.FullName) }

$RootPsm1 = Join-Path $Root 'ADMappingToolkit.psm1'
if (Test-Path $RootPsm1) { $Scripts.Add((Resolve-Path $RootPsm1).Path) }

# --- Sign ---
$SuccessCount = 0
$FailCount    = 0

foreach ($Path in $Scripts) {
    $Name = Split-Path $Path -Leaf
    Write-Host "   $Name ... " -NoNewline

    $Result = Set-AuthenticodeSignature `
        -FilePath        $Path `
        -Certificate     $Cert `
        -TimestampServer $TimestampServer `
        -HashAlgorithm   SHA256

    if ($Result.Status -eq 'Valid') {
        Write-Host "signed" -ForegroundColor Green
        $SuccessCount++
    }
    else {
        Write-Host "FAILED ($($Result.StatusMessage))" -ForegroundColor Red
        $FailCount++
    }
}

Write-Host ""
Write-Host "[*] Done: $SuccessCount signed, $FailCount failed." -ForegroundColor Cyan

# --- Remove temporary cert ---
if ($TempCert) {
    Write-Host "[*] Removing temporary certificate from store... " -NoNewline
    try {
        $Cert | Remove-Item -Force
        Write-Host "done." -ForegroundColor Green
    }
    catch {
        Write-Host "FAILED ($($_.Exception.Message))" -ForegroundColor Red
        Write-Host "[!] Remove manually: Get-ChildItem $StorePath | Where-Object Thumbprint -eq '$($Cert.Thumbprint)' | Remove-Item" -ForegroundColor Yellow
    }
}

if ($FailCount -gt 0) { exit 1 }
