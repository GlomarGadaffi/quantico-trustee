# Self-elevate to Admin
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}
$Subject = "CN=RDP-Signing-$env:COMPUTERNAME"
# 1. Get or create 10-year cert
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -eq $Subject } | Select-Object -First 1
if (-not $cert) {
    Write-Host "Generating cert..." -ForegroundColor Cyan
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $Subject -CertStoreLocation Cert:\LocalMachine\My -NotAfter (Get-Date).AddYears(10)
}
$thumb = $cert.Thumbprint
# 2. Add to trusted stores
$tmp = "$env:TEMP\rdptmp.cer"
Export-Certificate -Cert $cert -FilePath $tmp | Out-Null
foreach ($store in @('Cert:\LocalMachine\Root', 'Cert:\LocalMachine\TrustedPublisher')) {
    if (-not (Get-ChildItem $store | Where-Object { $_.Thumbprint -eq $thumb })) {
        Import-Certificate -FilePath $tmp -CertStoreLocation $store | Out-Null
    }
}
Remove-Item $tmp -Force
# 3. Configure Policies (Whitelist thumbprint)
$regPath = "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services"
if (-not (Test-Path $regPath)) { New-Item $regPath -Force | Out-Null }
Set-ItemProperty $regPath -Name "AllowSignedFiles" -Value 1 -Type DWord -Force
$existing = (Get-ItemProperty $regPath -Name "TrustedCertThumbprints" -ErrorAction SilentlyContinue).TrustedCertThumbprints
if ($existing -notlike "*$thumb*") {
    $newVal = if ($existing) { "$existing;$thumb" } else { $thumb }
    Set-ItemProperty $regPath -Name "TrustedCertThumbprints" -Value $newVal -Type String -Force
}
# Bypass educational first-launch dialog
$userVal = "HKCU:\Software\Microsoft\Terminal Server Client"
if (-not (Test-Path $userVal)) { New-Item $userVal -Force | Out-Null }
Set-ItemProperty $userVal -Name "RdpLaunchConsentAccepted" -Value 1 -Type DWord -Force
# 4. Sign RDP files on Desktop
$desktop = [Environment]::GetFolderPath('Desktop')
Get-ChildItem $desktop -Filter *.rdp | ForEach-Object {
    $content = Get-Content $_.FullName -Raw
    if ($content -notmatch "signscope:s:.*$thumb") {
        & "$env:SystemRoot\System32\rdpsign.exe" /sha256 $thumb $_.FullName
        Write-Host "Signed: $($_.Name)" -ForegroundColor Green
    } else {
        Write-Host "Already signed: $($_.Name)" -ForegroundColor Gray
    }
}
if ([Environment]::UserInteractive) {
    Read-Host "Done! Press Enter to close"
}
