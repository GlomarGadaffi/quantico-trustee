<#
.SYNOPSIS
    Reverts the self-signed RDP CA deployment (RDPtrustme.ps1 / Sign-MyRDPs.ps1)
    and ensures the April-2026 consolidated security dialog stays ENABLED.

.DESCRIPTION
    CORRECTION over the earlier reverter:
    The earlier script set RedirectionWarningDialogVersion = 1 as a "lighter"
    fix. That is WRONG. Per the IMsRdpExtendedSettings docs (MsTscAx.dll),
    version 2 (the April 2026 default) CONSOLIDATES the per-channel warnings and
    makes WarnAboutClipboardRedirection / WarnAboutSendingCredentials /
    WarnAboutPrinterRedirection / WarnAboutDirectXRedirection have NO EFFECT.
    Writing 1 re-enables that deprecated, individually-suppressible warning
    surface — i.e. it REOPENS the attack surface the update closed.

    This script therefore:
      1. Removes the self-signed cert from My, Root, TrustedPublisher.
      2. Prunes our thumbprint from TrustedCertThumbprints (HKLM + HKCU);
         removes AllowSignedFiles only if no thumbprints remain.
      3. Clears RdpLaunchConsentAccepted.
      4. Strips signature/signscope lines from desktop .rdp files.
      5. FORCES RedirectionWarningDialogVersion = 2 (removing any =1 left by a
         prior run), so the consolidated dialog stays intact. The popup is the
         mitigation; let it stand. Brad clicks through. That's correct.

    Idempotent. Self-elevates. Heals a box that ran the bad reverter.

.NOTES
    Log: $env:TEMP\Undo-RdpSigning-Corrected.log
#>

[CmdletBinding()]
param(
    [string[]]$CertSubjects = @(
        "CN=RDP Signing - $env:COMPUTERNAME",
        "CN=RDP-Signing-$env:COMPUTERNAME"
    ),
    [switch]$KeepRdpSignatures
)

$ErrorActionPreference = 'Stop'
$LogPath = Join-Path $env:TEMP 'Undo-RdpSigning-Corrected.log'

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Add-Content -Path $LogPath -Value $line
    $color = switch ($Level) { 'ERROR'{'Red'} 'WARN'{'Yellow'} 'OK'{'Green'} 'SKIP'{'DarkGray'} 'CRIT'{'Magenta'} default{'White'} }
    Write-Host $line -ForegroundColor $color
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Host "Elevating..." -ForegroundColor Yellow
    try {
        Start-Process powershell.exe -Verb RunAs -ArgumentList @(
            '-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`""
        )
    } catch { Write-Host "Elevation failed: $_" -ForegroundColor Red; exit 2 }
    exit 0
}

$IsInteractive = [Environment]::UserInteractive -and (-not [Console]::IsInputRedirected)
Write-Log "=== Undo-RdpSigning-Corrected on $env:COMPUTERNAME as $env:USERNAME ==="

# ----- Resolve console user ------------------------------------------------
$UserSID = $null
try {
    $cu = (Get-CimInstance Win32_ComputerSystem).UserName
    if ($cu) {
        $uname = $cu.Split('\')[-1]
        $UserSID = (New-Object System.Security.Principal.NTAccount($uname)
                   ).Translate([System.Security.Principal.SecurityIdentifier]).Value
        Write-Log "Console user: $cu (SID: $UserSID)"
    }
} catch { Write-Log "Console user SID resolve failed: $_" 'WARN' }

$OurThumbs = @()

try {
    # ----- Phase 1: Remove certs ------------------------------------------
    foreach ($storePath in @('Cert:\LocalMachine\My',
                             'Cert:\LocalMachine\Root',
                             'Cert:\LocalMachine\TrustedPublisher')) {
        $storeName = Split-Path $storePath -Leaf
        $matches = Get-ChildItem $storePath -ErrorAction SilentlyContinue |
            Where-Object { $CertSubjects -contains $_.Subject }
        if (-not $matches) { Write-Log "No matching cert in $storeName." 'SKIP'; continue }
        foreach ($c in $matches) {
            $OurThumbs += $c.Thumbprint.ToUpper()
            Remove-Item -Path (Join-Path $storePath $c.Thumbprint) -Force
            Write-Log "Removed cert $($c.Thumbprint) from $storeName." 'OK'
        }
    }
    $OurThumbs = $OurThumbs | Select-Object -Unique
    if ($OurThumbs) { Write-Log "Target thumbprint(s): $($OurThumbs -join ', ')" }

    # ----- Phase 2: Prune TrustedCertThumbprints --------------------------
    function Repair-Policy {
        param([string]$Key, [string]$Label)
        if (-not (Test-Path $Key)) { Write-Log "$Label policy key absent." 'SKIP'; return }
        $existing = (Get-ItemProperty -Path $Key -Name 'TrustedCertThumbprints' -ErrorAction SilentlyContinue).TrustedCertThumbprints
        if ($existing) {
            $remaining = $existing -split '[;,]' | ForEach-Object { $_.Trim().ToUpper() } |
                Where-Object { $_ -and ($OurThumbs -notcontains $_) }
            if ($remaining) {
                Set-ItemProperty -Path $Key -Name 'TrustedCertThumbprints' -Value ($remaining -join ';') -Type String -Force
                Write-Log "$Label : pruned our thumbprint, $($remaining.Count) other(s) kept." 'OK'
            } else {
                Remove-ItemProperty -Path $Key -Name 'TrustedCertThumbprints' -ErrorAction SilentlyContinue
                Remove-ItemProperty -Path $Key -Name 'AllowSignedFiles' -ErrorAction SilentlyContinue
                Write-Log "$Label : removed TrustedCertThumbprints + AllowSignedFiles (only ours)." 'OK'
            }
        } else { Write-Log "$Label : no TrustedCertThumbprints value." 'SKIP' }
    }
    Repair-Policy 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services' 'HKLM'
    if ($UserSID) {
        Repair-Policy "Registry::HKEY_USERS\$UserSID\Software\Policies\Microsoft\Windows NT\Terminal Services" 'HKCU'
    }

    # ----- Phase 3: Clear RdpLaunchConsentAccepted ------------------------
    if ($UserSID) {
        $clientKey = "Registry::HKEY_USERS\$UserSID\Software\Microsoft\Terminal Server Client"
        if (Test-Path $clientKey) {
            Remove-ItemProperty -Path $clientKey -Name 'RdpLaunchConsentAccepted' -ErrorAction SilentlyContinue
            Write-Log "Cleared RdpLaunchConsentAccepted." 'OK'
        }
    }

    # ----- Phase 4: Strip signatures from desktop .rdp --------------------
    if (-not $KeepRdpSignatures) {
        $Desktop = $null
        if ($UserSID) {
            try {
                $profilePath = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$UserSID" -ErrorAction SilentlyContinue).ProfileImagePath
                $usf = "Registry::HKEY_USERS\$UserSID\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
                $dRaw = (Get-ItemProperty -Path $usf -Name Desktop -ErrorAction SilentlyContinue).Desktop
                if ($dRaw) { $Desktop = [Environment]::ExpandEnvironmentVariables($dRaw.Replace('%USERPROFILE%', $profilePath)) }
            } catch { Write-Log "Desktop resolve failed: $_" 'WARN' }
        }
        if (-not $Desktop -or -not (Test-Path $Desktop)) { $Desktop = [Environment]::GetFolderPath('Desktop') }
        Write-Log "Desktop: $Desktop"
        foreach ($f in @(Get-ChildItem -Path $Desktop -Filter '*.rdp' -File -ErrorAction SilentlyContinue)) {
            $wasRO = $f.IsReadOnly
            if ($wasRO) { Set-ItemProperty $f.FullName -Name IsReadOnly -Value $false }
            $lines = Get-Content -Path $f.FullName
            $clean = $lines | Where-Object { $_ -notmatch '^(signature|signscope):s:' }
            if ($clean.Count -ne $lines.Count) {
                Set-Content -Path $f.FullName -Value $clean -Encoding Unicode
                Write-Log "Stripped signature from $($f.Name)." 'OK'
            } else { Write-Log "$($f.Name): no signature lines." 'SKIP' }
            if ($wasRO) { Set-ItemProperty $f.FullName -Name IsReadOnly -Value $true }
        }
    } else { Write-Log "KeepRdpSignatures set; .rdp untouched." 'SKIP' }

    # ----- Phase 5: FORCE RedirectionWarningDialogVersion = 2 -------------
    # This HEALS any box where the bad reverter set it to 1.
    # Version 2 = April 2026 consolidated dialog. Leave it. The popup is the fix.
    function Force-DialogV2 {
        param([string]$Key, [string]$Label)
        if (-not (Test-Path $Key)) { Write-Log "$Label TS key absent; nothing set to 1, default (2) applies." 'SKIP'; return }
        $cur = (Get-ItemProperty -Path $Key -Name 'RedirectionWarningDialogVersion' -ErrorAction SilentlyContinue).RedirectionWarningDialogVersion
        if ($null -eq $cur) {
            Write-Log "$Label : value not set; default 2 already in effect." 'OK'
        } elseif ($cur -eq 1) {
            # Remove the override entirely so the secure default (2) governs.
            Remove-ItemProperty -Path $Key -Name 'RedirectionWarningDialogVersion' -ErrorAction SilentlyContinue
            Write-Log "$Label : found =1 (INSECURE) from prior run; REMOVED it. Default 2 restored." 'CRIT'
        } else {
            Remove-ItemProperty -Path $Key -Name 'RedirectionWarningDialogVersion' -ErrorAction SilentlyContinue
            Write-Log "$Label : cleared explicit value ($cur); default 2 governs." 'OK'
        }
    }
    Force-DialogV2 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services' 'HKLM'
    if ($UserSID) {
        Force-DialogV2 "Registry::HKEY_USERS\$UserSID\Software\Policies\Microsoft\Windows NT\Terminal Services" 'HKCU'
    }

    Write-Log "---------------------------------------------"
    Write-Log "Done. CA removed, policy pruned, signatures stripped."
    Write-Log "Security dialog left at version 2 (the mitigation). The popup stays. That is correct."
    Write-Log "Real fix: vendor signs their .rdp files -> dialog shows a real publisher. Ticket is open."
    $exitCode = 0
}
catch {
    Write-Log "FATAL: $($_.Exception.Message)" 'ERROR'
    Write-Log $_.ScriptStackTrace 'ERROR'
    $exitCode = 2
}
finally {
    if ($IsInteractive) { Write-Host ""; Read-Host "Press Enter to close" }
}

exit $exitCode
