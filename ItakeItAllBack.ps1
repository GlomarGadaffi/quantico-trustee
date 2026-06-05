<#
.SYNOPSIS
    Reverts the changes made by Sign-DesktopRdpFiles.ps1 / RDPtrustme.ps1 and
    instead suppresses the post-April-2026 RDP warning (CVE-2026-26151) via the
    lower-power registry switch RedirectionWarningDialogVersion = 1.

.DESCRIPTION
    1. Removes the self-signed code-signing cert (CN=RDP Signing - <host> and the
       older CN=RDP-Signing-<host> variant) from LocalMachine\My, \Root, and
       \TrustedPublisher.
    2. Pulls that thumbprint out of the HKLM and HKCU TrustedCertThumbprints
       policy; removes AllowSignedFiles only if no thumbprints remain.
    3. Strips the signature: line from .rdp files on the desktop so they revert
       to plain unsigned files.
    4. Clears RdpLaunchConsentAccepted for the console user.
    5. Sets RedirectionWarningDialogVersion = 1 (HKLM + console-user HKCU) to
       restore pre-April popup behavior without any cert.

    Idempotent. Safe to re-run. Self-elevates.

.NOTES
    Log: $env:TEMP\Undo-RdpSigning.log
#>

[CmdletBinding()]
param(
    # Match both the pro-script subject and the gist-script subject.
    [string[]]$CertSubjects = @(
        "CN=RDP Signing - $env:COMPUTERNAME",
        "CN=RDP-Signing-$env:COMPUTERNAME"
    ),
    # If set, leave .rdp files signed and only undo trust + flip the bit.
    [switch]$KeepRdpSignatures
)

$ErrorActionPreference = 'Stop'
$LogPath = Join-Path $env:TEMP 'Undo-RdpSigning.log'

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Add-Content -Path $LogPath -Value $line
    $color = switch ($Level) { 'ERROR'{'Red'} 'WARN'{'Yellow'} 'OK'{'Green'} 'SKIP'{'DarkGray'} default{'White'} }
    Write-Host $line -ForegroundColor $color
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ----- Self-elevate --------------------------------------------------------
if (-not (Test-Admin)) {
    Write-Host "Elevating..." -ForegroundColor Yellow
    try {
        Start-Process powershell.exe -Verb RunAs -ArgumentList @(
            '-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$PSCommandPath`""
        )
    } catch {
        Write-Host "Elevation cancelled or failed: $_" -ForegroundColor Red
        exit 2
    }
    exit 0
}

$IsInteractive = [Environment]::UserInteractive -and (-not [Console]::IsInputRedirected)
Write-Log "=== Undo-RdpSigning starting on $env:COMPUTERNAME as $env:USERNAME ==="

# ----- Resolve console user (for HKCU + desktop) ---------------------------
$ConsoleUser = $null; $UserSID = $null
try {
    $ConsoleUser = (Get-CimInstance Win32_ComputerSystem).UserName
    if ($ConsoleUser) {
        $uname = $ConsoleUser.Split('\')[-1]
        $UserSID = (New-Object System.Security.Principal.NTAccount($uname)
                   ).Translate([System.Security.Principal.SecurityIdentifier]).Value
        Write-Log "Console user: $ConsoleUser (SID: $UserSID)"
    }
} catch { Write-Log "Could not resolve console user SID: $_" 'WARN' }

# Collect the thumbprints we are about to remove so we can prune the policy.
$OurThumbs = @()

try {
    # ----- Phase 1: Remove certs from all three stores ---------------------
    foreach ($storePath in @('Cert:\LocalMachine\My',
                             'Cert:\LocalMachine\Root',
                             'Cert:\LocalMachine\TrustedPublisher')) {
        $storeName = Split-Path $storePath -Leaf
        $matches = Get-ChildItem $storePath -ErrorAction SilentlyContinue |
            Where-Object { $CertSubjects -contains $_.Subject }
        if (-not $matches) {
            Write-Log "No matching cert in $storeName." 'SKIP'
            continue
        }
        foreach ($c in $matches) {
            $OurThumbs += $c.Thumbprint.ToUpper()
            Remove-Item -Path (Join-Path $storePath $c.Thumbprint) -Force
            Write-Log "Removed cert $($c.Thumbprint) from $storeName." 'OK'
        }
    }
    $OurThumbs = $OurThumbs | Select-Object -Unique
    if ($OurThumbs) { Write-Log "Target thumbprint(s): $($OurThumbs -join ', ')" }

    # ----- Phase 2: Prune TrustedCertThumbprints (HKLM + HKCU) -------------
    $polValName   = 'TrustedCertThumbprints'
    $allowValName = 'AllowSignedFiles'

    function Repair-Policy {
        param([string]$Key, [string]$Label)
        if (-not (Test-Path $Key)) { Write-Log "$Label policy key absent." 'SKIP'; return }

        $existing = (Get-ItemProperty -Path $Key -Name $polValName -ErrorAction SilentlyContinue).$polValName
        if ($existing) {
            $remaining = $existing -split '[;,]' |
                ForEach-Object { $_.Trim().ToUpper() } |
                Where-Object { $_ -and ($OurThumbs -notcontains $_) }
            if ($remaining) {
                Set-ItemProperty -Path $Key -Name $polValName -Value ($remaining -join ';') -Type String -Force
                Write-Log "$Label : removed our thumbprint, $($remaining.Count) other(s) preserved." 'OK'
            } else {
                Remove-ItemProperty -Path $Key -Name $polValName -ErrorAction SilentlyContinue
                Write-Log "$Label : removed TrustedCertThumbprints (was only ours)." 'OK'
                # Only clear AllowSignedFiles if no thumbprints remain.
                Remove-ItemProperty -Path $Key -Name $allowValName -ErrorAction SilentlyContinue
                Write-Log "$Label : removed AllowSignedFiles." 'OK'
            }
        } else {
            Write-Log "$Label : no TrustedCertThumbprints value." 'SKIP'
        }
    }

    Repair-Policy 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services' 'HKLM'
    if ($UserSID) {
        Repair-Policy "Registry::HKEY_USERS\$UserSID\Software\Policies\Microsoft\Windows NT\Terminal Services" 'HKCU'
    }

    # ----- Phase 3: Clear RdpLaunchConsentAccepted -------------------------
    if ($UserSID) {
        $clientKey = "Registry::HKEY_USERS\$UserSID\Software\Microsoft\Terminal Server Client"
        if (Test-Path $clientKey) {
            Remove-ItemProperty -Path $clientKey -Name 'RdpLaunchConsentAccepted' -ErrorAction SilentlyContinue
            Write-Log "Cleared RdpLaunchConsentAccepted for console user." 'OK'
        }
    }

    # ----- Phase 4: Strip signatures from desktop .rdp files ---------------
    if (-not $KeepRdpSignatures) {
        $Desktop = $null
        if ($UserSID) {
            try {
                $profilePath = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$UserSID" -ErrorAction SilentlyContinue).ProfileImagePath
                $usf = "Registry::HKEY_USERS\$UserSID\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
                $dRaw = (Get-ItemProperty -Path $usf -Name Desktop -ErrorAction SilentlyContinue).Desktop
                if ($dRaw) {
                    $Desktop = [System.Environment]::ExpandEnvironmentVariables($dRaw.Replace('%USERPROFILE%', $profilePath))
                }
            } catch { Write-Log "Desktop registry resolve failed: $_" 'WARN' }
        }
        if (-not $Desktop -or -not (Test-Path $Desktop)) {
            $Desktop = [Environment]::GetFolderPath('Desktop')
        }
        Write-Log "Desktop: $Desktop"

        $rdp = @(Get-ChildItem -Path $Desktop -Filter '*.rdp' -File -ErrorAction SilentlyContinue)
        foreach ($f in $rdp) {
            $wasRO = $f.IsReadOnly
            if ($wasRO) { Set-ItemProperty $f.FullName -Name IsReadOnly -Value $false }
            $lines = Get-Content -Path $f.FullName
            # rdpsign appends signscope:s: and signature:s: lines; drop them.
            $clean = $lines | Where-Object { $_ -notmatch '^(signature|signscope):s:' }
            if ($clean.Count -ne $lines.Count) {
                Set-Content -Path $f.FullName -Value $clean -Encoding Unicode
                Write-Log "Stripped signature from $($f.Name)." 'OK'
            } else {
                Write-Log "$($f.Name) had no signature lines." 'SKIP'
            }
            if ($wasRO) { Set-ItemProperty $f.FullName -Name IsReadOnly -Value $true }
        }
    } else {
        Write-Log "KeepRdpSignatures set; left .rdp files untouched." 'SKIP'
    }

    # ----- Phase 5: Flip RedirectionWarningDialogVersion = 1 ---------------
    # Lower-power suppression: restores pre-April popup behavior, no cert.
    $tsKeyHKLM = 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'
    if (-not (Test-Path $tsKeyHKLM)) { New-Item -Path $tsKeyHKLM -Force | Out-Null }
    Set-ItemProperty -Path $tsKeyHKLM -Name 'RedirectionWarningDialogVersion' -Value 1 -Type DWord -Force
    Write-Log "Set RedirectionWarningDialogVersion = 1 (HKLM)." 'OK'

    if ($UserSID) {
        $tsKeyHKCU = "Registry::HKEY_USERS\$UserSID\Software\Policies\Microsoft\Windows NT\Terminal Services"
        if (-not (Test-Path $tsKeyHKCU)) { New-Item -Path $tsKeyHKCU -Force | Out-Null }
        Set-ItemProperty -Path $tsKeyHKCU -Name 'RedirectionWarningDialogVersion' -Value 1 -Type DWord -Force
        Write-Log "Set RedirectionWarningDialogVersion = 1 (HKCU)." 'OK'
    }

    Write-Log "---------------------------------------------"
    Write-Log "Done. Cert removed, policy pruned, popup suppressed via registry bit."
    Write-Log "If the vendor later signs their .rdp files, no further action needed here."
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
