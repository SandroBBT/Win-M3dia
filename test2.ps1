# ================================================================
# Full Script: Windows 11 ISO + Duplicate SID Fix + Update Cleanup + Bypass Upgrade + Logging
# Safe-patched: do NOT delete active user or service SIDs
# ================================================================
$ErrorActionPreference = "Stop"

# -----------------------------
# LOGGING
# -----------------------------
$LogDir = "C:\Win11Media\Logs"
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
$LogFile = Join-Path $LogDir ("Win11_Upgrade_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".log")

function Write-Log {
    param($Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$ts - $Message"
    Write-Host $line
    Add-Content -Path $LogFile -Value $line
}

Write-Log "Starting Windows 11 upgrade script with SID fix and update cleanup."

# -----------------------------
# Grab current logged-in SID early (used to protect active profile)
# -----------------------------
$CurrentSID = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
Write-Log "Current logged-in SID: $CurrentSID"

# -----------------------------
# STEP 1 — FIX DUPLICATE SIDs (safe)
# -----------------------------
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "=== Duplicate User Profile Auto-Fix (safe) ===" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan

$Profiles = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
$DuplicateSIDs = @()

try {
    $CurrentProfilePath = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$CurrentSID" -ErrorAction SilentlyContinue).ProfileImagePath
    Write-Host "Current user profile path: $CurrentProfilePath" -ForegroundColor Yellow
} catch {
    Write-Host "WARNING: Cannot read current profile path." -ForegroundColor Yellow
    $CurrentProfilePath = $null
}

if ($CurrentProfilePath) {
    foreach ($Profile in $Profiles) {
        $SID = $Profile.PSChildName
        # Protect active user
        if ($SID -eq $CurrentSID) { continue }

        $Path = (Get-ItemProperty $Profile.PSPath -ErrorAction SilentlyContinue).ProfileImagePath
        if ($Path -and $Path -eq $CurrentProfilePath -and $SID -ne $CurrentSID) {
            $DuplicateSIDs += $SID
        }
    }
}

if ($DuplicateSIDs.Count -eq 0) {
    Write-Host "No duplicate SIDs found." -ForegroundColor Green
    Write-Log "No duplicate SIDs found."
} else {
    Write-Host "Duplicate SIDs detected:" -ForegroundColor Red
    $DuplicateSIDs | ForEach-Object { Write-Host " - $_" -ForegroundColor Red; Write-Log "Duplicate SID: $_" }
    foreach ($BadSID in $DuplicateSIDs) {
        Write-Host "Removing duplicate SID registry key: $BadSID" -ForegroundColor Yellow
        Write-Log "Removing duplicate SID registry key: $BadSID"
        # Extra safety: ensure not system/service SID pattern and not current user (already checked)
        if ($BadSID -notmatch "^(S-1-5-18|S-1-5-19|S-1-5-20|S-1-5-80-)" ) {
            Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$BadSID" -Recurse -Force -ErrorAction SilentlyContinue
        } else {
            Write-Log "Skipped removing system/service SID: $BadSID"
        }
    }
    Write-Host "Duplicate SIDs removed successfully. A reboot is recommended." -ForegroundColor Green
    Write-Log "Duplicate SID removal completed."
}

# -----------------------------
# STEP 2 — ADVANCED SID & PROFILE REPAIR (SAFE)
# Only operate on REAL user SIDs; skip service/virtual/system SIDs; never touch current SID
# -----------------------------
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "=== Advanced SID Repair Module (safe) ===" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan

# Get local user SIDs
$LocalUsers = @()
try { $LocalUsers = Get-LocalUser | Select-Object -ExpandProperty SID -ErrorAction SilentlyContinue } catch {}
# Try to get AD users if AD module available (non-fatal if missing)
$DomainUsers = @()
try {
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
    $DomainUsers = Get-ADUser -Filter * -Properties SID | Select-Object -ExpandProperty SID -ErrorAction SilentlyContinue
} catch {
    $DomainUsers = @()
}

$ValidUserSIDs = @()
if ($LocalUsers) { $ValidUserSIDs += $LocalUsers }
if ($DomainUsers) { $ValidUserSIDs += $DomainUsers }

# Re-read profile keys
$ProfileKeys = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"

foreach ($Key in $ProfileKeys) {
    $SID = $Key.PSChildName

    # PROTECTION: skip the active user always
    if ($SID -eq $CurrentSID) {
        Write-Host "Skipping active user SID: $SID" -ForegroundColor Cyan
        continue
    }

    # Skip well-known system/service/virtual SIDs
    if ($SID -in @("S-1-5-18","S-1-5-19","S-1-5-20")) {
        Write-Log "Skipping system SID: $SID"
        continue
    }
    if ($SID -like "S-1-5-21-*-500" -or $SID -like "S-1-5-21-*-501") {
        # skip built-in admin/guest patterns
        Write-Log "Skipping built-in admin/guest SID pattern: $SID"
        continue
    }
    if ($SID -like "S-1-5-80-*") {
        # virtual/service account SIDs
        Write-Log "Skipping service/virtual SID: $SID"
        continue
    }

    # Attempt to read ProfileImagePath; if cannot, skip (avoid removing service keys)
    $Props = $null
    try {
        $Props = Get-ItemProperty $Key.PSPath -ErrorAction Stop
    } catch {
        Write-Log "Cannot read profile key properties for $SID — skipping."
        continue
    }

    $Path = $Props.ProfileImagePath

    # If no path recorded, skip (do not delete blindly)
    if (-not $Path) {
        Write-Log "Profile key $SID has no ProfileImagePath — skipping."
        continue
    }

    # If this is a .bak key (user profile backup), attempt safe repair
    if ($SID -match "\.bak$") {
        Write-Host "Repairing .bak SID: $SID" -ForegroundColor Yellow
        Write-Log "Repairing .bak SID: $SID"
        $NewSID = $SID -replace "\.bak$", ""
        # Ensure we won't overwrite the active SID
        if ($NewSID -ne $CurrentSID) {
            try {
                Rename-Item -Path $Key.PSPath -NewName $NewSID -Force -ErrorAction Stop
                Write-Host "✔ Repaired: $NewSID" -ForegroundColor Green
                Write-Log "Repaired .bak -> $NewSID"
            } catch {
                Write-Log "Failed to rename $SID to $NewSID: $($_.Exception.Message)"
            }
        } else {
            Write-Log "Refused .bak rename because target equals current SID: $NewSID"
        }
        continue
    }

    # If profile folder is missing -> safe orphan removal
    if (-not (Test-Path $Path)) {
        Write-Host "Orphaned SID (folder missing): $SID" -ForegroundColor Red
        Write-Log "Orphaned SID (folder missing): $SID - removing registry key"
        # Only remove if SID is not a known service/system pattern
        if ($SID -notmatch "^(S-1-5-18|S-1-5-19|S-1-5-20|S-1-5-80-)") {
            Remove-Item $Key.PSPath -Recurse -Force -ErrorAction SilentlyContinue
        } else {
            Write-Log "Skipped removing system/service SID with missing folder: $SID"
        }
        continue
    }

    # If folder exists but NTUSER.DAT missing -> only remove if SID maps to a real user
    $NtUser = Join-Path $Path "NTUSER.DAT"
    if (-not (Test-Path $NtUser)) {
        if ($ValidUserSIDs -contains $SID) {
            Write-Host "Corrupt real user profile (missing NTUSER.DAT): $SID" -ForegroundColor Red
            Write-Log "Corrupt real user profile (missing NTUSER.DAT): $SID - removing registry key"
            Remove-Item $Key.PSPath -Recurse -Force -ErrorAction SilentlyContinue
        } else {
            Write-Log "Found missing NTUSER.DAT for non-user/service SID $SID — skipping to avoid breaking service accounts."
        }
        continue
    }

    # Additional safety: deduplicate registry entries pointing to same folder
    $Matching = $ProfileKeys | Where-Object {
        try {
            (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).ProfileImagePath -eq $Path
        } catch { $false }
    }

    if ($Matching.Count -gt 1) {
        foreach ($Dup in $Matching) {
            $DupSID = $Dup.PSChildName
            if ($DupSID -ne $SID -and $DupSID -ne $CurrentSID) {
                Write-Host "Removing duplicate SID entry: $DupSID" -ForegroundColor Yellow
                Write-Log "Removing duplicate SID entry: $DupSID (same profile path as $SID)"
                Remove-Item $Dup.PSPath -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

Write-Host "✔ Advanced SID repair complete." -ForegroundColor Green
Write-Log "Advanced SID repair complete."

# -----------------------------
# STEP 3 — RESET WINDOWS UPDATE
# -----------------------------
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "=== Resetting Windows Update System ===" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan

Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
Stop-Service bits -Force -ErrorAction SilentlyContinue

# Clear SoftwareDistribution safely (delete files in Download and DataStore only)
try {
    Remove-Item -Path "C:\Windows\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\Windows\SoftwareDistribution\DataStore\*" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Log "Cleared SoftwareDistribution Download and DataStore."
} catch {
    Write-Log "Failed to fully clear SoftwareDistribution: $($_.Exception.Message)"
}

if (Test-Path "C:\$WINDOWS.~BT") {
    Write-Log "Removing C:\$WINDOWS.~BT folder..."
    Remove-Item -Path "C:\$WINDOWS.~BT" -Recurse -Force -ErrorAction SilentlyContinue
    Write-Log "Removed C:\$WINDOWS.~BT"
}

Start-Service wuauserv -ErrorAction SilentlyContinue
Start-Service bits -ErrorAction SilentlyContinue
Write-Log "Windows Update cache cleared."

# -----------------------------
# STEP 4 — ENSURE ADMIN
# -----------------------------
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Not running as Administrator. Elevating..."
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

Write-Log "Starting Windows 11 upgrade script."

# -----------------------------
# STEP 5 — APPLY REGISTRY BYPASS TWEAKS
# -----------------------------
Write-Log "Step 5: Applying registry bypass tweaks..."

$moSetupPath = "HKLM:\SYSTEM\Setup\MoSetup"
$hwReqChkPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\HwReqChk"
if (-not (Test-Path $moSetupPath)) { New-Item -Path $moSetupPath -Force | Out-Null }
if (-not (Test-Path $hwReqChkPath)) { New-Item -Path $hwReqChkPath -Force | Out-Null }

New-ItemProperty -Path $moSetupPath -Name "AllowUpgradesWithUnsupportedTPMOrCPU" -Value 1 -PropertyType DWord -Force
New-ItemProperty -Path $hwReqChkPath -Name "HwReqChkVars" -PropertyType MultiString -Value @(
    "SQ_SecureBootCapable=TRUE",
    "SQ_SecureBootEnabled=TRUE",
    "SQ_TpmVersion=2",
    "SQ_RamMB=8192"
) -Force

Write-Log "Registry tweaks applied."

# -----------------------------
# STEP 6 — SET WINDOWS UPDATE TARGET RELEASE
# -----------------------------
Write-Log "Step 6: Setting Windows Update target release to 24H2..."

$WinUpdatePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
if (-not (Test-Path $WinUpdatePath)) { New-Item -Path $WinUpdatePath -Force | Out-Null }

New-ItemProperty -Path $WinUpdatePath -Name "ProductVersion" -Value "Windows 11" -PropertyType String -Force
New-ItemProperty -Path $WinUpdatePath -Name "TargetReleaseVersion" -Value 1 -PropertyType DWord -Force
New-ItemProperty -Path $WinUpdatePath -Name "TargetReleaseVersionInfo" -Value "24H2" -PropertyType String -Force

Write-Log "Windows Update target release set to 24H2."

# -----------------------------
# STEP 7 — ISO MOUNT & COPY
# -----------------------------
$PrimaryISO  = "C:\Win11Media\Win11_25H2_English_x64.iso"
$TempDir = "C:\Win11Media\Win11Temp"
if (Test-Path $TempDir) { Remove-Item $TempDir -Recurse -Force }
New-Item -Path $TempDir -ItemType Directory | Out-Null

Write-Log "Mounting ISO..."
$mount = Mount-DiskImage -ImagePath $PrimaryISO -PassThru
$driveLetter = ($mount | Get-Volume).DriveLetter + ":"
Write-Log "ISO mounted at $driveLetter"

Write-Log "Copying ISO contents to $TempDir..."
Copy-Item -Path "$driveLetter\*" -Destination $TempDir -Recurse -Force
Dismount-DiskImage -ImagePath $PrimaryISO
Write-Log "ISO copied and dismounted."

# -----------------------------
# STEP 8 — WINDOWS 11 SETUP
# -----------------------------
$SetupExe = Join-Path $TempDir "setup.exe"
if (-not (Test-Path $SetupExe)) {
    Write-Log "ERROR: setup.exe not found in ISO contents."
    exit 1
}

# -----------------------------
# Unsilent test run
# -----------------------------
Write-Log "Launching Windows 11 Setup unsilently for testing..."
Start-Process -FilePath $SetupExe -ArgumentList "/auto upgrade /showoobe none /eula accept /dynamicupdate enable /compat ignorewarning" -Wait
Write-Log "Test setup finished."

# -----------------------------
# Silent final run
# -----------------------------
Write-Log "Launching Windows 11 Setup silently..."
Start-Process -FilePath $SetupExe -ArgumentList "/auto upgrade /quiet /noreboot /showoobe none /eula accept /dynamicupdate enable /compat ignorewarning /migratedrivers all" -Wait

Write-Log "Silent setup finished."

Write-Log "Windows 11 upgrade process completed."
