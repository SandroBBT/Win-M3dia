# ==============================================
# Full Script: Windows 11 ISO + Duplicate SID Fix + Update Cleanup + Bypass Upgrade + Logging
# ==============================================
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
# STEP 1 — FIX DUPLICATE SIDs
# -----------------------------
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "=== Duplicate User Profile Auto-Fix ===" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan

$CurrentSID = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
Write-Host "Current logged in SID: $CurrentSID" -ForegroundColor Yellow

$Profiles = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
$DuplicateSIDs = @()

try {
    $CurrentProfilePath = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$CurrentSID").ProfileImagePath
    Write-Host "Current user profile path: $CurrentProfilePath" -ForegroundColor Yellow
} catch {
    Write-Host "ERROR: Cannot read current profile path. Skipping duplicate SID cleanup." -ForegroundColor Red
    $CurrentProfilePath = $null
}

if ($CurrentProfilePath) {
    foreach ($Profile in $Profiles) {
        $SID = $Profile.PSChildName
        $Path = (Get-ItemProperty $Profile.PSPath).ProfileImagePath
        if ($Path -eq $CurrentProfilePath -and $SID -ne $CurrentSID) {
            $DuplicateSIDs += $SID
        }
    }
}

if ($DuplicateSIDs.Count -eq 0) {
    Write-Host "No duplicate SIDs found." -ForegroundColor Green
} else {
    Write-Host "Duplicate SIDs detected:" -ForegroundColor Red
    $DuplicateSIDs | ForEach-Object { Write-Host " - $_" -ForegroundColor Red }
    foreach ($BadSID in $DuplicateSIDs) {
        Write-Host "Removing duplicate SID: $BadSID" -ForegroundColor Yellow
        Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$BadSID" -Recurse -Force
    }
    Write-Host "Duplicate SIDs removed successfully. A reboot is recommended." -ForegroundColor Green
}

# -----------------------------
# STEP 2 — RESET WINDOWS UPDATE
# -----------------------------
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "=== Resetting Windows Update System ===" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan

Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
Stop-Service bits -Force -ErrorAction SilentlyContinue

Remove-Item -Path "C:\Windows\SoftwareDistribution\*" -Recurse -Force -ErrorAction SilentlyContinue

if (Test-Path "C:\$WINDOWS.~BT") {
    Remove-Item -Path "C:\$WINDOWS.~BT" -Recurse -Force -ErrorAction SilentlyContinue
}

Start-Service wuauserv -ErrorAction SilentlyContinue
Start-Service bits -ErrorAction SilentlyContinue
Write-Log "Windows Update cache cleared."

# -----------------------------
# STEP 3 — ENSURE ADMIN
# -----------------------------
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Not running as Administrator. Elevating..."
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

Write-Log "Starting Windows 11 upgrade script."

# -----------------------------
# STEP 4 — APPLY REGISTRY BYPASS TWEAKS
# -----------------------------
Write-Log "Step 4: Applying registry bypass tweaks..."

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
# STEP 5 — SET WINDOWS UPDATE TARGET RELEASE
# -----------------------------
Write-Log "Step 5: Setting Windows Update target release to 24H2..."

$WinUpdatePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
if (-not (Test-Path $WinUpdatePath)) { New-Item -Path $WinUpdatePath -Force | Out-Null }

New-ItemProperty -Path $WinUpdatePath -Name "ProductVersion" -Value "Windows 11" -PropertyType String -Force
New-ItemProperty -Path $WinUpdatePath -Name "TargetReleaseVersion" -Value 1 -PropertyType DWord -Force
New-ItemProperty -Path $WinUpdatePath -Name "TargetReleaseVersionInfo" -Value "24H2" -PropertyType String -Force

Write-Log "Windows Update target release set to 24H2."

# -----------------------------
# STEP 6 — ISO MOUNT & COPY
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
# STEP 7 — WINDOWS 11 SETUP
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
