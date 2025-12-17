# Full Windows 11 Bypass & Upgrade Script
# Logs will be created at C:\Win11Media\Logs
$LogDir = "C:\Win11Media\Logs"
if (-not (Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory | Out-Null }
$LogFile = Join-Path $LogDir ("Win11_Upgrade_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".log")

function Write-Log {
    param($Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$ts - $Message"
    Write-Host $line
    Add-Content -Path $LogFile -Value $line
}

# Ensure running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Not running as Administrator. Elevating..."
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

Write-Log "Starting Windows 11 bypass and upgrade script."

# --- Step 0: Reset Windows Update ---
Write-Log "Step 0: Resetting Windows Update and network settings..."
Stop-Service -Name BITS,wuauserv,appidsvc,cryptsvc -Force -ErrorAction SilentlyContinue
Rename-Item "$env:systemroot\SoftwareDistribution" "SoftwareDistribution.bak" -ErrorAction SilentlyContinue
Rename-Item "$env:systemroot\System32\Catroot2" "Catroot2.bak" -ErrorAction SilentlyContinue
Start-Service -Name BITS,wuauserv,appidsvc,cryptsvc -ErrorAction SilentlyContinue
Write-Log "Windows Update reset complete."

# --- Step 1: Apply Registry Bypass Tweaks ---
Write-Log "Step 1: Applying registry bypass tweaks..."
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

# --- Step 1 1/2: Regedit ---
reg add HKLM\SYSTEM\Setup\LabConfig /v BypassTPMCheck /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\Setup\LabConfig /v BypassSecureBootCheck /t REG_DWORD /d 1 /f
reg add HKLM\SYSTEM\Setup\LabConfig /v BypassCPUCheck /t REG_DWORD /d 1 /f

# --- Step 2: Set Windows Update Target Release ---
Write-Log "Step 2: Setting Windows Update target release to 25H2..."
$WinUpdatePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
if (-not (Test-Path $WinUpdatePath)) { New-Item -Path $WinUpdatePath -Force | Out-Null }
New-ItemProperty -Path $WinUpdatePath -Name "ProductVersion" -Value "Windows 11" -PropertyType String -Force
New-ItemProperty -Path $WinUpdatePath -Name "TargetReleaseVersion" -Value 1 -PropertyType DWord -Force
New-ItemProperty -Path $WinUpdatePath -Name "TargetReleaseVersionInfo" -Value "24H2" -PropertyType String -Force
Write-Log "Windows Update target release set."

# --- Step 3: remove target release ---
# Write-Log "Step 3: Removing Windows Update target release..."
# Remove-ItemProperty -Path $WinUpdatePath -Name "ProductVersion","TargetReleaseVersion","TargetReleaseVersionInfo" -ErrorAction SilentlyContinue

# --- ISO Setup (with fallback) ---
$PrimaryISO = "C:\Win11Media\Win11_25H2_English_x64.iso"
$FallbackISO = "C:\Win11Media\Win11_24H2_English_x64.iso"

if (Test-Path $PrimaryISO) {
    $IsoPath = $PrimaryISO
    Write-Log "Primary ISO found: $PrimaryISO"
}
elseif (Test-Path $FallbackISO) {
    $IsoPath = $FallbackISO
    Write-Log "Primary ISO missing — using fallback ISO: $FallbackISO"
}
else {
    Write-Log "ERROR: Neither primary nor fallback ISO exists."
    exit 1
}

$TempDir = "C:\Win11Media\Win11Temp"
if (Test-Path $TempDir) { Remove-Item $TempDir -Recurse -Force }
New-Item -Path $TempDir -ItemType Directory | Out-Null

Write-Log "Mounting ISO..."
$mount = Mount-DiskImage -ImagePath $IsoPath -PassThru
$driveLetter = ($mount | Get-Volume).DriveLetter + ":"
Write-Log "ISO mounted at $driveLetter"
Write-Log "Copying ISO contents to $TempDir..."
Copy-Item -Path "$driveLetter\*" -Destination $TempDir -Recurse -Force
Dismount-DiskImage -ImagePath $IsoPath
Write-Log "ISO copied and dismounted."

# --- Windows 11 Setup ---
$SetupExe = Join-Path $TempDir "setup.exe"
if (-not (Test-Path $SetupExe)) { Write-Log "ERROR: setup.exe not found in ISO contents."; exit 1 }

# --- Unsilent test run ---
Write-Log "Launching Windows 11 Setup unsilently for testing..."
Start-Process -FilePath $SetupExe -ArgumentList "/auto upgrade /showoobe none /eula accept /dynamicupdate enable /compat ignorewarning" -Wait
Write-Log "Test setup finished."

# --- Silent final run ---
Write-Log "Launching Windows 11 Setup silently..."
Start-Process -FilePath $SetupExe -ArgumentList "/auto upgrade /quiet /noreboot /showoobe none /eula accept /dynamicupdate enable /compat ignorewarning /migratedrivers all" -Wait
Write-Log "Silent setup finished. Rebooting..."
Restart-Computer -Force
