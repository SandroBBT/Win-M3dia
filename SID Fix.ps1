<# 
    Safe-FixSIDs.ps1
    -----------------
    Purpose:
      - Safely clean up obviously broken ProfileList entries.
      - Avoid touching likely real user profiles.
      - Default is DRY-RUN (log only).

    Usage:
      - DRY RUN (recommended first):  .\Safe-FixSIDs.ps1
      - APPLY CHANGES:                .\Safe-FixSIDs.ps1 -DryRun:$false
#>

param(
    [switch]$DryRun = $true
)

$ErrorActionPreference = "Stop"

# -----------------------------
# Logging setup
# -----------------------------
$BaseDir = "C:\Win11Tools\SIDFix"
$LogDir  = Join-Path $BaseDir "Logs"

foreach ($d in @($BaseDir,$LogDir)) {
    if (-not (Test-Path $d)) { New-Item -Path $d -ItemType Directory -Force | Out-Null }
}

$LogFile = Join-Path $LogDir ("SIDFix_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".log")

function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$ts - $Message"
    Write-Host $line
    Add-Content -Path $LogFile -Value $line
}

Write-Log "=== Safe-FixSIDs.ps1 starting. DryRun = $DryRun ==="

# -----------------------------
# Admin check
# -----------------------------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Log "ERROR: Script must be run as Administrator. Exiting."
    throw "Must run as Administrator."
}

# -----------------------------
# Registry backup
# -----------------------------
$ProfileListKey = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
$BackupDir      = Join-Path $BaseDir "Backups"
if (-not (Test-Path $BackupDir)) { New-Item -Path $BackupDir -ItemType Directory -Force | Out-Null }

$BackupFile = Join-Path $BackupDir ("ProfileList_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".reg")

try {
    Write-Log "Exporting ProfileList backup to $BackupFile"
    reg.exe export $ProfileListKey $BackupFile /y | Out-Null
    Write-Log "ProfileList backup export completed."
} catch {
    Write-Log "WARNING: Failed to export ProfileList backup: $($_.Exception.Message)"
    # Still continue, but log it
}

# -----------------------------
# Build protected SID list
# -----------------------------
$ProtectedSIDs = New-Object System.Collections.Generic.HashSet[string]

# Core system SIDs
@(
    "S-1-5-18", # LocalSystem
    "S-1-5-19", # LocalService
    "S-1-5-20"  # NetworkService
) | ForEach-Object { [void]$ProtectedSIDs.Add($_) }

# Token SID (whoever we're running as)
try {
    $currentSID = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
    if ($currentSID) {
        [void]$ProtectedSIDs.Add($currentSID)
        Write-Log "Protected SID added (current token): $currentSID"
    }
} catch {}

# Last logged-on user SID (if resolvable)
try {
    $logonUIKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
    $lastUserName = (Get-ItemProperty -Path $logonUIKey -ErrorAction SilentlyContinue).LastLoggedOnUser
    if ($lastUserName) {
        try {
            $nt = New-Object System.Security.Principal.NTAccount($lastUserName)
            $sidObj = $nt.Translate([System.Security.Principal.SecurityIdentifier])
            $lluSID = $sidObj.Value
            if ($lluSID) {
                [void]$ProtectedSIDs.Add($lluSID)
                Write-Log "Protected SID added (LastLoggedOnUser $lastUserName): $lluSID"
            }
        } catch {
            Write-Log "Could not resolve LastLoggedOnUser '$lastUserName' to SID: $($_.Exception.Message)"
        }
    }
} catch {}

# -----------------------------
# Collect ProfileList entries
# -----------------------------
$ProfileListPathPS = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
$ProfileKeys = Get-ChildItem -Path $ProfileListPathPS -ErrorAction Stop

Write-Log "Discovered $($ProfileKeys.Count) ProfileList subkeys."

# Helper: is SID generally a "system/service" pattern
function Test-SystemLikeSID {
    param([string]$SID)

    if ($SID -in @("S-1-5-18","S-1-5-19","S-1-5-20")) { return $true }
    if ($SID -like "S-1-5-80-*") { return $true }  # service SIDs
    return $false
}

# -----------------------------
# Pass 1: Analyze & plan actions
# -----------------------------
$Plan_RenameBak = @()
$Plan_RemoveOrphan = @()

foreach ($key in $ProfileKeys) {
    $SID = $key.PSChildName

    # Skip obvious system/service SIDs
    if (Test-SystemLikeSID $SID) {
        Write-Log "INFO: Skipping system/service SID $SID"
        continue
    }

    # Basic properties
    $props = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
    $path  = $props.ProfileImagePath

    # -------------------------
    # Case A: .bak profiles
    # -------------------------
    if ($SID -match '\.bak$') {
        $OrigSID = $SID -replace '\.bak$',''

        # Only consider if there is NO non-bak key with this SID
        $origPath = Join-Path $ProfileListPathPS $OrigSID
        $origExists = Test-Path $origPath

        if ($origExists) {
            Write-Log "INFO: .bak SID $SID has existing non-bak key $OrigSID. No auto-rename."
            continue
        }

        # Ensure profile folder exists and looks valid
        $folderOK = $false
        if ($path -and (Test-Path $path)) {
            $ntuser = Join-Path $path "NTUSER.DAT"
            if (Test-Path $ntuser) {
                $folderOK = $true
            }
        }

        if (-not $folderOK) {
            Write-Log "INFO: .bak SID $SID with missing/invalid folder for '$path'. Logging only."
            continue
        }

        $Plan_RenameBak += [PSCustomObject]@{
            SID       = $SID
            NewSID    = $OrigSID
            RegPath   = $key.PSPath
            UserPath  = $path
        }
        Write-Log "PLAN: Rename .bak key '$SID' -> '$OrigSID' (Profile=$path)."
        continue
    }

    # -------------------------
    # Case B: Orphaned entries
    # -------------------------
    $pathExists = $false
    if ($path -and (Test-Path $path)) {
        $pathExists = $true
    }

    if (-not $path -or -not $pathExists) {
        # Fully orphaned: no path, or path does not exist at all
        $Plan_RemoveOrphan += [PSCustomObject]@{
            SID      = $SID
            RegPath  = $key.PSPath
            Reason   = if (-not $path) { "No ProfileImagePath" } else { "Profile folder missing: $path" }
        }
        Write-Log "PLAN: Remove orphaned SID $SID ($($Plan_RemoveOrphan[-1].Reason))."
        continue
    }

    # Otherwise, we leave it alone. We do NOT auto-delete "duplicates" here.
}

Write-Log "Planning complete. .bak-to-SID renames: $($Plan_RenameBak.Count); Orphan removals: $($Plan_RemoveOrphan.Count)."

# -----------------------------
# Pass 2: Execute plan (or DRY-RUN)
# -----------------------------
if ($DryRun) {
    Write-Log "DRY-RUN mode: No registry changes will be made."
} else {
    Write-Log "APPLY mode: Executing planned SID fixes."
}

# Helper to check protection
function Test-IsProtectedSID {
    param([string]$SID)
    return $ProtectedSIDs.Contains($SID)
}

# Apply .bak renames
foreach ($item in $Plan_RenameBak) {
    $SID    = $item.SID
    $NewSID = $item.NewSID

    if (Test-IsProtectedSID $SID -or Test-IsProtectedSID $NewSID) {
        Write-Log "SAFEGUARD: Skipping rename for protected SID $SID -> $NewSID"
        continue
    }

    $parentPath = Split-Path -Path $item.RegPath -Parent
    $newRegPath = Join-Path $parentPath $NewSID

    if ($DryRun) {
        Write-Log "DRY-RUN: Would rename registry key '$($item.RegPath)' to '$newRegPath'."
    } else {
        try {
            Write-Log "ACTION: Renaming registry key '$($item.RegPath)' to '$newRegPath'."
            Rename-Item -Path $item.RegPath -NewName $NewSID -Force -ErrorAction Stop
        } catch {
            Write-Log "ERROR: Failed to rename $SID -> $NewSID : $($_.Exception.Message)"
        }
    }
}

# Apply orphan removals
foreach ($item in $Plan_RemoveOrphan) {
    $SID = $item.SID

    if (Test-IsProtectedSID $SID) {
        Write-Log "SAFEGUARD: Skipping orphan removal for protected SID $SID ($($item.Reason))"
        continue
    }

    if ($DryRun) {
        Write-Log "DRY-RUN: Would remove orphaned SID $SID at '$($item.RegPath)' ($($item.Reason))."
    } else {
        try {
            Write-Log "ACTION: Removing orphaned SID $SID at '$($item.RegPath)' ($($item.Reason))."
            Remove-Item -Path $item.RegPath -Recurse -Force -ErrorAction Stop
        } catch {
            Write-Log "ERROR: Failed to remove orphaned SID $SID : $($_.Exception.Message)"
        }
    }
}

Write-Log "=== Safe-FixSIDs.ps1 finished. See log at $LogFile ==="
