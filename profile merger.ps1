# ================================================================
# Profile Merge Script: Merge .bbt profile into current user
# ================================================================
$ErrorActionPreference = "Stop"

# -----------------------------
# LOGGING
# -----------------------------
$LogDir = "C:\Win11Media\Logs"
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
$LogFile = Join-Path $LogDir ("ProfileMerge_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".log")

function Write-Log {
    param($Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "$ts - $Message"
    Write-Host $line
    Add-Content -Path $LogFile -Value $line
}

Write-Log "Starting profile merge script."

# -----------------------------
# DETERMINE PROFILES
# -----------------------------
$CurrentUser = [Environment]::UserName
$UserProfilePath = [Environment]::GetFolderPath("UserProfile")
$ProfileDir = Split-Path $UserProfilePath -Parent
$BBTProfileDir = Get-ChildItem $ProfileDir | Where-Object { $_.PSIsContainer -and $_.Name -like "*.bbt" } | Select-Object -First 1

if (-not $BBTProfileDir) {
    Write-Log "No .bbt profile found to merge. Exiting."
    exit 1
}

Write-Log "Current user profile: $UserProfilePath"
Write-Log ".bbt profile detected: $($BBTProfileDir.FullName)"

# -----------------------------
# DEFINE FOLDERS TO MERGE
# -----------------------------
$MergeFolders = @("Documents", "Desktop", "Downloads", "Pictures", "Videos", "Music", "Favorites", "AppData\Roaming", "AppData\Local")

foreach ($Folder in $MergeFolders) {
    $SourcePath = Join-Path $BBTProfileDir.FullName $Folder
    $TargetPath = Join-Path $UserProfilePath $Folder

    if (-not (Test-Path $SourcePath)) { continue }
    if (-not (Test-Path $TargetPath)) { New-Item -Path $TargetPath -ItemType Directory -Force | Out-Null }

    Write-Log "Merging folder: ${Folder}"

    $Items = Get-ChildItem -Path $SourcePath -Force -Recurse
    foreach ($Item in $Items) {
        $RelativePath = $Item.FullName.Substring($SourcePath.Length).TrimStart("\")
        $TargetFile = Join-Path $TargetPath $RelativePath

        try {
            if ($Item.PSIsContainer) {
                if (-not (Test-Path $TargetFile)) { New-Item -ItemType Directory -Path $TargetFile -Force | Out-Null }
            } else {
                Copy-Item -Path $Item.FullName -Destination $TargetFile -Force -ErrorAction Stop
            }
        } catch {
            $ErrorMessage = $_.Exception.Message
            Write-Log "Failed to copy ${RelativePath}: ${ErrorMessage}"
        }
    }
}

Write-Log "Profile merge completed successfully."

# -----------------------------
# OPTIONAL CLEANUP
# -----------------------------
# Uncomment to remove .bbt profile after merge
# Remove-Item -Path $BBTProfileDir.FullName -Recurse -Force
# Write-Log ".bbt profile deleted after merge."

Write-Log "Script finished."
