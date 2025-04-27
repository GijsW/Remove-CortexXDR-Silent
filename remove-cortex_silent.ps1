<#
.SYNOPSIS
    Silently uninstalls Cortex XDR (and Traps) with advanced cleanup and logging.

.DESCRIPTION
    1. Determines if Cortex XDR or Traps is installed.
    2. If installed, runs a silent uninstall using registry data and a default or specified password.
    3. Stops and removes any leftover services, registry keys, and directories.
    4. Logs all events to a designated file. No console output is produced.
    5. Returns appropriate exit codes for success or failure states.

.PARAMETER CortexUninstallPassword
    Password required for silent Cortex XDR removal (if applicable).
    Defaults to "DefaultXDRPassword" if not provided.

.PARAMETER LogFile
    Destination for all log entries. Defaults to C:\Temp\CortexXDRUninstall.log.

.PARAMETER VerboseOutput
    If specified, includes additional detail in the log file.

.EXAMPLE
    .\Remove-CortexXDR_Silent.ps1

.EXAMPLE
    .\Remove-CortexXDR_Silent.ps1 -CortexUninstallPassword "CortexUninstallPassword" -LogFile "C:\Logs\XDR_Uninstall.log"

.NOTES
    Run this script as an administrator.  
    Test in a controlled environment before large-scale deployment.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory=$false)]
    [string]$CortexUninstallPassword = "",

    [Parameter(Mandatory=$false)]
    [string]$LogFile = "C:\Temp\CortexXDRUninstall.log",

    [Parameter(Mandatory=$false)]
    [switch]$VerboseOutput
)

# Ensure the log directory exists
try {
    $logDir = Split-Path -Path $LogFile -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
} catch {
    # Since this script is silent, exit on error without writing to console.
    exit 1
}

# Central logging function (writes only to file)
function Write-Log {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Message,
        [Parameter(Mandatory=$false)]
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[${timestamp}] [$Level] $Message"
    Add-Content -Path $LogFile -Value $logEntry

    # If verbose is set, include a secondary verbose entry in the same log
    if ($VerboseOutput) {
        Add-Content -Path $LogFile -Value "[VERBOSE] $Message"
    }
}

# Verify script is running as Administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Write-Log "Script must be run as Administrator." "ERROR"
    exit 2
}

# Set default uninstall password if not provided
if ([string]::IsNullOrEmpty($CortexUninstallPassword)) {
    $CortexUninstallPassword = "DefaultXDRPassword"
    Write-Log "No uninstall password provided; using default password: $CortexUninstallPassword" "WARN"
}

Write-Log "=== Initiating Silent Cortex XDR Removal ==="

# Checks if Cortex XDR / Traps is installed
function Test-CortexXDRPresent {
    Write-Log "Checking registry for Cortex XDR/Traps..."

    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    foreach ($path in $uninstallPaths) {
        try {
            $found = Get-ItemProperty $path -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.DisplayName -like "*Cortex XDR*" -or
                    $_.DisplayName -like "*Traps*"
                }
            if ($found) {
                Write-Log "Uninstall info found in $path" "DEBUG"
                return $true
            }
        } catch {
            Write-Log "Error reading $path`:" $($_.Exception.Message) "ERROR"
        }
    }

    $services = @("Cyvera", "Traps", "CortexXDR", "CybAgent", "CyveraService", "CyveraMonitor", "Cyserver")
    foreach ($svc in $services) {
        try {
            if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
                Write-Log "XDR/Traps-related service found: $svc" "DEBUG"
                return $true
            }
        } catch {
            # Ignore if service not found
        }
    }
    return $false
}

# Uninstalls Cortex XDR (and Traps) silently
function Uninstall-CortexXDR {
    param(
        [string]$UninstallPassword
    )

    Write-Log "Starting silent uninstall using registry entries..."

    $uninstallPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $foundUninstallStrings = $false

    foreach ($path in $uninstallPaths) {
        try {
            $items = Get-ItemProperty $path -ErrorAction SilentlyContinue | Where-Object {
                $_.DisplayName -like "*Cortex XDR*" -or $_.DisplayName -like "*Traps*"
            }

            foreach ($item in $items) {
                $foundUninstallStrings = $true
                $displayName = $item.DisplayName
                $uninstallString = $item.UninstallString
                $quietUninstallString = $item.QuietUninstallString

                Write-Log "Uninstall entry found for $displayName" "DEBUG"

                try {
                    if ($quietUninstallString) {
                        Write-Log "Executing QuietUninstallString: $quietUninstallString" "DEBUG"
                        Start-Process cmd.exe -ArgumentList "/c $quietUninstallString /qn" -Wait -NoNewWindow
                    }
                    elseif ($uninstallString) {
                        Write-Log "Executing UninstallString with password: $uninstallString" "DEBUG"
                        Start-Process cmd.exe -ArgumentList "/c `"$uninstallString /qn UNINSTALL_PASSWORD=$UninstallPassword`"" -Wait -NoNewWindow
                    }
                    Write-Log "Silent uninstall command executed for $displayName."
                } catch {
                    Write-Log "Failed uninstall for $displayName`:" $($_.Exception.Message) "ERROR"
                }
            }
        } catch {
            Write-Log "Error enumerating $path`:" $($_.Exception.Message) "ERROR"
        }
    }

    if (-not $foundUninstallStrings) {
        Write-Log "No Cortex XDR/Traps uninstall entries found in the registry." "WARN"
    }
}

# Removes services, processes, registry keys, directories
function Remove-CortexXDRRemnants {
    Write-Log "Performing advanced cleanup..."

    $services = @(
        "Cyvera", "Traps", "CortexXDR", "CybAgent",
        "CyveraService", "CyveraMonitor", "CyveraConsoleAgent",
        "TrapsUpgrade", "TrapsMsi"
    )
    foreach ($svc in $services) {
        try {
            $serviceObj = Get-Service -Name $svc -ErrorAction SilentlyContinue
            if ($serviceObj) {
                Write-Log "Stopping service: $svc" "DEBUG"
                try {
                    Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
                    Set-Service -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
                    Write-Log "Service stopped/disabled: $svc"
                } catch {
                    Write-Log "Service $svc could not be stopped: $($_.Exception.Message)" "ERROR"
                }
            }
        } catch {
            # Service does not exist
        }
    }

    $processes = @(
        "cyserver", "cyvera", "cyvmon", "cyberobserver",
        "TrapsAgent", "CortexXDR", "CortexXDRAgent"
    )
    foreach ($proc in $processes) {
        try {
            $procObj = Get-Process -Name $proc -ErrorAction SilentlyContinue
            if ($procObj) {
                Write-Log "Terminating process: $proc" "DEBUG"
                $procObj | Stop-Process -Force -ErrorAction SilentlyContinue
                Write-Log "Terminated: $proc"
            }
        } catch {
            Write-Log "Could not terminate $proc`:" $($_.Exception.Message) "ERROR"
        }
    }

    $regPaths = @(
        "HKLM:\SOFTWARE\Cyvera",
        "HKLM:\SOFTWARE\Traps",
        "HKLM:\SOFTWARE\Palo Alto Networks\Traps",
        "HKLM:\SOFTWARE\Palo Alto Networks\Cortex XDR",
        "HKCU:\Software\Palo Alto Networks\Traps",
        "HKCU:\Software\Palo Alto Networks\Cortex XDR"
    )
    foreach ($rPath in $regPaths) {
        if (Test-Path $rPath) {
            Write-Log "Removing registry key: $rPath" "DEBUG"
            try {
                Remove-Item -Path $rPath -Recurse -Force -ErrorAction Stop
                Write-Log "Removed registry key: $rPath"
            } catch {
                Write-Log "Failed to remove $rPath`:" $($_.Exception.Message) "ERROR"
            }
        }
    }

    $directories = @(
        "$env:ProgramFiles\Cyvera",
        "$env:ProgramFiles\Traps",
        "$env:ProgramFiles\Cortex",
        "$env:ProgramData\Cyvera",
        "$env:ProgramData\Traps",
        "$env:ProgramData\Cortex"
    )
    foreach ($dir in $directories) {
        if (Test-Path $dir) {
            Write-Log "Removing directory: $dir" "DEBUG"
            try {
                Remove-Item -Path $dir -Recurse -Force -ErrorAction Stop
                Write-Log "Removed directory: $dir"
            } catch {
                Write-Log "Failed to remove $dir`:" $($_.Exception.Message) "ERROR"
            }
        }
    }

    Write-Log "Advanced cleanup complete."
}

# Checks final removal status
function Test-CortexXDRRemoval {
    if (Test-CortexXDRPresent) {
        Write-Log "Cortex XDR or Traps is still present." "WARN"
        return $false
    } else {
        Write-Log "Cortex XDR is no longer present."
        return $true
    }
}

# Main script execution
Write-Log "Checking for Cortex XDR presence..."
$XdrPresent = Test-CortexXDRPresent

if ($XdrPresent) {
    Write-Log "Cortex XDR/Traps detected; proceeding with uninstall..."

    # Attempt uninstall
    Uninstall-CortexXDR -UninstallPassword $CortexUninstallPassword

    Start-Sleep -Seconds 5

    # If still present, perform advanced cleanup
    if (Test-CortexXDRPresent) {
        Write-Log "Still detected; proceeding with cleanup..."
        Remove-CortexXDRRemnants
    }

    Start-Sleep -Seconds 3

    # Final verification
    if (Test-CortexXDRRemoval) {
        Write-Log "Removal verified. Script complete."
        exit 0
    } else {
        Write-Log "Warning: XDR may still be present. Manual intervention needed." "WARN"
        exit 3
    }
} else {
    Write-Log "Cortex XDR is not present. Script complete."
    exit 0
}
