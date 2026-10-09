param(
    [Parameter(Mandatory = $true)]
    [string]$TargetIp,

    [string]$Domain = "WORKGROUP",
    [string]$User = "invaliduser",
    [int]$FailedLogonAttempts = 10,
    [int]$BlockedTcpAttempts = 5,
    [string]$BlockedTcpRemoteIp = "198.51.100.10",
    [int]$BlockedTcpRemotePort = 4444,
    [switch]$SkipBlockedTcp,
    [switch]$SkipFailedLogon,
    [switch]$SkipEncodedPowerShell,
    [switch]$KeepFirewallRule
)

$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "[STEP] $Message" -ForegroundColor Cyan
}

function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "This script must be run in an elevated PowerShell session (Run as Administrator)."
    }
}

Assert-Admin

Write-Host "[INFO ] Target Windows IP: $TargetIp"
Write-Host "[INFO ] Authorized lab use only."

$ruleName = "PHASE4-Temp-Block-TCP-$BlockedTcpRemotePort"

try {
    if (-not $SkipBlockedTcp) {
        Write-Step "Create temporary outbound block rule and generate blocked TCP events"
        if (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue) {
            Remove-NetFirewallRule -DisplayName $ruleName | Out-Null
        }

        New-NetFirewallRule \
            -DisplayName $ruleName \
            -Direction Outbound \
            -Action Block \
            -Protocol TCP \
            -RemoteAddress $BlockedTcpRemoteIp \
            -RemotePort $BlockedTcpRemotePort \
            -Profile Any | Out-Null

        for ($i = 1; $i -le $BlockedTcpAttempts; $i++) {
            Write-Host "[INFO ] Blocked TCP attempt $i/$BlockedTcpAttempts"
            Test-NetConnection -ComputerName $BlockedTcpRemoteIp -Port $BlockedTcpRemotePort -InformationLevel Quiet | Out-Null
        }
    }

    if (-not $SkipFailedLogon) {
        Write-Step "Generate repeated failed logon events (4625)"
        for ($i = 1; $i -le $FailedLogonAttempts; $i++) {
            Write-Host "[INFO ] Failed logon attempt $i/$FailedLogonAttempts"
            cmd /c "net use \\127.0.0.1\IPC$ /user:$Domain\$User WrongPass123! >nul 2>&1"
        }

        cmd /c "net use \\127.0.0.1\IPC$ /delete >nul 2>&1"
    }

    if (-not $SkipEncodedPowerShell) {
        Write-Step "Generate encoded PowerShell execution for Sysmon Event ID 1 correlation"
        $payload = "Write-Output 'phase4-test'; Write-Output 'phase4-test-done'"
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
        powershell.exe -NoProfile -EncodedCommand $encoded | Out-Null
    }
}
finally {
    if ((-not $SkipBlockedTcp) -and (-not $KeepFirewallRule)) {
        Write-Step "Remove temporary firewall rule"
        if (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue) {
            Remove-NetFirewallRule -DisplayName $ruleName | Out-Null
        }
    }
}

Write-Host ""
Write-Host "[DONE ] Windows attack simulation complete." -ForegroundColor Green
Write-Host ""
Write-Host "Expected Windows Wazuh rule.id values:"
Write-Host "- 100434, 100435 (blocked TCP and repeated blocks)"
Write-Host "- 100418, 100421 (failed logon and brute-force correlation)"
Write-Host "- 100500, 100501 (PowerShell execution and encoded command)"
Write-Host ""
Write-Host "Next step: run scripts/validate_phase4_rule_ids.py in windows mode."
