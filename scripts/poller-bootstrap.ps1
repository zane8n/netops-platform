<#
.SYNOPSIS
    Set up a Windows machine as a Netrune traffic poller and keep it collecting
    across reboots.

.DESCRIPTION
    The collector shells out to snmpget, snmpwalk and bash, none of which exist
    natively on Windows, so the poller runs inside WSL2. This script does the
    Windows half: install WSL2 and a distro, hand the Linux installer its
    payload, and arrange for the whole thing to come back by itself after the
    machine is switched off.

    Three things have to be true for that last part, and each fails silently on
    its own:

      1. WSL must run systemd, or nothing supervises the collector.
      2. The distro must be started after boot. Windows does not start it for
         you, and nobody logs in to a poller.
      3. The laptop must be able to reach SSH inside the distro.

    A scheduled task covers 2 and 3 together, on a repeat, so it also repairs
    itself if WSL is shut down or its NAT address changes.

.PARAMETER Distro
    WSL distribution to use. Default: Ubuntu.

.PARAMETER SshPort
    Port on this machine that forwards to SSH inside the distro. Default: 22.

.PARAMETER CollectorId
    Identity stamped on every reading. Default: this machine's name, lowercased.

.PARAMETER StorePassword
    Run the boot task with a stored password instead of S4U. Use only if the
    task will not start otherwise.

.PARAMETER ConfigureNetworkOnly
    Skip installation; just redo the networking and the scheduled task.

.EXAMPLE
    .\poller-bootstrap.ps1
.EXAMPLE
    .\poller-bootstrap.ps1 -CollectorId site-a-poller -SshPort 2222
#>
[CmdletBinding()]
param(
    [string] $Distro = 'Ubuntu',
    [int]    $SshPort = 22,
    [string] $CollectorId = '',
    [int]    $RetentionDays = 365,
    [switch] $StorePassword,
    [switch] $ConfigureNetworkOnly
)

$ErrorActionPreference = 'Stop'
$TaskName  = 'Netrune poller'
$StateDir  = Join-Path $env:ProgramData 'Netrune'
$Keepalive = Join-Path $StateDir 'poller-keepalive.ps1'

function Write-Step { param($Text) Write-Host "[poller] $Text" -ForegroundColor Cyan }
function Write-Ok   { param($Text) Write-Host "[  ok  ] $Text" -ForegroundColor Green }
function Write-Skip { param($Text) Write-Host "[ skip ] $Text" -ForegroundColor DarkGray }
function Write-Warn { param($Text) Write-Host "[ warn ] $Text" -ForegroundColor Yellow }
function Fail       { param($Text) Write-Host "[ fail ] $Text" -ForegroundColor Red; exit 1 }

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail 'Run this from an elevated PowerShell: installing WSL, opening a firewall port, and creating a boot task all need it.'
}

if (-not $CollectorId) { $CollectorId = $env:COMPUTERNAME.ToLower() }
if ($CollectorId -notmatch '^[A-Za-z0-9._-]{1,64}$') {
    Fail "Collector id must be 1-64 characters of A-Z a-z 0-9 . _ -"
}

# ---------------------------------------------------------------------------
Write-Step '1/7  WSL2'
# ---------------------------------------------------------------------------
$wslPresent = $null -ne (Get-Command wsl.exe -ErrorAction SilentlyContinue)
if (-not $wslPresent) {
    Write-Step "Installing WSL and $Distro. This reboots the machine; re-run this script afterwards."
    wsl.exe --install -d $Distro
    Fail 'Reboot, finish creating your Linux user when the distro opens, then run this script again.'
}

$installed = (wsl.exe --list --quiet) -replace "`0", '' -split "`r?`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ }
if ($installed -notcontains $Distro) {
    Write-Step "Installing the $Distro distribution"
    wsl.exe --install -d $Distro
    Fail "Finish creating your Linux user when $Distro opens, then run this script again."
}
Write-Ok "$Distro is installed"

# Mirrored networking gives the distro the host's own addresses, so SSH from the
# laptop reaches it with no forwarding at all. Where it is unavailable the
# distro sits behind NAT on an address that changes at every boot, which is what
# the keepalive script below re-points the forwarding at.
$build = [Environment]::OSVersion.Version.Build
# wsl.exe writes several lines, and -match against an array returns the
# matching elements rather than a boolean -- it never fills $Matches. Join
# first, or the version parse throws on a null $Matches.
$wslVersionText = (((wsl.exe --version 2>$null) -replace "`0", '') -join "`n")
$wslVersion = if ($wslVersionText -match 'WSL[^\d]*(\d+\.\d+\.\d+)') { [version]$Matches[1] }
              elseif ($wslVersionText -match '(\d+\.\d+\.\d+)') { [version]$Matches[1] }
              else { [version]'0.0.0' }
$Mirrored = ($build -ge 22621) -and ($wslVersion -ge [version]'2.0.0')

$wslConfig = Join-Path $env:USERPROFILE '.wslconfig'
if ($Mirrored) {
    $existing = if (Test-Path $wslConfig) { Get-Content $wslConfig -Raw } else { '' }
    if ($existing -match 'networkingMode\s*=\s*mirrored') {
        Write-Skip 'Mirrored networking is already configured'
    } else {
        # vmIdleTimeout=-1 keeps the VM from being torn down while idle. A poller
        # is idle by design between polls, and a torn-down VM collects nothing.
        Add-Content -Path $wslConfig -Value "`r`n[wsl2]`r`nnetworkingMode=mirrored`r`nvmIdleTimeout=-1`r`n"
        Write-Ok "Enabled mirrored networking in $wslConfig"
    }
} else {
    Write-Warn "Windows build $build with WSL $wslVersion has no mirrored networking; using port forwarding instead."
}

# ---------------------------------------------------------------------------
Write-Step '2/7  systemd inside the distro'
# ---------------------------------------------------------------------------
# Without this WSL runs no init, so nothing supervises the collector: the units
# install cleanly and simply never run.
$wslConf = (((wsl.exe -d $Distro -u root --exec cat /etc/wsl.conf 2>$null) -replace "`0", '') -join "`n")
if ($wslConf -match 'systemd\s*=\s*true') {
    Write-Skip 'systemd is already enabled in /etc/wsl.conf'
} else {
    wsl.exe -d $Distro -u root --exec sh -c "printf '\n[boot]\nsystemd=true\n' >> /etc/wsl.conf"
    Write-Ok 'Enabled systemd in /etc/wsl.conf'
    Write-Step 'Restarting WSL so systemd takes effect'
    wsl.exe --shutdown
    Start-Sleep -Seconds 8
}

# ---------------------------------------------------------------------------
Write-Step '3/7  Payload'
# ---------------------------------------------------------------------------
if (-not $ConfigureNetworkOnly) {
    $here = Split-Path -Parent $MyInvocation.MyCommand.Path
    $installer = Join-Path $here 'poller-install.sh'
    if (-not (Test-Path $installer)) { Fail "poller-install.sh is not beside this script ($here)." }
    $wheel = Get-ChildItem -Path $here -Filter '*.whl' -ErrorAction SilentlyContinue |
             Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $wheel) { Fail "No .whl found in $here. Copy the netrune wheel next to this script." }

    $linuxUser = ((((wsl.exe -d $Distro --exec whoami) -replace "`0", '') -join '') -replace "`r?`n", '').Trim()
    if (-not $linuxUser -or $linuxUser -eq 'root') {
        Fail "The distro's default user is '$linuxUser'. Create a normal user first: the collector runs as a user service and root has no lingering user manager by default."
    }
    $stage = "/home/$linuxUser/netrune-poller"
    wsl.exe -d $Distro --exec mkdir -p $stage
    foreach ($file in @($installer, $wheel.FullName)) {
        # Passing the Windows path through /mnt keeps this to one copy with no
        # line-ending translation, which a wheel does not survive.
        $mnt = '/mnt/' + ($file.Substring(0,1).ToLower()) + ($file.Substring(2) -replace '\\','/')
        wsl.exe -d $Distro --exec cp "$mnt" "$stage/"
    }
    wsl.exe -d $Distro --exec chmod +x "$stage/poller-install.sh"
    Write-Ok "Staged the installer and $($wheel.Name) in $stage"

    # ---------------------------------------------------------------------------
    Write-Step '4/7  Running the Linux installer'
    # ---------------------------------------------------------------------------
    # A login shell, so sudo can prompt: the installer needs it for packages
    # and for linger, and a non-interactive run would fail at the first one.
    wsl.exe -d $Distro -- bash -lc "cd '$stage' && bash ./poller-install.sh --collector-id '$CollectorId' --retention $RetentionDays"
    if ($LASTEXITCODE -ne 0) { Fail "The Linux installer exited $LASTEXITCODE. Fix what it reported and re-run." }
    Write-Ok 'Poller installed inside the distro'
} else {
    Write-Skip 'Skipping installation (-ConfigureNetworkOnly)'
    $linuxUser = ((((wsl.exe -d $Distro --exec whoami) -replace "`0", '') -join '') -replace "`r?`n", '').Trim()
}

# ---------------------------------------------------------------------------
Write-Step '5/7  Keepalive and forwarding script'
# ---------------------------------------------------------------------------
New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
@"
# Generated by poller-bootstrap.ps1. Starts the poller's distro and, where WSL
# is behind NAT, keeps the port forwarding pointed at its current address.
#
# It runs on a repeat rather than once at boot, so a distro that was shut down
# comes back on its own and an address that changed is corrected within minutes.
`$ErrorActionPreference = 'SilentlyContinue'
`$distro = '$Distro'
`$port   = $SshPort

# Starting the distro is what boots systemd inside it, which starts the collector.
wsl.exe -d `$distro --exec /bin/true | Out-Null

if ('$Mirrored' -eq 'True') { exit 0 }

`$ip = ((((wsl.exe -d `$distro --exec hostname -I) -replace "``0", '') -join ' ') -split '\s+') |
       Where-Object { `$_ -match '^\d+\.\d+\.\d+\.\d+$' } | Select-Object -First 1
if (-not `$ip) { exit 0 }

`$current = netsh interface portproxy show v4tov4 | Select-String -Pattern "^\s*\S+\s+`$port\s+(\S+)\s+22"
if (`$current -and `$current.Matches[0].Groups[1].Value -eq `$ip) { exit 0 }

netsh interface portproxy delete v4tov4 listenport=`$port listenaddress=0.0.0.0 | Out-Null
netsh interface portproxy add v4tov4 listenport=`$port listenaddress=0.0.0.0 connectport=22 connectaddress=`$ip | Out-Null
"@ | Set-Content -Path $Keepalive -Encoding UTF8
Write-Ok "Wrote $Keepalive"

# ---------------------------------------------------------------------------
Write-Step '6/7  Boot task'
# ---------------------------------------------------------------------------
# At startup and then every five minutes. The repeat is the point: it makes the
# arrangement self-healing rather than something that works until the first time
# WSL is shut down.
$action  = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$Keepalive`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$trigger.Repetition = (New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes 5) `
    -RepetitionDuration ([TimeSpan]::MaxValue)).Repetition
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 10)

$me = "$env:USERDOMAIN\$env:USERNAME"
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue

if ($StorePassword) {
    $secure = Read-Host "Windows password for $me" -AsSecureString
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
        -User $me -Password $plain -RunLevel Highest `
        -Description 'Starts the Netrune poller distro and keeps its SSH forwarding current.' | Out-Null
    Remove-Variable plain
    Write-Ok "Registered '$TaskName' to run as $me with a stored password"
} else {
    # S4U runs the task as this user with no password kept anywhere. It is the
    # better default; a machine that refuses it can be re-run with
    # -StorePassword.
    $principal = New-ScheduledTaskPrincipal -UserId $me -LogonType S4U -RunLevel Highest
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
        -Principal $principal `
        -Description 'Starts the Netrune poller distro and keeps its SSH forwarding current.' | Out-Null
    Write-Ok "Registered '$TaskName' to run as $me without storing a password"
}
Start-ScheduledTask -TaskName $TaskName

# ---------------------------------------------------------------------------
Write-Step '7/7  Firewall'
# ---------------------------------------------------------------------------
$ruleName = "Netrune poller SSH ($SshPort)"
if (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue) {
    Write-Skip "Firewall rule '$ruleName' already exists"
} else {
    # Private and Domain only. A poller belongs on a management network, and a
    # public-profile rule would follow the machine onto any other one.
    New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP `
        -LocalPort $SshPort -Action Allow -Profile Domain,Private | Out-Null
    Write-Ok "Opened TCP $SshPort inbound on the Domain and Private profiles"
}

$hostIp = (Get-NetIPConfiguration |
    Where-Object { $null -ne $_.IPv4DefaultGateway } |
    Select-Object -First 1).IPv4Address.IPAddress
if (-not $hostIp) { $hostIp = '<this machine>' }

Write-Host ''
Write-Host 'Poller ready.' -ForegroundColor Green
Write-Host ''
Write-Host "  collector id   $CollectorId"
Write-Host "  distro         $Distro"
Write-Host "  linux user     $linuxUser"
Write-Host "  reachable at   ${hostIp}:$SshPort"
Write-Host "  networking     $(if ($Mirrored) { 'mirrored (no forwarding needed)' } else { "NAT with forwarding refreshed every 5 minutes" })"
Write-Host "  starts at boot yes, via the '$TaskName' scheduled task"
Write-Host ''
Write-Host 'On the laptop:' -ForegroundColor Cyan
Write-Host "  ssh-copy-id -p $SshPort $linuxUser@$hostIp"
Write-Host "  netrune traffic remote add $CollectorId --host $hostIp --ssh-user $linuxUser --profile-name poller"
Write-Host "  netrune traffic remote $CollectorId watch <switch> <interface> --interval 30"
Write-Host "  netrune traffic pull --remote $CollectorId"
Write-Host ''
Write-Host 'To confirm it survives a reboot, restart this machine, wait a minute, and from the laptop:' -ForegroundColor Cyan
Write-Host "  netrune traffic pull --remote $CollectorId"
Write-Host ''
