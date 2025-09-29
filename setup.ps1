<#
    Kompleksowy skrypt konfigurujący środowisko Minecraft + WWW + MeshCentral + Sklep BLIK (wariant B)
    Wymagania: patrz dokumentacja w repozytorium. Skrypt jest idempotentny i można go uruchamiać wielokrotnie.
#>

[CmdletBinding()]
param(
    [switch]$SkipDeviceLink
)

$ErrorActionPreference = 'Stop'

function Write-Section {
    param([string]$Title)
    Write-Host "`n### $Title" -ForegroundColor Cyan
}

function Ensure-Directory {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
}

function Download-IfMissing {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$Destination,
        [string]$Description = "Pobieranie"
    )

    if (Test-Path -LiteralPath $Destination) {
        Write-Host "[OK] Plik już istnieje: $Destination" -ForegroundColor DarkGreen
        return
    }

    Write-Host "[INFO] $Description..." -ForegroundColor Yellow
    $tmp = [System.IO.Path]::GetTempFileName()
    try {
        Invoke-WebRequest -Uri $Uri -OutFile $tmp -UseBasicParsing
        Ensure-Directory ([System.IO.Path]::GetDirectoryName($Destination))
        Move-Item -Path $tmp -Destination $Destination -Force
    }
    catch {
        Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue
        throw
    }
}

function Ensure-FirewallRule {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][string]$Action,
        [Parameter(Mandatory)][string]$Direction,
        [string]$Protocol = 'TCP',
        [string]$LocalPort = $null,
        [string]$RemotePort = $null,
        [string]$Profile = 'Any'
    )

    $rule = Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue
    if ($rule) {
        Write-Host "[FW] Reguła już istnieje: $DisplayName" -ForegroundColor DarkGreen
    }
    else {
        Write-Host "[FW] Tworzę regułę: $DisplayName" -ForegroundColor Yellow
        New-NetFirewallRule -Name $Name -DisplayName $DisplayName -Direction $Direction -Action $Action -Profile $Profile -Protocol $Protocol -LocalPort $LocalPort -RemotePort $RemotePort | Out-Null
    }
}

function Ensure-ScheduledTask {
    param(
        [Parameter(Mandatory)][string]$TaskName,
        [Parameter(Mandatory)][Microsoft.Management.Infrastructure.CimInstance]$Action,
        [Parameter(Mandatory)][Microsoft.Management.Infrastructure.CimInstance]$Trigger,
        [string]$Description = ''
    )

    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "[TASK] Aktualizuję zadanie $TaskName" -ForegroundColor Yellow
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
    else {
        Write-Host "[TASK] Tworzę zadanie $TaskName" -ForegroundColor Yellow
    }
    Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -RunLevel Highest -Description $Description -Force | Out-Null
}

function Ensure-Service {
    param(
        [Parameter(Mandatory)][string]$ServiceName,
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][string]$BinaryPath,
        [string]$Description = ''
    )

    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $service) {
        Write-Host "[SVC] Rejestruję usługę $DisplayName" -ForegroundColor Yellow
        New-Service -Name $ServiceName -BinaryPathName $BinaryPath -DisplayName $DisplayName -Description $Description -StartupType Automatic | Out-Null
    }
    else {
        Write-Host "[SVC] Usługa $DisplayName już istnieje" -ForegroundColor DarkGreen
        if ($service.StartType -ne 'Automatic') {
            Set-Service -Name $ServiceName -StartupType Automatic
        }
    }
}


function Generate-Secret {
    param([int]$Length = 32)
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}'
    $bytes = New-Object byte[] $Length
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    ($bytes | ForEach-Object { $chars[ $_ % $chars.Length ] }) -join ''
}

function Generate-CliSafeSecret {
    param([int]$Length = 32)
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    $bytes = New-Object byte[] $Length
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    ($bytes | ForEach-Object { $chars[ $_ % $chars.Length ] }) -join ''
}


function Protect-Secret {
    param([string]$Secret)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Secret)
    $protected = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
    [Convert]::ToBase64String($protected)
}

function Save-Json {
    param([string]$Path, [object]$Data)
    Ensure-Directory ([System.IO.Path]::GetDirectoryName($Path))
    $json = $Data | ConvertTo-Json -Depth 6
    $json | Out-File -FilePath $Path -Encoding UTF8
}


function Ensure-LogRotationConfig {
    param([string]$LogPath)
    $configPath = Join-Path $LogPath 'logrotate.config.txt'
    if (-not (Test-Path -LiteralPath $configPath)) {
        @'
Logi są rotowane przez skrypt zadań harmonogramu "InfraLogRotate". Maksymalny rozmiar pliku 10 MB, maksymalnie 10 kopii.
'@ | Out-File -FilePath $configPath -Encoding UTF8
    }
}

function Ensure-Nssm {
    param([string]$BinPath)
    $nssmExe = Join-Path $BinPath 'nssm.exe'
    if (-not (Test-Path -LiteralPath $nssmExe)) {
        Write-Host "[INFO] Pobieram NSSM" -ForegroundColor Yellow
        $zipPath = Join-Path ([System.IO.Path]::GetTempPath()) 'nssm.zip'
        Invoke-WebRequest -Uri 'https://nssm.cc/release/nssm-2.24.zip' -OutFile $zipPath -UseBasicParsing
        $extractDir = Join-Path ([System.IO.Path]::GetTempPath()) 'nssm-2.24'
        if (Test-Path $extractDir) { Remove-Item -Path $extractDir -Recurse -Force }
        Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force
        $src = Join-Path $extractDir 'nssm-2.24\win64\nssm.exe'
        if (-not (Test-Path -LiteralPath $src)) {
            throw "Nie udało się znaleźć pliku nssm.exe po rozpakowaniu"
        }
        Ensure-Directory $BinPath
        Copy-Item -Path $src -Destination $nssmExe -Force
        Remove-Item -Path $zipPath -Force
        Remove-Item -Path $extractDir -Recurse -Force
    }
    return $nssmExe
}

function Ensure-NssmService {
    param(
        [Parameter(Mandatory)][string]$ServiceName,
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][string]$Executable,
        [string]$Arguments = '',
        [string]$WorkingDirectory = '',
        [string]$StdOutLog = $null,
        [string]$StdErrLog = $null
    )

    $nssmExe = Ensure-Nssm -BinPath $paths.Bin
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $service) {
        Write-Host "[SVC] Tworzę usługę (NSSM) $DisplayName" -ForegroundColor Yellow
        & $nssmExe install $ServiceName $Executable $Arguments | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Nie udało się zainstalować usługi $ServiceName" }
        & $nssmExe set $ServiceName DisplayName $DisplayName | Out-Null
        & $nssmExe set $ServiceName Start SERVICE_AUTO_START | Out-Null
    }
    if ($WorkingDirectory) {
        & $nssmExe set $ServiceName AppDirectory $WorkingDirectory | Out-Null
    }
    if ($StdOutLog) {
        Ensure-Directory ([System.IO.Path]::GetDirectoryName($StdOutLog))
        & $nssmExe set $ServiceName AppStdout $StdOutLog | Out-Null
        & $nssmExe set $ServiceName AppRotateFiles 1 | Out-Null
        & $nssmExe set $ServiceName AppRotateOnline 1 | Out-Null
    }
    if ($StdErrLog) {
        Ensure-Directory ([System.IO.Path]::GetDirectoryName($StdErrLog))
        & $nssmExe set $ServiceName AppStderr $StdErrLog | Out-Null
    }
    Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
}

function Write-LogMessage {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Message
    )
    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    Ensure-Directory ([System.IO.Path]::GetDirectoryName($Path))
    "$timestamp`t$Message" | Out-File -FilePath $Path -Encoding UTF8 -Append
}

function Invoke-LocalHttps {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [int]$TimeoutSeconds = 15
    )

    $previous = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    try {
        Invoke-WebRequest -Uri $Uri -UseBasicParsing -TimeoutSec $TimeoutSeconds
    }
    finally {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $previous
    }
}

function Mask-Secret {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return '<brak>' }
    if ($Value.Length -le 4) { return ('*' * $Value.Length) }
    return ('*' * ($Value.Length - 4)) + $Value.Substring($Value.Length - 4)
}

function Test-JavaEnvironment {
    param(
        [string]$JavaCommand = 'java',
        [string]$ServerDirectory = 'C:\\SERWER'
    )

    $javaOk = $false
    try {
        $null = & $JavaCommand -version 2>&1
        if ($LASTEXITCODE -eq 0) { $javaOk = $true }
    }
    catch {
        $javaOk = $false
    }

    $jarPath = Join-Path $ServerDirectory 'server.jar'
    $jarExists = Test-Path -LiteralPath $jarPath

    return [ordered]@{
        JavaExecutable = $JavaCommand
        JavaAccessible = $javaOk
        ServerJarExists = $jarExists
        ServerJarPath = $jarPath
    }
}

function New-CaddyConfig {
    param(
        [ValidateSet('path','host')]
        [string]$MeshMode = 'path',
        [Parameter(Mandatory)][string]$ShopRoot
    )

    $config = @"
{
    admin off
}

https://:8443 {
    tls internal
    encode gzip

    @desk path /desk /desk/*
    handle @desk {
        header Cache-Control "no-store"
        reverse_proxy https://127.0.0.1:4430 {
            header_up Host {http.request.host}
            header_up X-Forwarded-Host {http.request.host}
            header_up X-Forwarded-Proto {http.request.scheme}
            transport http {
                tls
                tls_insecure_skip_verify
            }
        }
    }

    handle_path /shop* {
        root * $ShopRoot
        php_fastcgi 127.0.0.1:9000
        file_server
    }

    handle_path /map* {
        reverse_proxy 127.0.0.1:11141
    }

    handle / {
        respond "OK" 200
    }
}
"@

    if ($MeshMode -eq 'host') {
        $config += @"

https://desk.localhost:8443 {
    tls internal
    encode gzip
    header Cache-Control "no-store"
    reverse_proxy https://127.0.0.1:4430 {
        header_up Host {http.request.host}
        header_up X-Forwarded-Host {http.request.host}
        header_up X-Forwarded-Proto {http.request.scheme}
        transport http {
            tls
            tls_insecure_skip_verify
        }
    }
}
"@
    }

    return $config
}

$global:MeshAdminPass = $null
$global:MeshAdminUser = 'meshadmin'
$global:MeshAgentInstalled = $false

try {
    Write-Section "Walidacja uprawnień"
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "Skrypt musi być uruchomiony jako Administrator."; exit 1
    }
    Set-ExecutionPolicy Bypass -Scope Process -Force

    Write-Section "Ścieżki i katalogi"
    $paths = [ordered]@{
        Infra = 'C:\Infra'
        Caddy = 'C:\Infra\caddy'
        Mesh = 'C:\Infra\meshcentral'
        PHP = 'C:\Infra\php'
        Shop = 'C:\Infra\shop'
        Logs = 'C:\Infra\logs'
        Bin = 'C:\Infra\bin'
        FirstBoot = 'C:\Infra\firstboot'
        ShopPublic = 'C:\Infra\shop\public'
        ShopConfig = 'C:\Infra\shop\config'
        ShopData = 'C:\Infra\shop\data'
        ShopBin = 'C:\Infra\shop\bin'
        ShopAdmin = 'C:\Infra\shop\admin'
    }

    foreach ($p in $paths.Values) { Ensure-Directory $p }

    Ensure-LogRotationConfig -LogPath $paths.Logs

    Write-Section "Weryfikacja środowiska Java/Minecraft"
    $javaStatus = Test-JavaEnvironment -JavaCommand 'java' -ServerDirectory 'C:\\SERWER'
    if (-not $javaStatus.JavaAccessible) {
        Write-Warning "Polecenie 'java -version' zakończyło się niepowodzeniem. Zweryfikuj instalację JDK." 
    }
    else {
        Write-Host "[OK] java -version zwróciło kod 0" -ForegroundColor DarkGreen
    }
    if (-not $javaStatus.ServerJarExists) {
        Write-Warning "Nie znaleziono pliku $($javaStatus.ServerJarPath). Upewnij się, że server.jar jest dostępny."
    }

    Write-Section "Konfiguracja zapory"
    Ensure-FirewallRule -Name 'Allow-Portal-8443' -DisplayName 'Allow Portal HTTPS 8443' -Action Allow -Direction Inbound -LocalPort 8443

    Ensure-FirewallRule -Name 'Allow-Minecraft-11131' -DisplayName 'Allow Minecraft 11131' -Action Allow -Direction Inbound -LocalPort 11131
    Ensure-FirewallRule -Name 'Allow-BlueMap-11141' -DisplayName 'Allow BlueMap 11141' -Action Allow -Direction Inbound -LocalPort 11141
    Ensure-FirewallRule -Name 'Block-RDP-3389' -DisplayName 'Block RDP 3389' -Action Block -Direction Inbound -LocalPort 3389

    Write-Section "Caddy - Reverse Proxy"
    $caddyExe = Join-Path $paths.Caddy 'caddy.exe'
    $caddyUrl = 'https://caddyserver.com/api/download?os=windows&arch=amd64&id=github.com%2Fcaddyserver%2Fcaddy'
    Download-IfMissing -Uri $caddyUrl -Destination $caddyExe -Description 'Pobieranie Caddy (Windows)'

    $caddyFile = Join-Path $paths.Caddy 'Caddyfile'
    $meshRoutingMode = 'path'
    $caddyConfig = New-CaddyConfig -MeshMode $meshRoutingMode -ShopRoot $paths.ShopPublic
    $caddyConfig | Out-File -FilePath $caddyFile -Encoding UTF8

    $caddyLog = Join-Path $paths.Logs 'caddy-service.log'
    Ensure-NssmService -ServiceName 'CaddyReverseProxy' -DisplayName 'Caddy Reverse Proxy' -Executable $caddyExe -Arguments "run --config `"$caddyFile`"" -WorkingDirectory $paths.Caddy -StdOutLog $caddyLog -StdErrLog $caddyLog

    Start-Sleep -Seconds 5

    $deskCheck = $null
    $deskScriptCheck = $null
    try {
        $deskCheck = Invoke-LocalHttps -Uri 'https://localhost:8443/desk/'
    }
    catch {
        $deskCheck = $_
    }
    try {
        $deskScriptCheck = Invoke-LocalHttps -Uri 'https://localhost:8443/desk/scripts/common.js'
    }
    catch {
        $deskScriptCheck = $_
    }

    if (-not ($deskCheck -is [Microsoft.PowerShell.Commands.BasicHtmlWebResponseObject] -and $deskCheck.StatusCode -eq 200 -and $deskScriptCheck -is [Microsoft.PowerShell.Commands.BasicHtmlWebResponseObject] -and $deskScriptCheck.StatusCode -eq 200)) {
        Write-Warning 'Przekierowanie MeshCentral po ścieżce /desk nie działa – przełączam na routing host-based (desk.localhost).'
        $meshRoutingMode = 'host'
        $caddyConfig = New-CaddyConfig -MeshMode $meshRoutingMode -ShopRoot $paths.ShopPublic
        $caddyConfig | Out-File -FilePath $caddyFile -Encoding UTF8
        & (Ensure-Nssm -BinPath $paths.Bin) restart CaddyReverseProxy | Out-Null
        Start-Sleep -Seconds 5
        try { $deskCheck = Invoke-LocalHttps -Uri 'https://localhost:8443/desk/' } catch { $deskCheck = $_ }
        try { $deskScriptCheck = Invoke-LocalHttps -Uri 'https://localhost:8443/desk/scripts/common.js' } catch { $deskScriptCheck = $_ }
    }


    Write-Section "Node.js + MeshCentral"
    $nodeRoot = Join-Path $paths.Bin 'node'
    $nodeExe = Join-Path $nodeRoot 'node.exe'
    $npmCmd = Join-Path $nodeRoot 'npm.cmd'
    if (-not (Test-Path -LiteralPath $nodeExe)) {
        Write-Host "[INFO] Pobieram Node.js LTS" -ForegroundColor Yellow
        $nodeZip = Join-Path ([System.IO.Path]::GetTempPath()) 'node.zip'
        Invoke-WebRequest -Uri 'https://nodejs.org/dist/v18.20.2/node-v18.20.2-win-x64.zip' -OutFile $nodeZip -UseBasicParsing
        Expand-Archive -Path $nodeZip -DestinationPath $paths.Bin -Force
        Remove-Item -Path $nodeZip -Force
        $extracted = Join-Path $paths.Bin 'node-v18.20.2-win-x64'
        if (Test-Path $extracted) {
            if (Test-Path $nodeRoot) { Remove-Item -Recurse -Force $nodeRoot }

            Rename-Item -Path $extracted -NewName 'node'
        }
    }
    else {
        Write-Host "[OK] Node.js już obecny" -ForegroundColor DarkGreen
    }

    $env:Path = $nodeRoot + ';' + $env:Path
    [Environment]::SetEnvironmentVariable('Path', $nodeRoot + ';' + [Environment]::GetEnvironmentVariable('Path', 'Machine'), 'Machine')

    Ensure-Directory (Join-Path $paths.Mesh 'meshcentral-data')
    Ensure-Directory (Join-Path $paths.Mesh 'meshcentral-files')

    Push-Location $paths.Mesh
    try {
        if (-not (Test-Path -LiteralPath (Join-Path $paths.Mesh 'node_modules\meshcentral'))) {
            Write-Host "[INFO] Instaluję MeshCentral (npm)" -ForegroundColor Yellow
            & $npmCmd install meshcentral --no-fund --loglevel error | Out-Null
        }
        else {
            Write-Host "[OK] MeshCentral już zainstalowany" -ForegroundColor DarkGreen
        }
    }
    finally {
        Pop-Location
    }

    $meshConfigPath = Join-Path $paths.Mesh 'meshcentral-data\config.json'
    $meshConfig = @{
        settings = @{
            Cert = 'meshcentral'
            Port = 4430
            RedirPort = 0
            Minify = $true
            AllowLoginToken = $false
            UserSessionIdleTimeout = 0
            WebRTC = $true
        }
        domains = @{
            '' = @{
                Title = 'MeshCentral'
                NewAccounts = $false
                UserMeshCentral = $true
                Auth = 'default'
                CookieIpCheck = $true
                TwoFactorAuth = 'required'
            }
        }
    }
    $meshConfigJson = $meshConfig | ConvertTo-Json -Depth 6
    $meshConfigJson | Out-File -FilePath $meshConfigPath -Encoding UTF8

    $meshModule = Join-Path $paths.Mesh 'node_modules\meshcentral'
    if (Test-Path $meshModule) {
        Write-Host "[INFO] Rejestruję usługę MeshCentral" -ForegroundColor Yellow
        & $nodeExe $meshModule --install --installPath $paths.Mesh | Out-Null
    }

    $meshService = Get-Service -Name 'MeshCentral' -ErrorAction SilentlyContinue
    if ($meshService) {
        if ($meshService.Status -ne 'Running') { Start-Service -Name 'MeshCentral' }
    }
    else {
        Write-Host "[WARN] Nie znaleziono usługi MeshCentral. Tworzę zadanie." -ForegroundColor Yellow
        $meshAction = New-ScheduledTaskAction -Execute $nodeExe -Argument "`"$meshModule`" --config `"$meshConfigPath`""
        $meshTrigger = New-ScheduledTaskTrigger -AtStartup
        Ensure-ScheduledTask -TaskName 'MeshCentral@Startup' -Action $meshAction -Trigger $meshTrigger -Description 'MeshCentral serwer zdalnego pulpitu'
    }


    Start-Sleep -Seconds 5

    $meshAdminAccountPath = Join-Path $paths.Mesh "meshcentral-data\users\$($global:MeshAdminUser).json"
    if (-not (Test-Path -LiteralPath $meshAdminAccountPath)) {
        $global:MeshAdminPass = Generate-CliSafeSecret -Length 32
        try {
            & $nodeExe $meshModule --createaccount $global:MeshAdminUser --pass $global:MeshAdminPass --email "" --admin | Out-Null
            Write-Host "[INFO] Utworzono konto administracyjne MeshCentral ($global:MeshAdminUser)" -ForegroundColor Yellow
        }
        catch {
            Write-Warning "Nie udało się automatycznie utworzyć konta MeshCentral: $_"
            $global:MeshAdminPass = $null
        }
    }

    try {
        & $nodeExe $meshModule --createDeviceGroup 'LocalWindowsHost' --user $global:MeshAdminUser | Out-Null
    }
    catch {
        if ($_.Exception.Message -notmatch 'exists') {
            Write-Warning "Nie udało się utworzyć grupy urządzeń MeshCentral: $_"
        }
    }

    $meshAgentService = Get-Service -Name 'Mesh Agent' -ErrorAction SilentlyContinue
    if (-not $meshAgentService) {
        Write-Host "[INFO] Instaluję MeshAgent dla zdalnego pulpitu" -ForegroundColor Yellow
        $agentDir = Join-Path $paths.Mesh 'agent'
        Ensure-Directory $agentDir
        $agentExe = Join-Path $agentDir 'meshagent.exe'
        $previousCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        try {
            Invoke-WebRequest -Uri 'https://localhost:4430/meshagents?id=1&install=2' -OutFile $agentExe -UseBasicParsing
            Start-Process -FilePath $agentExe -ArgumentList '-fullinstall' -Wait -WindowStyle Hidden | Out-Null
            $global:MeshAgentInstalled = $true
        }
        catch {
            Write-Warning "Instalacja MeshAgent nie powiodła się: $_"
        }
        finally {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $previousCallback
        }
    }

    Write-Section "PHP 8.x + środowisko sklepu"
    $phpExe = Join-Path $paths.PHP 'php.exe'
    if (-not (Test-Path -LiteralPath $phpExe)) {
        Write-Host "[INFO] Pobieram PHP 8.3 NTS" -ForegroundColor Yellow
        $phpZip = Join-Path ([System.IO.Path]::GetTempPath()) 'php.zip'
        Invoke-WebRequest -Uri 'https://windows.php.net/downloads/releases/php-8.3.3-nts-Win32-vs16-x64.zip' -OutFile $phpZip -UseBasicParsing
        Expand-Archive -Path $phpZip -DestinationPath $paths.PHP -Force

        Remove-Item -Path $phpZip -Force
    }
    else {
        Write-Host "[OK] PHP już obecny" -ForegroundColor DarkGreen
    }

    $env:Path = $paths.PHP + ';' + $env:Path
    [Environment]::SetEnvironmentVariable('Path', $paths.PHP + ';' + [Environment]::GetEnvironmentVariable('Path', 'Machine'), 'Machine')

    $phpIni = Join-Path $paths.PHP 'php.ini'
    if (-not (Test-Path -LiteralPath $phpIni)) {
        $iniSource = @('php.ini-production','php.ini-development') | ForEach-Object { Join-Path $paths.PHP $_ } | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
        if ($iniSource) {
            Copy-Item -Path $iniSource -Destination $phpIni -Force
        }
        else {
            New-Item -Path $phpIni -ItemType File -Force | Out-Null
        }
    }
    $iniContent = Get-Content -Path $phpIni
    $iniContent = $iniContent | ForEach-Object {
        if ($_ -match '^\s*;\s*extension_dir\s*=') { 'extension_dir = "ext"' }
        elseif ($_ -match '^\s*extension_dir\s*=') { 'extension_dir = "ext"' }
        elseif ($_ -match '^\s*;\s*extension\s*=\s*sqlite3') { 'extension = sqlite3' }
        elseif ($_ -match '^\s*;\s*extension\s*=\s*pdo_sqlite') { 'extension = pdo_sqlite' }
        elseif ($_ -match '^\s*extension\s*=\s*sqlite3') { 'extension = sqlite3' }
        elseif ($_ -match '^\s*extension\s*=\s*pdo_sqlite') { 'extension = pdo_sqlite' }
        else { $_ }
    }
    if ($iniContent -notmatch 'extension_dir\s*=\s*"ext"') { $iniContent += 'extension_dir = "ext"' }
    if ($iniContent -notmatch 'extension\s*=\s*sqlite3') { $iniContent += 'extension = sqlite3' }
    if ($iniContent -notmatch 'extension\s*=\s*pdo_sqlite') { $iniContent += 'extension = pdo_sqlite' }
    $iniContent | Set-Content -Path $phpIni -Encoding UTF8


    $configPhp = @'
<?php
return [
    "DB_PATH" => "C:\\Infra\\shop\\data\\shop.sqlite",
    "LOG_PATH" => "C:\\Infra\\logs\\shop.log",
    "SECRETS_PATH" => "C:\\Infra\\shop\\config\\secrets.json",
    "DELIVER_SCRIPT" => "C:\\Infra\\shop\\bin\\deliver.ps1",
    "RCON_HOST" => "127.0.0.1",
    "RCON_PORT" => 25575,
    "SANDBOX" => true
];
'@
    $configPath = Join-Path $paths.ShopConfig 'shop.config.php'
    $configPhp | Out-File -FilePath $configPath -Encoding UTF8

    $secretsPath = Join-Path $paths.ShopConfig 'secrets.json'
    if (Test-Path -LiteralPath $secretsPath) {
        $secretsData = Get-Content -Path $secretsPath | ConvertFrom-Json
    }
    else {
        $secretsData = [ordered]@{
            PSP = [ordered]@{
                Provider = 'TPAY'
                EncryptedPayload = ''
                Credentials = @{}
            }
            Rcon = [ordered]@{
                EncryptedPassword = ''
                UpdatedAt = ''
            }
            Admin = [ordered]@{}
        }
    }

    $adminUser = $secretsData.Admin.Username
    if (-not $adminUser) { $adminUser = 'admin' }
    if (-not $secretsData.Admin.PasswordHash) {
        $adminPass = Generate-Secret -Length 24
        $hashBytes = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($adminPass))
        $hash = [Convert]::ToBase64String($hashBytes)
        $secretsData.Admin = [ordered]@{
            Username = $adminUser
            PasswordHash = $hash
            PasswordProtected = Protect-Secret -Secret $adminPass
            UpdatedAt = (Get-Date).ToString('o')
        }
    }
    else {
        $adminPass = $null
        $secretsData.Admin.Username = $adminUser
    }

    $rconClient = @'
param(
    [Parameter(Mandatory)][string]$Command,
    [string]$Host = '127.0.0.1',
    [int]$Port = 25575,
    [Parameter(Mandatory)][string]$Password
)

if (-not ('RconHelper' -as [type])) {
Add-Type -TypeDefinition @"
using System;
using System.Net.Sockets;
using System.Text;
public static class RconHelper
{
    public static void WritePacket(NetworkStream stream, int type, string body)
    {
        var payload = Encoding.UTF8.GetBytes(body);
        var length = 4 + 4 + payload.Length + 2;
        var buffer = new byte[length + 4];
        BitConverter.GetBytes(length).CopyTo(buffer, 0);
        BitConverter.GetBytes(0).CopyTo(buffer, 4);
        BitConverter.GetBytes(type).CopyTo(buffer, 8);
        Array.Copy(payload, 0, buffer, 12, payload.Length);
        buffer[length + 2] = 0;
        buffer[length + 3] = 0;
        stream.Write(buffer, 0, buffer.Length);
    }

    public static string ReadPacket(NetworkStream stream)
    {
        var header = new byte[4];
        stream.Read(header, 0, 4);
        var length = BitConverter.ToInt32(header, 0);
        var buffer = new byte[length];
        stream.Read(buffer, 0, length);
        var payloadLength = length - 10;
        return Encoding.UTF8.GetString(buffer, 8, payloadLength);
    }
}
"@
}

$client = New-Object System.Net.Sockets.TcpClient
$client.Connect($Host, $Port)
$stream = $client.GetStream()
[RconHelper]::WritePacket($stream, 3, $Password)
[RconHelper]::ReadPacket($stream) | Out-Null
[RconHelper]::WritePacket($stream, 2, $Command)
$result = [RconHelper]::ReadPacket($stream)
$client.Close()
return $result
'@
    $rconPath = Join-Path $paths.ShopBin 'rcon.ps1'
    $rconClient | Out-File -FilePath $rconPath -Encoding UTF8

    $deliverScript = @'
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Player,
    [Parameter(Mandatory)][string]$CommandTemplate,
    [string]$SecretsPath = 'C:\\Infra\\shop\\config\\secrets.json',
    [string]$Host = '127.0.0.1',
    [int]$Port = 25575,
    [string]$LogPath = 'C:\\Infra\\logs\\shop-delivery.log'
)

function Write-DeliveryLog {
    param([string]$Message)
    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    "$timestamp`t$Message" | Out-File -FilePath $LogPath -Encoding UTF8 -Append
}

try {
    if (-not (Test-Path -LiteralPath $SecretsPath)) {
        throw "Brak pliku z sekretami: $SecretsPath"
    }
    $data = Get-Content -LiteralPath $SecretsPath | ConvertFrom-Json
    $encrypted = $data.Rcon.EncryptedPassword
    if ([string]::IsNullOrWhiteSpace($encrypted)) {
        throw 'Brak zaszyfrowanego hasła RCON w secrets.json'
    }
    $bytes = [Convert]::FromBase64String($encrypted)
    $password = [System.Text.Encoding]::UTF8.GetString([System.Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine))
    $cmd = $CommandTemplate.Replace('%player%', $Player)
    $result = & 'C:\\Infra\\shop\\bin\\rcon.ps1' -Command $cmd -Host $Host -Port $Port -Password $password
    Write-DeliveryLog "Wysłano polecenie '$cmd' do gracza $Player: $result"
    Write-Output $result
}
catch {
    Write-DeliveryLog "Błąd podczas dostarczania nagrody dla $Player: $_"
    throw
}
'@
    $deliverPath = Join-Path $paths.ShopBin 'deliver.ps1'
    $deliverScript | Out-File -FilePath $deliverPath -Encoding UTF8

    $secretReader = @'
param(
    [Parameter(Mandatory)][string]$Encrypted
)

$bytes = [Convert]::FromBase64String($Encrypted)
$plain = [System.Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
[System.Text.Encoding]::UTF8.GetString($plain)
'@
    $secretReaderPath = Join-Path $paths.ShopBin 'read-secret.ps1'
    $secretReader | Out-File -FilePath $secretReaderPath -Encoding UTF8

    $indexPhp = @'
<?php
declare(strict_types=1);
$config = require __DIR__ . '/../config/shop.config.php';
$secrets = json_decode(file_get_contents($config['SECRETS_PATH']), true);
$providerName = strtoupper($secrets['PSP']['Provider'] ?? 'TPAY');
$db = new SQLite3($config['DB_PATH']);
$db->exec('PRAGMA foreign_keys = ON');
$products = [];
$result = $db->query('SELECT id, name, price, command FROM products ORDER BY id');
while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
    $products[] = $row;
}
$message = '';
$reference = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $player = trim($_POST['player'] ?? '');
    $productId = (int)($_POST['product'] ?? 0);
    if ($player && $productId) {
        $stmt = $db->prepare('SELECT id, name, price, command FROM products WHERE id = :id');
        $stmt->bindValue(':id', $productId, SQLITE3_INTEGER);
        $product = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
        if ($product) {
            $reference = bin2hex(random_bytes(8));
            $insert = $db->prepare('INSERT INTO orders (external_id, product_id, player, amount, currency, status, provider, created_at, updated_at) VALUES (:ext, :pid, :player, :amount, :currency, :status, :provider, datetime("now"), datetime("now"))');
            $insert->bindValue(':ext', $reference, SQLITE3_TEXT);
            $insert->bindValue(':pid', $product['id'], SQLITE3_INTEGER);
            $insert->bindValue(':player', $player, SQLITE3_TEXT);
            $insert->bindValue(':amount', $product['price'], SQLITE3_FLOAT);
            $insert->bindValue(':currency', 'PLN', SQLITE3_TEXT);
            $insert->bindValue(':status', 'PENDING', SQLITE3_TEXT);
            $insert->bindValue(':provider', $providerName, SQLITE3_TEXT);
            $insert->execute();
            $message = 'Zamówienie utworzone. Użyj poniższego identyfikatora jako session_id/order_id w panelu PSP sandbox.';
        } else {
            $message = 'Nie znaleziono produktu.';
        }
    } else {
        $message = 'Podaj nick gracza i produkt.';
    }
}
?>
<!doctype html>
<html lang="pl">
<head>
    <meta charset="utf-8">
    <title>Sklep Minecraft</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 2rem; }
        form { margin-top: 1rem; display: grid; gap: 1rem; max-width: 420px; }
        label { display: flex; flex-direction: column; font-weight: 600; }
        input, select { padding: 0.5rem; font-size: 1rem; }
        .message { margin-top: 1rem; padding: 1rem; background: #eef; border-left: 4px solid #36c; }
        code { background: #f4f4f4; padding: 0.1rem 0.3rem; }
    </style>
</head>
<body>
<h1>Sklep Minecraft — płatności <?= htmlspecialchars($providerName); ?> (sandbox)</h1>
<p>Wypełnij formularz, aby utworzyć zamówienie. Po pomyślnej płatności BLIK przedmiot zostanie wydany automatycznie na serwerze.</p>
<?php if ($message): ?>
    <div class="message">
        <p><?= htmlspecialchars($message); ?></p>
        <?php if ($reference): ?>
            <p><strong>Identyfikator zamówienia:</strong> <code><?= htmlspecialchars($reference); ?></code></p>
            <p>Wprowadź ten identyfikator jako <em>session_id/order_id</em> w panelu sandbox wybranego PSP.</p>
        <?php endif; ?>
    </div>
<?php endif; ?>
<form method="post" action="">
    <label>Nick gracza
        <input type="text" name="player" required minlength="3" maxlength="16">
    </label>
    <label>Produkt
        <select name="product" required>
            <option value="">-- Wybierz --</option>
            <?php foreach ($products as $product): ?>
                <option value="<?= (int)$product['id']; ?>">
                    <?= htmlspecialchars($product['name']); ?> — <?= number_format((float)$product['price'], 2); ?> PLN
                </option>
            <?php endforeach; ?>
        </select>
    </label>
    <button type="submit">Generuj zamówienie sandbox</button>
</form>
<p>Webhook: <code>/shop/webhook.php</code>. Skonfiguruj go w panelu PSP.</p>
</body>
</html>
'@
    $indexPath = Join-Path $paths.ShopPublic 'index.php'
    $indexPhp | Out-File -FilePath $indexPath -Encoding UTF8

    $webhookPhp = @'
<?php
declare(strict_types=1);
$config = require __DIR__ . '/../config/shop.config.php';
$logFile = $config['LOG_PATH'];
$secrets = json_decode(file_get_contents($config['SECRETS_PATH']), true);
$provider = strtoupper($secrets['PSP']['Provider'] ?? 'TPAY');

function shop_log(string $message, string $logFile): void {
    $timestamp = (new DateTimeImmutable('now'))->format('Y-m-d H:i:s');
    file_put_contents($logFile, $timestamp . "\t" . $message . PHP_EOL, FILE_APPEND | LOCK_EX);
}

function decrypt_secret(array $secrets, string $logFile): ?array {
    $encrypted = $secrets['PSP']['EncryptedPayload'] ?? '';
    if (!$encrypted) {
        return null;
    }
    $reader = realpath(__DIR__ . '/../bin/read-secret.ps1');
    if (!$reader) {
        shop_log('Brak read-secret.ps1', $logFile);
        return null;
    }
    $command = 'powershell -NoProfile -ExecutionPolicy Bypass -File ' . escapeshellarg($reader) . ' -Encrypted ' . escapeshellarg($encrypted);
    $json = shell_exec($command);
    if (!$json) {
        shop_log('Nie udało się odszyfrować sekretów PSP', $logFile);
        return null;
    }
    $decoded = json_decode(trim($json), true);
    if (!is_array($decoded)) {
        shop_log('Niepoprawny JSON z sekretów PSP', $logFile);
        return null;
    }
    return $decoded;
}

function verify_tpay(array $data, array $creds): bool {
    $sign = strtolower($data['sign'] ?? '');
    $merchant = $creds['merchant_id'] ?? '';
    $secret = $creds['secret'] ?? '';
    $trId = $data['tr_id'] ?? '';
    if (!$sign || !$merchant || !$secret || !$trId) {
        return false;
    }
    $expected = hash('sha256', $merchant . '|' . $trId . '|' . ($data['amount'] ?? '') . '|' . $secret);
    return hash_equals($expected, $sign);
}

function verify_p24(array $data, array $creds): bool {
    $sign = strtolower($data['p24_sign'] ?? '');
    $crc = $creds['crc'] ?? '';
    $sessionId = $data['p24_session_id'] ?? '';
    $orderId = $data['p24_order_id'] ?? '';
    $amount = $data['p24_amount'] ?? '';
    $currency = $data['p24_currency'] ?? '';
    if (!$sign || !$crc || !$sessionId || !$orderId || !$amount || !$currency) {
        return false;
    }
    $expected = md5($sessionId . '|' . $orderId . '|' . $amount . '|' . $currency . '|' . $crc);
    return hash_equals($expected, $sign);
}

$payload = file_get_contents('php://input');
$data = $_POST ?: json_decode($payload, true) ?: [];
if (!$data) {
    http_response_code(400);
    echo json_encode(['error' => 'Brak danych']);
    exit;
}

$db = new SQLite3($config['DB_PATH']);
$db->exec('PRAGMA foreign_keys = ON');
$reference = $data['order_id'] ?? $data['tr_id'] ?? $data['p24_session_id'] ?? '';
if (!$reference) {
    shop_log('Brak identyfikatora zamówienia w webhooku', $logFile);
    http_response_code(400);
    echo json_encode(['error' => 'Brak reference']);
    exit;
}

$stmt = $db->prepare('SELECT o.id, o.external_id, o.player, o.amount, o.currency, o.status, p.command FROM orders o JOIN products p ON p.id = o.product_id WHERE o.external_id = :ext');
$stmt->bindValue(':ext', $reference, SQLITE3_TEXT);
$order = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
if (!$order) {
    shop_log('Webhook dla nieznanego zamówienia: ' . $reference, $logFile);
    http_response_code(404);
    echo json_encode(['error' => 'Order not found']);
    exit;
}

$creds = decrypt_secret($secrets, $logFile) ?? [];
$verified = false;
if ($provider === 'TPAY') {
    $verified = verify_tpay($data, $creds);
} elseif ($provider === 'P24' || $provider === 'PRZELEWY24') {
    $verified = verify_p24($data, $creds);
}

if (!$verified) {
    shop_log('Webhook odrzucony — weryfikacja podpisu nie powiodła się dla zamówienia ' . $reference, $logFile);
    http_response_code(403);
    echo json_encode(['error' => 'Signature invalid']);
    exit;
}

$expectedAmount = (int)round((float)$order['amount'] * 100);
$receivedAmount = 0;
if ($provider === 'TPAY') {
    $receivedAmount = (int)round((float)($data['amount'] ?? 0) * 100);
} elseif ($provider === 'P24' || $provider === 'PRZELEWY24') {
    $receivedAmount = (int)($data['p24_amount'] ?? 0);
}
if ($expectedAmount && $receivedAmount && $expectedAmount !== $receivedAmount) {
    shop_log('Webhook odrzucony — kwota niezgodna dla zamówienia ' . $reference, $logFile);
    http_response_code(409);
    echo json_encode(['error' => 'Amount mismatch']);
    exit;
}

$status = strtoupper($data['status'] ?? $data['tr_status'] ?? $data['p24_status'] ?? '');
$recognizedPaid = in_array($status, ['PAID', 'SUCCESS', 'CORRECT'], true);

$db->exec('BEGIN IMMEDIATE TRANSACTION');
$update = $db->prepare('UPDATE orders SET status = :status, payload = :payload, updated_at = datetime("now") WHERE id = :id');
$update->bindValue(':status', $recognizedPaid ? 'PAID' : $status, SQLITE3_TEXT);
$update->bindValue(':payload', json_encode($data, JSON_UNESCAPED_UNICODE));
$update->bindValue(':id', $order['id'], SQLITE3_INTEGER);
$update->execute();
$db->exec('COMMIT');

if ($recognizedPaid) {
    $deliver = $config['DELIVER_SCRIPT'];
    $command = $order['command'];
    $player = $order['player'];
    $args = ' -Player ' . escapeshellarg($player) . ' -CommandTemplate ' . escapeshellarg($command);
    $output = shell_exec('powershell -NoProfile -ExecutionPolicy Bypass -File ' . escapeshellarg($deliver) . $args);
    shop_log('Zrealizowano zamówienie ' . $reference . ' dla gracza ' . $player . '. RCON: ' . trim((string)$output), $logFile);
    http_response_code(200);
    echo json_encode(['status' => 'DELIVERED']);
    exit;
}

shop_log('Webhook przyjęty, status oczekujący: ' . $status . ' (zamówienie ' . $reference . ')', $logFile);
http_response_code(202);
echo json_encode(['status' => 'ACCEPTED']);
'@
    $webhookPath = Join-Path $paths.ShopPublic 'webhook.php'
    $webhookPhp | Out-File -FilePath $webhookPath -Encoding UTF8

    $adminPhp = @'
<?php
declare(strict_types=1);
$config = require __DIR__ . '/../config/shop.config.php';
$secrets = json_decode(file_get_contents($config['SECRETS_PATH']), true);
$admin = $secrets['Admin'] ?? [];
$user = $_SERVER['PHP_AUTH_USER'] ?? '';
$pass = $_SERVER['PHP_AUTH_PW'] ?? '';
$hash = base64_encode(hash('sha256', $pass, true));
if (!$user || $user !== ($admin['Username'] ?? '') || $hash !== ($admin['PasswordHash'] ?? '')) {
    header('WWW-Authenticate: Basic realm="Shop Admin"');
    header('HTTP/1.0 401 Unauthorized');
    echo 'Unauthorized';
    exit;
}
$db = new SQLite3($config['DB_PATH']);
$orders = $db->query('SELECT external_id, player, amount, currency, status, created_at FROM orders ORDER BY id DESC LIMIT 25');
$products = $db->query('SELECT id, name, price FROM products ORDER BY id');
?>
<!doctype html>
<html lang="pl">
<head>
    <meta charset="utf-8">
    <title>Panel sklepu</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 2rem; }
        table { border-collapse: collapse; width: 100%; margin-top: 1rem; }
        th, td { border: 1px solid #ccc; padding: 0.5rem; text-align: left; }
        h1, h2 { margin-top: 0; }
        .section { margin-bottom: 2rem; }
    </style>
</head>
<body>
<h1>Panel administracyjny sklepu</h1>
<div class="section">
    <h2>Produkty</h2>
    <table>
        <tr><th>ID</th><th>Nazwa</th><th>Cena (PLN)</th></tr>
        <?php while ($row = $products->fetchArray(SQLITE3_ASSOC)): ?>
            <tr>
                <td><?= (int)$row['id']; ?></td>
                <td><?= htmlspecialchars($row['name']); ?></td>
                <td><?= number_format((float)$row['price'], 2); ?></td>
            </tr>
        <?php endwhile; ?>
    </table>
    <p>Dodawaj produkty poleceniem <code>php manage.php products:add</code> (do implementacji) lub ręcznie w SQLite.</p>
</div>
<div class="section">
    <h2>Ostatnie zamówienia</h2>
    <table>
        <tr><th>Ref</th><th>Gracz</th><th>Kwota</th><th>Status</th><th>Data</th></tr>
        <?php while ($row = $orders->fetchArray(SQLITE3_ASSOC)): ?>
            <tr>
                <td><code><?= htmlspecialchars($row['external_id']); ?></code></td>
                <td><?= htmlspecialchars($row['player']); ?></td>
                <td><?= number_format((float)$row['amount'], 2) . ' ' . htmlspecialchars($row['currency']); ?></td>
                <td><?= htmlspecialchars($row['status']); ?></td>
                <td><?= htmlspecialchars($row['created_at']); ?></td>
            </tr>
        <?php endwhile; ?>
    </table>
</div>
</body>
</html>

'@
    $adminPath = Join-Path $paths.ShopAdmin 'index.php'
    $adminPhp | Out-File -FilePath $adminPath -Encoding UTF8

    $readme = @'
=== Sklep BLIK – instrukcje sandbox ===
1. Uruchom C:\Infra\shop\configure-psp.ps1 i wklej dane merchanta (TPay lub Przelewy24). Sekrety są szyfrowane DPAPI.
2. W panelu PSP ustaw webhook na adres: https://twoj-host/shop/webhook.php oraz identyfikator zamówienia z formularza sklepu.
3. Tunele Playit: 443→8443 (HTTPS Caddy), 11131→11131 (Minecraft), 11141→11141 (BlueMap).
4. Logi sklepu znajdziesz w C:\Infra\logs\shop.log oraz C:\Infra\logs\shop-delivery.log.
5. W przypadku problemów sprawdź panel admina pod /shop/admin i logi systemowe.

'@
    $readmePath = Join-Path $paths.Shop 'README-FIRST.txt'
    $readme | Out-File -FilePath $readmePath -Encoding UTF8

    $configurePsp = @'
[CmdletBinding()]
param()

function Protect-PlainText {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    [Convert]::ToBase64String([System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine))
}

$secretsPath = 'C:\Infra\shop\config\secrets.json'
if (-not (Test-Path -LiteralPath $secretsPath)) {
    Write-Error "Nie znaleziono pliku $secretsPath"; exit 1
}
$data = Get-Content -LiteralPath $secretsPath | ConvertFrom-Json
$provider = (Read-Host "Wybierz dostawcę PSP (TPAY/P24)").ToUpper()
$payload = [ordered]@{}
$display = [ordered]@{}
switch ($provider) {
    'TPAY' {
        $payload.merchant_id = Read-Host 'Merchant ID'
        $payload.api_key = Read-Host 'API key'
        $payload.secret = Read-Host 'CRC/Secret'
        $display.merchant_id = $payload.merchant_id
    }
    'P24' { $provider = 'P24';
        $payload.merchant_id = Read-Host 'Merchant ID'
        $payload.pos_id = Read-Host 'POS ID'
        $payload.secret = Read-Host 'CRC'
        $display.merchant_id = $payload.merchant_id
        $display.pos_id = $payload.pos_id
    }
    default {
        Write-Error 'Nieznany dostawca. Obsługiwani: TPAY, P24.'; exit 1
    }
}

$json = ($payload | ConvertTo-Json -Depth 4)
$data.PSP.Provider = $provider
$data.PSP.EncryptedPayload = Protect-PlainText $json
$data.PSP.Credentials = $display

$changeRcon = Read-Host 'Czy zaktualizować hasło RCON? (T/N)'
if ($changeRcon -match '^[TtYy]') {
    $newRcon = Read-Host 'Nowe hasło RCON'
    if ($newRcon) {
        $data.Rcon.EncryptedPassword = Protect-PlainText $newRcon
        $data.Rcon.UpdatedAt = (Get-Date).ToString('o')
    }
}

$data | ConvertTo-Json -Depth 6 | Out-File -FilePath $secretsPath -Encoding UTF8
Write-Host "Sekrety PSP zapisane." -ForegroundColor Green
'@
    $configurePath = Join-Path $paths.Shop 'configure-psp.ps1'
    $configurePsp | Out-File -FilePath $configurePath -Encoding UTF8

    Write-Section "Inicjalizacja bazy SQLite"
    $sqlitePath = Join-Path $paths.ShopData 'shop.sqlite'
    $schema = @'
CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    price REAL NOT NULL,
    command TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    external_id TEXT UNIQUE,
    product_id INTEGER NOT NULL,
    player TEXT NOT NULL,
    amount REAL NOT NULL,
    currency TEXT NOT NULL DEFAULT 'PLN',
    status TEXT NOT NULL,
    provider TEXT,
    payload TEXT,
    created_at TEXT,
    updated_at TEXT,
    FOREIGN KEY(product_id) REFERENCES products(id)
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message TEXT,
    created_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_orders_external_id ON orders(external_id);

INSERT OR IGNORE INTO products (id, name, price, command) VALUES (1, 'Diamentowy miecz', 1.00, '/give %player% diamond_sword 1');
INSERT OR IGNORE INTO products (id, name, price, command) VALUES (2, 'Elytra', 15.00, '/give %player% elytra 1');
'@
    $schemaFile = Join-Path $paths.ShopData 'schema.sql'
    $schema | Out-File -FilePath $schemaFile -Encoding UTF8
    & $phpExe -r "\$db=new SQLite3('$sqlitePath');\$schema=file_get_contents('$schemaFile');\$db->exec(\$schema);"
    & $phpExe -r "\$db=new SQLite3('$sqlitePath');\$columns=array();\$result=\$db->query('PRAGMA table_info(orders)');while(\$row=\$result->fetchArray(SQLITE3_ASSOC)){\$columns[] = \$row['name'];}if(!in_array('payload',\$columns,true)){\$db->exec('ALTER TABLE orders ADD COLUMN payload TEXT');}\$result2=\$db->query('PRAGMA table_info(orders)');\$columns2=array();while(\$row2=\$result2->fetchArray(SQLITE3_ASSOC)){\$columns2[] = \$row2['name'];}if(!in_array('provider',\$columns2,true)){\$db->exec('ALTER TABLE orders ADD COLUMN provider TEXT');}\$db->close();"

    Write-Section "Serwer PHP (FastCGI)"
    $phpCgiExe = Join-Path $paths.PHP 'php-cgi.exe'
    if (-not (Test-Path -LiteralPath $phpCgiExe)) {
        throw "Nie znaleziono $phpCgiExe. Upewnij się, że wersja NTS PHP zawiera php-cgi.exe"
    }
    $phpCgiLog = Join-Path $paths.Logs 'shop-phpcgi.log'
    Ensure-NssmService -ServiceName 'ShopPhpCgi' -DisplayName 'Minecraft Shop FastCGI' -Executable $phpCgiExe -Arguments '-b 127.0.0.1:9000' -WorkingDirectory $paths.Shop -StdOutLog $phpCgiLog -StdErrLog $phpCgiLog
    $legacyTask = Get-ScheduledTask -TaskName 'ShopService@Startup' -ErrorAction SilentlyContinue
    if ($legacyTask) { Unregister-ScheduledTask -TaskName 'ShopService@Startup' -Confirm:$false }
    $legacyService = Get-Service -Name 'ShopPhpService' -ErrorAction SilentlyContinue
    if ($legacyService) {
        Write-Host "[INFO] Usuwam przestarzałą usługę ShopPhpService" -ForegroundColor Yellow
        Stop-Service -Name 'ShopPhpService' -Force -ErrorAction SilentlyContinue
        & (Ensure-Nssm -BinPath $paths.Bin) remove ShopPhpService confirm | Out-Null
    }

    Write-Section "Konfiguracja RCON serwera Minecraft"
    $serverProps = 'C:\SERWER\server.properties'
    if (-not (Test-Path -LiteralPath $serverProps)) {
        throw "Nie znaleziono C:\SERWER\server.properties"
    }

    $props = Get-Content -Path $serverProps
    $rconPassword = $null
    $modified = $false
    if ($props -notmatch '^enable-rcon=') {
        $props += 'enable-rcon=true'
        $modified = $true
    }
    else {
        $props = $props | ForEach-Object { if ($_ -match '^enable-rcon=') { if ($_ -ne 'enable-rcon=true') { $modified = $true }; 'enable-rcon=true' } else { $_ } }
    }
    if ($props -notmatch '^rcon.port=') {
        $props += 'rcon.port=25575'
        $modified = $true
    }
    if ($props -notmatch '^rcon.password=') {
        $rconPassword = Generate-Secret -Length 24
        $props += "rcon.password=$rconPassword"
        $modified = $true
    }
    else {
        foreach ($line in $props) {
            if ($line -like 'rcon.password=*') { $rconPassword = $line.Split('=')[1] }
        }
    }
    if ($modified) { $props | Set-Content -Path $serverProps -Encoding UTF8 }

    if ($rconPassword) {
        $secretsData.Rcon.EncryptedPassword = Protect-Secret -Secret $rconPassword
        $secretsData.Rcon.UpdatedAt = (Get-Date).ToString('o')
    }
    Save-Json -Path $secretsPath -Data $secretsData
    $recoveryPath = Join-Path $paths.FirstBoot 'recovery.txt'
    @"
MeshCentral login: $global:MeshAdminUser
MeshCentral password: $([string]::IsNullOrEmpty($global:MeshAdminPass) ? '<niezmienione>' : $global:MeshAdminPass)
Shop admin login: $($secretsData.Admin.Username)
Shop admin password: $([string]::IsNullOrEmpty($adminPass) ? '<niezmienione>' : $adminPass)
RCON password: $([string]::IsNullOrEmpty($rconPassword) ? '<bez zmian>' : $rconPassword)
"@ | Out-File -FilePath $recoveryPath -Encoding UTF8

    $adminCredPath = Join-Path $paths.FirstBoot 'admin.credentials'
    $adminCredContent = @{
        MeshAdmin = @{ Username = $global:MeshAdminUser; Password = if ($global:MeshAdminPass) { $global:MeshAdminPass } else { '<niezmienione>' } }
        ShopAdmin = @{ Username = $secretsData.Admin.Username; Password = if ($adminPass) { $adminPass } else { '<niezmienione>' } }
        Rcon = @{ Password = if ($rconPassword) { $rconPassword } else { '<bez zmian>' } }
    }
    Save-Json -Path $adminCredPath -Data $adminCredContent

    foreach ($secureFile in @($secretsPath,$recoveryPath,$adminCredPath)) {
        icacls $secureFile /inheritance:r | Out-Null
        icacls $secureFile /grant:r 'Administrators:F' | Out-Null
    }

    Write-Section "Autostart serwera Minecraft"
    $startBat = 'C:\SERWER\start-server.bat'
    if (-not (Test-Path -LiteralPath $startBat)) {
        @'
@echo off
cd /d "C:\SERWER"
"C:\Program Files\Microsoft\jdk-21.0.8.9-hotspot\bin\java.exe" -Xms128M -XX:MaxRAMPercentage=95.0 -Dterminal.jline=false -Dterminal.ansi=true -jar server.jar
'@ | Out-File -FilePath $startBat -Encoding ASCII
    }

    $mcAction = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c "C:\SERWER\start-server.bat"'
    $mcTrigger = New-ScheduledTaskTrigger -AtStartup
    Ensure-ScheduledTask -TaskName 'Minecraft@Startup' -Action $mcAction -Trigger $mcTrigger -Description 'Start serwera Minecraft'

    Write-Section "playit.gg"
    $playitExe = Join-Path $paths.Bin 'playit.exe'
    Download-IfMissing -Uri 'https://github.com/playit-cloud/playit-agent/releases/latest/download/playit.exe' -Destination $playitExe -Description 'Pobieranie playit.gg agent'
    $playitStatus = [ordered]@{
        DeviceLinkStarted = $false
        AppliedFromFile = $false
        AppliedMessage = ''
        Tunnels = @()
        TunnelsError = ''
    }
    if (-not $SkipDeviceLink) {
        Write-Host "Uruchamiam tryb device-link. Postępuj zgodnie z instrukcjami w konsoli." -ForegroundColor Yellow
        Start-Process -FilePath $playitExe -ArgumentList 'device-link'
        $playitStatus.DeviceLinkStarted = $true
        Write-Host "Połącz urządzenie w przeglądarce i utwórz tunele." -ForegroundColor Green
    }
    $playitConfigPath = Join-Path $paths.Bin 'playit-tunnels.txt'
    if (Test-Path -LiteralPath $playitConfigPath) {
        Write-Host "Wykryto playit-tunnels.txt – próbuję zastosować tunelową konfigurację." -ForegroundColor Yellow
        try {
            $applyOutput = & $playitExe 'tunnels' 'apply' $playitConfigPath 2>&1
            if ($LASTEXITCODE -eq 0) {
                $playitStatus.AppliedFromFile = $true
                $playitStatus.AppliedMessage = ($applyOutput | Out-String).Trim()
                Write-Host "[OK] Zastosowano konfigurację tuneli z pliku." -ForegroundColor DarkGreen
            }
            else {
                $playitStatus.AppliedMessage = ($applyOutput | Out-String).Trim()
                Write-Warning "Nie udało się zastosować konfiguracji tuneli: $($playitStatus.AppliedMessage)"
            }
        }
        catch {
            $playitStatus.AppliedMessage = $_.Exception.Message
            Write-Warning "Błąd podczas stosowania konfiguracji tuneli: $($playitStatus.AppliedMessage)"
        }
    }
    try {
        $tunnelOutput = & $playitExe 'tunnels' 'list' '--json' 2>&1
        if ($LASTEXITCODE -eq 0) {
            $playitStatus.Tunnels = ($tunnelOutput | Out-String | ConvertFrom-Json -ErrorAction Stop)
        }
        else {
            $playitStatus.TunnelsError = ($tunnelOutput | Out-String).Trim()
        }
    }
    catch {
        $playitStatus.TunnelsError = $_.Exception.Message
    }
    Write-Host "Docelowe tunele: 443→8443, 11131→11131, 11141→11141." -ForegroundColor Cyan

    Write-Section "Zadania i logi"
    foreach ($logName in @('shop.log','shop-delivery.log','shop-phpcgi.log','caddy-service.log')) {

        $logFilePath = Join-Path $paths.Logs $logName
        if (-not (Test-Path -LiteralPath $logFilePath)) {
            New-Item -Path $logFilePath -ItemType File -Force | Out-Null
        }
    }
    $logRotateCommand = "Get-ChildItem '$($paths.Logs)' -Filter *.log | ForEach-Object { if ($_.Length -gt 10MB) { for($i=9;$i -ge 1;$i--) { $src = $_.FullName + '.' + $i; $dst = $_.FullName + '.' + ($i + 1); if (Test-Path $src) { Move-Item $src $dst -Force } } $backup = $_.FullName + '.1'; Move-Item $_.FullName $backup -Force } }"
    $logRotateTaskAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -Command `$ErrorActionPreference='Stop'; $logRotateCommand"
    $logRotateTaskTrigger = New-ScheduledTaskTrigger -Daily -At 3am
    Ensure-ScheduledTask -TaskName 'InfraLogRotate' -Action $logRotateTaskAction -Trigger $logRotateTaskTrigger -Description 'Rotacja logów infra'

    Write-Section "Zapis sekretów"
    $secretFile = Join-Path $paths.FirstBoot 'secrets.json'
    $secrets = @{
        AdminPanel = @{ Username = $secretsData.Admin.Username; Password = if ($adminPass) { $adminPass } else { '<niezmienione>' } }
        RconPassword = if ($rconPassword) { $rconPassword } else { '<bez zmian>' }
        MeshCentral = @{ Username = $global:MeshAdminUser; Password = if ($global:MeshAdminPass) { $global:MeshAdminPass } else { '<niezmienione>' } }
        PSPProvider = $secretsData.PSP.Provider

    }
    Save-Json -Path $secretFile -Data $secrets
    icacls $secretFile /inheritance:r | Out-Null
    icacls $secretFile /grant:r 'Administrators:F' | Out-Null

    Write-Section "Uruchamianie usług"
    $services = @('CaddyReverseProxy','MeshCentral','ShopPhpCgi','Mesh Agent') | ForEach-Object { Get-Service -Name $_ -ErrorAction SilentlyContinue }
    foreach ($svc in $services) {
        if ($svc -and $svc.Status -ne 'Running') { Start-Service -Name $svc.Name }
    }

    if (-not $global:MeshAgentInstalled -and -not (Get-Service -Name 'Mesh Agent' -ErrorAction SilentlyContinue)) {
        Write-Warning 'MeshAgent nie został zainstalowany automatycznie. Pobierz instalator z https://localhost:8443/desk po zalogowaniu.'
    }

    Write-Section "Kontrola zdrowia usług"
    $webCheckSummary = {
        param($result, $url)
        $obj = [ordered]@{ Url = $url; Success = $false; StatusCode = $null; Error = '' }
        if ($result -is [Microsoft.PowerShell.Commands.BasicHtmlWebResponseObject]) {
            $obj.Success = ($result.StatusCode -eq 200)
            $obj.StatusCode = $result.StatusCode
        }
        else {
            $obj.Error = ($result | Out-String).Trim()
        }
        if (-not $obj.Success -and -not [string]::IsNullOrEmpty($obj.Error)) {
            Write-Warning "Health-check nie powiódł się dla $url: $($obj.Error)"
        }
        elseif (-not $obj.Success) {
            Write-Warning "Health-check nie powiódł się dla $url"
        }
        else {
            Write-Host "[OK] $url" -ForegroundColor DarkGreen
        }
        return $obj
    }

    $shopCheck = $null
    $mapCheck = $null
    try { $shopCheck = Invoke-LocalHttps -Uri 'https://localhost:8443/shop/' } catch { $shopCheck = $_ }
    try { $mapCheck = Invoke-LocalHttps -Uri 'https://localhost:8443/map/' } catch { $mapCheck = $_ }

    $meshDeskResult = & $webCheckSummary $deskCheck 'https://localhost:8443/desk/'
    $meshDeskScriptResult = & $webCheckSummary $deskScriptCheck 'https://localhost:8443/desk/scripts/common.js'
    $shopResult = & $webCheckSummary $shopCheck 'https://localhost:8443/shop/'
    $mapResult = & $webCheckSummary $mapCheck 'https://localhost:8443/map/'

    $rconResult = [ordered]@{ Success = $false; Output = ''; Error = '' }
    try {
        $rconOutput = & $deliverPath -Player 'InfraHealth' -CommandTemplate 'say Infra setup health-check OK' -ErrorAction Stop
        $rconResult.Success = $true
        $rconResult.Output = ($rconOutput | Out-String).Trim()
        Write-Host "[OK] Test komendy RCON wykonany." -ForegroundColor DarkGreen
    }
    catch {
        $rconResult.Error = $_.Exception.Message
        Write-Warning "Test komendy RCON nie powiódł się: $($rconResult.Error)"
    }

    $playitReport = [ordered]@{
        Success = $false
        DeviceLinkStarted = $playitStatus.DeviceLinkStarted
        AppliedFromFile = $playitStatus.AppliedFromFile
        AppliedMessage = $playitStatus.AppliedMessage
        Tunnels = $playitStatus.Tunnels
        TunnelsError = $playitStatus.TunnelsError
    }
    if ($playitStatus.Tunnels) {
        $tunnelCount = ($playitStatus.Tunnels | Measure-Object).Count
        if ($tunnelCount -gt 0) { $playitReport.Success = $true }
    }
    elseif (-not [string]::IsNullOrEmpty($playitStatus.TunnelsError)) {
        $playitReport.Tunnels = @()
    }

    $readyReport = [ordered]@{
        Timestamp = (Get-Date).ToString('o')
        MeshRoutingMode = $meshRoutingMode
        Java = $javaStatus
        MeshDesk = $meshDeskResult
        MeshDeskScript = $meshDeskScriptResult
        Shop = $shopResult
        Map = $mapResult
        Rcon = $rconResult
        Playit = $playitReport
    }
    $readyReportPath = Join-Path $paths.FirstBoot 'ready-report.json'
    Save-Json -Path $readyReportPath -Data $readyReport

    $failedChecks = $readyReport.GetEnumerator() | Where-Object { $_.Value -is [System.Collections.IDictionary] -and $_.Value.Contains('Success') -and -not $_.Value.Success }
    if ($failedChecks) {
        Write-Host "[ALERT] Nie wszystkie health-checki zakończyły się sukcesem – sprawdź ready-report.json" -ForegroundColor Red
    }
    else {
        Write-Host "[OK] Wszystkie health-checki zakończone powodzeniem." -ForegroundColor DarkGreen
    }


    Write-Section "Status końcowy"
    $status = [ordered]@{
        Caddy = (Get-Service -Name 'CaddyReverseProxy' -ErrorAction SilentlyContinue)?.Status
        MeshCentral = (Get-Service -Name 'MeshCentral' -ErrorAction SilentlyContinue)?.Status
        ShopService = (Get-Service -Name 'ShopPhpCgi' -ErrorAction SilentlyContinue)?.Status
        MeshAgent = (Get-Service -Name 'Mesh Agent' -ErrorAction SilentlyContinue)?.Status

        Minecraft = (Get-ScheduledTask -TaskName 'Minecraft@Startup' -ErrorAction SilentlyContinue) ? 'ScheduledTask'
    }
    $status.GetEnumerator() | ForEach-Object { Write-Host ("{0,-12}: {1}" -f $_.Key, $_.Value) }

    Write-Host "`nSekrety (maskowane):" -ForegroundColor Cyan
    $meshPassDisplay = if ($global:MeshAdminPass) { Mask-Secret $global:MeshAdminPass } else { '<niezmienione>' }
    $shopPassDisplay = if ($adminPass) { Mask-Secret $adminPass } else { '<niezmienione>' }
    $rconPassDisplay = if ($rconPassword) { Mask-Secret $rconPassword } else { '<bez zmian>' }
    Write-Host "   MeshCentral: $global:MeshAdminUser / $meshPassDisplay"
    Write-Host "   Sklep admin: $($secretsData.Admin.Username) / $shopPassDisplay"
    Write-Host "   RCON: $rconPassDisplay"
    Write-Host "   Raport health-check: $readyReportPath"

    Write-Host "`nCo teraz:" -ForegroundColor Green
    Write-Host "1. Dokończ device-link w Playit i utwórz tunele:" -ForegroundColor Green
    Write-Host "   - 443 -> 8443 (HTTPS portal/sklep/desk)" -ForegroundColor Green
    Write-Host "   - 11131 -> 11131 (Minecraft)" -ForegroundColor Green
    Write-Host "   - 11141 -> 11141 (BlueMap)" -ForegroundColor Green
    Write-Host "2. Testuj lokalnie: https://localhost:8443/desk, /shop, /map (certyfikat self-signed)." -ForegroundColor Green
    Write-Host "3. Skonfiguruj klucze PSP: C:\Infra\shop\configure-psp.ps1" -ForegroundColor Green
    Write-Host "4. Zanotuj dane dostępowe zapisane w C:\Infra\firstboot\secrets.json (admin panel, MeshCentral)." -ForegroundColor Green
    Write-Host "5. Wykonaj test sandbox BLIK 1 PLN i potwierdź dostarczenie przedmiotu." -ForegroundColor Green
    Write-Host "6. Po pierwszym logowaniu do MeshCentral włącz 2FA dla konta administratora." -ForegroundColor Green
    Write-Host "7. Jeśli posiadasz domenę publiczną, podmień blok TLS w Caddy na konfigurację ACME/Let's Encrypt." -ForegroundColor Green

    if ($meshRoutingMode -eq 'host') {
        Write-Warning 'Aktywowano dodatkowy host https://desk.localhost:8443 dla MeshCentral – użyj go, jeśli ścieżka /desk nie działa przez tunel.'
    }

}
catch {
    Write-Error $_
    exit 1
}
