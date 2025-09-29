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

function Ensure-PathEntry {
    param(
        [Parameter(Mandatory)][string]$Entry
    )

    $normalized = $Entry.TrimEnd(';')
    $machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
    $pattern = "(?i)(^|;){0}(;|$)" -f [Regex]::Escape($normalized)

    if ([string]::IsNullOrEmpty($machinePath)) {
        [Environment]::SetEnvironmentVariable('Path', $normalized, 'Machine')
    }
    elseif ($machinePath -notmatch $pattern) {
        [Environment]::SetEnvironmentVariable('Path', "$normalized;$machinePath", 'Machine')
    }

    $processPath = $env:Path
    if ([string]::IsNullOrEmpty($processPath)) {
        $env:Path = $normalized
    }
    elseif ($processPath -notmatch $pattern) {
        $env:Path = "$normalized;$processPath"
    }
}

function Generate-Secret {
    param([int]$Length = 32)
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}'
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

function Ensure-Nssm {
    param([string]$DestinationRoot)

    $nssmDir = Join-Path $DestinationRoot 'nssm'
    $nssmExe = Join-Path $nssmDir 'nssm.exe'
    if (Test-Path -LiteralPath $nssmExe) {
        return $nssmExe
    }

    Write-Host "[INFO] Pobieram NSSM" -ForegroundColor Yellow
    $zipPath = Join-Path ([System.IO.Path]::GetTempPath()) 'nssm.zip'
    Invoke-WebRequest -Uri 'https://nssm.cc/release/nssm-2.24.zip' -OutFile $zipPath -UseBasicParsing
    try {
        $extractPath = Join-Path ([System.IO.Path]::GetTempPath()) 'nssm_extract'
        if (Test-Path $extractPath) { Remove-Item -Path $extractPath -Recurse -Force }
        Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force
        $sourceExe = Join-Path $extractPath 'nssm-2.24\win64\nssm.exe'
        if (-not (Test-Path -LiteralPath $sourceExe)) {
            throw 'Nie znaleziono nssm.exe w archiwum.'
        }
        Ensure-Directory $nssmDir
        Copy-Item -Path $sourceExe -Destination $nssmExe -Force
    }
    finally {
        Remove-Item -LiteralPath $zipPath -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $extractPath -ErrorAction SilentlyContinue
    }

    return $nssmExe
}

function Install-NssmService {
    param(
        [Parameter(Mandatory)][string]$NssmExe,
        [Parameter(Mandatory)][string]$ServiceName,
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][string]$Executable,
        [string]$Arguments,
        [string]$WorkingDirectory,
        [string]$StdOut,
        [string]$StdErr
    )

    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $service) {
        Write-Host "[SVC] Rejestruję usługę $DisplayName (NSSM)" -ForegroundColor Yellow
        $installArgs = @('install', $ServiceName, $Executable)
        if ($Arguments) { $installArgs += $Arguments }
        & $NssmExe @installArgs | Out-Null
    }
    elseif ($service.Status -eq 'Running') {
        & $NssmExe stop $ServiceName | Out-Null
    }

    if ($Arguments) { & $NssmExe set $ServiceName AppParameters $Arguments | Out-Null }
    if ($WorkingDirectory) { & $NssmExe set $ServiceName AppDirectory $WorkingDirectory | Out-Null }
    if ($StdOut) { & $NssmExe set $ServiceName AppStdout $StdOut | Out-Null }
    if ($StdErr) { & $NssmExe set $ServiceName AppStderr $StdErr | Out-Null }
    & $NssmExe set $ServiceName AppRotateFiles 1 | Out-Null
    & $NssmExe set $ServiceName AppRotateSeconds 86400 | Out-Null
    & $NssmExe set $ServiceName AppRotateBytes 10485760 | Out-Null
    & $NssmExe set $ServiceName Start SERVICE_AUTO_START | Out-Null
    & $NssmExe set $ServiceName AppRestartDelay 5000 | Out-Null
    & $NssmExe set $ServiceName DisplayName $DisplayName | Out-Null

    if (-not $service) {
        & $NssmExe set $ServiceName Description $DisplayName | Out-Null
    }

    & $NssmExe start $ServiceName | Out-Null
}

function Ensure-Java21 {
    param([string]$InfraBin)

    $candidatePaths = New-Object System.Collections.Generic.List[string]
    if ($env:JAVA_HOME) {
        $candidatePaths.Add((Join-Path $env:JAVA_HOME 'bin\java.exe'))
    }

    $registryPaths = @(
        'HKLM:\SOFTWARE\JavaSoft\JDK',
        'HKLM:\SOFTWARE\WOW6432Node\JavaSoft\JDK',
        'HKLM:\SOFTWARE\Microsoft\JDK'
    )
    foreach ($regPath in $registryPaths) {
        try {
            Get-ChildItem -Path $regPath -ErrorAction Stop | ForEach-Object {
                $home = (Get-ItemProperty -Path $_.PSPath -Name JavaHome -ErrorAction SilentlyContinue).JavaHome
                if ($home) {
                    $candidatePaths.Add((Join-Path $home 'bin\java.exe'))
                }
            }
        }
        catch {
        }
    }

    $programDirs = @('C:\Program Files\Microsoft', 'C:\Program Files', 'C:\Program Files (x86)', (Join-Path $InfraBin 'java'))
    foreach ($dir in $programDirs) {
        if (Test-Path -LiteralPath $dir) {
            Get-ChildItem -Path $dir -Directory -Filter 'jdk-21*' -ErrorAction SilentlyContinue | ForEach-Object {
                $candidatePaths.Add((Join-Path $_.FullName 'bin\java.exe'))
            }
        }
    }

    foreach ($path in $candidatePaths | Select-Object -Unique) {
        if (Test-Path -LiteralPath $path) {
            Write-Host "[JAVA] Znaleziono Java 21: $path" -ForegroundColor DarkGreen
            return $path
        }
    }

    Write-Host "[JAVA] Brak JDK 21 — instaluję Microsoft OpenJDK" -ForegroundColor Yellow
    $javaRoot = Join-Path $InfraBin 'java'
    Ensure-Directory $javaRoot
    $downloadUrl = 'https://aka.ms/download-jdk/microsoft-jdk-21.0.5-windows-x64.zip'
    $zipPath = Join-Path ([System.IO.Path]::GetTempPath()) 'jdk21.zip'
    Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -UseBasicParsing
    try {
        Expand-Archive -Path $zipPath -DestinationPath $javaRoot -Force
        $jdkFolder = Get-ChildItem -Path $javaRoot -Directory -Filter 'jdk-21*' | Sort-Object Name -Descending | Select-Object -First 1
        if (-not $jdkFolder) {
            throw 'Nie udało się rozpakować JDK.'
        }
        $javaExe = Join-Path $jdkFolder.FullName 'bin\java.exe'
        [Environment]::SetEnvironmentVariable('JAVA_HOME', $jdkFolder.FullName, 'Machine')
        Ensure-PathEntry (Join-Path $jdkFolder.FullName 'bin')
        return $javaExe
    }
    finally {
        Remove-Item -LiteralPath $zipPath -ErrorAction SilentlyContinue
    }
}

function Test-JavaServer {
    param(
        [Parameter(Mandatory)][string]$JavaExe,
        [Parameter(Mandatory)][string]$ServerJar
    )

    if (-not (Test-Path -LiteralPath $ServerJar)) {
        throw "Nie znaleziono pliku serwera: $ServerJar"
    }

    Write-Host "[JAVA] Weryfikuję uruchomienie server.jar" -ForegroundColor Yellow
    $commonArgs = @('-Xms128M','-XX:MaxRAMPercentage=95.0','-Dterminal.jline=false','-Dterminal.ansi=true','-jar',$ServerJar)
    $attempts = @('--version','--help')
    $lastExit = $null
    foreach ($suffix in $attempts) {
        $process = Start-Process -FilePath $JavaExe -ArgumentList ($commonArgs + $suffix) -NoNewWindow -PassThru -Wait -ErrorAction SilentlyContinue
        if ($process -and $process.ExitCode -eq 0) {
            Write-Host "[JAVA] server.jar odpowiada poprawnie." -ForegroundColor DarkGreen
            return
        }
        $lastExit = $process?.ExitCode
        Write-Host "[JAVA] Próba walidacji z argumentem $suffix nie powiodła się (kod: $lastExit)." -ForegroundColor Yellow
    }
    throw "server.jar nie uruchomił się poprawnie (ostatni kod wyjścia: $lastExit)"
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

    $nssmExe = Ensure-Nssm -DestinationRoot $paths.Bin
    $javaExe = Ensure-Java21 -InfraBin $paths.Bin

    Write-Section "Konfiguracja zapory"
    $legacyPortalRule = Get-NetFirewallRule -DisplayName 'Allow Portal HTTP 8080' -ErrorAction SilentlyContinue
    if ($legacyPortalRule) {
        Write-Host "[FW] Usuwam przestarzałą regułę 8080" -ForegroundColor Yellow
        Remove-NetFirewallRule -DisplayName 'Allow Portal HTTP 8080'
    }
    Ensure-FirewallRule -Name 'Allow-Portal-8443' -DisplayName 'Allow Portal HTTPS 8443' -Action Allow -Direction Inbound -LocalPort 8443
    Ensure-FirewallRule -Name 'Allow-Minecraft-11131' -DisplayName 'Allow Minecraft 11131' -Action Allow -Direction Inbound -LocalPort 11131
    Ensure-FirewallRule -Name 'Allow-BlueMap-11141' -DisplayName 'Allow BlueMap 11141' -Action Allow -Direction Inbound -LocalPort 11141
    Ensure-FirewallRule -Name 'Block-RDP-3389' -DisplayName 'Block RDP 3389' -Action Block -Direction Inbound -LocalPort 3389

    Write-Section "Caddy - Reverse Proxy"
    $caddyExe = Join-Path $paths.Caddy 'caddy.exe'
    $caddyUrl = 'https://caddyserver.com/api/download?os=windows&arch=amd64&id=github.com%2Fcaddyserver%2Fcaddy'
    Download-IfMissing -Uri $caddyUrl -Destination $caddyExe -Description 'Pobieranie Caddy (Windows)'

    $caddyFile = Join-Path $paths.Caddy 'Caddyfile'
    $caddyConfig = @'
:8443 {
    tls internal
    encode gzip

    handle_path /desk* {
        header Cache-Control "no-store"
        reverse_proxy https://127.0.0.1:4430 {
            transport http {
                tls_insecure_skip_verify
            }
            header_up Host {host}
        }
    }

    handle_path /map* {
        reverse_proxy http://127.0.0.1:11141
    }

    handle_path /shop* {
        root * C:/Infra/shop/public
        php_fastcgi 127.0.0.1:9000
        file_server
    }

    handle / {
        respond "OK" 200
    }
}
'@
    $caddyConfig | Out-File -FilePath $caddyFile -Encoding UTF8

    $caddyLog = Join-Path $paths.Logs 'caddy.log'
    Install-NssmService -NssmExe $nssmExe -ServiceName 'CaddyReverseProxy' -DisplayName 'Caddy Reverse Proxy' -Executable $caddyExe -Arguments "run --config `"$caddyFile`"" -WorkingDirectory $paths.Caddy -StdOut $caddyLog -StdErr $caddyLog

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
            if (Test-Path $nodeRoot) {
                $timestamp = Get-Date -Format 'yyyyMMddHHmmss'
                $backupCandidate = "$nodeRoot.backup.$timestamp"
                while (Test-Path -LiteralPath $backupCandidate) {
                    $timestamp = Get-Date -Format 'yyyyMMddHHmmssff'
                    $backupCandidate = "$nodeRoot.backup.$timestamp"
                }
                Move-Item -Path $nodeRoot -Destination $backupCandidate -Force
                Write-Host "[SAFE] Istniejąca kopia Node.js przeniesiona do $backupCandidate" -ForegroundColor Yellow
            }
            Rename-Item -Path $extracted -NewName 'node'
        }
    }
    else {
        Write-Host "[OK] Node.js już obecny" -ForegroundColor DarkGreen
    }

    Ensure-PathEntry $nodeRoot

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
            AllowFraming = $true
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
    $meshLog = Join-Path $paths.Logs 'meshcentral.log'
    $meshArgs = '"' + $meshModule + '" --config "' + $meshConfigPath + '"'
    Install-NssmService -NssmExe $nssmExe -ServiceName 'MeshCentral' -DisplayName 'MeshCentral Server' -Executable $nodeExe -Arguments $meshArgs -WorkingDirectory $paths.Mesh -StdOut $meshLog -StdErr $meshLog

    Write-Section "PHP 8.x + środowisko sklepu"
    $phpExe = Join-Path $paths.PHP 'php.exe'
    if (-not (Test-Path -LiteralPath $phpExe)) {
        Write-Host "[INFO] Pobieram PHP 8.3 NTS" -ForegroundColor Yellow
        $phpZip = Join-Path ([System.IO.Path]::GetTempPath()) 'php.zip'
        Invoke-WebRequest -Uri 'https://windows.php.net/downloads/releases/php-8.3.3-nts-Win32-vs16-x64.zip' -OutFile $phpZip -UseBasicParsing
        $phpExtract = Join-Path ([System.IO.Path]::GetTempPath()) 'php_extract'
        if (Test-Path $phpExtract) { Remove-Item -Path $phpExtract -Recurse -Force }
        Expand-Archive -Path $phpZip -DestinationPath $phpExtract -Force
        $extractedRoot = Get-ChildItem -Path $phpExtract | Select-Object -First 1
        $sourcePath = if ($extractedRoot -and $extractedRoot.PSIsContainer) { $extractedRoot.FullName } else { $phpExtract }
        Get-ChildItem -Path $sourcePath | ForEach-Object { Move-Item -Path $_.FullName -Destination $paths.PHP -Force }
        Remove-Item -Path $phpExtract -Recurse -Force
        Remove-Item -Path $phpZip -Force
    }
    else {
        Write-Host "[OK] PHP już obecny" -ForegroundColor DarkGreen
    }

    Ensure-PathEntry $paths.PHP

    $phpCgiExe = Join-Path $paths.PHP 'php-cgi.exe'
    if (-not (Test-Path -LiteralPath $phpCgiExe)) {
        throw "Nie znaleziono php-cgi.exe w $($paths.PHP)"
    }

    $phpIni = Join-Path $paths.PHP 'php.ini'
    if (-not (Test-Path -LiteralPath $phpIni)) {
        $phpIniSource = Join-Path $paths.PHP 'php.ini-production'
        if (Test-Path -LiteralPath $phpIniSource) {
            Copy-Item -Path $phpIniSource -Destination $phpIni -Force
        }
        else {
            '' | Out-File -FilePath $phpIni -Encoding UTF8
        }
    }

    $configPhp = @'
<?php
return [
    "PSP_PROVIDER" => "TPAY",
    "ENCRYPTED_CREDENTIALS" => "",
    "PUBLIC_KEY" => "",
    "PRIVATE_KEY" => "",
    "API_KEY" => "",
    "RCON_PASSWORD" => "",
    "RCON_HOST" => "127.0.0.1",
    "RCON_PORT" => 25575,
    "DELIVER_SCRIPT" => "C:\\Infra\\shop\\bin\\deliver.ps1"
];
'@
    $configPath = Join-Path $paths.ShopConfig 'shop.config.php'
    if (-not (Test-Path -LiteralPath $configPath)) {
        $configPhp | Out-File -FilePath $configPath -Encoding UTF8
    }

    $adminCredPath = Join-Path $paths.ShopConfig 'admin.credentials.json'
    if (-not (Test-Path -LiteralPath $adminCredPath)) {
        $adminUser = 'admin'
        $adminPass = Generate-Secret -Length 20
        $hash = [Convert]::ToBase64String([System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($adminPass)))
        $adminData = @{ Username = $adminUser; PasswordHash = $hash }
        Save-Json -Path $adminCredPath -Data $adminData
    }
    else {
        $adminData = Get-Content -Path $adminCredPath | ConvertFrom-Json
        $adminPass = $null
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
    [string]$Host = '127.0.0.1',
    [int]$Port = 25575,
    [Parameter(Mandatory)][string]$Password
)

$cmd = $CommandTemplate.Replace('%player%', $Player)
& 'C:\\Infra\\shop\\bin\\rcon.ps1' -Command $cmd -Host $Host -Port $Port -Password $Password | Out-Null
'@
    $deliverPath = Join-Path $paths.ShopBin 'deliver.ps1'
    $deliverScript | Out-File -FilePath $deliverPath -Encoding UTF8

    $indexPhp = @'
<?php
$config = require __DIR__ . '/../config/shop.config.php';
$products = [
    ['id' => 1, 'name' => 'Diamentowy miecz', 'price' => 1.00, 'command' => '/give %player% diamond_sword 1'],
    ['id' => 2, 'name' => 'Elytra', 'price' => 15.00, 'command' => '/give %player% elytra 1']
];
?>
<!doctype html>
<html lang="pl">
<head>
    <meta charset="utf-8">
    <title>Sklep Minecraft</title>
</head>
<body>
<h1>Sklep Minecraft — płatności BLIK</h1>
<form method="post" action="/shop/webhook.php">
    <label>Nick gracza: <input type="text" name="player" required></label>
    <label>Produkt:
        <select name="product" required>
            <?php foreach ($products as $product): ?>
                <option value="<?= $product['id']; ?>"><?= htmlspecialchars($product['name']); ?> — <?= number_format($product['price'], 2); ?> PLN</option>
            <?php endforeach; ?>
        </select>
    </label>
    <button type="submit">Kup teraz (sandbox)</button>
</form>
<p>Po zrealizowaniu płatności BLIK przedmiot zostanie wysłany automatycznie.</p>
</body>
</html>
'@
    $indexPath = Join-Path $paths.ShopPublic 'index.php'
    $indexPhp | Out-File -FilePath $indexPath -Encoding UTF8

    $webhookPhp = @'
<?php
$config = require __DIR__ . '/../config/shop.config.php';
$payload = file_get_contents('php://input');
$data = $_POST ?: json_decode($payload, true) ?: [];
$status = strtoupper($data['status'] ?? '');
$player = $data['player'] ?? '';
$command = $data['command'] ?? '';
if ($status === 'PAID' && $player && $command) {
    $password = $config['RCON_PASSWORD'];
    $deliver = $config['DELIVER_SCRIPT'];
    $cmd = 'powershell -ExecutionPolicy Bypass -File ' . escapeshellarg($deliver) . ' -Player ' . escapeshellarg($player) . ' -CommandTemplate ' . escapeshellarg($command) . ' -Password ' . escapeshellarg($password);
    shell_exec($cmd);
    http_response_code(200);
    echo json_encode(['status' => 'OK']);
    exit;
}
http_response_code(202);
echo json_encode(['status' => 'ACCEPTED']);
'@
    $webhookPath = Join-Path $paths.ShopPublic 'webhook.php'
    $webhookPhp | Out-File -FilePath $webhookPath -Encoding UTF8

    $adminPhp = @'
<?php
$config = require __DIR__ . '/../config/shop.config.php';
$creds = json_decode(file_get_contents(__DIR__ . '/../config/admin.credentials.json'), true);
$user = $_SERVER['PHP_AUTH_USER'] ?? '';
$pass = $_SERVER['PHP_AUTH_PW'] ?? '';
$hash = base64_encode(hash('sha256', $pass, true));
if (!$user || $user !== $creds['Username'] || $hash !== $creds['PasswordHash']) {
    header('WWW-Authenticate: Basic realm="Shop Admin"');
    header('HTTP/1.0 401 Unauthorized');
    echo 'Unauthorized';
    exit;
}
echo '<h1>Panel administracyjny</h1>';
echo '<p>Dodaj produkty poprzez edycję bazy danych lub przyszły panel.</p>';
'@
    $adminPath = Join-Path $paths.ShopAdmin 'index.php'
    $adminPhp | Out-File -FilePath $adminPath -Encoding UTF8

    $readme = @'
=== Sklep BLIK – instrukcje sandbox ===
1. Skonfiguruj klucze PSP w pliku config/shop.config.php lub uruchom C:\Infra\shop\configure-psp.ps1.
2. Utwórz produkt testowy w SQLite (tabela products) – domyślnie dwa przykładowe produkty.
3. Użyj środowiska sandbox PSP (TPay/Przelewy24) i ustaw webhook: https://twoj-host/shop/webhook.php.
4. Po dokonaniu płatności sprawdź logi w C:\Infra\logs oraz konsolę serwera Minecraft.
'@
    $readmePath = Join-Path $paths.Shop 'README-FIRST.txt'
    $readme | Out-File -FilePath $readmePath -Encoding UTF8

    $configurePsp = @'
[CmdletBinding()]
param()
$configPath = 'C:\Infra\shop\config\shop.config.php'
if (-not (Test-Path $configPath)) {
    Write-Error "Nie znaleziono pliku konfiguracyjnego."; exit 1
}
$provider = Read-Host "Wybierz dostawcę PSP (TPAY/P24)"
$apiKey = Read-Host "Wklej API KEY"
$merchant = Read-Host "Merchant ID"
$secret = Read-Host "Secret/Tpay Password"
$rconPassword = Read-Host "Hasło RCON (pozostaw puste aby nie zmieniać)"

$protected = [Convert]::ToBase64String([System.Security.Cryptography.ProtectedData]::Protect([System.Text.Encoding]::UTF8.GetBytes($secret), $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine))

$content = "<?php`nreturn [`n    'PSP_PROVIDER' => '" + $provider.ToUpper() + "',`n    'ENCRYPTED_CREDENTIALS' => '" + $protected + "',`n    'API_KEY' => '" + $apiKey + "',`n    'PUBLIC_KEY' => '" + $merchant + "',`n    'PRIVATE_KEY' => '',`n    'RCON_PASSWORD' => '" + $rconPassword + "',`n    'RCON_HOST' => '127.0.0.1',`n    'RCON_PORT' => 25575,`n    'DELIVER_SCRIPT' => 'C:\\Infra\\shop\\bin\\deliver.ps1'`n];"
$content | Out-File -FilePath $configPath -Encoding UTF8
Write-Host "Zapisano konfigurację PSP." -ForegroundColor Green
'@
    $configurePath = Join-Path $paths.Shop 'configure-psp.ps1'
    $configurePsp | Out-File -FilePath $configurePath -Encoding UTF8

    Write-Section "Inicjalizacja bazy SQLite"
    $sqlitePath = Join-Path $paths.ShopData 'shop.sqlite'
    if (-not (Test-Path -LiteralPath $sqlitePath)) {
        $schema = @'
CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    price REAL NOT NULL,
    command TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    product_id INTEGER,
    player TEXT,
    status TEXT,
    reference TEXT,
    created_at TEXT,
    updated_at TEXT
);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message TEXT,
    created_at TEXT
);
INSERT OR IGNORE INTO products (id, name, price, command) VALUES (1, 'Diamentowy miecz', 1.00, '/give %player% diamond_sword 1');
INSERT OR IGNORE INTO products (id, name, price, command) VALUES (2, 'Elytra', 15.00, '/give %player% elytra 1');
'@
        $schemaFile = Join-Path $paths.ShopData 'schema.sql'
        $schema | Out-File -FilePath $schemaFile -Encoding UTF8
        & $phpExe -r "\$db=new SQLite3('$sqlitePath');\$schema=file_get_contents('$schemaFile');\$db->exec(\$schema);"
    }

    Write-Section "Serwer PHP (php-cgi)"
    $phpLog = Join-Path $paths.Logs 'php-cgi.log'
    $phpArgs = '-b 127.0.0.1:9000 -c "' + $paths.PHP + '"'
    Install-NssmService -NssmExe $nssmExe -ServiceName 'ShopPhpCgi' -DisplayName 'Sklep Minecraft PHP (FastCGI)' -Executable $phpCgiExe -Arguments $phpArgs -WorkingDirectory $paths.ShopPublic -StdOut $phpLog -StdErr $phpLog

    Write-Section "Konfiguracja RCON serwera Minecraft"
    $serverProps = 'C:\SERWER\server.properties'
    $serverJar = 'C:\SERWER\server.jar'
    if (-not (Test-Path -LiteralPath $serverProps)) {
        throw "Nie znaleziono C:\SERWER\server.properties"
    }
    Test-JavaServer -JavaExe $javaExe -ServerJar $serverJar
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

    Write-Section "Autostart serwera Minecraft"
    $startBat = 'C:\SERWER\start-server.bat'
    $javaPathFile = Join-Path $paths.FirstBoot 'java-path.txt'
    Set-Content -Path $javaPathFile -Value $javaExe -Encoding ASCII
    icacls $javaPathFile /inheritance:r | Out-Null
    icacls $javaPathFile /grant:r 'Administrators:F' | Out-Null

    @'
@echo off
setlocal ENABLEDELAYEDEXPANSION

set "SERVER_DIR=C:\SERWER"
set "SERVER_JAR=%SERVER_DIR%\server.jar"
set "JAVA_HINT_FILE=C:\Infra\firstboot\java-path.txt"

if exist "%JAVA_HINT_FILE%" (
    set /p JAVA_PATH=<"%JAVA_HINT_FILE%"
)

if not defined JAVA_PATH (
    if defined JAVA_HOME (
        if exist "%JAVA_HOME%\bin\java.exe" set "JAVA_PATH=%JAVA_HOME%\bin\java.exe"
    )
)

if not defined JAVA_PATH (
    for /f "usebackq delims=" %%J in (`powershell -NoProfile -Command "& { $c=@(); if ($env:JAVA_HOME) { $c += Join-Path $env:JAVA_HOME 'bin\\java.exe' }; if (Test-Path 'C:\\Infra\\bin\\java') { Get-ChildItem -Path 'C:\\Infra\\bin\\java' -Directory -Filter 'jdk-21*' -EA SilentlyContinue | Sort-Object Name -Descending | ForEach-Object { $c += (Join-Path $_.FullName 'bin\\java.exe') } }; $c += 'C:\\Program Files\\Microsoft\\jdk-21.0.8.9-hotspot\\bin\\java.exe'; $c | Where-Object { Test-Path $_ } | Select-Object -First 1 }"`) do set "JAVA_PATH=%%~J"
)

if not defined JAVA_PATH (
    echo [ERROR] Nie znaleziono Java 21. Uruchom ponownie setup.ps1.
    exit /b 1
)

if not exist "%JAVA_PATH%" (
    echo [ERROR] Skonfigurowany plik java.exe nie istnieje: %JAVA_PATH%
    exit /b 1
)

if not exist "%SERVER_JAR%" (
    echo [ERROR] Nie znaleziono pliku "%SERVER_JAR%".
    exit /b 1
)

cd /d "%SERVER_DIR%"
"%JAVA_PATH%" -Xms128M -XX:MaxRAMPercentage=95.0 -Dterminal.jline=false -Dterminal.ansi=true -jar "%SERVER_JAR%"
'@ | Out-File -FilePath $startBat -Encoding ASCII
    $mcAction = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c "C:\SERWER\start-server.bat"'
    $mcTrigger = New-ScheduledTaskTrigger -AtStartup
    Ensure-ScheduledTask -TaskName 'Minecraft@Startup' -Action $mcAction -Trigger $mcTrigger -Description 'Start serwera Minecraft'

    Write-Section "playit.gg"
    $playitExe = Join-Path $paths.Bin 'playit.exe'
    Download-IfMissing -Uri 'https://github.com/playit-cloud/playit-agent/releases/latest/download/playit.exe' -Destination $playitExe -Description 'Pobieranie playit.gg agent'
    if (-not $SkipDeviceLink) {
        Write-Host "Uruchamiam tryb device-link. Postępuj zgodnie z instrukcjami w konsoli." -ForegroundColor Yellow
        Start-Process -FilePath $playitExe -ArgumentList 'device-link'
        Write-Host "Połącz urządzenie w przeglądarce i utwórz tunele." -ForegroundColor Green
    }

    $playitCommands = @(
        'playit.exe tunnel create tcp --local 127.0.0.1:8443 --remote 0.0.0.0:443 --name "Portal HTTPS"'
        'playit.exe tunnel create tcp --local 127.0.0.1:11131 --remote 0.0.0.0:11131 --name "Minecraft"'
        'playit.exe tunnel create tcp --local 127.0.0.1:11141 --remote 0.0.0.0:11141 --name "BlueMap"'
    )
    $playitHints = Join-Path $paths.FirstBoot 'playit-tunnels.txt'
    $playitCommands | Out-File -FilePath $playitHints -Encoding UTF8
    Write-Host "Lista komend Playit zapisana w $playitHints" -ForegroundColor Green

    Write-Section "Zadania i logi"
    $logRotateCommand = "Get-ChildItem '$($paths.Logs)' -Filter *.log | ForEach-Object { if ($_.Length -gt 10MB) { for($i=9;$i -ge 1;$i--) { $src = $_.FullName + '.' + $i; $dst = $_.FullName + '.' + ($i + 1); if (Test-Path $src) { Move-Item $src $dst -Force } } $backup = $_.FullName + '.1'; Move-Item $_.FullName $backup -Force } }"
    $logRotateTaskAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -Command `$ErrorActionPreference='Stop'; $logRotateCommand"
    $logRotateTaskTrigger = New-ScheduledTaskTrigger -Daily -At 3am
    Ensure-ScheduledTask -TaskName 'InfraLogRotate' -Action $logRotateTaskAction -Trigger $logRotateTaskTrigger -Description 'Rotacja logów infra'

    Write-Section "Zapis sekretów"
    $secretFile = Join-Path $paths.FirstBoot 'secrets.json'
    $secrets = @{
        AdminPanel = @{
            Username = $adminData.Username
            PasswordProtected = if ($adminPass) { Protect-Secret $adminPass } else { '<niezmienione>' }
        }
        RconPasswordProtected = Protect-Secret $rconPassword
    }
    Save-Json -Path $secretFile -Data $secrets
    icacls $secretFile /inheritance:r | Out-Null
    icacls $secretFile /grant:r 'Administrators:F' | Out-Null

    $recoveryFile = Join-Path $paths.FirstBoot 'recovery.txt'
    $recoveryLines = @()
    if ($adminPass) {
        $recoveryLines += "Sklep admin login: $($adminData.Username)"
        $recoveryLines += "Sklep admin hasło: $adminPass"
    }
    if ($rconPassword) {
        $recoveryLines += "RCON hasło: $rconPassword"
    }
    if ($recoveryLines.Count -gt 0) {
        $recoveryLines | Out-File -FilePath $recoveryFile -Encoding UTF8
        icacls $recoveryFile /inheritance:r | Out-Null
        icacls $recoveryFile /grant:r 'Administrators:F' | Out-Null
    }

    Write-Section "Uruchamianie usług"
    $services = @('CaddyReverseProxy','MeshCentral') | ForEach-Object { Get-Service -Name $_ -ErrorAction SilentlyContinue }
    foreach ($svc in $services) {
        if ($svc -and $svc.Status -ne 'Running') { Start-Service -Name $svc.Name }
    }

    Write-Section "Status końcowy"
    $status = [ordered]@{
        Caddy = (Get-Service -Name 'CaddyReverseProxy' -ErrorAction SilentlyContinue)?.Status
        MeshCentral = (Get-Service -Name 'MeshCentral' -ErrorAction SilentlyContinue)?.Status
        ShopPhpCgi = (Get-Service -Name 'ShopPhpCgi' -ErrorAction SilentlyContinue)?.Status
        Minecraft = (Get-ScheduledTask -TaskName 'Minecraft@Startup' -ErrorAction SilentlyContinue) ? 'ScheduledTask'
    }
    $status.GetEnumerator() | ForEach-Object { Write-Host ("{0,-12}: {1}" -f $_.Key, $_.Value) }

    $readyFlag = Join-Path $paths.FirstBoot 'READY.flag'
    'READY' | Out-File -FilePath $readyFlag -Encoding ASCII
    icacls $readyFlag /inheritance:r | Out-Null
    icacls $readyFlag /grant:r 'Administrators:F' | Out-Null

    $readyReport = @{
        Timestamp = (Get-Date).ToString('o')
        Endpoints = @{
            Portal = 'https://localhost:8443/'
            Desk = 'https://localhost:8443/desk'
            Shop = 'https://localhost:8443/shop'
            Map = 'https://localhost:8443/map'
        }
        Services = $status
    }
    Save-Json -Path (Join-Path $paths.FirstBoot 'ready-report.json') -Data $readyReport

    Write-Host "`nCo teraz:" -ForegroundColor Green
    Write-Host "1. Dokończ device-link w Playit i utwórz tunele:" -ForegroundColor Green
    Write-Host "   - 443 -> 8443 (HTTPS portal/sklep/desk)" -ForegroundColor Green
    Write-Host "   - 11131 -> 11131 (Minecraft)" -ForegroundColor Green
    Write-Host "   - 11141 -> 11141 (BlueMap)" -ForegroundColor Green
    Write-Host "2. Testuj lokalnie: https://localhost:8443/desk, /shop, /map (zaakceptuj ostrzeżenie TLS)" -ForegroundColor Green
    Write-Host "3. Skonfiguruj klucze PSP: C:\Infra\shop\configure-psp.ps1" -ForegroundColor Green
    Write-Host "4. Wykonaj test sandbox BLIK 1 PLN i potwierdź dostarczenie przedmiotu." -ForegroundColor Green
    Write-Host "5. Pamiętaj: certyfikat TLS od Caddy (tls internal) jest self-signed – przeglądarka pokaże ostrzeżenie do czasu podpięcia własnej domeny." -ForegroundColor Yellow

}
catch {
    Write-Error $_
    exit 1
}
