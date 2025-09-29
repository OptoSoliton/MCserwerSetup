<#
    Automatyczna konfiguracja środowiska Minecraft + WWW + MeshCentral + Sklep BLIK (wariant B)
    System docelowy: Windows 10 Pro (Administrator).
    Skrypt jest idempotentny i może być uruchamiany wielokrotnie.
#>

[CmdletBinding()]
param(
    [switch]$SkipDeviceLink
)

$ErrorActionPreference = 'Stop'

### Funkcje pomocnicze #########################################################

function Write-Section {
    param([string]$Title)
    Write-Host "`n### $Title" -ForegroundColor Cyan
}

function Ensure-Directory {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -ItemType Directory | Out-Null
    }
}

function Download-IfMissing {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$Destination,
        [string]$Description = 'Pobieranie'
    )

    if (Test-Path -LiteralPath $Destination) {
        Write-Host "[OK] Plik już istnieje: $Destination" -ForegroundColor DarkGreen
        return
    }

    Write-Host "[INFO] $Description" -ForegroundColor Yellow
    $temp = [System.IO.Path]::GetTempFileName()
    try {
        Invoke-WebRequest -Uri $Uri -OutFile $temp -UseBasicParsing
        Ensure-Directory ([System.IO.Path]::GetDirectoryName($Destination))
        Move-Item -Path $temp -Destination $Destination -Force
    }
    catch {
        Remove-Item -LiteralPath $temp -ErrorAction SilentlyContinue
        throw
    }
}

function Ensure-FirewallRule {
    param(
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][ValidateSet('Allow','Block')][string]$Action,
        [Parameter(Mandatory)][ValidateSet('Inbound','Outbound')][string]$Direction,
        [string]$Protocol = 'TCP',
        [string]$LocalPort = $null
    )

    $existing = Get-NetFirewallRule -DisplayName $DisplayName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "[FW] Reguła istnieje: $DisplayName" -ForegroundColor DarkGreen
    }
    else {
        Write-Host "[FW] Tworzę regułę: $DisplayName" -ForegroundColor Yellow
        $params = @{ DisplayName = $DisplayName; Direction = $Direction; Action = $Action; Profile = 'Any'; Protocol = $Protocol }
        if ($LocalPort) { $params['LocalPort'] = $LocalPort }
        New-NetFirewallRule @params | Out-Null
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
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
    Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -RunLevel Highest -Description $Description -Force | Out-Null
    Write-Host "[TASK] Upewniono się, że zadanie $TaskName istnieje" -ForegroundColor DarkGreen
}

function Ensure-Nssm {
    param([string]$BinFolder)
    $nssmExe = Join-Path $BinFolder 'nssm.exe'
    if (Test-Path -LiteralPath $nssmExe) { return $nssmExe }

    Download-IfMissing -Uri 'https://nssm.cc/release/nssm-2.24.zip' -Destination (Join-Path $env:TEMP 'nssm.zip') -Description 'Pobieranie NSSM'
    $zip = Join-Path $env:TEMP 'nssm.zip'
    $extract = Join-Path $env:TEMP 'nssm-2.24'
    if (Test-Path $extract) { Remove-Item -Path $extract -Recurse -Force }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zip, $extract)
    $source = Get-ChildItem -Path $extract -Recurse -Filter 'nssm.exe' | Where-Object { $_.FullName -like '*win64*' } | Select-Object -First 1
    if (-not $source) { throw 'Nie znaleziono nssm.exe w archiwum.' }
    Ensure-Directory $BinFolder
    Copy-Item -Path $source.FullName -Destination $nssmExe -Force
    return $nssmExe
}

function Ensure-ServiceOrTask {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][string]$Executable,
        [string]$Arguments = '',
        [string]$WorkingDirectory = '',
        [string]$StdOutLog = '',
        [string]$StdErrLog = '',
        [string]$FallbackTaskName = '',
        [string]$Description = ''
    )

    $nssmExe = $null
    try {
        $nssmExe = Ensure-Nssm -BinFolder 'C:\Infra\bin'
    }
    catch {
        Write-Warning "NSSM nie jest dostępny: $_"
    }

    if ($nssmExe) {
        $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($service) {
            & $nssmExe stop $Name | Out-Null
            & $nssmExe remove $Name confirm | Out-Null
        }
        $args = @($Name, $Executable)
        if ($Arguments) { $args += $Arguments }
        & $nssmExe install @args | Out-Null
        if ($WorkingDirectory) { & $nssmExe set $Name AppDirectory $WorkingDirectory | Out-Null }
        if ($StdOutLog) { & $nssmExe set $Name AppStdout $StdOutLog | Out-Null }
        if ($StdErrLog) { & $nssmExe set $Name AppStderr $StdErrLog | Out-Null }
        & $nssmExe set $Name Start SERVICE_AUTO_START | Out-Null
        Start-Service -Name $Name -ErrorAction SilentlyContinue
        Write-Host "[SVC] Zapewniono usługę $Name" -ForegroundColor DarkGreen
        return 'service'
    }

    if (-not $FallbackTaskName) { $FallbackTaskName = $Name }
    $action = New-ScheduledTaskAction -Execute $Executable -Argument $Arguments -WorkingDirectory $WorkingDirectory
    $trigger = New-ScheduledTaskTrigger -AtStartup
    Ensure-ScheduledTask -TaskName $FallbackTaskName -Action $action -Trigger $trigger -Description $Description
    return 'task'
}

function Generate-Secret {
    param([int]$Length = 32)
    $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+'
    $bytes = New-Object byte[] $Length
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    ($bytes | ForEach-Object { $chars[ $_ % $chars.Length ] }) -join ''
}

function Protect-Secret {
    param([Parameter(Mandatory)][string]$Secret)
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Secret)
    $encrypted = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
    [Convert]::ToBase64String($encrypted)
}

function Mask-Secret {
    param([string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return '<brak>' }
    if ($Value.Length -le 4) { return ('*' * $Value.Length) }
    return ('*' * ($Value.Length - 4)) + $Value.Substring($Value.Length - 4)
}

function Initialize-LogRotation {
    param([string]$BinFolder, [string]$LogFolder)
    $scriptPath = Join-Path $BinFolder 'Rotate-Logs.ps1'
    $content = @'
param(
    [string]$TargetFolder = "C:\Infra\logs",
    [int]$MaxSizeMB = 10,
    [int]$MaxFiles = 10
)

Get-ChildItem -Path $TargetFolder -File -Filter '*.log' | ForEach-Object {
    if ($_.Length -gt ($MaxSizeMB * 1MB)) {
        for ($i = $MaxFiles - 1; $i -ge 1; $i--) {
            $older = "$($_.FullName).$i"
            $newer = "$($_.FullName).$($i + 1)"
            if (Test-Path $older) { Move-Item -Path $older -Destination $newer -Force }
        }
        $firstArchive = "$($_.FullName).1"
        Move-Item -Path $_.FullName -Destination $firstArchive -Force
        New-Item -Path $_.FullName -ItemType File | Out-Null
    }
}
'@
    $content | Out-File -FilePath $scriptPath -Encoding UTF8

    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`""
    $trigger = New-ScheduledTaskTrigger -Daily -At 3:00AM
    Ensure-ScheduledTask -TaskName 'InfraLogRotate' -Action $action -Trigger $trigger -Description 'Rotacja logów infra'
}

function Ensure-PhpIni {
    param([string]$PhpRoot)
    $iniPath = Join-Path $PhpRoot 'php.ini'
    if (-not (Test-Path -LiteralPath $iniPath)) {
        Copy-Item -Path (Join-Path $PhpRoot 'php.ini-production') -Destination $iniPath -Force
    }
    $ini = Get-Content -Path $iniPath
    $ini = $ini | Where-Object { $_ -notmatch '^extension_dir' -and $_ -notmatch '^extension\s*=\s*sqlite3' -and $_ -notmatch '^extension\s*=\s*pdo_sqlite' }
    $ini += 'extension_dir = "ext"'
    $ini += 'extension = sqlite3'
    $ini += 'extension = pdo_sqlite'
    $ini | Set-Content -Path $iniPath -Encoding UTF8
}

function Initialize-SqliteSchema {
    param([string]$PhpExe, [string]$ShopRoot)
    $schema = @'
<?php
$database = new SQLite3(__DIR__ . '/../data/shop.sqlite');
$database->exec('CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, price INTEGER NOT NULL, command TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)');
$database->exec('CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY AUTOINCREMENT, order_id TEXT NOT NULL, player TEXT NOT NULL, product_id INTEGER NOT NULL, status TEXT NOT NULL, provider TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)');
$database->exec('CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, context TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)');
?>
'@
    $schemaPath = Join-Path $ShopRoot 'bin\init-db.php'
    $schema | Out-File -FilePath $schemaPath -Encoding UTF8
    & $PhpExe $schemaPath
    Remove-Item -LiteralPath $schemaPath -Force -ErrorAction SilentlyContinue
}

function Ensure-AclAdministratorsOnly {
    param([string]$Path)
    icacls $Path /inheritance:r | Out-Null
    icacls $Path /grant:r 'Administrators:(R,W)' | Out-Null
}

function Ensure-ServerPropertiesRcon {
    param([string]$ServerDir)
    $propertiesPath = Join-Path $ServerDir 'server.properties'
    if (-not (Test-Path -LiteralPath $propertiesPath)) {
        throw "Brak pliku $propertiesPath"
    }
    $content = Get-Content -Path $propertiesPath -Raw
    $content = [System.Text.RegularExpressions.Regex]::Replace($content, '^enable-rcon\s*=.*$', 'enable-rcon=true', [System.Text.RegularExpressions.RegexOptions]::Multiline)
    if ($content -notmatch 'enable-rcon=') {
        $content += "`nenable-rcon=true"
    }
    $rconPassword = $null
    if ($content -match '^rcon.password\s*=([^\r\n]+)') {
        $rconPassword = $Matches[1]
    }
    if (-not $rconPassword -or $rconPassword.Trim() -eq '') {
        $rconPassword = Generate-Secret -Length 24
        if ($content -match '^rcon.password=') {
            $content = [System.Text.RegularExpressions.Regex]::Replace($content, '^rcon.password\s*=.*$', "rcon.password=$rconPassword", [System.Text.RegularExpressions.RegexOptions]::Multiline)
        }
        else {
            $content += "`nrcon.password=$rconPassword"
        }
    }
    if ($content -match '^rcon.port=') {
        $content = [System.Text.RegularExpressions.Regex]::Replace($content, '^rcon.port\s*=.*$', 'rcon.port=25575', [System.Text.RegularExpressions.RegexOptions]::Multiline)
    }
    else {
        $content += "`nrcon.port=25575"
    }
    Set-Content -Path $propertiesPath -Value $content -Encoding UTF8
    return $rconPassword
}

function Ensure-StartServerBat {
    param([string]$ServerDir)
    $batPath = Join-Path $ServerDir 'start-server.bat'
    if (-not (Test-Path -LiteralPath $batPath)) {
        @'
@echo off
cd /d "C:\SERWER"
"C:\Program Files\Microsoft\jdk-21.0.8.9-hotspot\bin\java.exe" -Xms128M -XX:MaxRAMPercentage=95.0 -Dterminal.jline=false -Dterminal.ansi=true -jar server.jar
'@ | Out-File -FilePath $batPath -Encoding ASCII
    }
    return $batPath
}

function Register-MinecraftStartup {
    param([string]$BatPath)
    $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument "/c `"$BatPath`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    Ensure-ScheduledTask -TaskName 'Minecraft@Startup' -Action $action -Trigger $trigger -Description 'Uruchamianie serwera Minecraft'
}

### Walidacja uprawnień ########################################################

Write-Section 'Walidacja uprawnień'
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error 'Skrypt musi być uruchomiony jako Administrator.'
    exit 1
}
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

### Katalogi ###################################################################

Write-Section 'Przygotowanie katalogów'
$paths = [ordered]@{
    Infra      = 'C:\Infra'
    Caddy      = 'C:\Infra\caddy'
    Mesh       = 'C:\Infra\meshcentral'
    PHP        = 'C:\Infra\php'
    Shop       = 'C:\Infra\shop'
    ShopPublic = 'C:\Infra\shop\public'
    ShopConfig = 'C:\Infra\shop\config'
    ShopData   = 'C:\Infra\shop\data'
    ShopBin    = 'C:\Infra\shop\bin'
    ShopAdmin  = 'C:\Infra\shop\admin'
    Logs       = 'C:\Infra\logs'
    Bin        = 'C:\Infra\bin'
    FirstBoot  = 'C:\Infra\firstboot'
}
$paths.Values | ForEach-Object { Ensure-Directory $_ }
Initialize-LogRotation -BinFolder $paths.Bin -LogFolder $paths.Logs
$script:GeneratedShopAdminPassword = $null

Write-Section 'Weryfikacja środowiska Java i plików serwera'
$javaOk = $false
try {
    & java -version 2>$null
    if ($LASTEXITCODE -eq 0) {
        $javaOk = $true
        Write-Host '[OK] java -version zwróciło kod 0' -ForegroundColor DarkGreen
    }
}
catch {
    $javaOk = $false
}
if (-not $javaOk) {
    Write-Warning 'Nie wykryto poprawnej instalacji Java. Zainstaluj JDK 21 lub popraw JAVA_HOME.'
}
$serverJar = 'C:\SERWER\server.jar'
if (-not (Test-Path -LiteralPath $serverJar)) {
    Write-Warning "Brak pliku $serverJar"
}

### Zapora #####################################################################

Write-Section 'Konfiguracja zapory'
Ensure-FirewallRule -DisplayName 'Allow Portal HTTP 8080' -Action Allow -Direction Inbound -LocalPort 8080
Ensure-FirewallRule -DisplayName 'Allow Minecraft 11131' -Action Allow -Direction Inbound -LocalPort 11131
Ensure-FirewallRule -DisplayName 'Allow BlueMap 11141' -Action Allow -Direction Inbound -LocalPort 11141
Ensure-FirewallRule -DisplayName 'Block RDP 3389' -Action Block -Direction Inbound -LocalPort 3389

### Caddy ######################################################################

Write-Section 'Caddy - reverse proxy'
$caddyExe = Join-Path $paths.Caddy 'caddy.exe'
Download-IfMissing -Uri 'https://caddyserver.com/api/download?os=windows&arch=amd64' -Destination $caddyExe -Description 'Pobieranie Caddy'

$caddyFile = Join-Path $paths.Caddy 'Caddyfile'
$caddyConfig = @'
:8080 {
    encode gzip
    handle_path /shop* {
        reverse_proxy 127.0.0.1:8081
    }
    handle_path /desk* {
        header Cache-Control "no-store"
        reverse_proxy https://127.0.0.1:4430 {
            transport http {
                tls_insecure_skip_verify
            }
        }
    }
    handle_path /map* {
        reverse_proxy 127.0.0.1:11141
    }
    route / {
        respond "OK" 200
    }
}
'@
$caddyConfig | Out-File -FilePath $caddyFile -Encoding UTF8

$caddyLog = Join-Path $paths.Logs 'caddy.log'
$serviceMode = Ensure-ServiceOrTask -Name 'CaddyReverseProxy' -DisplayName 'Caddy Reverse Proxy' -Executable $caddyExe -Arguments "run --config `"$caddyFile`"" -WorkingDirectory $paths.Caddy -StdOutLog $caddyLog -StdErrLog $caddyLog -FallbackTaskName 'Caddy@Startup' -Description 'Reverse proxy Minecraft infra'
if ($serviceMode -eq 'task') {
    Start-ScheduledTask -TaskName 'Caddy@Startup' -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
}

### Node.js & MeshCentral ######################################################

Write-Section 'Node.js i MeshCentral'
$nodeInstalled = $false
try {
    $nodeVersion = (& node -v) 2>$null
    if ($LASTEXITCODE -eq 0) { $nodeInstalled = $true }
}
catch { $nodeInstalled = $false }

if (-not $nodeInstalled) {
    $nodeMsi = Join-Path $env:TEMP 'node-v20.11.1-x64.msi'
    Download-IfMissing -Uri 'https://nodejs.org/dist/v20.11.1/node-v20.11.1-x64.msi' -Destination $nodeMsi -Description 'Pobieranie Node.js LTS'
    Write-Host '[INFO] Instalacja Node.js...' -ForegroundColor Yellow
    Start-Process msiexec.exe -ArgumentList "/i `"$nodeMsi`" /qn" -Wait
}

$env:Path = "C:\Program Files\nodejs;$($env:Path)"

$meshModules = Join-Path $paths.Mesh 'node_modules'
if (-not (Test-Path -LiteralPath $meshModules)) {
    Push-Location $paths.Mesh
    try {
        npm install meshcentral --save | Out-Null
    }
    finally {
        Pop-Location
    }
}

$meshData = Join-Path $paths.Mesh 'meshcentral-data'
Ensure-Directory $meshData
$meshConfigPath = Join-Path $meshData 'config.json'
if (-not (Test-Path -LiteralPath $meshConfigPath)) {
    $meshConfig = @{
        settings = @{
            port = 4430
            redirport = 0
            allowlegacywebsocket = true
            agentpong = true
        }
        domains = @{
            '' = @{
                title = 'Minecraft Desk'
                title2 = 'MeshCentral'
                userNameIsEmail = $false
                auth = @{ mfa = 1 }
            }
        }
    }
    ($meshConfig | ConvertTo-Json -Depth 4) | Out-File -FilePath $meshConfigPath -Encoding UTF8
}

$meshLog = Join-Path $paths.Logs 'meshcentral.log'
$nodeExe = (Get-Command node -ErrorAction Stop).Source
$meshServiceMode = Ensure-ServiceOrTask -Name 'MeshCentral' -DisplayName 'MeshCentral' -Executable $nodeExe -Arguments "`"$paths.Mesh\node_modules\meshcentral\meshcentral.js`" --launch 1" -WorkingDirectory $paths.Mesh -StdOutLog $meshLog -StdErrLog $meshLog -FallbackTaskName 'MeshCentral@Startup' -Description 'MeshCentral serwer'
if ($meshServiceMode -eq 'task') {
    Start-ScheduledTask -TaskName 'MeshCentral@Startup' -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
}

### PHP i sklep ###############################################################

Write-Section 'PHP i sklep'
$phpZip = Join-Path $env:TEMP 'php-8.3.6-nts-Win32-vs16-x64.zip'
Download-IfMissing -Uri 'https://windows.php.net/downloads/releases/php-8.3.6-nts-Win32-vs16-x64.zip' -Destination $phpZip -Description 'Pobieranie PHP 8.3 NTS'
if (-not (Test-Path -LiteralPath (Join-Path $paths.PHP 'php.exe'))) {
    if (Test-Path $paths.PHP) {
        Get-ChildItem -Path $paths.PHP -Recurse -Force | Remove-Item -Force -Recurse
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($phpZip, $paths.PHP)
}

Ensure-PhpIni -PhpRoot $paths.PHP
$env:Path = "$($paths.PHP);$env:Path"

Ensure-Directory $paths.ShopPublic
Ensure-Directory $paths.ShopConfig
Ensure-Directory $paths.ShopData
Ensure-Directory $paths.ShopBin
Ensure-Directory $paths.ShopAdmin

# Pliki sklepu
$indexPhp = @'
<?php
require_once __DIR__ . '/../config/shop.config.php';
$products = include __DIR__ . '/../config/products.php';
?>
<!DOCTYPE html>
<html lang="pl">
<head>
    <meta charset="utf-8">
    <title>Minecraft Shop</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 720px; margin: 0 auto; padding: 20px; }
        header { text-align: center; }
        .product { border: 1px solid #ccc; padding: 12px; margin: 12px 0; }
    </style>
</head>
<body>
<header>
    <h1>Sklep BLIK</h1>
    <p>Wybierz produkt, podaj nick i potwierdź płatność.</p>
</header>
<section>
    <?php foreach ($products as $product): ?>
        <div class="product">
            <h2><?= htmlspecialchars($product['name']) ?> — <?= number_format($product['price'] / 100, 2) ?> PLN</h2>
            <form method="post" action="/shop/webhook.php?action=create">
                <input type="hidden" name="product_id" value="<?= (int)$product['id'] ?>">
                <label>Nick gracza <input required name="player" pattern="[A-Za-z0-9_]{3,16}"></label>
                <button type="submit">Kup teraz</button>
            </form>
        </div>
    <?php endforeach; ?>
</section>
<footer>
    <p>Po opłaceniu zamówienia przedmiot zostanie dostarczony automatycznie.</p>
</footer>
</body>
</html>
'@
$indexPhp | Out-File -FilePath (Join-Path $paths.ShopPublic 'index.php') -Encoding UTF8

$webhookPhp = @'
<?php
require_once __DIR__ . '/../config/shop.config.php';
require_once __DIR__ . '/../bin/helpers.php';
$databasePath = __DIR__ . '/../data/shop.sqlite';
$db = new SQLite3($databasePath);
$action = $_GET['action'] ?? 'notify';
if ($action === 'create') {
    $productId = (int)($_POST['product_id'] ?? 0);
    $player = trim($_POST['player'] ?? '');
    if (!$productId || !$player) {
        http_response_code(400);
        echo 'Brak danych';
        exit;
    }
    $products = include __DIR__ . '/../config/products.php';
    if (!isset($products[$productId])) {
        http_response_code(404);
        echo 'Produkt nie istnieje';
        exit;
    }
    $orderId = 'ORD-' . bin2hex(random_bytes(6));
    $stmt = $db->prepare('INSERT INTO orders(order_id, player, product_id, status, provider) VALUES (:id, :player, :pid, :status, :provider)');
    $stmt->bindValue(':id', $orderId, SQLITE3_TEXT);
    $stmt->bindValue(':player', $player, SQLITE3_TEXT);
    $stmt->bindValue(':pid', $productId, SQLITE3_INTEGER);
    $stmt->bindValue(':status', 'PENDING', SQLITE3_TEXT);
    $stmt->bindValue(':provider', PSP_PROVIDER, SQLITE3_TEXT);
    $stmt->execute();
    echo "Zamówienie utworzone. ID: $orderId";
    exit;
}
$payload = file_get_contents('php://input');
$signature = $_SERVER['HTTP_X_SIGNATURE'] ?? '';
if (!verify_signature($payload, $signature)) {
    http_response_code(403);
    echo 'Błędny podpis';
    exit;
}
$data = json_decode($payload, true);
if (!is_array($data)) {
    http_response_code(400);
    echo 'Błędne dane';
    exit;
}
$orderId = $data['order_id'] ?? '';
$status = $data['status'] ?? '';
if ($status !== 'PAID') {
    http_response_code(200);
    echo 'IGNORED';
    exit;
}
$stmt = $db->prepare('SELECT orders.id, orders.player, orders.status, products.command FROM orders JOIN products ON orders.product_id = products.id WHERE orders.order_id = :id');
$stmt->bindValue(':id', $orderId, SQLITE3_TEXT);
$result = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
if (!$result) {
    http_response_code(404);
    echo 'Zlecenie nie istnieje';
    exit;
}
if ($result['status'] === 'COMPLETED') {
    echo 'OK';
    exit;
}
$deliverScript = __DIR__ . '/../bin/deliver.ps1';
$psArg = function ($value) {
    return "\"" . str_replace("\"", "\\\"", $value) . "\"";
};
$cmd = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File ' . $psArg($deliverScript) . ' -Player ' . $psArg($result['player']) . ' -CommandTemplate ' . $psArg($result['command']) . ' -OrderId ' . $psArg($orderId);
exec($cmd, $output, $code);
if ($code !== 0) {
    $db->exec("INSERT INTO audit(context, payload) VALUES('deliver-error', '" . SQLite3::escapeString(json_encode($output)) . "')");
    http_response_code(500);
    echo 'Błąd dostawy';
    exit;
}
$db->exec("UPDATE orders SET status='COMPLETED', updated_at=CURRENT_TIMESTAMP WHERE order_id='" . SQLite3::escapeString($orderId) . "'");
http_response_code(200);
$db->exec("INSERT INTO audit(context, payload) VALUES('deliver-ok', '" . SQLite3::escapeString($orderId) . "')");
echo 'OK';
'@
$webhookPhp | Out-File -FilePath (Join-Path $paths.ShopPublic 'webhook.php') -Encoding UTF8

$helpersPhp = @'
<?php
require_once __DIR__ . '/../config/shop.config.php';
function get_secrets() {
    $raw = file_get_contents(__DIR__ . '/../config/shop.config.secure.json');
    return json_decode($raw, true);
}
function verify_signature($payload, $signature) {
    $secrets = get_secrets();
    $key = base64_decode($secrets['webhook_secret']);
    $calc = base64_encode(hash_hmac('sha256', $payload, $key, true));
    return hash_equals($calc, $signature);
}
'@
$helpersPhp | Out-File -FilePath (Join-Path $paths.ShopBin 'helpers.php') -Encoding UTF8

$adminPhp = @'
<?php
require_once __DIR__ . '/../config/shop.config.php';
$secrets = json_decode(file_get_contents(__DIR__ . '/../config/shop.config.secure.json'), true);
$auth = $_SERVER['PHP_AUTH_USER'] ?? '';
$pass = $_SERVER['PHP_AUTH_PW'] ?? '';
if (!hash_equals($secrets['admin_user'], $auth) || !password_verify($pass, $secrets['admin_pass_hash'])) {
    header('WWW-Authenticate: Basic realm="Shop Admin"');
    http_response_code(401);
    echo 'Auth required';
    exit;
}
$products = include __DIR__ . '/../config/products.php';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $name = trim($_POST['name'] ?? '');
    $price = (int)($_POST['price'] ?? 0);
    $command = trim($_POST['command'] ?? '');
    if ($name && $price > 0 && $command) {
        $db = new SQLite3(__DIR__ . '/../data/shop.sqlite');
        $stmt = $db->prepare('INSERT INTO products(name, price, command) VALUES (:name, :price, :command)');
        $stmt->bindValue(':name', $name, SQLITE3_TEXT);
        $stmt->bindValue(':price', $price, SQLITE3_INTEGER);
        $stmt->bindValue(':command', $command, SQLITE3_TEXT);
        $stmt->execute();
        header('Location: /shop/admin/index.php');
        exit;
    }
}
?>
<!DOCTYPE html>
<html lang="pl">
<head>
    <meta charset="utf-8">
    <title>Admin sklepu</title>
</head>
<body>
<h1>Panel administracyjny</h1>
<form method="post">
    <label>Nazwa <input name="name" required></label><br>
    <label>Cena (grosze) <input name="price" type="number" min="100" required></label><br>
    <label>Komenda RCON <input name="command" required></label><br>
    <button type="submit">Dodaj produkt</button>
</form>
<h2>Aktualne produkty</h2>
<ul>
    <?php foreach ($products as $product): ?>
        <li><?= htmlspecialchars($product['name']) ?> — <?= number_format($product['price']/100, 2) ?> PLN</li>
    <?php endforeach; ?>
</ul>
</body>
</html>
'@
$adminPhp | Out-File -FilePath (Join-Path $paths.ShopAdmin 'index.php') -Encoding UTF8

$productsPhp = @'
<?php
return [
    1 => [ 'id' => 1, 'name' => 'Diamentowy Pakiet', 'price' => 500, 'command' => 'give %player% diamond 5' ],
];
'@
$productsPhp | Out-File -FilePath (Join-Path $paths.ShopConfig 'products.php') -Encoding UTF8

$configPhp = @'
<?php
$securePath = __DIR__ . '/shop.config.secure.json';
if (file_exists($securePath)) {
    $secure = json_decode(file_get_contents($securePath), true);
    define('PSP_PROVIDER', $secure['psp_provider'] ?? 'TPAY');
} else {
    define('PSP_PROVIDER', 'TPAY');
}
'@
$configPhp | Out-File -FilePath (Join-Path $paths.ShopConfig 'shop.config.php') -Encoding UTF8

$secureConfigPath = Join-Path $paths.ShopConfig 'shop.config.secure.json'
if (-not (Test-Path -LiteralPath $secureConfigPath)) {
    $adminUser = 'admin'
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$secretBytes = New-Object byte[] 32
$rng.GetBytes($secretBytes)
$webhookSecret = [Convert]::ToBase64String($secretBytes)
$adminPasswordPlain = Generate-Secret -Length 16
$phpExe = Join-Path $paths.PHP 'php.exe'
$escaped = $adminPasswordPlain -replace "'", "\\'"
$adminPasswordHash = (& $phpExe -r "echo password_hash('$escaped', PASSWORD_DEFAULT);").Trim()
$secure = [ordered]@{
    admin_user = $adminUser
    admin_pass_hash = $adminPasswordHash
    webhook_secret = $webhookSecret
    psp_provider = 'TPAY'
    psp_client_id = ''
    psp_client_secret = ''
}
($secure | ConvertTo-Json -Depth 3) | Out-File -FilePath $secureConfigPath -Encoding UTF8
Write-Host "[INFO] Dane logowania do panelu: $adminUser / $adminPasswordPlain" -ForegroundColor Yellow
$script:GeneratedShopAdminPassword = $adminPasswordPlain
}
Ensure-AclAdministratorsOnly -Path $secureConfigPath

$helpersPs1 = @'
param(
    [Parameter(Mandatory)][string]$Player,
    [Parameter(Mandatory)][string]$CommandTemplate,
    [string]$OrderId
)

$command = $CommandTemplate -replace '%player%', $Player
& "C:\Infra\shop\bin\rcon.ps1" -Command $command -OrderId $OrderId
'@
$helpersPs1 | Out-File -FilePath (Join-Path $paths.ShopBin 'deliver.ps1') -Encoding UTF8

$rconPs1 = @'
param(
    [Parameter(Mandatory)][string]$Command,
    [string]$OrderId
)

$serverProperties = 'C:\SERWER\server.properties'
if (-not (Test-Path -LiteralPath $serverProperties)) {
    throw "Brak pliku $serverProperties"
}
$content = Get-Content -Path $serverProperties
$passwordLine = $content | Where-Object { $_ -like 'rcon.password=*' }
if (-not $passwordLine) { throw 'Brak hasła RCON' }
$pass = $passwordLine.Split('=')[1]
$client = New-Object System.Net.Sockets.TcpClient('127.0.0.1', 25575)
$stream = $client.GetStream()

function Send-Packet {
    param($stream, [int]$Type, [string]$Body)
    $encoding = [System.Text.Encoding]::UTF8
    $payload = $encoding.GetBytes($Body)
    $length = [BitConverter]::GetBytes($payload.Length + 10)
    $id = [BitConverter]::GetBytes(1)
    $type = [BitConverter]::GetBytes($Type)
    $buffer = New-Object byte[] ($payload.Length + 14)
    $length.CopyTo($buffer, 0)
    $id.CopyTo($buffer, 4)
    $type.CopyTo($buffer, 8)
    $payload.CopyTo($buffer, 12)
    $buffer[$buffer.Length - 2] = 0
    $buffer[$buffer.Length - 1] = 0
    $stream.Write($buffer, 0, $buffer.Length)
    $stream.Flush()
}

Send-Packet -stream $stream -Type 3 -Body $pass
Send-Packet -stream $stream -Type 2 -Body $Command
$client.Close()
'@
$rconPs1 | Out-File -FilePath (Join-Path $paths.ShopBin 'rcon.ps1') -Encoding UTF8

$readme = @'
Sklep BLIK — pierwsze kroki (sandbox)
1. Uruchom playit.exe i dokończ device-link.
2. W panelu PSP ustaw webhook na https://twoj-host/shop/webhook.php.
3. Uruchom C:\Infra\shop\configure-psp.ps1 aby uzupełnić klucze merchanta.
4. Wygeneruj testową transakcję 1 PLN i sprawdź, czy gracz otrzymuje przedmiot.
'@
$readme | Out-File -FilePath (Join-Path $paths.Shop 'README-FIRST.txt') -Encoding UTF8

$configurePsp = @'
param()

$securePath = 'C:\Infra\shop\config\shop.config.secure.json'
if (-not (Test-Path -LiteralPath $securePath)) {
    throw "Brak pliku $securePath"
}
$data = Get-Content -Path $securePath | ConvertFrom-Json
$provider = Read-Host 'Wybierz PSP (TPAY/P24)'
if ($provider -notin @('TPAY','P24')) {
    Write-Host 'Błędny wybór.' -ForegroundColor Red
    exit 1
}
$data.psp_provider = $provider
$data.psp_client_id = Read-Host 'Wklej client_id'
$data.psp_client_secret = Read-Host 'Wklej client_secret'
$data.webhook_secret = Read-Host 'Wklej webhook_secret base64'
$data | ConvertTo-Json -Depth 3 | Out-File -FilePath $securePath -Encoding UTF8
Write-Host 'Zapisano.'
'@
$configurePsp | Out-File -FilePath (Join-Path $paths.Shop 'configure-psp.ps1') -Encoding UTF8

Initialize-SqliteSchema -PhpExe (Join-Path $paths.PHP 'php.exe') -ShopRoot $paths.Shop

# Start PHP serwera (scheduled task)
$phpArguments = "-S 127.0.0.1:8081 -t `"$($paths.ShopPublic)`""
$phpTaskAction = New-ScheduledTaskAction -Execute (Join-Path $paths.PHP 'php.exe') -Argument $phpArguments -WorkingDirectory $paths.Shop
$phpTaskTrigger = New-ScheduledTaskTrigger -AtStartup
Ensure-ScheduledTask -TaskName 'ShopService@Startup' -Action $phpTaskAction -Trigger $phpTaskTrigger -Description 'Serwer PHP sklepu'
Start-ScheduledTask -TaskName 'ShopService@Startup' -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

### Konfiguracja RCON i Minecraft #############################################

Write-Section 'Minecraft / RCON'
$serverDir = 'C:\SERWER'
if (-not (Test-Path -LiteralPath $serverDir)) {
    throw 'Brak katalogu C:\SERWER'
}
$rconPassword = Ensure-ServerPropertiesRcon -ServerDir $serverDir
$batPath = Ensure-StartServerBat -ServerDir $serverDir
Register-MinecraftStartup -BatPath $batPath
$eulaPath = Join-Path $serverDir 'eula.txt'
if (Test-Path -LiteralPath $eulaPath) {
    $eulaContent = Get-Content -Path $eulaPath -Raw
    if ($eulaContent -notmatch 'eula=') {
        $eulaContent += "`neula=true"
    }
    else {
        $eulaContent = [System.Text.RegularExpressions.Regex]::Replace($eulaContent, 'eula\s*=.*', 'eula=true')
    }
    Set-Content -Path $eulaPath -Value $eulaContent -Encoding UTF8
}
else {
    Set-Content -Path $eulaPath -Value 'eula=true' -Encoding UTF8
}

### Playit #####################################################################

Write-Section 'playit.gg'
$playitExe = Join-Path $paths.Bin 'playit.exe'
Download-IfMissing -Uri 'https://github.com/playit-cloud/playit-agent/releases/latest/download/playit.exe' -Destination $playitExe -Description 'Pobieranie playit.exe'
if (-not $SkipDeviceLink) {
    Write-Host 'Uruchamiam playit.exe (device-link)...' -ForegroundColor Yellow
    & $playitExe 'device-link'
}
Write-Host 'Połącz urządzenie w panelu Playit i dodaj tunele: 443->8080, 11131->11131, 11141->11141.' -ForegroundColor Yellow

### Sekrety ###################################################################

Write-Section 'Sekrety'
$secrets = [ordered]@{
    RconPassword = $rconPassword
}
if (Test-Path -LiteralPath $secureConfigPath) {
    $secureData = Get-Content -Path $secureConfigPath | ConvertFrom-Json
    $secrets.ShopAdminUser = $secureData.admin_user
    if ($script:GeneratedShopAdminPassword) {
        $secrets.ShopAdminPassword = $script:GeneratedShopAdminPassword
    }
}
$secretsPath = Join-Path $paths.FirstBoot 'secrets.json'
$protectedSecrets = [ordered]@{}
foreach ($entry in $secrets.GetEnumerator()) {
    if ([string]::IsNullOrEmpty($entry.Value)) { continue }
    $protectedSecrets[$entry.Key] = Protect-Secret -Secret $entry.Value
}
($protectedSecrets | ConvertTo-Json -Depth 3) | Out-File -FilePath $secretsPath -Encoding UTF8
Ensure-AclAdministratorsOnly -Path $secretsPath

### Testy końcowe #############################################################

Write-Section 'Testy końcowe'
$tests = @()
try {
    $resp = Invoke-WebRequest -Uri 'http://localhost:8080/' -UseBasicParsing -TimeoutSec 5
    $tests += [ordered]@{ name = 'Portal /'; status = ($resp.StatusCode -eq 200) }
}
catch { $tests += [ordered]@{ name = 'Portal /'; status = $false; message = $_.Exception.Message } }
try {
    $resp = Invoke-WebRequest -Uri 'http://localhost:8080/shop' -UseBasicParsing -TimeoutSec 5
    $tests += [ordered]@{ name = 'Portal /shop'; status = ($resp.StatusCode -eq 200) }
}
catch { $tests += [ordered]@{ name = 'Portal /shop'; status = $false; message = $_.Exception.Message } }
try {
    $resp = Invoke-WebRequest -Uri 'http://localhost:8080/map' -UseBasicParsing -TimeoutSec 5
    $tests += [ordered]@{ name = 'Portal /map'; status = ($resp.StatusCode -eq 200 -or $resp.StatusCode -eq 302) }
}
catch { $tests += [ordered]@{ name = 'Portal /map'; status = $false; message = $_.Exception.Message } }

### Raport ####################################################################

Write-Section 'Raport'
foreach ($test in $tests) {
    $symbol = if ($test.status) { '[OK]' } else { '[!!]' }
    Write-Host "$symbol $($test.name)" -ForegroundColor (if ($test.status) { 'DarkGreen' } else { 'Red' })
    if (-not $test.status -and $test.ContainsKey('message')) {
        Write-Host "    $($test.message)" -ForegroundColor DarkYellow
    }
}

Write-Host "`nCo dalej:" -ForegroundColor Cyan
Write-Host '1. Dokończ device-link playit i utwórz tunele: 443->8080, 11131->11131, 11141->11141.'
Write-Host '2. Wejdź lokalnie: http://localhost:8080/desk, /shop, /map.'
Write-Host '3. Uruchom C:\Infra\shop\configure-psp.ps1 i wklej dane merchanta.'
Write-Host '4. Przetestuj płatność sandbox (1 PLN) i sprawdź dostawę.'
Write-Host '5. Zaakceptuj EULA Minecraft jeżeli jeszcze tego nie zrobiłeś.'

Write-Host "`nRaport usług:" -ForegroundColor Cyan
foreach ($svc in 'CaddyReverseProxy','MeshCentral') {
    try {
        $service = Get-Service -Name $svc -ErrorAction Stop
        Write-Host "$($service.Name): $($service.Status)"
    }
    catch {
        Write-Host "$svc: brak usługi (sprawdź zadania harmonogramu)."
    }
}
Write-Host 'ShopService@Startup: zadanie w Harmonogramie zadań.'
Write-Host 'Minecraft@Startup: zadanie w Harmonogramie zadań.'

Write-Host "Sekrety zapisane w: $secretsPath (ACL tylko Administratorzy)." -ForegroundColor Yellow

Write-Host "Jeśli masz domenę, uruchom tryb ACME w Caddy — podmień blok TLS zgodnie z dokumentacją." -ForegroundColor Cyan

