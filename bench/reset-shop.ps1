# Restore the Juice Shop instance to its seed data before a bench run.
#
# A scan writes records: reviews, feedback, complaints, registered accounts,
# a stored login IP. The application reads those back, so a second run measures
# a database the first run left behind. Deleting the SQLite file makes the
# server rebuild it from its seed data on the next start, which is the only
# state the bench is defined against.
#
# Usage:
#   powershell -File bench/reset-shop.ps1
#   powershell -File bench/reset-shop.ps1 -App "D:\path\to\juice-shop"
param(
    [string]$App = "D:\home\modal\hacking\juiceshop-run\juice-shop_20.3.0"
)

$db = Join-Path $App "data\juiceshop.sqlite"
if (-not (Test-Path $App)) {
    Write-Error "Juice Shop source not found at $App"
    exit 1
}

# Stop only the server started from this directory, never another node process.
Get-CimInstance Win32_Process -Filter "Name='node.exe'" |
    Where-Object { $_.CommandLine -match 'build[/\\]app\.js' } |
    ForEach-Object {
        Write-Host "stopping node $($_.ProcessId)"
        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
    }
Start-Sleep -Seconds 2

if (Test-Path $db) {
    Remove-Item $db -Force
    Write-Host "removed $db; the next start rebuilds it from seed data"
} else {
    Write-Host "no database at $db; the next start creates it from seed data"
}
