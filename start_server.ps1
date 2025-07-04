Write-Host "Su Aritma Uzmani Server baslatiliyor..." -ForegroundColor Green
Write-Host ""
Write-Host "Ana sayfa: http://localhost:4505" -ForegroundColor Cyan
Write-Host "Admin paneli: http://localhost:4505/admin" -ForegroundColor Cyan
Write-Host ""
Write-Host "Server'i durdurmak icin Ctrl+C tuslayabilirsin." -ForegroundColor Yellow
Write-Host ""

# Server'i baslat
.\main.exe

# Kullanici Enter'a basana kadar bekle
Read-Host "Cikmak icin Enter'a bas" 