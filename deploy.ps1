# Google Cloud Platform Deployment Script for Windows
# Cenap Water Filters - Go Web Application

Write-Host "🚀 Cenap Water Filters - Google Cloud Platform Deployment" -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Green

# 1. Google Cloud SDK kontrolü
try {
    $gcloudVersion = gcloud version --format="value(version)" 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "Google Cloud SDK bulunamadı"
    }
    Write-Host "✅ Google Cloud SDK bulundu: $gcloudVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Google Cloud SDK bulunamadı!" -ForegroundColor Red
    Write-Host "📥 Lütfen Google Cloud SDK'yı indirin: https://cloud.google.com/sdk/docs/install" -ForegroundColor Yellow
    exit 1
}

# 2. Proje ID'sini ayarla (kendi proje ID'nizi buraya yazın)
$PROJECT_ID = "cenap-water-filters"
Write-Host "📋 Proje ID: $PROJECT_ID" -ForegroundColor Cyan

# 3. Google Cloud projesini ayarla
Write-Host "🔧 Google Cloud projesi ayarlanıyor..." -ForegroundColor Yellow
gcloud config set project $PROJECT_ID

# 4. Gerekli API'leri etkinleştir
Write-Host "🔌 Gerekli API'ler etkinleştiriliyor..." -ForegroundColor Yellow
gcloud services enable appengine.googleapis.com
gcloud services enable cloudbuild.googleapis.com

# 5. App Engine uygulamasını deploy et
Write-Host "📦 Uygulama deploy ediliyor..." -ForegroundColor Yellow
gcloud app deploy app.yaml --quiet

# 6. Deployment sonucunu kontrol et
if ($LASTEXITCODE -eq 0) {
    Write-Host "✅ Deployment başarılı!" -ForegroundColor Green
    Write-Host "🌐 Uygulama URL'si: https://$PROJECT_ID.appspot.com" -ForegroundColor Cyan
    Write-Host "📊 App Engine Dashboard: https://console.cloud.google.com/appengine?project=$PROJECT_ID" -ForegroundColor Cyan
} else {
    Write-Host "❌ Deployment başarısız!" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "🎉 Cenap Water Filters başarıyla yayınlandı!" -ForegroundColor Green
Write-Host "📱 Mobil uygulama için QR kod: https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=https://$PROJECT_ID.appspot.com" -ForegroundColor Cyan 