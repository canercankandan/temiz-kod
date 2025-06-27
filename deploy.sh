#!/bin/bash

# Google Cloud Platform Deployment Script
# Cenap Water Filters - Go Web Application

echo "🚀 Cenap Water Filters - Google Cloud Platform Deployment"
echo "========================================================"

# 1. Google Cloud SDK kontrolü
if ! command -v gcloud &> /dev/null; then
    echo "❌ Google Cloud SDK bulunamadı!"
    echo "📥 Lütfen Google Cloud SDK'yı indirin: https://cloud.google.com/sdk/docs/install"
    exit 1
fi

# 2. Proje ID'sini ayarla (kendi proje ID'nizi buraya yazın)
PROJECT_ID="cenap-water-filters"
echo "📋 Proje ID: $PROJECT_ID"

# 3. Google Cloud projesini ayarla
echo "🔧 Google Cloud projesi ayarlanıyor..."
gcloud config set project $PROJECT_ID

# 4. Gerekli API'leri etkinleştir
echo "🔌 Gerekli API'ler etkinleştiriliyor..."
gcloud services enable appengine.googleapis.com
gcloud services enable cloudbuild.googleapis.com

# 5. App Engine uygulamasını deploy et
echo "📦 Uygulama deploy ediliyor..."
gcloud app deploy app.yaml --quiet

# 6. Deployment sonucunu kontrol et
if [ $? -eq 0 ]; then
    echo "✅ Deployment başarılı!"
    echo "🌐 Uygulama URL'si: https://$PROJECT_ID.appspot.com"
    echo "📊 App Engine Dashboard: https://console.cloud.google.com/appengine?project=$PROJECT_ID"
else
    echo "❌ Deployment başarısız!"
    exit 1
fi

echo ""
echo "🎉 Cenap Water Filters başarıyla yayınlandı!"
echo "📱 Mobil uygulama için QR kod: https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=https://$PROJECT_ID.appspot.com" 