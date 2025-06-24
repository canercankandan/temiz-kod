# 🚀 Render.com Deployment Rehberi

Bu rehber, Su Arıtama Uzmanı uygulamasını Render.com'da yayınlamak için adım adım talimatları içerir.

## 📋 Ön Gereksinimler

1. **GitHub Hesabı**: Kodunuzu GitHub'da barındırmak için
2. **Render.com Hesabı**: Ücretsiz hesap oluşturun

## 🔧 Adım 1: GitHub Repository Oluşturun

1. **GitHub'da yeni repository oluşturun:**
   - Repository adı: `suaritamauzumani`
   - Public veya Private (ikisi de çalışır)
   - README.md eklemeyin (zaten var)

2. **Kodunuzu GitHub'a yükleyin:**
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   git remote add origin https://github.com/KULLANICI_ADINIZ/suaritamauzumani.git
   git push -u origin main
   ```

   **Not:** `KULLANICI_ADINIZ` yerine kendi GitHub kullanıcı adınızı yazın.

## 🌐 Adım 2: Render.com'da Deployment

### 2.1 Render.com'a Giriş
1. https://render.com adresine gidin
2. "Get Started for Free" butonuna tıklayın
3. GitHub ile giriş yapın

### 2.2 Web Service Oluşturun
1. Dashboard'da "New +" butonuna tıklayın
2. "Web Service" seçin
3. GitHub repository'nizi seçin (`suaritamauzumani`)

### 2.3 Deployment Ayarları
Render otomatik olarak `render.yaml` dosyasını algılayacak ve ayarları uygulayacak:

- **Name**: `suaritamauzumani`
- **Environment**: `Go`
- **Region**: `Frankfurt` (Türkiye'ye yakın)
- **Plan**: `Free`
- **Build Command**: `go build -o main cmd/web/main.go`
- **Start Command**: `./main`

### 2.4 Environment Variables (Opsiyonel)
Gerekirse şu environment variable'ları ekleyebilirsiniz:
- `PORT`: 8080 (otomatik ayarlanır)
- `GIN_MODE`: release
- `HOST`: 0.0.0.0

### 2.5 Deploy
1. "Create Web Service" butonuna tıklayın
2. Deployment başlayacak (2-3 dakika sürer)
3. Başarılı olursa yeşil "Live" durumu görünecek

## 🎯 Adım 3: Erişim

Deployment tamamlandıktan sonra:
- **URL**: `https://suaritamauzumani.onrender.com`
- **Admin Panel**: `https://suaritamauzumani.onrender.com/admin`
- **Canlı Destek**: `https://suaritamauzumani.onrender.com/support`

## ⚙️ Önemli Notlar

### SSL/HTTPS
- Render.com otomatik olarak SSL sertifikası sağlar
- Tüm bağlantılar HTTPS üzerinden olacak

### Dosya Sistemi
- Render.com'da dosya sistemi geçicidir
- `data.json` ve `orders.json` dosyaları her deployment'ta sıfırlanabilir
- Production için gerçek veritabanı kullanılması önerilir

### Free Plan Sınırları
- **750 saat/ay** çalışma süresi
- **Otomatik sleep**: 15 dakika boşta kalırsa uyur
- **Cold start**: İlk istekte 10-30 saniye gecikme olabilir

### Video Call Özelliği
- WebRTC HTTPS gerektirir
- Render.com otomatik HTTPS sağladığı için video call çalışacak

## 🔧 Güncelleme

Kod güncellemesi için:
1. Değişiklikleri GitHub'a push edin
2. Render otomatik olarak yeniden deploy edecek

## 🆘 Sorun Giderme

### Build Hatası
- `go.mod` dosyasındaki module adını kontrol edin
- Import path'lerin doğru olduğundan emin olun

### Runtime Hatası
- Render Dashboard'da "Logs" sekmesinden hata mesajlarını kontrol edin
- Environment variable'ların doğru ayarlandığından emin olun

### Dosya Yükleme Sorunu
- Template ve static dosyaların doğru konumda olduğundan emin olun
- `render.yaml` dosyasının doğru ayarlandığından emin olun

## 🎉 Tebrikler!

Uygulamanız artık canlı! Render.com'un avantajları:
- ✅ Ücretsiz HTTPS
- ✅ Otomatik deployment
- ✅ Global CDN
- ✅ Türkiye'ye yakın sunucu (Frankfurt)

## 📞 Destek

Herhangi bir sorun yaşarsanız:
1. Önce bu rehberi tekrar kontrol edin
2. Render.com documentation'ına bakın
3. GitHub Issues'da soru sorabilirsiniz 