# 🚀 Google Cloud Platform Deployment Rehberi

Bu rehber, Cenap Water Filters Go web uygulamanızı Google Cloud Platform'da yayınlamak için hazırlanmıştır.

## 📋 Ön Gereksinimler

1. **Google Cloud SDK** - [İndirme Linki](https://cloud.google.com/sdk/docs/install)
2. **Google Cloud Hesabı** - [Kayıt Ol](https://console.cloud.google.com/)
3. **Proje Oluşturma** - Google Cloud Console'da yeni proje oluşturun

## 🎯 Deployment Seçenekleri

### 1. Google App Engine (Önerilen)

**Avantajları:**
- Otomatik ölçeklendirme
- SSL sertifikası otomatik
- Yüksek performans
- Kolay deployment

**Deployment Adımları:**

1. **Proje ID'sini ayarlayın:**
   ```bash
   # deploy.sh dosyasında PROJECT_ID değişkenini güncelleyin
   PROJECT_ID="your-project-id"
   ```

2. **Google Cloud SDK ile giriş yapın:**
   ```bash
   gcloud auth login
   ```

3. **Deployment script'ini çalıştırın:**
   ```bash
   # Linux/Mac için
   chmod +x deploy.sh
   ./deploy.sh
   
   # Windows için
   .\deploy.ps1
   ```

### 2. Google Cloud Run

**Avantajları:**
- Container tabanlı
- Pay-per-use fiyatlandırma
- Hızlı deployment

**Deployment Adımları:**

1. **Cloud Build API'yi etkinleştirin:**
   ```bash
   gcloud services enable cloudbuild.googleapis.com
   gcloud services enable run.googleapis.com
   ```

2. **Cloud Build ile deploy edin:**
   ```bash
   gcloud builds submit --config cloudbuild.yaml
   ```

## 🔧 Konfigürasyon

### Environment Variables

`app.yaml` dosyasında SMTP ayarlarını güncelleyin:

```yaml
env_variables:
  SMTP_HOST: "smtp.gmail.com"
  SMTP_PORT: "587"
  SMTP_USER: "your-email@gmail.com"
  SMTP_PASS: "your-app-password"
```

### Gmail App Password

Gmail SMTP için App Password oluşturun:
1. Google Hesabınıza gidin
2. Güvenlik > 2 Adımlı Doğrulama > Uygulama Şifreleri
3. Yeni uygulama şifresi oluşturun

## 📊 Monitoring ve Logs

### App Engine Logs
```bash
gcloud app logs tail -s default
```

### Cloud Run Logs
```bash
gcloud logging read "resource.type=cloud_run_revision"
```

## 💰 Maliyet Optimizasyonu

### App Engine
- **F1 Instance**: $0.05/saat (yaklaşık $36/ay)
- **F2 Instance**: $0.10/saat (yaklaşık $72/ay)

### Cloud Run
- **Pay-per-use**: Sadece kullanıldığında ödeme
- **Minimum**: $0.00002400/100ms

## 🔒 Güvenlik

1. **Environment Variables**: Hassas bilgileri environment variables olarak saklayın
2. **HTTPS**: App Engine otomatik SSL sağlar
3. **Firewall**: Gerekirse Cloud Armor kullanın

## 🚨 Sorun Giderme

### Yaygın Hatalar

1. **"Permission denied"**
   ```bash
   gcloud auth application-default login
   ```

2. **"Project not found"**
   ```bash
   gcloud projects list
   gcloud config set project YOUR_PROJECT_ID
   ```

3. **"API not enabled"**
   ```bash
   gcloud services enable appengine.googleapis.com
   ```

### Log Kontrolü
```bash
gcloud app logs tail -s default --level=error
```

## 📱 Mobil Erişim

Deployment sonrası mobil erişim için:
- QR kod otomatik oluşturulur
- PWA özellikleri mevcuttur
- Responsive tasarım

## 🎉 Başarılı Deployment

Deployment başarılı olduğunda:
- ✅ Uygulama URL'si: `https://your-project-id.appspot.com`
- ✅ Admin paneli: `https://your-project-id.appspot.com/admin`
- ✅ Mobil QR kod otomatik oluşturulur

## 📞 Destek

Sorun yaşarsanız:
1. Google Cloud Console'da logs kontrol edin
2. `gcloud app logs tail` komutu ile canlı logları izleyin
3. Google Cloud Support'a başvurun

---

**Not:** Bu rehber sürekli güncellenmektedir. En güncel bilgiler için Google Cloud dokümantasyonunu kontrol edin. 