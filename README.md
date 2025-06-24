# Su Arıtama Uzmanı

Türkiye'nin en güvenilir su arıtma sistemleri e-ticaret platformu.

## 🚀 Özellikler

- 🛒 E-ticaret sistemi
- 👥 Kullanıcı yönetimi
- 📦 Sipariş takibi
- 💬 Canlı destek sistemi
- 📹 Video görüşme desteği
- 📱 Mobil uyumlu tasarım
- 🔒 Güvenli ödeme sistemi

## 🛠️ Teknolojiler

- **Backend**: Go (Gin Framework)
- **Frontend**: HTML, CSS, JavaScript, Bootstrap
- **Database**: JSON dosya sistemi
- **Real-time**: WebSocket
- **Video**: WebRTC

## 📋 Kurulum

### Yerel Geliştirme

1. Repository'yi klonlayın:
```bash
git clone https://github.com/canercankandan/su-aritma-uzmani.git
cd su-aritma-uzmani
```

2. Bağımlılıkları yükleyin:
```bash
go mod download
```

3. Uygulamayı çalıştırın:
```bash
go run cmd/web/main.go
```

4. Tarayıcıda açın:
- HTTP: http://localhost:8080
- HTTPS: https://localhost:8081

### Production Deployment

#### Render.com (Önerilen)

1. GitHub'a push edin
2. Render.com'da hesap oluşturun
3. "New Web Service" seçin
4. Repository'nizi bağlayın
5. `render.yaml` otomatik algılanacak

#### Docker ile

```bash
docker build -t suaritamauzumani .
docker run -p 8080:8080 suaritamauzumani
```

## 🔧 Yapılandırma

### Environment Variables

- `PORT`: Server portu (varsayılan: 8080)
- `GIN_MODE`: release/debug
- `HTTPS_PORT`: HTTPS portu (varsayılan: 8081)

### Admin Paneli

- URL: `/admin`
- Varsayılan kullanıcı: `sa`
- Şifre: Admin panelinden ayarlayın

## 📞 İletişim

- Web: https://suaritamauzumani.com
- E-posta: info@suaritamauzumani.com
- Telefon: +90 XXX XXX XX XX

## 📄 Lisans

Bu proje MIT lisansı altında lisanslanmıştır.
