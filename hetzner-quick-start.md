# 🚀 Hetzner Cloud Hızlı Başlangıç

## 1️⃣ Hetzner Console'da Server Oluştur

```bash
1. https://console.hetzner.com/projects git
2. "Create Server" tıkla
3. Ubuntu 22.04 LTS seç
4. Server boyutu: CX21 (önerilen)
5. SSH Key ekle
6. "Create" bas
```

## 2️⃣ SSH ile Bağlan

```bash
ssh root@YOUR_SERVER_IP
```

## 3️⃣ Deployment Script Çalıştır

```bash
# Repository'yi klonla
git clone your-repo-url /var/www/cenap
cd /var/www/cenap

# Deployment script'i çalıştır
chmod +x deploy-hetzner.sh
./deploy-hetzner.sh
```

## 4️⃣ Domain Bağla (Opsiyonel)

```bash
# DNS A kaydı ekle: your-domain.com -> SERVER_IP
# SSL sertifikası al
sudo certbot --nginx -d your-domain.com
```

## ✅ Test Et

```bash
# Uygulama çalışıyor mu kontrol et
curl http://YOUR_SERVER_IP:8080

# Admin panel erişimi
https://YOUR_SERVER_IP/admin/login
```

## 🔧 Environment Variables

```bash
# Hetzner.env dosyasını düzenle
nano /var/www/cenap/.env

# SMTP ayarları
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password

# Güvenlik
ADMIN_PASSWORD=secure-password
```

## 📊 İzleme

```bash
# Uygulama status
sudo systemctl status cenap

# Nginx status  
sudo systemctl status nginx

# Log'ları görüntüle
sudo journalctl -f -u cenap
```

## 💡 Faydalı Komutlar

```bash
# Restart app
sudo systemctl restart cenap

# Restart nginx
sudo systemctl restart nginx

# Backup data
cp /var/www/cenap/data.json ~/backup-$(date +%Y%m%d).json
``` 