# 🚀 Hetzner'da Yeni Server Oluşturma

## 1️⃣ Server Oluştur

### Hetzner Console'da:
```
1. https://console.hetzner.com/projects → Git
2. "Create Server" butonuna tıkla
3. Aşağıdaki ayarları seç:
```

### ⚙️ Server Konfigürasyonu:

**Location (Konum):**
- 🇩🇪 **Falkenstein** (Almanya) - Önerilen
- 🇩🇪 **Nuremberg** (Almanya) - Alternatif  
- 🇫🇮 **Helsinki** (Finlandiya) - Türkiye'ye yakın

**Image (İşletim Sistemi):**
- 🐧 **Ubuntu 22.04 LTS** (Önerilen)
- ✅ En stabil ve güncel

**Type (Server Boyutu):**
```
📦 CX11 - €3.29/ay
   1 vCPU, 4 GB RAM, 20 GB Disk
   ✅ Test için yeterli

🚀 CX21 - €5.83/ay (ÖNERİLEN)
   2 vCPU, 8 GB RAM, 40 GB Disk  
   ✅ Production için ideal

⚡ CX31 - €11.05/ay
   2 vCPU, 16 GB RAM, 80 GB Disk
   ✅ Yüksek trafik için
```

**Additional Features:**
- ❌ IPv6: Devre dışı (isteğe bağlı)
- ❌ Backup: Şimdilik devre dışı
- ❌ Private network: Gerekmiyor

## 2️⃣ SSH Key Ekle

### Yeni SSH Key Oluştur (Windows):
```powershell
# PowerShell'de çalıştır:
ssh-keygen -t rsa -b 4096 -f ~/.ssh/hetzner_key
```

**Veya mevcut key'i kullan:**
```powershell
# Public key'i göster:
cat ~/.ssh/id_rsa.pub

# Veya:
type %USERPROFILE%\.ssh\id_rsa.pub
```

### Hetzner'a SSH Key Ekle:
```
1. "SSH Keys" sekmesi → "Add SSH Key"
2. Public key içeriğini kopyala yapıştır
3. İsim ver: "cenap-deployment"
4. "Add SSH Key" tıkla
```

## 3️⃣ Server'ı Başlat

```
1. "Create & Buy now" tıkla
2. 1-2 dakika bekle
3. Server IP adresini not et
```

## 4️⃣ İlk Bağlantı

### SSH ile Bağlan:
```bash
ssh root@YOUR_SERVER_IP
```

**İlk bağlantıda:**
```bash
# Sistem güncellemesi
apt update && apt upgrade -y

# Gerekli araçları yükle
apt install git curl wget nginx -y
```

## 5️⃣ Su Arıtma Uygulamasını Deploy Et

### Kolay Yöntem:
```bash
# Repository klonla
cd /var/www
git clone YOUR_REPO_URL cenap
cd cenap

# Deploy script'ini çalıştır
chmod +x deploy-hetzner.sh
./deploy-hetzner.sh
```

## ✅ Test Et

### Bağlantı Kontrolleri:
```bash
# HTTP test
curl http://YOUR_SERVER_IP:8080

# Uygulama durumu
systemctl status cenap
systemctl status nginx
```

### Tarayıcıda Test:
```
🌐 Ana Sayfa: http://YOUR_SERVER_IP:8080
🔒 Admin Panel: https://YOUR_SERVER_IP:8443/admin/login
```

## 🔧 Sorun Giderme

### Log Kontrolleri:
```bash
# Uygulama logları
journalctl -f -u cenap

# Nginx logları  
tail -f /var/log/nginx/error.log

# Port kontrolleri
netstat -tlnp | grep :8080
netstat -tlnp | grep :8443
```

### Restart Komutları:
```bash
# Uygulamayı yeniden başlat
systemctl restart cenap

# Nginx'i yeniden başlat
systemctl restart nginx

# Firewall kontrol
ufw status
``` 