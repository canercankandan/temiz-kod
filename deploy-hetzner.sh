#!/bin/bash

# Hetzner Cloud Deployment Script for Cenap Water Filters App

echo "🚀 Hetzner Cloud'a deployment başlıyor..."

# 1. Sistem güncellemeleri
sudo apt update && sudo apt upgrade -y

# 2. Go kurulumu
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# 3. Nginx kurulumu
sudo apt install nginx -y

# 4. Uygulama dizini oluştur
sudo mkdir -p /var/www/cenap
sudo chown $USER:$USER /var/www/cenap

# 5. Uygulamayı kopyala (git clone veya scp ile)
cd /var/www/cenap
# git clone your-repo-url .

# 6. Go modülleri indir
go mod tidy

# 7. Uygulamayı build et
go build -o cenap cmd/web/main.go

# 8. Nginx konfigürasyonu
sudo cp nginx.conf /etc/nginx/sites-available/cenap
sudo ln -s /etc/nginx/sites-available/cenap /etc/nginx/sites-enabled/
sudo rm /etc/nginx/sites-enabled/default

# 9. SSL sertifikası (Let's Encrypt)
sudo apt install certbot python3-certbot-nginx -y
# sudo certbot --nginx -d yourdomain.com

# 10. Systemd service oluştur
sudo tee /etc/systemd/system/cenap.service > /dev/null <<EOF
[Unit]
Description=Cenap Water Filters App
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=/var/www/cenap
ExecStart=/var/www/cenap/cenap
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# 11. Service'i aktif et
sudo systemctl daemon-reload
sudo systemctl enable cenap
sudo systemctl start cenap

# 12. Nginx'i yeniden başlat
sudo systemctl reload nginx

echo "✅ Deployment tamamlandı!"
echo "🌐 Uygulamanız https://your-server-ip adresinde çalışıyor" 