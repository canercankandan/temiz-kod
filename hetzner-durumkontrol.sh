#!/bin/bash

echo "🔍 Hetzner Server Durum Kontrol Script'i"
echo "================================="

# Server IP'sini kullanıcıdan al
read -p "🌐 Server IP adresinizi girin (örn: 135.181.81.88): " SERVER_IP

if [ -z "$SERVER_IP" ]; then
    echo "❌ IP adresi girilmedi!"
    exit 1
fi

echo ""
echo "📡 Server Bağlantı Testi..."

# Ping testi
if ping -c 3 $SERVER_IP > /dev/null 2>&1; then
    echo "✅ Server erişilebilir"
else
    echo "❌ Server erişilemiyor!"
    exit 1
fi

echo ""
echo "🔍 Port Kontrolleri..."

# HTTP Port 8080 kontrol
if nc -z $SERVER_IP 8080 2>/dev/null; then
    echo "✅ HTTP Port 8080 açık"
    HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://$SERVER_IP:8080/ || echo "HATA")
    echo "   HTTP Response: $HTTP_STATUS"
else
    echo "❌ HTTP Port 8080 kapalı"
fi

# HTTPS Port 8443 kontrol
if nc -z $SERVER_IP 8443 2>/dev/null; then
    echo "✅ HTTPS Port 8443 açık"
    echo "   Admin Panel: https://$SERVER_IP:8443/admin/login"
else
    echo "❌ HTTPS Port 8443 kapalı"
fi

# SSH Port 22 kontrol
if nc -z $SERVER_IP 22 2>/dev/null; then
    echo "✅ SSH Port 22 açık"
    echo "   SSH Bağlantı: ssh root@$SERVER_IP"
else
    echo "❌ SSH Port 22 kapalı"
fi

echo ""
echo "🌐 Web Kontrolleri..."

# Ana sayfa kontrol
if curl -s http://$SERVER_IP:8080/ | grep -q "Cenap\|Su Arıtma" 2>/dev/null; then
    echo "✅ Cenap uygulaması çalışıyor!"
    echo "   Ana Sayfa: http://$SERVER_IP:8080/"
else
    echo "❓ Cenap uygulaması bulunamadı"
fi

echo ""
echo "📋 ÖZET:"
echo "================================="
echo "Server IP: $SERVER_IP"
echo "SSH: ssh root@$SERVER_IP"
echo "Web: http://$SERVER_IP:8080/"
echo "Admin: https://$SERVER_IP:8443/admin/login"
echo ""

# SSH bağlantı önerisi
echo "🔧 Detaylı kontrol için SSH ile bağlanın:"
echo "ssh root@$SERVER_IP"
echo ""
echo "SSH'ta çalıştırılacak komutlar:"
echo "sudo systemctl status cenap"
echo "sudo systemctl status nginx"
echo "ps aux | grep cenap" 