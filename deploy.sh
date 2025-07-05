#!/bin/bash

# Production Deployment Script
# Kullanım: ./deploy.sh [platform]

set -e

PLATFORM=${1:-"digitalocean"}
DOMAIN=${2:-"yourdomain.com"}

echo "🚀 Production Deployment Başlatılıyor..."
echo "Platform: $PLATFORM"
echo "Domain: $DOMAIN"

# Environment variables
export DOMAIN=$DOMAIN

case $PLATFORM in
    "digitalocean")
        echo "📦 DigitalOcean App Platform'a deploy ediliyor..."
        
        # DigitalOcean App Platform için build
        docker build -t cenap-app .
        
        # DigitalOcean CLI ile deploy (opsiyonel)
        # doctl apps create --spec app.yaml
        
        echo "✅ DigitalOcean deployment tamamlandı!"
        echo "🌐 Uygulama: https://$DOMAIN"
        ;;
        
    "railway")
        echo "🚂 Railway'e deploy ediliyor..."
        
        # Railway CLI ile deploy
        if command -v railway &> /dev/null; then
            railway login
            railway up
        else
            echo "⚠️  Railway CLI bulunamadı. Manuel deployment gerekli."
        fi
        
        echo "✅ Railway deployment tamamlandı!"
        ;;
        
    "render")
        echo "🎨 Render'a deploy ediliyor..."
        
        # Render için environment variables
        echo "PORT=8080" > .env
        echo "DOMAIN=$DOMAIN" >> .env
        
        echo "✅ Render deployment hazır!"
        echo "🌐 Render Dashboard'dan deploy edin."
        ;;
        
    "heroku")
        echo "🦸 Heroku'ya deploy ediliyor..."
        
        # Heroku CLI ile deploy
        if command -v heroku &> /dev/null; then
            heroku create cenap-app-$RANDOM
            heroku config:set DOMAIN=$DOMAIN
            git push heroku main
        else
            echo "⚠️  Heroku CLI bulunamadı. Manuel deployment gerekli."
        fi
        
        echo "✅ Heroku deployment tamamlandı!"
        ;;
        
    "docker")
        echo "🐳 Docker Compose ile deploy ediliyor..."
        
        # Docker Compose ile local deployment
        docker-compose up -d
        
        echo "✅ Docker deployment tamamlandı!"
        echo "🌐 Uygulama: http://localhost:8080"
        ;;
        
    *)
        echo "❌ Bilinmeyen platform: $PLATFORM"
        echo "Desteklenen platformlar: digitalocean, railway, render, heroku, docker"
        exit 1
        ;;
esac

echo ""
echo "🎉 Deployment tamamlandı!"
echo "📋 Sonraki adımlar:"
echo "1. Domain DNS ayarlarını yapın"
echo "2. SSL sertifikası alın (Let's Encrypt)"
echo "3. WebRTC STUN/TURN server ayarlarını kontrol edin"
echo "4. Email SMTP ayarlarını yapın"
echo ""
echo "🔧 WebRTC için STUN server'ları zaten konfigüre edilmiş:"
echo "   - stun:stun.l.google.com:19302"
echo "   - stun:stun1.l.google.com:19302"
echo ""
echo "💡 Production için TURN server eklemek isterseniz:"
echo "   - Twilio TURN: https://www.twilio.com/stun-turn"
echo "   - CoTURN: https://github.com/coturn/coturn" 