package main

import (
	"fmt"
	"net/http"
)

// Handler Vercel'in beklediği ana fonksiyon
func Handler(w http.ResponseWriter, r *http.Request) {
	// CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	
	// OPTIONS request için
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}
	
	// HTML response
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	
	html := `
	<!DOCTYPE html>
	<html lang="tr">
	<head>
		<meta charset="UTF-8">
		<meta name="viewport" content="width=device-width, initial-scale=1.0">
		<title>Su Arıtma Uzmanı - Vercel</title>
		<style>
			body {
				font-family: Arial, sans-serif;
				max-width: 800px;
				margin: 0 auto;
				padding: 20px;
				background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
				color: white;
				min-height: 100vh;
			}
			.container {
				background: rgba(255,255,255,0.1);
				padding: 30px;
				border-radius: 15px;
				backdrop-filter: blur(10px);
				box-shadow: 0 8px 32px rgba(0,0,0,0.1);
			}
			h1 {
				text-align: center;
				margin-bottom: 30px;
				font-size: 2.5em;
			}
			.status {
				background: rgba(76, 175, 80, 0.2);
				padding: 15px;
				border-radius: 10px;
				margin: 20px 0;
				border-left: 4px solid #4CAF50;
			}
			.info {
				background: rgba(33, 150, 243, 0.2);
				padding: 15px;
				border-radius: 10px;
				margin: 20px 0;
				border-left: 4px solid #2196F3;
			}
			.warning {
				background: rgba(255, 193, 7, 0.2);
				padding: 15px;
				border-radius: 10px;
				margin: 20px 0;
				border-left: 4px solid #FFC107;
			}
		</style>
	</head>
	<body>
		<div class="container">
			<h1>🚰 Su Arıtma Uzmanı</h1>
			
			<div class="status">
				<h2>✅ Durum: Çalışıyor</h2>
				<p>Uygulama Vercel'de başarıyla çalışıyor!</p>
			</div>
			
			<div class="info">
				<h3>📊 Teknik Bilgiler:</h3>
				<ul>
					<li><strong>URL:</strong> ` + r.URL.Path + `</li>
					<li><strong>Method:</strong> ` + r.Method + `</li>
					<li><strong>Host:</strong> ` + r.Host + `</li>
					<li><strong>User Agent:</strong> ` + r.UserAgent() + `</li>
				</ul>
			</div>
			
			<div class="warning">
				<h3>⚠️ Önemli Not:</h3>
				<p>Bu basit bir test sayfasıdır. Tam uygulama için daha kapsamlı bir yapılandırma gereklidir.</p>
			</div>
			
			<div class="info">
				<h3>🔧 Sonraki Adımlar:</h3>
				<ol>
					<li>Veritabanı bağlantısı kurulacak</li>
					<li>Template'ler eklenecek</li>
					<li>Static dosyalar yapılandırılacak</li>
					<li>Canlı destek sistemi entegre edilecek</li>
				</ol>
			</div>
		</div>
	</body>
	</html>
	`
	
	fmt.Fprintf(w, html)
} 