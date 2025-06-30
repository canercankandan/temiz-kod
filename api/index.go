package handler

import (
	"fmt"
	"net/http"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	// Basit bir test sayfası
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	
	html := `
	<!DOCTYPE html>
	<html>
	<head>
		<title>Su Arıtma Uzmanı - Test</title>
		<meta charset="utf-8">
	</head>
	<body>
		<h1>🎉 Vercel'de Go Uygulaması Çalışıyor!</h1>
		<p>Su Arıtma Uzmanı - Test Sayfası</p>
		<p>URL: ` + r.URL.Path + `</p>
		<p>Method: ` + r.Method + `</p>
		<p>Host: ` + r.Host + `</p>
	</body>
	</html>
	`
	
	fmt.Fprintf(w, html)
} 