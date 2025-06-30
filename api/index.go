package main

import (
	"context"
	"net/http"
	"os"

	"cenap/internal/database"
	"cenap/internal/handlers"

	"github.com/gin-gonic/gin"
	"github.com/vercel/vercel-go"
)

func init() {
	// Production modunu aktif et
	gin.SetMode(gin.ReleaseMode)
	
	// SMTP ayarlarını environment variable olarak ayarla
	os.Setenv("SMTP_HOST", "smtp.gmail.com")
	os.Setenv("SMTP_PORT", "587")
	os.Setenv("SMTP_USER", "irmaksuaritmam@gmail.com")
	os.Setenv("SMTP_PASS", "znpg ejga sekw bmsw")
}

func Handler(w http.ResponseWriter, r *http.Request) {
	// Veritabanını başlat
	db, err := database.NewDatabase()
	if err != nil {
		http.Error(w, "Veritabanı başlatılamadı", http.StatusInternalServerError)
		return
	}

	h := handlers.NewHandler(db)

	// Gin engine oluştur
	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())

	// Template'leri yükle
	templates := map[string]*template.Template{}
	templateFiles := map[string][]string{
		"home.html": {"templates/home.html", "templates/base.html"},
		// Diğer template'ler...
	}

	for name, files := range templateFiles {
		tmpl, err := template.New(name).Funcs(handlers.TemplateFuncs).ParseFiles(files...)
		if err != nil {
			continue
		}
		templates[name] = tmpl
	}

	router.HTMLRender = &handlers.HTMLRenderer{
		Templates: templates,
	}

	// Route'ları tanımla
	router.GET("/", h.HomePage)
	router.GET("/products", h.ProductsPage)
	router.GET("/about", h.AboutPage)
	router.GET("/contact", h.ContactPage)

	// Static dosyalar
	router.Static("/static", "./static")

	// HTTP handler'ı Gin'e yönlendir
	router.ServeHTTP(w, r)
} 