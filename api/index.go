package api

import (
	"net/http"
	"log"
	
	"cenap/internal/database"
	"cenap/internal/handlers"
	
	"github.com/gin-gonic/gin"
)

// Handler Vercel'in beklediği ana fonksiyon
func Handler(w http.ResponseWriter, r *http.Request) {
	// Gin engine'i oluştur
	gin.SetMode(gin.ReleaseMode)
	
	// Veritabanını başlat
	db, err := database.NewDatabase()
	if err != nil {
		log.Printf("Veritabanı başlatılamadı: %v", err)
		http.Error(w, "Database connection failed", http.StatusInternalServerError)
		return
	}
	
	// Handler'ı oluştur
	h := handlers.NewHandler(db)
	
	// Router'ı oluştur
	router := gin.New()
	router.Use(gin.Recovery())
	
	// Static dosyalar için middleware (Vercel'de farklı çalışır)
	router.Static("/static", "./static")
	
	// Template'leri yükle (basitleştirilmiş)
	router.LoadHTMLGlob("templates/*")
	
	// Ana route'ları tanımla
	router.GET("/", h.HomePage)
	router.GET("/products", h.ProductsPage)
	router.GET("/product/:id", h.ProductDetailPage)
	router.GET("/spare-part/:id", h.SparePartDetailPage)
	router.GET("/about", h.AboutPage)
	router.GET("/contact", h.ContactPage)
	router.GET("/teknik-servis", h.TeknikServisPage)
	router.GET("/chat", h.SupportChatPage)
	router.GET("/support", h.SupportChatPage)
	router.GET("/guest-checkout", h.GuestCheckoutPage)
	
	// SEO route'ları
	router.GET("/sitemap.xml", func(c *gin.Context) {
		c.Header("Content-Type", "application/xml")
		c.File("./templates/sitemap.xml")
	})
	
	router.GET("/robots.txt", func(c *gin.Context) {
		c.Header("Content-Type", "text/plain")
		c.String(200, `User-agent: *
Allow: /
Sitemap: https://irmaksuaritma.com/sitemap.xml`)
	})
	
	// 404 handler
	router.NoRoute(func(c *gin.Context) {
		c.HTML(http.StatusNotFound, "404.html", gin.H{
			"title": "Sayfa Bulunamadı",
			"error": "Aradığınız sayfa mevcut değil",
		})
	})
	
	// Request'i handle et
	router.ServeHTTP(w, r)
} 