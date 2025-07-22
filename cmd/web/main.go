
package main

import (
	"crypto/tls"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"

	"cenap/internal/database"
	"cenap/internal/handlers"

	"github.com/gin-gonic/gin"
)

func main() {
	// Production modunu aktif et
	gin.SetMode(gin.ReleaseMode)
	
	// SMTP ayarlarını environment variable olarak ayarla
	os.Setenv("SMTP_HOST", "smtp.gmail.com")
	os.Setenv("SMTP_PORT", "587")
	os.Setenv("SMTP_USER", "irmaksuaritmam@gmail.com")
	os.Setenv("SMTP_PASS", "znpg ejga sekw bmsw")
	
	db, err := database.NewDatabase()
	if err != nil {
		log.Fatalf("Veritabanı başlatılamadı: %v", err)
	}

	h := handlers.NewHandler(db)

	// Engine'i manuel olarak oluştur (middleware'leri kontrol etmek için)
	r := gin.New()
	
	// Middleware'leri manuel olarak ekle
	r.Use(gin.Logger())
	r.Use(gin.Recovery())
	
	// Proxy güvenlik ayarları
	r.SetTrustedProxies([]string{"127.0.0.1", "::1"})

	// Her sayfa için ayrı template setleri oluştur
	log.Printf("📄 Template'ler yükleniyor...")
	templates := map[string]*template.Template{}
	
	templateFiles := map[string][]string{
		"home.html":           {"templates/home.html", "templates/base.html"},
		"products.html":       {"templates/products.html", "templates/base.html"},
		"about.html":          {"templates/about.html", "templates/base.html"},
		"contact.html":        {"templates/contact.html", "templates/base.html"},
		"admin.html":          {"templates/admin.html", "templates/base.html"},
		"admin_login.html":    {"templates/admin_login.html", "templates/base.html"},
		"login.html":          {"templates/login.html", "templates/base.html"},
		"register.html":       {"templates/register.html", "templates/base.html"},
		"profile.html":        {"templates/profile.html", "templates/base.html"},
		"forgot_password.html": {"templates/forgot_password.html", "templates/base.html"},
		"reset_password.html":  {"templates/reset_password.html", "templates/base.html"},
		"cart.html":           {"templates/cart.html", "templates/base.html"},
		"checkout.html":       {"templates/checkout.html", "templates/base.html"},
		"order_success.html":  {"templates/order_success.html", "templates/base.html"},
		"orders.html":         {"templates/orders.html", "templates/base.html"},
		"order_tracking.html": {"templates/order_tracking.html", "templates/base.html"},
		"support_chat.html":   {"templates/support_chat.html", "templates/base.html"},
		"admin_support.html":  {"templates/admin_support.html", "templates/base.html"},
	}
	
	for name, files := range templateFiles {
		log.Printf("📄 Template yükleniyor: %s", name)
		log.Printf("📁 Dosyalar: %v", files)
		
		// Dosyaların varlığını kontrol et
		for _, file := range files {
			if _, err := os.Stat(file); os.IsNotExist(err) {
				log.Printf("❌ Template dosyası bulunamadı: %s", file)
			} else {
				log.Printf("✅ Template dosyası mevcut: %s", file)
			}
		}
		
		tmpl, err := template.New(name).Funcs(handlers.TemplateFuncs).ParseFiles(files...)
		if err != nil {
			log.Printf("❌ Template yüklenemedi %s: %v", name, err)
			log.Fatalf("Template yüklenemedi %s: %v", name, err)
		}
		templates[name] = tmpl
		log.Printf("✅ Template yüklendi: %s", name)
	}
	
	log.Printf("🎯 Toplam %d template yüklendi", len(templates))
	
	r.HTMLRender = &handlers.HTMLRenderer{
		Templates: templates,
	}

	// Static dosyaları serve et
	r.Static("/static", "./static")
	
	// SEO için özel route'lar
	r.GET("/sitemap.xml", func(c *gin.Context) {
		c.Header("Content-Type", "application/xml")
		c.File("./templates/sitemap.xml")
	})
	
	r.GET("/robots.txt", func(c *gin.Context) {
		c.Header("Content-Type", "text/plain")
		c.File("./static/robots.txt")
	})
	
	// Favicon için route ekle - static dosya olarak serve et
	r.GET("/favicon.ico", func(c *gin.Context) {
		c.File("./static/favicon.ico")
	})

	// Chrome DevTools için route ekle
	r.GET("/.well-known/appspecific/com.chrome.devtools.json", func(c *gin.Context) {
		c.Status(204) // No content
	})

	// ANA SAYFA ROUTE'U - EN BAŞTA OLMALI
	log.Printf("🏠 Ana sayfa route'u tanımlanıyor: /")
	r.GET("/", h.HomePage)
	log.Printf("✅ Ana sayfa route'u tanımlandı")

	// Diğer ana sayfa rotaları
	r.GET("/products", h.ProductsPage)
	r.GET("/about", h.AboutPage)
	r.GET("/contact", h.ContactPage)

	// Order tracking routes (public) - ÖNCELİKLE KAYDET!
	log.Printf("Registering order tracking routes...")
	r.GET("/track", h.OrderTrackingPage)
	r.POST("/track-order", h.TrackOrderByNumber)
	r.GET("/track-session-orders", h.TrackOrderBySession)
	r.POST("/cancel-order/:id", h.CustomerCancelOrder)
	log.Printf("Order tracking routes registered successfully")

	// Support chat routes (public)
	log.Printf("Registering support chat routes...")
	r.GET("/support", h.SupportChatPage)
	r.POST("/support/send", h.SendSupportMessage)
	r.GET("/support/messages", h.GetSupportMessages)
	r.POST("/support/video-call-request", h.HandleVideoCallRequest)
	r.POST("/support/webrtc-signal", h.HandleWebRTCSignal)
	r.GET("/support/webrtc-signals/:sessionId", h.GetWebRTCSignals)
	r.POST("/support/ping", h.SupportPing)
	r.POST("/support/leave", h.SupportLeave)
	log.Printf("Support chat routes registered successfully")

	// Sepet rotaları
	r.GET("/cart", h.CartPage)
	r.POST("/cart/add", h.AddToCart)
	r.POST("/cart/update", h.UpdateCartItem)
	r.POST("/cart/remove", h.RemoveFromCart)  // ✅ Doğru tanımlanmış
	r.GET("/cart/count", h.GetCartCount)
	r.GET("/checkout", h.CheckoutPage)
	r.POST("/checkout", h.HandleCheckout)
	r.GET("/order-success", h.OrderSuccessPage)

	// User authentication routes
	r.GET("/login", h.LoginPage)
	r.POST("/login", h.HandleLogin)
	r.GET("/register", h.RegisterPage)
	r.POST("/register", h.HandleRegister)
	r.GET("/logout", h.UserLogout)

	// Şifre sıfırlama route'ları
	r.GET("/forgot-password", h.ForgotPasswordPage)
	r.POST("/forgot-password", h.HandleForgotPassword)
	r.GET("/reset-password", h.ResetPasswordPage)
	r.POST("/reset-password", h.HandleResetPassword)

	// Admin authentication rotaları (korumasız)
	r.GET("/admin/login", h.AdminLoginPage)
	r.POST("/admin/login", h.AdminLogin)
	r.GET("/admin/logout", h.AdminLogout)

	// Admin paneli rotaları (korumalı)
	admin := r.Group("/admin")
	admin.Use(h.AuthMiddleware())
	{
		admin.GET("", h.AdminPage)
		admin.POST("/add-product", h.AddProduct)
		admin.POST("/update-product", h.UpdateProduct)
		admin.DELETE("/delete-product/:id", h.DeleteProduct)
		// Admin sipariş yönetimi
		admin.GET("/orders", h.AdminGetOrders)
		admin.GET("/orders/:id", h.AdminGetOrderDetail)
		admin.PUT("/orders/:id", h.AdminUpdateOrder)
		admin.DELETE("/orders/:id", h.AdminDeleteOrder)
		
		// Admin kullanıcı yönetimi
		admin.GET("/users", h.AdminGetUsers)
		admin.DELETE("/users/:id", h.AdminDeleteUser)
		
		// Admin support routes
		admin.GET("/support", h.AdminSupportPage)
		admin.GET("/support/sessions", h.AdminGetSupportSessions)
		admin.GET("/support/messages/:sessionId", h.AdminGetSupportMessages)
		admin.POST("/support/send/:sessionId", h.AdminSendSupportMessage)
		admin.POST("/support/video-call-response", h.AdminVideoCallResponse)
		admin.POST("/support/start-video-call", h.AdminStartVideoCall)
		admin.GET("/support/video-call-status/:sessionId", h.CheckVideoCallStatus)
		admin.GET("/support/video-call-requests", h.AdminGetVideoCallRequests)
		admin.POST("/support/webrtc-signal", h.HandleAdminWebRTCSignal)
		admin.GET("/support/webrtc-signals/:sessionId", h.GetAdminWebRTCSignals)
	}

	// User profile routes (protected)
	user := r.Group("/profile")
	user.Use(h.AuthUserMiddleware())
	{
		user.GET("", h.ProfilePage)
		user.POST("/change-password", h.HandleChangePassword)
	}

	// Sipariş geçmişi (protected)
	orders := r.Group("/orders")
	orders.Use(h.AuthUserMiddleware())
	{
		orders.GET("", h.OrdersPage)
		orders.GET("/:id", h.GetOrderDetail)
		orders.DELETE("/:id", h.UserCancelOrder)
	}

	// Certificate yükle ve HTTPS'i aktif et
	certPath := os.Getenv("SSL_CERT_PATH")
	keyPath := os.Getenv("SSL_KEY_PATH")
	if certPath == "" {
	    certPath = "localhost.crt"
	}
	if keyPath == "" {
	    keyPath = "localhost.key"
	}
	
	// Sertifika dosyalarının varlığını kontrol et
	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		log.Printf("❌ Sertifika dosyası bulunamadı: %s", certPath)
		log.Printf("HTTPS devre dışı, sadece HTTP kullanılıyor")
	} else if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		log.Printf("❌ Anahtar dosyası bulunamadı: %s", keyPath)
		log.Printf("HTTPS devre dışı, sadece HTTP kullanılıyor")
	} else {
		cert, certErr := tls.LoadX509KeyPair(certPath, keyPath)
		if certErr != nil {
			log.Printf("❌ Sertifika yüklenemedi: %v", certErr)
			log.Printf("HTTPS devre dışı, sadece HTTP kullanılıyor")
		} else {
			log.Printf("✅ SSL Sertifikası başarıyla yüklendi")
			
			// TLS yapılandırması - Güvenlik ayarları iyileştirildi
			tlsConfig := &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
				CipherSuites: []uint16{
					tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
					tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
					tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				},
			}
			
			// HTTPS sunucusu - Port 8443
			httpsServer := &http.Server{
				Addr:      "0.0.0.0:8443",
				Handler:   r,
				TLSConfig: tlsConfig,
				ReadTimeout:  15 * time.Second,
				WriteTimeout: 15 * time.Second,
				IdleTimeout:  60 * time.Second,
			}
			
			// HTTPS sunucusunu arka planda başlat
			go func() {
				log.Printf("🔒 HTTPS Server başlatılıyor (port: 8443)...")
				log.Printf("🔐 Yerel HTTPS erişim: https://localhost:8443")
				log.Printf("🌐 HTTPS erişim için: https://xn--suartmauzman-44bi.com:8443")
				if err := httpsServer.ListenAndServeTLS("", ""); err != nil {
					log.Printf("❌ HTTPS Server hatası: %v", err)
				}
			}()
			
			log.Printf("✅ HTTPS sunucusu başarıyla başlatıldı")
		}
	}

	// Render.com için ortam değişkeni kontrolü
	port := os.Getenv("PORT")
	if port != "" {
		// Render ortamı: Sadece HTTP başlat
		log.Printf("🚀 Render.com ortamı tespit edildi")
		log.Printf("🌐 HTTP Server başlatılıyor (port: %s)...", port)
		log.Printf("📱 Erişim için: http://localhost:%s", port)
		
		if err := r.Run(":" + port); err != nil {
			log.Fatalf("HTTP Server başlatılamadı: %v", err)
		}
		return
	}

	// HTTP sunucusu çalıştır
	httpPort := "3000"  // Port tanımlandı

	// HTTP server - r engine'ini kullan (httpEngine yerine)
	httpServer := &http.Server{
		Addr:    "0.0.0.0:" + httpPort,
		Handler: r,  // httpEngine yerine r kullan
	}

	// HTTP Server'ı başlat
	log.Printf("🌐 HTTP Server başlatılıyor...")
	log.Printf("📱 HTTP erişim için: http://localhost:%s", httpPort)
	log.Printf("🌐 Mobil HTTP erişim için: http://xn--suartmauzman-44bi.com:%s", httpPort)
	log.Printf("✅ HTTP (3000) ve HTTPS (8443) sunucuları aktif")
	
	if err := httpServer.ListenAndServe(); err != nil {
		log.Fatalf("HTTP Server başlatılamadı: %v", err)
	}
}
