package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"html/template"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"

	"cenap/internal/database"
	"cenap/internal/handlers"

	"github.com/gin-gonic/gin"
)

// generateSelfSignedCert creates a self-signed certificate for HTTPS
func generateSelfSignedCert() (tls.Certificate, error) {
	// Create private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Cenap Water Filters"},
			Country:       []string{"TR"},
			Province:      []string{""},
			Locality:      []string{"Istanbul"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback, net.ParseIP("192.168.1.133")},
		DNSNames:     []string{"localhost", "*.localhost", "192.168.1.133"},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	// Encode certificate
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return tls.X509KeyPair(certPEM, keyPEM)
}

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
	r.POST("/cart/remove", h.RemoveFromCart)
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

	// Load external certificate files
	cert, err := tls.LoadX509KeyPair("localhost.crt", "localhost.key")
	if err != nil {
		log.Printf("External certificate yüklenemedi, self-signed kullanılıyor: %v", err)
		// Fallback to self-signed certificate
		cert, err = generateSelfSignedCert()
		if err != nil {
			log.Fatalf("SSL sertifikası oluşturulamadı: %v", err)
		}
	} else {
		log.Printf("✅ External certificate yüklendi: localhost.crt")
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	// Render.com için ortam değişkeni kontrolü
	port := os.Getenv("PORT")
	if port != "" {
		// Render ortamı: Sadece HTTP başlat
		log.Printf("🚀 Render.com ortamı tespit edildi")
		log.Printf("🌐 HTTP Server başlatılıyor (port: %s)...", port)
		log.Printf("📱 Erişim için: http://localhost:%s", port)
		
		// Render için CORS ayarları
		r.Use(func(c *gin.Context) {
			c.Header("Access-Control-Allow-Origin", "*")
			c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
			
			if c.Request.Method == "OPTIONS" {
				c.AbortWithStatus(204)
				return
			}
			
			c.Next()
		})
		
		if err := r.Run(":" + port); err != nil {
			log.Fatalf("HTTP Server başlatılamadı: %v", err)
		}
		return
	}

	// Lokal geliştirme: HTTPS ve HTTP yönlendirme
	httpsPort := "8083"
	httpPort := "8082"
	
	// Create HTTPS server
	httpsServer := &http.Server{
		Addr:      ":" + httpsPort,
		Handler:   r,
		TLSConfig: tlsConfig,
	}

	// HTTP'den HTTPS'e yönlendirme için handler
	httpHandler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// HTTPS'e yönlendir
		httpsURL := "https://" + req.Host + ":" + httpsPort + req.RequestURI
		http.Redirect(w, req, httpsURL, http.StatusMovedPermanently)
	})

	// HTTP server
	httpServer := &http.Server{
		Addr:    ":" + httpPort,
		Handler: httpHandler,
	}

	// HTTP Server'ı goroutine'de başlat
	go func() {
		log.Printf("🌐 HTTP Server başlatılıyor (HTTPS'e yönlendirme)...")
		log.Printf("📱 HTTP erişim için: http://localhost:%s", httpPort)
		log.Printf("🌐 Mobil HTTP erişim için: http://192.168.1.133:%s", httpPort)
		
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP Server hatası: %v", err)
		}
	}()

	// HTTPS Server'ı başlat
	log.Printf("🔒 HTTPS Server başlatılıyor...")
	log.Printf("📱 iPhone Safari desteği için: https://localhost:%s", httpsPort)
	log.Printf("🌐 Mobil HTTPS erişim için: https://192.168.1.133:%s", httpsPort)
	log.Printf("⚠️  Self-signed certificate kullanılıyor - tarayıcıda güvenlik uyarısı çıkabilir")
	
	if err := httpsServer.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("HTTPS Server başlatılamadı: %v", err)
	}
} 