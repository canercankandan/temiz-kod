
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
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback, net.ParseIP("192.168.1.133"), net.ParseIP("135.181.81.88")},
		DNSNames:     []string{"localhost", "*.localhost", "192.168.1.133", "135.181.81.88"},
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

	// Certificate yükle
	cert, err := tls.LoadX509KeyPair("/etc/letsencrypt/live/xn--suartmauzman-44bi.com/fullchain.pem", "/etc/letsencrypt/live/xn--suartmauzman-44bi.com/privkey.pem")
	if err != nil {
		log.Printf("Let's Encrypt certificate yüklenemedi, self-signed kullanılıyor: %v", err)
		// Fallback to self-signed certificate
		cert, err = generateSelfSignedCert()
		if err != nil {
			log.Fatalf("SSL sertifikası oluşturulamadı: %v", err)
		}
	} else {
		log.Printf("✅ Let's Encrypt certificate yüklendi: xn--suartmauzman-44bi.com")
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
		
		if err := r.Run(":" + port); err != nil {
			log.Fatalf("HTTP Server başlatılamadı: %v", err)
		}
		return
	}

	// HTTP ve HTTPS sunucusu çalıştır
	httpPort := "8080"
	httpsPort := "8443"

	// HTTP sunucusu için ayrı bir Gin engine oluştur
	httpEngine := gin.New()
	httpEngine.Use(gin.Logger())
	httpEngine.Use(gin.Recovery())
	httpEngine.SetTrustedProxies([]string{"127.0.0.1", "::1"})
	
	// HTTP engine için template renderer ayarla
	httpEngine.HTMLRender = &handlers.HTMLRenderer{
		Templates: templates,
	}
	
	// HTTP engine için static dosyalar
	httpEngine.Static("/static", "./static")
	
	// HTTP engine için tüm route'ları kopyala
	httpEngine.GET("/", h.HomePage)
	httpEngine.GET("/home", h.HomePage)
	httpEngine.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "Test sayfası - HTTP Server aktif!")
	})
	httpEngine.GET("/products", h.ProductsPage)
	httpEngine.GET("/about", h.AboutPage)
	httpEngine.GET("/contact", h.ContactPage)
	
	// Order tracking routes
	httpEngine.GET("/track", h.OrderTrackingPage)
	httpEngine.POST("/track-order", h.TrackOrderByNumber)
	httpEngine.GET("/track-session-orders", h.TrackOrderBySession)
	httpEngine.POST("/cancel-order/:id", h.CustomerCancelOrder)
	
	// Support chat routes
	httpEngine.GET("/support", h.SupportChatPage)
	httpEngine.POST("/support/send", h.SendSupportMessage)
	httpEngine.GET("/support/messages", h.GetSupportMessages)
	httpEngine.POST("/support/video-call-request", h.HandleVideoCallRequest)
	httpEngine.POST("/support/webrtc-signal", h.HandleWebRTCSignal)
	httpEngine.GET("/support/webrtc-signals/:sessionId", h.GetWebRTCSignals)
	httpEngine.POST("/support/ping", h.SupportPing)
	httpEngine.POST("/support/leave", h.SupportLeave)
	
	// Sepet rotaları
	httpEngine.GET("/cart", h.CartPage)
	httpEngine.POST("/cart/add", h.AddToCart)
	httpEngine.POST("/cart/update", h.UpdateCartItem)
	httpEngine.POST("/cart/remove", h.RemoveFromCart)
	httpEngine.GET("/cart/count", h.GetCartCount)
	httpEngine.GET("/checkout", h.CheckoutPage)
	httpEngine.POST("/checkout", h.HandleCheckout)
	httpEngine.GET("/order-success", h.OrderSuccessPage)
	
	// User authentication routes
	httpEngine.GET("/login", h.LoginPage)
	httpEngine.POST("/login", h.HandleLogin)
	httpEngine.GET("/register", h.RegisterPage)
	httpEngine.POST("/register", h.HandleRegister)
	httpEngine.GET("/logout", h.UserLogout)
	
	// Şifre sıfırlama route'ları
	httpEngine.GET("/forgot-password", h.ForgotPasswordPage)
	httpEngine.POST("/forgot-password", h.HandleForgotPassword)
	httpEngine.GET("/reset-password", h.ResetPasswordPage)
	httpEngine.POST("/reset-password", h.HandleResetPassword)
	
	// Admin authentication rotaları
	httpEngine.GET("/admin/login", h.AdminLoginPage)
	httpEngine.POST("/admin/login", h.AdminLogin)
	httpEngine.GET("/admin/logout", h.AdminLogout)
	
	// Admin paneli rotaları (korumalı)
	httpAdmin := httpEngine.Group("/admin")
	httpAdmin.Use(h.AuthMiddleware())
	{
		httpAdmin.GET("", h.AdminPage)
		httpAdmin.POST("/add-product", h.AddProduct)
		httpAdmin.POST("/update-product", h.UpdateProduct)
		httpAdmin.DELETE("/delete-product/:id", h.DeleteProduct)
		httpAdmin.GET("/orders", h.AdminGetOrders)
		httpAdmin.GET("/orders/:id", h.AdminGetOrderDetail)
		httpAdmin.PUT("/orders/:id", h.AdminUpdateOrder)
		httpAdmin.DELETE("/orders/:id", h.AdminDeleteOrder)
		httpAdmin.GET("/users", h.AdminGetUsers)
		httpAdmin.DELETE("/users/:id", h.AdminDeleteUser)
		httpAdmin.GET("/support", h.AdminSupportPage)
		httpAdmin.GET("/support/sessions", h.AdminGetSupportSessions)
		httpAdmin.GET("/support/messages/:sessionId", h.AdminGetSupportMessages)
		httpAdmin.POST("/support/send/:sessionId", h.AdminSendSupportMessage)
		httpAdmin.POST("/support/video-call-response", h.AdminVideoCallResponse)
		httpAdmin.POST("/support/start-video-call", h.AdminStartVideoCall)
		httpAdmin.GET("/support/video-call-status/:sessionId", h.CheckVideoCallStatus)
		httpAdmin.GET("/support/video-call-requests", h.AdminGetVideoCallRequests)
		httpAdmin.POST("/support/webrtc-signal", h.HandleAdminWebRTCSignal)
		httpAdmin.GET("/support/webrtc-signals/:sessionId", h.GetAdminWebRTCSignals)
	}
	
	// User profile routes (protected)
	httpUser := httpEngine.Group("/profile")
	httpUser.Use(h.AuthUserMiddleware())
	{
		httpUser.GET("", h.ProfilePage)
		httpUser.POST("/change-password", h.HandleChangePassword)
	}
	
	// Sipariş geçmişi (protected)
	httpOrders := httpEngine.Group("/orders")
	httpOrders.Use(h.AuthUserMiddleware())
	{
		httpOrders.GET("", h.OrdersPage)
		httpOrders.GET("/:id", h.GetOrderDetail)
		httpOrders.DELETE("/:id", h.UserCancelOrder)
	}
	
	httpEngine.GET("/sitemap.xml", func(c *gin.Context) {
		c.Header("Content-Type", "application/xml")
		c.File("./templates/sitemap.xml")
	})
	httpEngine.GET("/robots.txt", func(c *gin.Context) {
		c.Header("Content-Type", "text/plain")
		c.File("./static/robots.txt")
	})
	httpEngine.GET("/favicon.ico", func(c *gin.Context) {
		c.File("./static/favicon.ico")
	})

	// HTTP server
	httpServer := &http.Server{
		Addr:    "0.0.0.0:" + httpPort,
		Handler: httpEngine,
	}

	// HTTPS sunucusu için ayrı bir Gin engine oluştur
	httpsEngine := gin.New()
	httpsEngine.Use(gin.Logger())
	httpsEngine.Use(gin.Recovery())
	httpsEngine.SetTrustedProxies([]string{"127.0.0.1", "::1"})
	
	// HTTPS engine için template renderer ayarla
	httpsEngine.HTMLRender = &handlers.HTMLRenderer{
		Templates: templates,
	}
	
	// HTTPS engine için static dosyalar
	httpsEngine.Static("/static", "./static")
	
	// HTTPS engine için tüm route'ları kopyala
	httpsEngine.GET("/", h.HomePage)
	httpsEngine.GET("/home", h.HomePage)
	httpsEngine.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "HTTPS Test sayfası - HTTPS Server aktif!")
	})
	httpsEngine.GET("/products", h.ProductsPage)
	httpsEngine.GET("/about", h.AboutPage)
	httpsEngine.GET("/contact", h.ContactPage)
	
	// Order tracking routes
	httpsEngine.GET("/track", h.OrderTrackingPage)
	httpsEngine.POST("/track-order", h.TrackOrderByNumber)
	httpsEngine.GET("/track-session-orders", h.TrackOrderBySession)
	httpsEngine.POST("/cancel-order/:id", h.CustomerCancelOrder)
	
	// Support chat routes
	httpsEngine.GET("/support", h.SupportChatPage)
	httpsEngine.POST("/support/send", h.SendSupportMessage)
	httpsEngine.GET("/support/messages", h.GetSupportMessages)
	httpsEngine.POST("/support/video-call-request", h.HandleVideoCallRequest)
	httpsEngine.POST("/support/webrtc-signal", h.HandleWebRTCSignal)
	httpsEngine.GET("/support/webrtc-signals/:sessionId", h.GetWebRTCSignals)
	httpsEngine.POST("/support/ping", h.SupportPing)
	httpsEngine.POST("/support/leave", h.SupportLeave)
	
	// Sepet rotaları
	httpsEngine.GET("/cart", h.CartPage)
	httpsEngine.POST("/cart/add", h.AddToCart)
	httpsEngine.POST("/cart/update", h.UpdateCartItem)
	httpsEngine.POST("/cart/remove", h.RemoveFromCart)
	httpsEngine.GET("/cart/count", h.GetCartCount)
	httpsEngine.GET("/checkout", h.CheckoutPage)
	httpsEngine.POST("/checkout", h.HandleCheckout)
	httpsEngine.GET("/order-success", h.OrderSuccessPage)
	
	// User authentication routes
	httpsEngine.GET("/login", h.LoginPage)
	httpsEngine.POST("/login", h.HandleLogin)
	httpsEngine.GET("/register", h.RegisterPage)
	httpsEngine.POST("/register", h.HandleRegister)
	httpsEngine.GET("/logout", h.UserLogout)
	
	// Şifre sıfırlama route'ları
	httpsEngine.GET("/forgot-password", h.ForgotPasswordPage)
	httpsEngine.POST("/forgot-password", h.HandleForgotPassword)
	httpsEngine.GET("/reset-password", h.ResetPasswordPage)
	httpsEngine.POST("/reset-password", h.HandleResetPassword)
	
	// Admin authentication rotaları
	httpsEngine.GET("/admin/login", h.AdminLoginPage)
	httpsEngine.POST("/admin/login", h.AdminLogin)
	httpsEngine.GET("/admin/logout", h.AdminLogout)
	
	// Admin paneli rotaları (korumalı)
	httpsAdmin := httpsEngine.Group("/admin")
	httpsAdmin.Use(h.AuthMiddleware())
	{
		httpsAdmin.GET("", h.AdminPage)
		httpsAdmin.POST("/add-product", h.AddProduct)
		httpsAdmin.POST("/update-product", h.UpdateProduct)
		httpsAdmin.DELETE("/delete-product/:id", h.DeleteProduct)
		httpsAdmin.GET("/orders", h.AdminGetOrders)
		httpsAdmin.GET("/orders/:id", h.AdminGetOrderDetail)
		httpsAdmin.PUT("/orders/:id", h.AdminUpdateOrder)
		httpsAdmin.DELETE("/orders/:id", h.AdminDeleteOrder)
		httpsAdmin.GET("/users", h.AdminGetUsers)
		httpsAdmin.DELETE("/users/:id", h.AdminDeleteUser)
		httpsAdmin.GET("/support", h.AdminSupportPage)
		httpsAdmin.GET("/support/sessions", h.AdminGetSupportSessions)
		httpsAdmin.GET("/support/messages/:sessionId", h.AdminGetSupportMessages)
		httpsAdmin.POST("/support/send/:sessionId", h.AdminSendSupportMessage)
		httpsAdmin.POST("/support/video-call-response", h.AdminVideoCallResponse)
		httpsAdmin.POST("/support/start-video-call", h.AdminStartVideoCall)
		httpsAdmin.GET("/support/video-call-status/:sessionId", h.CheckVideoCallStatus)
		httpsAdmin.GET("/support/video-call-requests", h.AdminGetVideoCallRequests)
		httpsAdmin.POST("/support/webrtc-signal", h.HandleAdminWebRTCSignal)
		httpsAdmin.GET("/support/webrtc-signals/:sessionId", h.GetAdminWebRTCSignals)
	}
	
	// User profile routes (protected)
	httpsUser := httpsEngine.Group("/profile")
	httpsUser.Use(h.AuthUserMiddleware())
	{
		httpsUser.GET("", h.ProfilePage)
		httpsUser.POST("/change-password", h.HandleChangePassword)
	}
	
	// Sipariş geçmişi (protected)
	httpsOrders := httpsEngine.Group("/orders")
	httpsOrders.Use(h.AuthUserMiddleware())
	{
		httpsOrders.GET("", h.OrdersPage)
		httpsOrders.GET("/:id", h.GetOrderDetail)
		httpsOrders.DELETE("/:id", h.UserCancelOrder)
	}
	
	httpsEngine.GET("/sitemap.xml", func(c *gin.Context) {
		c.Header("Content-Type", "application/xml")
		c.File("./templates/sitemap.xml")
	})
	httpsEngine.GET("/robots.txt", func(c *gin.Context) {
		c.Header("Content-Type", "text/plain")
		c.File("./static/robots.txt")
	})
	httpsEngine.GET("/favicon.ico", func(c *gin.Context) {
		c.File("./static/favicon.ico")
	})

	// HTTPS server
	httpsServer := &http.Server{
		Addr:      "0.0.0.0:" + httpsPort,
		Handler:   httpsEngine,
		TLSConfig: tlsConfig,
	}

	// HTTP Server'ı goroutine'de başlat
	go func() {
		log.Printf("🌐 HTTP Server başlatılıyor...")
		log.Printf("📱 HTTP erişim için: http://localhost:%s", httpPort)
		log.Printf("🌐 Mobil HTTP erişim için: http://192.168.1.133:%s", httpPort)
		
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP Server hatası: %v", err)
		}
	}()

	// HTTPS Server'ı başlat
	log.Printf("🔒 HTTPS Server başlatılıyor...")
	log.Printf("📱 HTTPS erişim için: https://localhost:%s", httpsPort)
	log.Printf("🌐 Mobil HTTPS erişim için: https://192.168.1.133:%s", httpsPort)
	log.Printf("⚠️  Self-signed certificate kullanılıyor - tarayıcıda güvenlik uyarısı çıkabilir")
	
	if err := httpsServer.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("HTTPS Server başlatılamadı: %v", err)
	}
} 
