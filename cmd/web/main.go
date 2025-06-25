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
	"os"
	"time"

	"suaritamauzumani/internal/database"
	"suaritamauzumani/internal/handlers"

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
	log.Println("[DEBUG] Sunucu başlatılıyor...")
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[PANIC] Uygulama çöktü: %v", r)
		}
	}()

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

	// Port'u environment variable'dan al, yoksa default kullan
	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}
	
	// Host'u environment variable'dan al
	host := os.Getenv("HOST")
	if host == "" {
		host = "0.0.0.0"
	}

	// Engine'i manuel olarak oluştur (middleware'leri kontrol etmek için)
	r := gin.New()
	
	// Middleware'leri manuel olarak ekle
	r.Use(gin.Logger())
	r.Use(gin.Recovery())
	
	// Proxy güvenlik ayarları
	r.SetTrustedProxies([]string{"127.0.0.1", "::1"})

	// Her sayfa için ayrı template setleri oluştur
	templates := map[string]*template.Template{}
	
	// Template engine'i basitleştir - Render uyumluluğu için
	templateFiles := map[string][]string{
		"home.html":           {"templates/base.html", "templates/home.html"},
		"products.html":       {"templates/base.html", "templates/products.html"},
		"about.html":          {"templates/base.html", "templates/about.html"},
		"contact.html":        {"templates/base.html", "templates/contact.html"},
		"admin.html":          {"templates/base.html", "templates/admin.html"},
		"admin_login.html":    {"templates/base.html", "templates/admin_login.html"},
		"login.html":          {"templates/base.html", "templates/login.html"},
		"register.html":       {"templates/base.html", "templates/register.html"},
		"profile.html":        {"templates/base.html", "templates/profile.html"},
		"forgot_password.html": {"templates/base.html", "templates/forgot_password.html"},
		"reset_password.html":  {"templates/base.html", "templates/reset_password.html"},
		"cart.html":           {"templates/base.html", "templates/cart.html"},
		"checkout.html":       {"templates/base.html", "templates/checkout.html"},
		"order_success.html":  {"templates/base.html", "templates/order_success.html"},
		"orders.html":         {"templates/base.html", "templates/orders.html"},
		"order_tracking.html": {"templates/base.html", "templates/order_tracking.html"},
		"support_chat.html":   {"templates/base.html", "templates/support_chat.html"},
		"admin_support.html":  {"templates/base.html", "templates/admin_support.html"},
	}
	
	for name, files := range templateFiles {
		tmpl, err := template.New(name).ParseFiles(files...)
		if err != nil {
			log.Printf("Template yüklenemedi %s: %v", name, err)
			// Template yüklenemezse devam et, sadece log'la
			continue
		}
		templates[name] = tmpl
		log.Printf("Template yüklendi: %s", name)
	}
	
	r.HTMLRender = &handlers.HTMLRenderer{
		Templates: templates,
	}

	// Static dosyaları serve et
	r.Static("/static", "./static")
	
	// Favicon için route ekle - static dosya olarak serve et
	r.GET("/favicon.ico", func(c *gin.Context) {
		c.File("./static/favicon.ico")
	})

	// Chrome DevTools için route ekle
	r.GET("/.well-known/appspecific/com.chrome.devtools.json", func(c *gin.Context) {
		c.Status(204) // No content
	})

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
	log.Printf("Support chat routes registered successfully")

	// Ana sayfa rotaları
	r.GET("/", h.HomePage)
	r.GET("/products", h.ProductsPage)
	r.GET("/about", h.AboutPage)
	r.GET("/contact", h.ContactPage)

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
		user.POST("/update-address", h.UpdateUserAddress)
	}

	// Sipariş geçmişi (protected)
	orders := r.Group("/orders")
	orders.Use(h.AuthUserMiddleware())
	{
		orders.GET("", h.OrdersPage)
		orders.GET("/:id", h.GetOrderDetail)
		orders.DELETE("/:id", h.UserCancelOrder)
	}

	// Render.com için tek server kullan
	log.Printf("🌐 Server başlatılıyor...")
	log.Printf("📱 Erişim için: http://%s:%s", host, port)
	
	// Tek server başlat
	if err := r.Run(host + ":" + port); err != nil {
		log.Fatalf("Server başlatılamadı: %v", err)
	}
} 
