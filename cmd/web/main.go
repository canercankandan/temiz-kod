package main

import (
	"html/template"
	"log"
	"net/http"
	"os"

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

	// App Engine için port ayarı
	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"  // Yerel geliştirme için port 8081
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
		tmpl, err := template.ParseFiles(files...)
		if err != nil {
			log.Fatalf("Template yüklenemedi %s: %v", name, err)
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

	// SEO Route'ları
	r.GET("/sitemap.xml", h.SitemapHandler)
	r.GET("/robots.txt", h.RobotsTxtHandler)

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

	// Test endpoint'leri (authentication olmadan)
	r.GET("/test/support/sessions", h.TestSupportSessions)
	r.GET("/test/support/video-call-requests", h.TestVideoCallRequests)

	// Admin authentication rotaları (korumasız)
	r.GET("/admin/login", h.AdminLoginPage)
	r.POST("/admin/login", h.AdminLogin)
	r.GET("/admin/logout", h.AdminLogout)

	// Admin paneli rotaları (korumalı)
	admin := r.Group("/admin")
	admin.Use(h.AdminAuthMiddleware())
	{
		admin.GET("/", h.AdminDashboard)
		admin.GET("/products", h.AdminProducts)
		admin.GET("/add-product", h.AdminAddProductPage)
		admin.POST("/products/add", h.AddProduct)
		admin.POST("/products/edit/:id", h.EditProduct)
		admin.POST("/products/delete/:id", h.DeleteProduct)
		admin.GET("/orders", h.AdminOrders)
		admin.POST("/orders/update-status/:id", h.UpdateOrderStatus)
		admin.GET("/users", h.AdminUsers)
		admin.POST("/users/delete/:id", h.DeleteUser)
		admin.GET("/support", h.AdminSupportPage)
		admin.POST("/support/reply", h.AdminReplyToSupport)
		admin.GET("/support/sessions", h.AdminGetSupportSessions)
		admin.GET("/support/video-call-requests", h.AdminGetVideoCallRequests)
	}

	// App Engine için HTTP server başlat
	log.Printf("Server başlatılıyor: http://192.168.1.133:%s", port)
	
	// HTTPS için SSL sertifikası kontrolü
	certFile := "cert.pem"
	keyFile := "key.pem"
	
	// SSL sertifikası varsa HTTPS, yoksa HTTP kullan
	if _, err := os.Stat(certFile); err == nil {
		if _, err := os.Stat(keyFile); err == nil {
			log.Printf("HTTPS server başlatılıyor: https://192.168.1.133:%s", port)
			if err := http.ListenAndServeTLS(":"+port, certFile, keyFile, r); err != nil {
				log.Fatalf("HTTPS server başlatılamadı: %v", err)
			}
		}
	}
	
	// HTTP server (varsayılan)
	log.Printf("HTTP server başlatılıyor: http://192.168.1.133:%s", port)
	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatalf("Server başlatılamadı: %v", err)
	}
} 