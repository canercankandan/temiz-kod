package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"cenap/internal/models"
	"cenap/internal/services"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// DBInterface, veritabanı işlemlerini tanımlar.
type DBInterface interface {
	GetAllProducts() ([]models.Product, error)
	GetProductByID(id int) (*models.Product, error)
	CreateProduct(product *models.Product) error
	DeleteProduct(id int) error
	// User methods
	CreateUser(user *models.User) error
	GetUserByUsername(username string) (*models.User, error)
	GetUserByEmail(email string) (*models.User, error)
	GetAllUsers() ([]models.User, error)
	UpdateUser(user *models.User) error
	DeleteUser(userID int) error
	CreatePasswordResetToken(email string, token string) error
	GetUserByResetToken(token string) (*models.User, error)
	ClearResetToken(userID int) error
	GetUserByEmailVerifyToken(token string) (*models.User, error)
	VerifyUserEmail(userID int) error
	UpdateUserVerificationToken(userID int, token string) error
	// Order methods
	CreateOrder(order *models.Order) error
	GetOrdersByUserID(userID int) ([]models.Order, error)
	GetOrderByID(orderID int) (*models.Order, error)
	GetAllOrders() ([]models.Order, error)
	SaveOrder(order *models.Order) error
	UpdateOrderStatus(orderID int, status string) error
	UpdateOrderWithNotes(orderID int, status string, adminNotes string) error
	DeleteOrder(orderID int) error
	GetOrderByNumberAndEmail(orderNumber, email string) (*models.Order, error)
	GetOrderByNumber(orderNumber string) (*models.Order, error)
	GetOrdersBySessionID(sessionID string) ([]models.Order, error)
	GetOrCreateSupportSession(sessionID, displayName string, userID *int, userAgent string) (*models.SupportSession, error)
	SaveMessage(message *models.Message) error
	GetMessagesBySession(sessionID string) ([]models.Message, error)
	MarkMessagesAsRead(sessionID string, isUser bool) error
	GetActiveSupportSessions() ([]models.SupportSession, error)
	// Video Call Request methods
	CreateVideoCallRequest(sessionID, username string, userID *int) error
	GetVideoCallRequestBySession(sessionID string) (*models.VideoCallRequest, error)
	UpdateVideoCallRequestStatus(sessionID, status string) error
	EndVideoCallRequest(sessionID string) error
	GetAllActiveVideoCallRequests() ([]models.VideoCallRequest, error)
	CreateVideoCallRequestWithInitiator(sessionID, username string, userID *int, initiator string) error
	UpdateProduct(product *models.Product) error
	UpdateSupportSessionLastActive(sessionID string) error
	MarkSupportSessionOffline(sessionID string) error
	// Cart methods
	GetCartBySessionID(sessionID string) (*models.Cart, error)
	CreateCart(cart *models.Cart) error
	UpdateCart(cart *models.Cart) error
	DeleteCart(cartID int) error
	AddCartItem(item *models.CartItem) error
	UpdateCartItem(item *models.CartItem) error
	DeleteCartItem(itemID int) error
	GetCartItemsByCartID(cartID int) ([]models.CartItem, error)
	// Address methods
	AddAddress(address *models.Address) error
	UpdateAddress(address *models.Address) error
	DeleteAddress(addressID int, userID int) error
	MakeDefaultAddress(addressID int, userID int) error
	GetUserAddresses(userID int) ([]models.Address, error)
	// Utility methods
	FixOldOrderAddresses() error
}

// Handler, HTTP isteklerini yönetir.
type Handler struct {
	db           DBInterface
	email        *services.EmailService
	cartService  *services.CartService
	securityLog  *services.SecurityLogger
	spamDetector *services.SpamDetector
	rateLimit    map[string]time.Time // Rate limiting için
}

// NewHandler, yeni bir Handler örneği oluşturur.
func NewHandler(db DBInterface) *Handler {
	return &Handler{
		db:           db,
		email:        services.NewEmailService(),
		cartService:  services.NewCartService(db),
		securityLog:  services.NewSecurityLogger(),
		spamDetector: services.NewSpamDetector(),
		rateLimit:    make(map[string]time.Time),
	}
}

// Admin credentials (in production, these should be stored securely)
const (
	ADMIN_USERNAME = "cenap"
	ADMIN_PASSWORD = "cenap1980"
)

// AuthMiddleware checks if user is authenticated for admin routes
func (h *Handler) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.URL.Path == "/admin/login" {
			c.Next()
			return
		}

		session, _ := c.Cookie("admin_session")
		if session == "" {
			c.Redirect(http.StatusSeeOther, "/admin/login")
			c.Abort()
			return
		}
		c.Next()
	}
}

func (h *Handler) AdminLoginPage(c *gin.Context) {
	c.HTML(http.StatusOK, "admin_login.html", gin.H{
		"title": "Admin Girişi",
	})
}

func (h *Handler) AdminLogin(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	log.Printf("Login attempt - Username: %s, Password: %s", username, password)

	if username == ADMIN_USERNAME && password == ADMIN_PASSWORD {
		log.Printf("Login successful for user: %s", username)
		sessionID := uuid.New().String()
		c.SetCookie("admin_session", sessionID, 3600, "/", "", false, true)
		c.Redirect(http.StatusSeeOther, "/admin")
		return
	}

	log.Printf("Login failed for user: %s", username)
	c.HTML(http.StatusUnauthorized, "admin_login.html", gin.H{
		"title": "Admin Girişi",
		"error": "Geçersiz kullanıcı adı veya şifre",
	})
}

func (h *Handler) AdminLogout(c *gin.Context) {
	c.SetCookie("admin_session", "", -1, "/", "", false, true)
	c.Redirect(http.StatusSeeOther, "/admin/login")
}

// --- User Authentication Handlers ---

// AuthUserMiddleware, kullanıcıların kimliğini doğrular.
func (h *Handler) AuthUserMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		session, err := c.Cookie("user_session")
		if err != nil || session == "" {
			c.Redirect(http.StatusSeeOther, "/login")
			c.Abort()
			return
		}
		// Oturumun geçerli olup olmadığını kontrol et (örneğin, session ID'yi veritabanında saklayarak)
		// Bu basit örnekte sadece cookie varlığına bakıyoruz.
		c.Next()
	}
}

// LoginPage, kullanıcı giriş sayfasını oluşturur.
func (h *Handler) LoginPage(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", gin.H{
		"title": "Giriş Yap",
	})
}

// HandleLogin, kullanıcı girişini yönetir.
func (h *Handler) HandleLogin(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	user, err := h.db.GetUserByUsername(username)
	if err != nil {
		log.Printf("Login failed for user %s: %v", username, err)
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{
			"title": "Giriş Yap",
			"error": "Kullanıcı adı veya parola hatalı.",
		})
		return
	}

	log.Printf("DEBUG: User found - Username: %s, PasswordHash: %s", username, user.PasswordHash)
	log.Printf("DEBUG: Attempting login with password: %s", password)

	// Şifre kontrolü - hem hash hem de plain text kontrol et
	passwordValid := false

	// Önce hash ile kontrol et
	if user.PasswordHash != "" && CheckPasswordHash(password, user.PasswordHash) {
		passwordValid = true
		log.Printf("Password validated with hash for user %s", username)
	}

	// Hash başarısız olursa plain text ile kontrol et (geçici çözüm)
	if !passwordValid && user.PlainPassword != "" && user.PlainPassword == password {
		passwordValid = true
		log.Printf("Password validated with plain text for user %s", username)
	}

	if !passwordValid {
		log.Printf("Incorrect password for user %s. Hash: %s, Plain: %s, Entered: %s",
			username, user.PasswordHash, user.PlainPassword, password)
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{
			"title": "Giriş Yap",
			"error": "Kullanıcı adı veya parola hatalı.",
		})
		return
	}

	// E-posta doğrulama kontrolü
	if !user.EmailVerified {
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{
			"title": "Giriş Yap",
			"error": "Lütfen önce e-posta adresinizi doğrulayın.",
		})
		return
	}

	// Mevcut session ID'yi al (eğer varsa)
	oldSessionID, _ := c.Cookie("user_session")

	// Yeni session ID oluştur
	sessionID := uuid.New().String()
	c.SetCookie("user_session", sessionID, 3600, "/", "", false, true)
	c.SetCookie("username", user.Username, 3600, "/", "", false, true)

	// Eğer eski session varsa, yeni session ID ile güncelle
	if oldSessionID != "" {
		userAgent := c.GetHeader("User-Agent")
		if userAgent == "" {
			userAgent = "Unknown"
		}

		// Eski session'ı yeni session ID ile güncelle
		_, err := h.db.GetOrCreateSupportSession(sessionID, user.Username, &user.ID, userAgent)
		if err != nil {
			log.Printf("HandleLogin - Error updating support session: %v", err)
		} else {
			log.Printf("HandleLogin - Support session updated for user %s: %s -> %s", user.Username, oldSessionID, sessionID)
		}
	}

	c.Redirect(http.StatusSeeOther, "/")
}

// RegisterPage, kullanıcı kayıt sayfasını oluşturur.
func (h *Handler) RegisterPage(c *gin.Context) {
	c.HTML(http.StatusOK, "register.html", gin.H{
		"title": "Kayıt Ol",
	})
}

// HandleRegister, kullanıcı kayıt işlemini yönetir.
func (h *Handler) HandleRegister(c *gin.Context) {
	log.Printf("🚨🚨🚨 HANDLEREGISTER ÇAĞRILDI! 🚨🚨🚨")
	fullName := c.PostForm("fullName")
	email := c.PostForm("email")
	password := c.PostForm("password")
	confirmPassword := c.PostForm("confirmPassword")
	captcha := c.PostForm("captcha")

	log.Printf("🔍 HandleRegister - Form Data: fullName='%s', email='%s', password='%s', confirmPassword='%s', captcha='%s'",
		fullName, email, password, confirmPassword, captcha)

	// Validasyon
	if fullName == "" || email == "" || password == "" || captcha == "" {
		c.HTML(http.StatusBadRequest, "register.html", gin.H{
			"title": "Kayıt Ol",
			"error": "Tüm alanları doldurun.",
		})
		return
	}

	if password != confirmPassword {
		c.HTML(http.StatusBadRequest, "register.html", gin.H{
			"title": "Kayıt Ol",
			"error": "Parolalar eşleşmiyor.",
		})
		return
	}

	// Captcha kontrolü
	if captcha != "1234" {
		c.HTML(http.StatusBadRequest, "register.html", gin.H{
			"title": "Kayıt Ol",
			"error": "Güvenlik kodu hatalı.",
		})
		return
	}

	// E-posta format kontrolü
	emailRegex := regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
	if !emailRegex.MatchString(email) {
		c.HTML(http.StatusBadRequest, "register.html", gin.H{
			"title": "Kayıt Ol",
			"error": "Geçerli bir e-posta adresi girin.",
		})
		return
	}

	// Anti-spam filtresi - Bitcoin/crypto spam kayıtları engelle
	spamKeywords := []string{
		"BTC", "bitcoin", "crypto", "deposit", "transfer", "pending", "redeem",
		"graph.org", "blockchain", "wallet", "exchange", "trading", "investment",
		"📂", "📲", "✉️", "🔷", "=>", "Review?", "Accept?",
	}

	fullNameLower := strings.ToLower(fullName)
	emailLower := strings.ToLower(email)

	for _, keyword := range spamKeywords {
		keywordLower := strings.ToLower(keyword)
		if strings.Contains(fullNameLower, keywordLower) || strings.Contains(emailLower, keywordLower) {
			log.Printf("Spam kayıt engellendi - Kullanıcı: %s, Email: %s, Keyword: %s", fullName, email, keyword)
			c.HTML(http.StatusBadRequest, "register.html", gin.H{
				"title": "Kayıt Ol",
				"error": "Kayıt işlemi tamamlanamadı. Lütfen farklı bilgiler deneyin.",
			})
			return
		}
	}

	// Şifreyi hashle
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		c.HTML(http.StatusInternalServerError, "register.html", gin.H{
			"title": "Kayıt Ol",
			"error": "Kayıt işlemi sırasında bir hata oluştu.",
		})
		return
	}

	// Kullanıcıyı oluştur (e-posta adresini kullanıcı adı olarak kullan)
	user := &models.User{
		FullName:      fullName,
		Username:      email, // E-posta adresini kullanıcı adı olarak kullan
		Email:         email,
		PasswordHash:  string(hashedPassword),
		PlainPassword: password, // Admin paneli için gerçek şifreyi sakla
	}

	if err := h.db.CreateUser(user); err != nil {
		log.Printf("Error creating user: %v", err)
		c.HTML(http.StatusInternalServerError, "register.html", gin.H{
			"title": "Kayıt Ol",
			"error": "Bu e-posta adresi zaten kullanımda.",
		})
		return
	}

	// E-posta doğrulama token'ı oluştur ve gönder
	verificationToken := uuid.New().String()

	// Kullanıcının doğrulama token'ını veritabanında güncelle
	if err := h.db.UpdateUserVerificationToken(user.ID, verificationToken); err != nil {
		log.Printf("Error updating verification token: %v", err)
		// Token güncellenemese bile kayıt işlemi devam eder
	}

	// E-posta doğrulama e-postası gönder
	emailSent := true
	if err := h.email.SendEmailVerification(email, fullName, verificationToken); err != nil {
		log.Printf("Error sending verification email: %v", err)
		emailSent = false
	} else {
		log.Printf("✅ Verification email sent successfully to: %s", email)
	}

	// Hoş geldin e-postası gönder
	if err := h.email.SendWelcomeEmail(email, fullName); err != nil {
		log.Printf("Error sending welcome email: %v", err)
	} else {
		log.Printf("✅ Welcome email sent successfully to: %s", email)
	}

	successMessage := "Kayıt işlemi başarılı! "
	if emailSent {
		successMessage += "Lütfen e-posta adresinizi kontrol edin ve doğrulama linkine tıklayın."
	} else {
		successMessage += "E-posta gönderilemedi. Lütfen manuel olarak e-posta doğrulaması yapın."
	}

	c.HTML(http.StatusOK, "register.html", gin.H{
		"title":   "Kayıt Ol",
		"success": successMessage,
	})
}

// UserLogout, kullanıcı oturumunu kapatır.
func (h *Handler) UserLogout(c *gin.Context) {
	c.SetCookie("user_session", "", -1, "/", "", false, true)
	c.SetCookie("username", "", -1, "/", "", false, true)
	c.Redirect(http.StatusSeeOther, "/login")
}

// ProfilePage, kullanıcı profil sayfasını oluşturur.
func (h *Handler) ProfilePage(c *gin.Context) {
	username, _ := c.Cookie("username")
	isLoggedIn := username != ""

	user, err := h.db.GetUserByUsername(username)
	if err != nil {
		c.Redirect(http.StatusSeeOther, "/login")
		return
	}

	addresses, err := h.db.GetUserAddresses(user.ID)
	if err != nil {
		log.Printf("ProfilePage - Error getting addresses: %v", err)
		addresses = []models.Address{}
	}

	// URL parametrelerini al
	success := c.Query("success")
	error := c.Query("error")

	c.HTML(http.StatusOK, "profile.html", gin.H{
		"title":      "Profilim",
		"username":   username,
		"isLoggedIn": isLoggedIn,
		"addresses":  addresses,
		"success":    success,
		"error":      error,
	})
}

func (h *Handler) HomePage(c *gin.Context) {
	log.Printf("🔍 HomePage çağrıldı - URL: %s", c.Request.URL.Path)

	// Veritabanından ürünleri al
	log.Printf("📦 Ürünler veritabanından alınıyor...")
	products, err := h.db.GetAllProducts()
	if err != nil {
		log.Printf("❌ Ürünler alınırken hata: %v", err)
		products = []models.Product{}
	} else {
		log.Printf("✅ %d ürün başarıyla alındı", len(products))
	}

	// Kullanıcı bilgilerini al
	username, _ := c.Cookie("username")
	isLoggedIn := username != ""
	log.Printf("👤 Kullanıcı durumu - Username: %s, IsLoggedIn: %t", username, isLoggedIn)

	// Template verilerini hazırla
	templateData := gin.H{
		"products":    products,
		"title":       "Su Arıtma Uzmanı - Ana Sayfa",
		"isLoggedIn":  isLoggedIn,
		"username":    username,
		"current_url": c.Request.URL.Path,
	}

	log.Printf("📄 Template render ediliyor: home.html")
	log.Printf("📊 Template verileri: %+v", templateData)

	// Template'i render et
	c.HTML(http.StatusOK, "home.html", templateData)

	log.Printf("✅ HomePage başarıyla tamamlandı")
}

func (h *Handler) ProductsPage(c *gin.Context) {
	allProducts, err := h.db.GetAllProducts()
	if err != nil {
		log.Printf("Error getting products: %v", err)
		allProducts = []models.Product{}
	}

	// Kategoriye göre filtreleme
	category := c.Query("category")
	var filteredProducts []models.Product
	if category != "" {
		for _, p := range allProducts {
			if p.Category == category {
				filteredProducts = append(filteredProducts, p)
			}
		}
	} else {
		filteredProducts = allProducts
	}

	// Sabit kategoriler - su arıtma işi için
	categories := []string{
		"Su Arıtma Ürünleri",
		"Yedek Parça",
		"Aksesuarlar",
	}

	username, _ := c.Cookie("username")
	isLoggedIn := username != ""

	c.HTML(http.StatusOK, "products.html", gin.H{
		"products":         filteredProducts,
		"categories":       categories,
		"title":            "Ürünler",
		"selectedCategory": category,
		"isLoggedIn":       isLoggedIn,
		"username":         username,
	})
}

func (h *Handler) AdminPage(c *gin.Context) {
	// Cache kontrolü ekle
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Header("Pragma", "no-cache")
	c.Header("Expires", "0")

	products, err := h.db.GetAllProducts()
	if err != nil {
		log.Printf("Error getting products: %v", err)
		products = []models.Product{}
	}

	c.HTML(http.StatusOK, "admin.html", gin.H{
		"products": products,
		"title":    "Admin Paneli",
	})
}

func (h *Handler) AddProduct(c *gin.Context) {
	var form models.ProductForm
	if err := c.ShouldBind(&form); err != nil {
		c.HTML(http.StatusBadRequest, "admin.html", gin.H{
			"error": "Form verileri eksik veya hatalı",
		})
		return
	}

	// Aynı isimde ürün var mı kontrol et
	existingProducts, err := h.db.GetAllProducts()
	if err == nil {
		for _, existing := range existingProducts {
			if existing.Name == form.Name {
				c.HTML(http.StatusBadRequest, "admin.html", gin.H{
					"error":    "Bu isimde bir ürün zaten mevcut",
					"products": existingProducts,
				})
				return
			}
		}
	}

	file, err := c.FormFile("image")
	var imagePath string
	if err == nil && file != nil {
		ext := filepath.Ext(file.Filename)
		if ext != ".jpg" && ext != ".jpeg" && ext != ".png" && ext != ".gif" {
			c.HTML(http.StatusBadRequest, "admin.html", gin.H{
				"error": "Sadece JPG, PNG ve GIF dosyaları kabul edilir",
			})
			return
		}

		filename := uuid.New().String() + ext
		uploadPath := filepath.Join("static", "uploads", filename)

		if err := c.SaveUploadedFile(file, uploadPath); err != nil {
			log.Printf("Error saving file: %v", err)
			c.HTML(http.StatusInternalServerError, "admin.html", gin.H{
				"error": "Resim yüklenirken hata oluştu",
			})
			return
		}
		imagePath = "/static/uploads/" + filename
	}

	// Dinamik özellikleri manuel olarak parse et
	features := make(map[string]string)
	formValues := c.Request.PostForm

	for key, values := range formValues {
		if len(values) > 0 && strings.HasPrefix(key, "features[") && strings.Contains(key, "_key") {
			// Key'i çıkar
			keyValue := values[0]
			// Value'yu bul
			valueKey := strings.Replace(key, "_key", "_value", 1)
			if valueValues, exists := formValues[valueKey]; exists && len(valueValues) > 0 {
				valueValue := valueValues[0]
				if keyValue != "" && valueValue != "" {
					features[keyValue] = valueValue
				}
			}
		}
	}

	// Dinamik özellikleri JSON'a çevir
	var featuresJSON string
	if len(features) > 0 {
		featuresBytes, err := json.Marshal(features)
		if err != nil {
			log.Printf("Error marshaling features: %v", err)
			c.HTML(http.StatusInternalServerError, "admin.html", gin.H{
				"error": "Özellikler kaydedilirken hata oluştu",
			})
			return
		}
		featuresJSON = string(featuresBytes)
	}

	product := &models.Product{
		Name:        form.Name,
		Description: form.Description,
		Price:       form.Price,
		Image:       imagePath,
		Category:    form.Category,
		Stock:       form.Stock,
		Features:    featuresJSON,
	}

	if err := h.db.CreateProduct(product); err != nil {
		log.Printf("Error creating product: %v", err)
		products, _ := h.db.GetAllProducts()
		c.HTML(http.StatusInternalServerError, "admin.html", gin.H{
			"error":    "Ürün eklenirken hata oluştu",
			"products": products,
		})
		return
	}

	// Başarılı ekleme sonrası cache'i temizle
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Header("Pragma", "no-cache")
	c.Header("Expires", "0")

	c.Redirect(http.StatusSeeOther, "/admin")
}

func (h *Handler) DeleteProduct(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Geçersiz ürün ID"})
		return
	}

	err = h.db.DeleteProduct(id)
	if err != nil {
		log.Printf("Error deleting product: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ürün silinirken hata oluştu"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Ürün başarıyla silindi"})
}

func (h *Handler) UpdateProduct(c *gin.Context) {
	idStr := c.PostForm("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Geçersiz ürün ID"})
		return
	}

	// Mevcut ürünü al
	existingProduct, err := h.db.GetProductByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Ürün bulunamadı"})
		return
	}

	// Form verilerini al
	name := c.PostForm("name")
	description := c.PostForm("description")
	category := c.PostForm("category")
	priceStr := c.PostForm("price")
	stockStr := c.PostForm("stock")

	price, err := strconv.ParseFloat(priceStr, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Geçersiz fiyat"})
		return
	}

	stock, err := strconv.Atoi(stockStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Geçersiz stok miktarı"})
		return
	}

	// Ürün bilgilerini güncelle
	existingProduct.Name = name
	existingProduct.Description = description
	existingProduct.Category = category
	existingProduct.Price = price
	existingProduct.Stock = stock

	// Yeni görsel yüklendiyse işle
	file, header, err := c.Request.FormFile("image")
	if err == nil && file != nil {
		defer file.Close()

		// Dosya uzantısını kontrol et
		ext := filepath.Ext(header.Filename)
		if ext != ".jpg" && ext != ".jpeg" && ext != ".png" && ext != ".gif" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Sadece jpg, jpeg, png ve gif dosyaları kabul edilir"})
			return
		}

		// Yeni dosya adı oluştur
		filename := uuid.New().String() + ext
		uploadPath := filepath.Join("static", "uploads", filename)

		// Dosyayı kaydet
		err = c.SaveUploadedFile(header, uploadPath)
		if err != nil {
			log.Printf("Error saving uploaded file: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Dosya yüklenirken hata oluştu"})
			return
		}

		// Eski görseli sil (varsa)
		if existingProduct.Image != "" {
			oldImagePath := filepath.Join("static", "uploads", existingProduct.Image)
			os.Remove(oldImagePath)
		}

		existingProduct.Image = filename
	}

	// Veritabanını güncelle
	err = h.db.UpdateProduct(existingProduct)
	if err != nil {
		log.Printf("Error updating product: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ürün güncellenirken hata oluştu"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Ürün başarıyla güncellendi"})
}

func (h *Handler) AboutPage(c *gin.Context) {
	username, _ := c.Cookie("username")
	isLoggedIn := username != ""

	c.HTML(http.StatusOK, "about.html", gin.H{
		"title":      "Hakkımızda",
		"isLoggedIn": isLoggedIn,
		"username":   username,
	})
}

func (h *Handler) ContactPage(c *gin.Context) {
	username, _ := c.Cookie("username")
	isLoggedIn := username != ""

	c.HTML(http.StatusOK, "contact.html", gin.H{
		"title":      "İletişim",
		"isLoggedIn": isLoggedIn,
		"username":   username,
	})
}

func (h *Handler) TeknikServisPage(c *gin.Context) {
	username, _ := c.Cookie("username")
	isLoggedIn := username != ""

	c.HTML(http.StatusOK, "teknik_servis.html", gin.H{
		"title":      "Teknik Servis",
		"isLoggedIn": isLoggedIn,
		"username":   username,
	})
}

// HandleTeknikServisForm - Teknik servis formu gönderimi
func (h *Handler) HandleTeknikServisForm(c *gin.Context) {
	var request struct {
		Name        string `json:"name"`
		Phone       string `json:"phone"`
		Email       string `json:"email"`
		Address     string `json:"address"`
		DeviceType  string `json:"device_type"`
		Brand       string `json:"brand"`
		Model       string `json:"model"`
		Problem     string `json:"problem"`
		Description string `json:"description"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Geçersiz form verisi"})
		return
	}

	// Form verilerini kontrol et
	if strings.TrimSpace(request.Name) == "" || strings.TrimSpace(request.Phone) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Ad ve telefon alanları zorunludur"})
		return
	}

	// MAIL GÖNDERİMİ EKLE
	if h.email != nil {
		subject := "Yeni Teknik Servis Talebi - " + request.Name
		body := fmt.Sprintf(`
			<h3>Yeni Teknik Servis Talebi</h3>
			<p><strong>Ad Soyad:</strong> %s</p>
			<p><strong>Telefon:</strong> %s</p>
			<p><strong>E-posta:</strong> %s</p>
			<p><strong>Adres:</strong> %s</p>
			<p><strong>Cihaz Türü:</strong> %s</p>
			<p><strong>Marka:</strong> %s</p>
			<p><strong>Model:</strong> %s</p>
			<p><strong>Problem:</strong> %s</p>
			<p><strong>Açıklama:</strong> %s</p>
			<br>
			<p><strong>Tarih:</strong> %s</p>
			<br>
			<p><strong>Admin Panel:</strong> <a href="https://irmaksuaritma.com/admin">https://irmaksuaritma.com/admin</a></p>
		`, request.Name, request.Phone, request.Email, request.Address, request.DeviceType, request.Brand, request.Model, request.Problem, request.Description, time.Now().Format("2006-01-02 15:04:05"))

		err := h.email.SendEmail("wbcenapoktay@gmail.com", subject, body)
		if err != nil {
			log.Printf("HandleTeknikServisForm - Mail gönderim hatası: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Form gönderilemedi"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Teknik servis talebiniz başarıyla gönderildi. En kısa sürede size ulaşacağız.",
	})
}

// --- Product Detail Handlers ---

// ProductDetailPage, tekil ürün detay sayfasını gösterir
func (h *Handler) ProductDetailPage(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		log.Printf("Invalid product ID: %s", idStr)
		c.HTML(http.StatusNotFound, "404.html", gin.H{
			"title": "Ürün Bulunamadı",
			"error": "Geçersiz ürün ID'si",
		})
		return
	}

	product, err := h.db.GetProductByID(id)
	if err != nil {
		log.Printf("Product not found: %d", id)
		c.HTML(http.StatusNotFound, "404.html", gin.H{
			"title": "Ürün Bulunamadı",
			"error": "Ürün bulunamadı",
		})
		return
	}

	username, _ := c.Cookie("username")
	isLoggedIn := username != ""

	c.HTML(http.StatusOK, "product_detail.html", gin.H{
		"product":    product,
		"title":      product.Name + " - Ürün Detayı",
		"isLoggedIn": isLoggedIn,
		"username":   username,
	})
}

// SparePartDetailPage, yedek parça detay sayfasını gösterir
func (h *Handler) SparePartDetailPage(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		log.Printf("Invalid spare part ID: %s", idStr)
		c.HTML(http.StatusNotFound, "404.html", gin.H{
			"title": "Yedek Parça Bulunamadı",
			"error": "Geçersiz yedek parça ID'si",
		})
		return
	}

	// Yedek parça kategorisindeki ürünleri ara
	product, err := h.db.GetProductByID(id)
	if err != nil || product.Category != "Yedek Parça" {
		log.Printf("Spare part not found: %d", id)
		c.HTML(http.StatusNotFound, "404.html", gin.H{
			"title": "Yedek Parça Bulunamadı",
			"error": "Yedek parça bulunamadı",
		})
		return
	}

	username, _ := c.Cookie("username")
	isLoggedIn := username != ""

	c.HTML(http.StatusOK, "spare_part_detail.html", gin.H{
		"product":    product,
		"title":      product.Name + " - Yedek Parça Detayı",
		"isLoggedIn": isLoggedIn,
		"username":   username,
	})
}

// GuestCheckoutPage, misafir ödeme sayfasını gösterir
func (h *Handler) GuestCheckoutPage(c *gin.Context) {
	c.HTML(http.StatusOK, "guest_checkout.html", gin.H{
		"title":      "Misafir Ödeme",
		"isLoggedIn": false,
	})
}

// --- Password Reset Handlers ---

// ForgotPasswordPage, şifremi unuttum sayfasını oluşturur.
func (h *Handler) ForgotPasswordPage(c *gin.Context) {
	c.HTML(http.StatusOK, "forgot_password.html", gin.H{
		"title": "Şifremi Unuttum",
	})
}

// HandleForgotPassword, şifre sıfırlama isteğini yönetir.
func (h *Handler) HandleForgotPassword(c *gin.Context) {
	email := c.PostForm("email")

	// Kullanıcının var olup olmadığını kontrol et
	_, err := h.db.GetUserByEmail(email)
	if err != nil {
		// Güvenlik için kullanıcı bulunamasa bile başarılı mesajı göster
		c.HTML(http.StatusOK, "forgot_password.html", gin.H{
			"title":   "Şifremi Unuttum",
			"success": "Eğer bu e-posta adresi kayıtlıysa, şifre sıfırlama bağlantısı gönderilecektir.",
		})
		return
	}

	// Şifre sıfırlama token'ı oluştur
	token := uuid.New().String()
	if err := h.db.CreatePasswordResetToken(email, token); err != nil {
		log.Printf("Error creating reset token: %v", err)
		c.HTML(http.StatusInternalServerError, "forgot_password.html", gin.H{
			"title": "Şifremi Unuttum",
			"error": "Şifre sıfırlama işlemi sırasında bir hata oluştu.",
		})
		return
	}

	// E-posta gönder
	if err := h.email.SendPasswordResetEmail(email, token); err != nil {
		log.Printf("Error sending password reset email: %v", err)
		// E-posta gönderilemese bile kullanıcıya başarılı mesajı göster
		// Token terminal log'unda görünecek
	}

	c.HTML(http.StatusOK, "forgot_password.html", gin.H{
		"title":   "Şifremi Unuttum",
		"success": "Şifre sıfırlama bağlantısı e-posta adresinize gönderildi. Lütfen e-postanızı kontrol edin.",
	})
}

// ResetPasswordPage, şifre sıfırlama sayfasını oluşturur.
func (h *Handler) ResetPasswordPage(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.HTML(http.StatusBadRequest, "reset_password.html", gin.H{
			"title": "Şifre Sıfırlama",
			"error": "Geçersiz şifre sıfırlama bağlantısı.",
		})
		return
	}

	// Token'ın geçerli olup olmadığını kontrol et
	_, err := h.db.GetUserByResetToken(token)
	if err != nil {
		c.HTML(http.StatusBadRequest, "reset_password.html", gin.H{
			"title": "Şifre Sıfırlama",
			"error": "Geçersiz veya süresi dolmuş şifre sıfırlama bağlantısı.",
		})
		return
	}

	c.HTML(http.StatusOK, "reset_password.html", gin.H{
		"title": "Şifre Sıfırlama",
		"token": token,
	})
}

// HandleResetPassword, şifre sıfırlama işlemini yönetir.
func (h *Handler) HandleResetPassword(c *gin.Context) {
	token := c.PostForm("token")
	password := c.PostForm("password")
	confirmPassword := c.PostForm("confirmPassword")

	if password != confirmPassword {
		c.HTML(http.StatusBadRequest, "reset_password.html", gin.H{
			"title": "Şifre Sıfırlama",
			"error": "Parolalar eşleşmiyor.",
			"token": token,
		})
		return
	}

	// Token'ın geçerli olup olmadığını kontrol et
	user, err := h.db.GetUserByResetToken(token)
	if err != nil {
		c.HTML(http.StatusBadRequest, "reset_password.html", gin.H{
			"title": "Şifre Sıfırlama",
			"error": "Geçersiz veya süresi dolmuş şifre sıfırlama bağlantısı.",
		})
		return
	}

	// Yeni şifreyi hashle
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		c.HTML(http.StatusInternalServerError, "reset_password.html", gin.H{
			"title": "Şifre Sıfırlama",
			"error": "Şifre güncellenirken bir hata oluştu.",
			"token": token,
		})
		return
	}

	// Kullanıcının şifresini güncelle
	user.PasswordHash = string(hashedPassword)
	user.PlainPassword = password // Yeni şifreyi plain password alanına da kaydet
	if err := h.db.UpdateUser(user); err != nil {
		log.Printf("Error updating user password: %v", err)
		c.HTML(http.StatusInternalServerError, "reset_password.html", gin.H{
			"title": "Şifre Sıfırlama",
			"error": "Şifre güncellenirken bir hata oluştu.",
			"token": token,
		})
		return
	}

	// Reset token'ını temizle
	if err := h.db.ClearResetToken(user.ID); err != nil {
		log.Printf("Error clearing reset token: %v", err)
	}

	c.HTML(http.StatusOK, "reset_password.html", gin.H{
		"title":   "Şifre Sıfırlama",
		"success": "Şifreniz başarıyla güncellendi. Yeni şifrenizle giriş yapabilirsiniz.",
	})
}

// UserUpdateOrderStatus, kullanıcının kendi siparişinin durumunu güncellemesini sağlar
func (h *Handler) UserUpdateOrderStatus(c *gin.Context) {
	orderIDStr := c.Param("id")
	orderID, err := strconv.Atoi(orderIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Geçersiz sipariş ID"})
		return
	}

	// Kullanıcı ID'sini al
	username, _ := c.Cookie("username")
	user, err := h.db.GetUserByUsername(username)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "Oturum geçersiz"})
		return
	}

	// Siparişin var olup olmadığını kontrol et
	order, err := h.db.GetOrderByID(orderID)
	if err != nil {
		log.Printf("UserUpdateOrderStatus - Order not found: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "Sipariş bulunamadı"})
		return
	}

	// Session tabanlı siparişler için kontrol
	sessionID, _ := c.Cookie("user_session")
	if order.UserID != user.ID && order.SessionID != sessionID {
		log.Printf("UserUpdateOrderStatus - User %s not authorized to update order %d", username, orderID)
		c.JSON(http.StatusForbidden, gin.H{"success": false, "error": "Bu siparişi güncelleme yetkiniz yok"})
		return
	}

	// Yeni durumu al
	var request struct {
		Status string `json:"status" binding:"required"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Geçersiz istek"})
		return
	}

	// Geçerli durumları kontrol et
	validStatuses := []string{"pending", "confirmed", "shipped", "delivered", "cancelled"}
	isValidStatus := false
	for _, status := range validStatuses {
		if request.Status == status {
			isValidStatus = true
			break
		}
	}

	if !isValidStatus {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Geçersiz sipariş durumu"})
		return
	}

	// Sipariş durumunu güncelle
	err = h.db.UpdateOrderStatus(orderID, request.Status)
	if err != nil {
		log.Printf("UserUpdateOrderStatus - Error updating order status: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Sipariş durumu güncellenemedi"})
		return
	}

	log.Printf("UserUpdateOrderStatus - Order %d status updated to %s by user %s", orderID, request.Status, username)
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Sipariş durumu başarıyla güncellendi",
	})
}

// UserCancelOrder, kullanıcının kendi siparişini iptal etmesini sağlar (sadece pending durumunda)
func (h *Handler) UserCancelOrder(c *gin.Context) {
	orderIDStr := c.Param("id")
	orderID, err := strconv.Atoi(orderIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Geçersiz sipariş ID"})
		return
	}

	// Kullanıcı ID'sini al
	username, _ := c.Cookie("username")
	user, err := h.db.GetUserByUsername(username)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "Oturum geçersiz"})
		return
	}

	log.Printf("UserCancelOrder - User %s (%d) attempting to cancel order %d", username, user.ID, orderID)

	// Siparişin var olup olmadığını kontrol et
	order, err := h.db.GetOrderByID(orderID)
	if err != nil {
		log.Printf("UserCancelOrder - Order not found: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "Sipariş bulunamadı"})
		return
	}

	// Session tabanlı siparişler için kontrol
	sessionID, _ := c.Cookie("user_session")
	if order.UserID != user.ID && order.SessionID != sessionID {
		log.Printf("UserCancelOrder - User %s not authorized to cancel order %d", username, orderID)
		c.JSON(http.StatusForbidden, gin.H{"success": false, "error": "Bu siparişi iptal etme yetkiniz yok"})
		return
	}

	// "pending" ve "cancelled" durumundaki siparişler silinebilir
	if order.Status != "pending" && order.Status != "cancelled" {
		log.Printf("UserCancelOrder - Cannot delete order %d with status %s", orderID, order.Status)

		var errorMessage string
		switch order.Status {
		case "confirmed":
			errorMessage = "Sipariş onaylandığı için artık silinemez"
		case "shipped":
			errorMessage = "Siparişiniz kargoya verildi. Artık silinemez"
		case "delivered":
			errorMessage = "Sipariş teslim edildiği için silinemez"
		default:
			errorMessage = "Bu sipariş durumunda silme işlemi yapılamaz"
		}

		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": errorMessage})
		return
	}

	// Eğer sipariş "pending" ise önce "cancelled" yap, sonra sil
	if order.Status == "pending" {
		err = h.db.UpdateOrderStatus(orderID, "cancelled")
		if err != nil {
			log.Printf("UserCancelOrder - Error updating order status: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Sipariş iptal edilemedi"})
			return
		}
	}

	// Siparişi tamamen sil
	err = h.db.DeleteOrder(orderID)
	if err != nil {
		log.Printf("UserCancelOrder - Error deleting order: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Sipariş silinemedi"})
		return
	}

	log.Printf("UserCancelOrder - Order %d successfully deleted by user %s", orderID, username)
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Sipariş başarıyla silindi",
	})
}

// OrdersPage, kullanıcının sipariş geçmişini gösterir
func (h *Handler) OrdersPage(c *gin.Context) {
	username, _ := c.Cookie("username")
	if username == "" {
		c.Redirect(http.StatusSeeOther, "/login")
		return
	}

	user, err := h.db.GetUserByUsername(username)
	if err != nil {
		log.Printf("OrdersPage - Error getting user: %v", err)
		c.Redirect(http.StatusSeeOther, "/login")
		return
	}

	log.Printf("OrdersPage - Getting orders for UserID: %d", user.ID)

	orders, err := h.db.GetOrdersByUserID(user.ID)
	if err != nil {
		log.Printf("OrdersPage - Error getting orders: %v", err)
		orders = []models.Order{}
	}

	log.Printf("OrdersPage - Found %d orders for UserID: %d", len(orders), user.ID)

	c.HTML(http.StatusOK, "orders.html", gin.H{
		"title":      "Siparişlerim",
		"orders":     orders,
		"isLoggedIn": true,
		"username":   username,
	})
}

// GetOrderDetail, kullanıcının sipariş detayını getirir
func (h *Handler) GetOrderDetail(c *gin.Context) {
	orderIDStr := c.Param("id")
	orderID, err := strconv.Atoi(orderIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Geçersiz sipariş ID"})
		return
	}

	username, _ := c.Cookie("username")
	user, err := h.db.GetUserByUsername(username)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "Oturum geçersiz"})
		return
	}

	log.Printf("GetOrderDetail - Getting order %d for user %d", orderID, user.ID)

	order, err := h.db.GetOrderByID(orderID)
	if err != nil {
		log.Printf("GetOrderDetail - Error getting order: %v", err)
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "Sipariş bulunamadı"})
		return
	}

	// Session tabanlı siparişler için kontrol
	sessionID, _ := c.Cookie("user_session")
	if order.UserID != user.ID && order.SessionID != sessionID {
		log.Printf("GetOrderDetail - User %d not authorized to view order %d", user.ID, orderID)
		c.JSON(http.StatusForbidden, gin.H{"success": false, "error": "Bu siparişi görüntüleme yetkiniz yok"})
		return
	}

	log.Printf("GetOrderDetail - Successfully returning order %d", orderID)
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"order":   order,
	})
}

// Cart handlers
func (h *Handler) CartPage(c *gin.Context) {
	sessionID, _ := c.Cookie("user_session")
	if sessionID == "" {
		sessionID = generateSessionID()
		c.SetCookie("user_session", sessionID, 3600*24*30, "/", "", false, true)
		log.Printf("CartPage - Created new session ID: %s", sessionID)
	} else {
		log.Printf("CartPage - Using existing session ID: %s", sessionID)
	}

	cart := h.cartService.GetCart(sessionID)
	log.Printf("CartPage - Cart has %d items, total: %.2f", len(cart.Items), cart.TotalPrice)

	username, _ := c.Cookie("username")
	isLoggedIn := username != ""

	c.HTML(http.StatusOK, "cart.html", gin.H{
		"title":      "Sepetim",
		"cart":       cart,
		"isLoggedIn": isLoggedIn,
		"username":   username,
	})
}

func (h *Handler) AddToCart(c *gin.Context) {
	sessionID, _ := c.Cookie("user_session")
	if sessionID == "" {
		sessionID = generateSessionID()
		c.SetCookie("user_session", sessionID, 3600*24*30, "/", "", false, true)
		log.Printf("AddToCart - Created new session ID: %s", sessionID)
	} else {
		log.Printf("AddToCart - Using existing session ID: %s", sessionID)
	}

	var req struct {
		ProductID int `json:"product_id"`
		Quantity  int `json:"quantity"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("AddToCart - JSON bind error: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Geçersiz veri"})
		return
	}

	log.Printf("AddToCart - Adding product %d, quantity %d to session %s", req.ProductID, req.Quantity, sessionID)

	product, err := h.db.GetProductByID(req.ProductID)
	if err != nil {
		log.Printf("AddToCart - Product not found: %d", req.ProductID)
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "Ürün bulunamadı"})
		return
	}

	err = h.cartService.AddToCart(sessionID, *product, req.Quantity)
	if err != nil {
		log.Printf("AddToCart - Error adding to cart: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Sepete eklenemedi"})
		return
	}

	// Sepet sayısını da logla
	cart := h.cartService.GetCart(sessionID)
	log.Printf("AddToCart - Cart now has %d items, total: %.2f", len(cart.Items), cart.TotalPrice)

	log.Printf("AddToCart - Successfully added product %d to cart for session %s", req.ProductID, sessionID)
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Ürün sepete eklendi"})
}

func (h *Handler) UpdateCartItem(c *gin.Context) {
	sessionID, _ := c.Cookie("user_session")
	if sessionID == "" {
		log.Printf("UpdateCartItem - No session ID found")
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Oturum bulunamadı"})
		return
	}

	var req struct {
		ProductID int `json:"product_id"`
		Quantity  int `json:"quantity"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("UpdateCartItem - JSON bind error: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Geçersiz veri"})
		return
	}

	log.Printf("UpdateCartItem - SessionID: %s, ProductID: %d, Quantity: %d", sessionID, req.ProductID, req.Quantity)

	err := h.cartService.UpdateCartItem(sessionID, req.ProductID, req.Quantity)
	if err != nil {
		log.Printf("UpdateCartItem - CartService error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Sepet güncellenemedi"})
		return
	}

	log.Printf("UpdateCartItem - Successfully updated cart for session %s", sessionID)
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Sepet güncellendi"})
}

func (h *Handler) RemoveFromCart(c *gin.Context) {
	sessionID, _ := c.Cookie("user_session")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Oturum bulunamadı"})
		return
	}

	var req struct {
		ProductID int `json:"product_id"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Geçersiz veri"})
		return
	}

	err := h.cartService.RemoveFromCart(sessionID, req.ProductID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Ürün sepetten çıkarılamadı"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Ürün sepetten çıkarıldı"})
}

func (h *Handler) GetCartCount(c *gin.Context) {
	sessionID, _ := c.Cookie("user_session")
	if sessionID == "" {
		c.JSON(http.StatusOK, gin.H{"count": 0})
		return
	}

	count := h.cartService.GetCartCount(sessionID)

	log.Printf("GetCartCount - SessionID: %s, Count: %d", sessionID, count)
	c.JSON(http.StatusOK, gin.H{"count": count})
}

// Checkout handlers
func (h *Handler) CheckoutPage(c *gin.Context) {
	sessionID, _ := c.Cookie("user_session")
	if sessionID == "" {
		c.Redirect(http.StatusSeeOther, "/cart")
		return
	}

	cart := h.cartService.GetCart(sessionID)
	if len(cart.Items) == 0 {
		c.Redirect(http.StatusSeeOther, "/cart")
		return
	}

	// Kullanıcının adreslerini al
	var addresses []models.Address
	var defaultAddress string
	var userEmail string
	var userName string
	var isLoggedIn bool
	username, _ := c.Cookie("username")
	if username != "" {
		isLoggedIn = true
		user, err := h.db.GetUserByUsername(username)
		if err == nil {
			userEmail = user.Email   // Kullanıcının email'ini al
			userName = user.Username // Kullanıcının username'ini al
			addresses, err = h.db.GetUserAddresses(user.ID)
			if err != nil {
				log.Printf("Adresler alınırken hata: %v", err)
				addresses = []models.Address{}
			}

			// Varsayılan adresi bul
			for _, addr := range addresses {
				if addr.IsDefault {
					defaultAddress = fmt.Sprintf("%s\n%s\n%s, %s\n%s",
						addr.RecipientName,
						addr.PhoneNumber,
						addr.FullAddress,
						addr.Province,
						addr.District)
					break
				}
			}
		}
	} else {
		isLoggedIn = false
		// Kayıt olmadan sipariş veren kullanıcılar için boş değerler
		userEmail = ""
		userName = ""
	}

	c.HTML(http.StatusOK, "checkout.html", gin.H{
		"title":          "Sipariş Ver",
		"cart":           cart,
		"isLoggedIn":     isLoggedIn,
		"addresses":      addresses,
		"defaultAddress": defaultAddress,
		"userEmail":      userEmail, // Email'i template'e geçir
		"userName":       userName,  // Username'i template'e geçir
	})
}

func (h *Handler) HandleCheckout(c *gin.Context) {
	sessionID, _ := c.Cookie("user_session")
	if sessionID == "" {
		log.Printf("HandleCheckout - No session ID found")
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Oturum bulunamadı"})
		return
	}

	var form models.OrderForm
	if err := c.ShouldBind(&form); err != nil {
		log.Printf("HandleCheckout - Form bind error: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Geçersiz form verisi"})
		return
	}

	cart := h.cartService.GetCart(sessionID)
	if len(cart.Items) == 0 {
		log.Printf("HandleCheckout - Empty cart for session: %s", sessionID)
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Sepet boş"})
		return
	}

	userID := 0
	username, _ := c.Cookie("username")
	var selectedAddress *models.Address

	if username != "" {
		user, err := h.db.GetUserByUsername(username)
		if err == nil {
			userID = user.ID

			// Seçilen adres ID'sini al
			selectedAddressIDStr := c.PostForm("selected_address_id")
			if selectedAddressIDStr != "" {
				selectedAddressID, err := strconv.Atoi(selectedAddressIDStr)
				if err == nil {
					// Seçilen adresi bul
					addresses, err := h.db.GetUserAddresses(userID)
					if err == nil {
						for _, addr := range addresses {
							if addr.ID == selectedAddressID {
								selectedAddress = &addr
								break
							}
						}
					}
				}
			}

			// Eğer adres seçilmemişse varsayılan adresi kullan
			if selectedAddress == nil {
				addresses, err := h.db.GetUserAddresses(userID)
				if err == nil && len(addresses) > 0 {
					for _, addr := range addresses {
						if addr.IsDefault {
							selectedAddress = &addr
							break
						}
					}
				}
			}
		}
	}

	// Adres bilgilerini hazırla
	var orderAddress, customerName, phone string
	if selectedAddress != nil {
		orderAddress = fmt.Sprintf("%s, %s, %s, %s, %s",
			selectedAddress.RecipientName,
			selectedAddress.PhoneNumber,
			selectedAddress.FullAddress,
			selectedAddress.Province,
			selectedAddress.District)
		customerName = selectedAddress.RecipientName
		phone = selectedAddress.PhoneNumber
	} else {
		// Eğer hiç adres yoksa form'dan gelen bilgileri kullan
		orderAddress = form.Address
		customerName = form.CustomerName
		phone = form.Phone
	}

	order := models.Order{
		UserID:        userID,
		SessionID:     sessionID,
		CustomerName:  customerName,
		Email:         form.Email,
		Phone:         phone,
		Address:       orderAddress,
		Items:         cart.Items,
		TotalPrice:    cart.TotalPrice,
		Status:        "pending",
		PaymentMethod: form.PaymentMethod,
		Notes:         form.Notes,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}

	log.Printf("HandleCheckout - Creating order for user %d, cart total: %.2f", userID, cart.TotalPrice)

	if err := h.db.SaveOrder(&order); err != nil {
		log.Printf("HandleCheckout - Order save error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Sipariş kaydedilemedi"})
		return
	}

	log.Printf("HandleCheckout - Order created successfully: ID=%d, OrderNumber=%s", order.ID, order.OrderNumber)

	// Admin'e sipariş bildirimi gönder (asenkron)
	go func() {
		if err := h.email.SendAdminOrderNotification("irmaksuaritmam@gmail.com", &order); err != nil {
			log.Printf("HandleCheckout - Admin email notification error: %v", err)
		} else {
			log.Printf("HandleCheckout - Admin email notification sent successfully for order: %s", order.OrderNumber)
		}
	}()

	// Eski siparişlerdeki adres bilgilerini düzelt
	go func() {
		if err := h.db.FixOldOrderAddresses(); err != nil {
			log.Printf("HandleCheckout - Fix old order addresses error: %v", err)
		} else {
			log.Printf("HandleCheckout - Old order addresses fixed successfully")
		}
	}()

	// Müşteriye sipariş onay e-postası gönder (asenkron)
	go func() {
		if err := h.email.SendCustomerOrderConfirmation(order.Email, &order); err != nil {
			log.Printf("HandleCheckout - Customer email notification error: %v", err)
		} else {
			log.Printf("HandleCheckout - Customer email notification sent successfully for order: %s", order.OrderNumber)
		}
	}()

	h.cartService.ClearCart(sessionID)

	// Sipariş başarı sayfasına yönlendir
	c.Redirect(http.StatusSeeOther, fmt.Sprintf("/order-success?order_id=%d&order_number=%s", order.ID, order.OrderNumber))
}

func (h *Handler) OrderSuccessPage(c *gin.Context) {
	orderID := c.Query("order_id")
	orderNumber := c.Query("order_number")
	if orderID == "" {
		c.Redirect(http.StatusSeeOther, "/")
		return
	}

	// Kullanıcının giriş durumunu kontrol et - username cookie'sine bak
	username, _ := c.Cookie("username")
	isLoggedIn := username != ""
	log.Printf("OrderSuccessPage - username: %s, isLoggedIn: %t", username, isLoggedIn)

	// Sipariş detaylarını getir (Analytics için)
	var orderTotal float64
	var productID, productName string
	var productPrice float64
	var productQuantity int

	if orderID != "" {
		orderIDInt, err := strconv.Atoi(orderID)
		if err == nil {
			order, err := h.db.GetOrderByID(orderIDInt)
			if err == nil && order != nil {
				orderTotal = order.TotalPrice

				// Siparişteki ilk ürün bilgilerini al
				cart, err := h.db.GetCartBySessionID(order.SessionID)
				if err == nil && cart != nil {
					cartItems, err := h.db.GetCartItemsByCartID(cart.ID)
					if err == nil && len(cartItems) > 0 {
						item := cartItems[0]
						productID = strconv.Itoa(item.ProductID)
						productName = item.Name
						productPrice = item.Price
						productQuantity = item.Quantity
					}
				}
			}
		}
	}

	c.HTML(http.StatusOK, "order_success.html", gin.H{
		"title":           "Sipariş Başarılı",
		"order_id":        orderID,
		"order_number":    orderNumber,
		"isLoggedIn":      isLoggedIn,
		"OrderID":         orderID,
		"OrderTotal":      orderTotal,
		"ProductID":       productID,
		"ProductName":     productName,
		"ProductPrice":    productPrice,
		"ProductQuantity": productQuantity,
	})
}

// TestAnalyticsPage - Analytics tracking test sayfası
func (h *Handler) TestAnalyticsPage(c *gin.Context) {
	c.HTML(http.StatusOK, "test_analytics.html", gin.H{
		"title": "Analytics Test",
	})
}

// Admin handlers
func (h *Handler) AdminGetOrders(c *gin.Context) {
	log.Printf("AdminGetOrders - Getting all orders for admin panel")

	orders, err := h.db.GetAllOrders()
	if err != nil {
		log.Printf("AdminGetOrders - Error getting orders: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Siparişler getirilemedi"})
		return
	}

	log.Printf("AdminGetOrders - Found %d orders", len(orders))
	for i, order := range orders {
		log.Printf("AdminGetOrders - Order %d: ID=%d, OrderNumber=%s, CustomerName=%s, Status=%s",
			i+1, order.ID, order.OrderNumber, order.CustomerName, order.Status)
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"orders":  orders,
	})
}

func (h *Handler) AdminGetOrderDetail(c *gin.Context) {
	orderIDStr := c.Param("id")
	orderID, err := strconv.Atoi(orderIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Geçersiz sipariş ID"})
		return
	}

	order, err := h.db.GetOrderByID(orderID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "Sipariş bulunamadı"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"order":   order,
	})
}

// Helper functions
func generateSessionID() string {
	return uuid.New().String()
}

// Admin handlers for missing routes
func (h *Handler) AdminUpdateOrder(c *gin.Context) {
	orderIDStr := c.Param("id")
	orderID, err := strconv.Atoi(orderIDStr)
	if err != nil {
		log.Printf("AdminUpdateOrder - Invalid order ID: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Geçersiz sipariş ID"})
		return
	}

	var req struct {
		Status     string `json:"status"`
		AdminNotes string `json:"admin_notes"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("AdminUpdateOrder - Invalid JSON data: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Geçersiz veri"})
		return
	}

	log.Printf("AdminUpdateOrder - Updating order %d with status: %s, notes: %s", orderID, req.Status, req.AdminNotes)

	// Siparişi güncellemeden önce mevcut durumu al
	existingOrder, err := h.db.GetOrderByID(orderID)
	if err != nil {
		log.Printf("AdminUpdateOrder - Error getting existing order: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Sipariş bulunamadı"})
		return
	}

	// Admin notları ile birlikte sipariş durumunu güncelle
	if err := h.db.UpdateOrderWithNotes(orderID, req.Status, req.AdminNotes); err != nil {
		log.Printf("AdminUpdateOrder - Error updating order: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Sipariş güncellenemedi"})
		return
	}

	// Eğer sipariş durumu "confirmed" olarak değiştirildiyse müşteriye email gönder
	if req.Status == "confirmed" && existingOrder.Status != "confirmed" {
		go func() {
			if err := h.email.SendAdminOrderConfirmationEmail(existingOrder.Email, existingOrder); err != nil {
				log.Printf("AdminUpdateOrder - Error sending customer confirmation email: %v", err)
			} else {
				log.Printf("AdminUpdateOrder - Customer confirmation email sent successfully for order: %s", existingOrder.OrderNumber)
			}
		}()
	}

	log.Printf("AdminUpdateOrder - Order %d updated successfully", orderID)
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Sipariş güncellendi"})
}

func (h *Handler) AdminDeleteOrder(c *gin.Context) {
	orderIDStr := c.Param("id")
	orderID, err := strconv.Atoi(orderIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Geçersiz sipariş ID"})
		return
	}

	if err := h.db.DeleteOrder(orderID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Sipariş silinemedi"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Sipariş silindi"})
}

func (h *Handler) AdminGetUsers(c *gin.Context) {
	users, err := h.db.GetAllUsers()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Kullanıcılar getirilemedi"})
		return
	}

	// Her kullanıcı için adresleri ekle
	for i := range users {
		// PlainPassword zaten veritabanından gelecek, hash'i temizle
		users[i].PasswordHash = ""

		// Kullanıcının adreslerini al
		addresses, err := h.db.GetUserAddresses(users[i].ID)
		if err != nil {
			log.Printf("Kullanıcı %d için adresler alınırken hata: %v", users[i].ID, err)
			users[i].Addresses = []models.Address{}
		} else {
			users[i].Addresses = addresses
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"users":   users,
	})
}

func (h *Handler) AdminDeleteUser(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Geçersiz kullanıcı ID"})
		return
	}

	if err := h.db.DeleteUser(userID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Kullanıcı silinemedi"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Kullanıcı silindi"})
}

// AdminBulkDeleteUsers, seçili kullanıcıları topluca siler
func (h *Handler) AdminBulkDeleteUsers(c *gin.Context) {
	var req struct {
		UserIDs []int `json:"user_ids"`
	}

	// Debug: Raw body'yi logla
	body, _ := c.GetRawData()
	log.Printf("Raw request body: %s", string(body))

	// Body'yi tekrar okuyabilmek için reset et
	c.Request.Body = io.NopCloser(bytes.NewBuffer(body))

	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("JSON bind error: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Geçersiz veri"})
		return
	}

	if len(req.UserIDs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Silinecek kullanıcı seçilmedi"})
		return
	}

	log.Printf("Bulk deleting users: %v", req.UserIDs)

	deletedCount := 0
	errors := []string{}

	for _, userID := range req.UserIDs {
		if err := h.db.DeleteUser(userID); err != nil {
			log.Printf("Error deleting user %d: %v", userID, err)
			errors = append(errors, fmt.Sprintf("Kullanıcı %d silinemedi", userID))
		} else {
			deletedCount++
		}
	}

	if len(errors) > 0 {
		c.JSON(http.StatusPartialContent, gin.H{
			"success":       false,
			"deleted_count": deletedCount,
			"error":         fmt.Sprintf("%d kullanıcı silindi, %d hatada: %s", deletedCount, len(errors), strings.Join(errors, ", ")),
		})
		return
	}

	log.Printf("Successfully bulk deleted %d users", deletedCount)
	c.JSON(http.StatusOK, gin.H{
		"success":       true,
		"deleted_count": deletedCount,
		"message":       fmt.Sprintf("%d kullanıcı başarıyla silindi", deletedCount),
	})
}

func (h *Handler) HandleChangePassword(c *gin.Context) {
	username, _ := c.Cookie("username")
	if username == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "Oturum geçersiz"})
		return
	}

	// Form verilerini al
	currentPassword := c.PostForm("currentPassword")
	newPassword := c.PostForm("newPassword")
	confirmPassword := c.PostForm("confirmPassword")

	if currentPassword == "" || newPassword == "" || confirmPassword == "" {
		c.Redirect(http.StatusSeeOther, "/profile?error=Tüm alanları doldurun")
		return
	}

	if newPassword != confirmPassword {
		c.Redirect(http.StatusSeeOther, "/profile?error=Yeni şifreler eşleşmiyor")
		return
	}

	user, err := h.db.GetUserByUsername(username)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "Kullanıcı bulunamadı"})
		return
	}

	// Mevcut parolayı kontrol et (hem hash hem plain text)
	passwordValid := false

	if user.PasswordHash != "" && CheckPasswordHash(currentPassword, user.PasswordHash) {
		passwordValid = true
	} else if user.PlainPassword != "" && user.PlainPassword == currentPassword {
		passwordValid = true
	}

	if !passwordValid {
		c.Redirect(http.StatusSeeOther, "/profile?error=Mevcut parola yanlış")
		return
	}

	// Yeni parolayı hashle
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		c.Redirect(http.StatusSeeOther, "/profile?error=Parola güncellenemedi")
		return
	}

	user.PasswordHash = string(hashedPassword)
	user.PlainPassword = newPassword // Yeni şifreyi plain password alanına da kaydet
	if err := h.db.UpdateUser(user); err != nil {
		c.Redirect(http.StatusSeeOther, "/profile?error=Parola güncellenemedi")
		return
	}

	// Başarılı mesajı ile profil sayfasına yönlendir
	c.Redirect(http.StatusSeeOther, "/profile?success=Şifreniz başarıyla değiştirildi")
}

// CheckPasswordHash helper function
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// Order tracking handlers

// OrderTrackingPage - Sipariş takip sayfası
func (h *Handler) OrderTrackingPage(c *gin.Context) {
	username, _ := c.Cookie("username")
	isLoggedIn := username != ""

	c.HTML(http.StatusOK, "order_tracking.html", gin.H{
		"title":      "Sipariş Takip",
		"isLoggedIn": isLoggedIn,
		"username":   username,
	})
}

// TrackOrderByNumber - Sipariş numarası ile takip
func (h *Handler) TrackOrderByNumber(c *gin.Context) {
	orderNumber := c.PostForm("order_number")

	log.Printf("TrackOrderByNumber - Gelen sipariş numarası: '%s'", orderNumber)
	log.Printf("TrackOrderByNumber - Content-Type: %s", c.GetHeader("Content-Type"))
	log.Printf("TrackOrderByNumber - User-Agent: %s", c.GetHeader("User-Agent"))

	if orderNumber == "" {
		log.Printf("TrackOrderByNumber - Sipariş numarası boş")
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Sipariş numarası gerekli",
		})
		return
	}

	// Sipariş numarasını temizle (boşlukları kaldır)
	orderNumber = strings.TrimSpace(orderNumber)
	log.Printf("TrackOrderByNumber - Temizlenmiş sipariş numarası: '%s'", orderNumber)

	// Sadece sipariş numarası ile sipariş bul
	order, err := h.db.GetOrderByNumber(orderNumber)
	if err != nil {
		log.Printf("TrackOrderByNumber - Sipariş bulunamadı: %v", err)
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "Sipariş bulunamadı. Sipariş numarasını kontrol edin.",
		})
		return
	}

	log.Printf("TrackOrderByNumber - Sipariş bulundu: ID=%d, OrderNumber=%s", order.ID, order.OrderNumber)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"order":   order,
	})
}

// TrackOrderBySession - Session ile takip (kayıt olmayan kullanıcılar için)
func (h *Handler) TrackOrderBySession(c *gin.Context) {
	sessionID, _ := c.Cookie("user_session")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Oturum bulunamadı",
		})
		return
	}

	orders, err := h.db.GetOrdersBySessionID(sessionID)
	if err != nil {
		log.Printf("TrackOrderBySession - Error getting orders: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Siparişler getirilemedi",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"orders":  orders,
	})
}

// GetPublicOrderDetail - Herkes için sipariş detayı
func (h *Handler) GetPublicOrderDetail(c *gin.Context) {
	orderIDStr := c.Param("id")
	orderID, err := strconv.Atoi(orderIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Geçersiz sipariş ID"})
		return
	}

	order, err := h.db.GetOrderByID(orderID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "Sipariş bulunamadı"})
		return
	}

	// Yetki kontrolü - sadece sipariş sahibi görebilir
	sessionID, _ := c.Cookie("user_session")
	username, _ := c.Cookie("username")

	var authorized bool
	var user *models.User

	// Kayıtlı kullanıcı kontrolü
	if username != "" {
		user, err = h.db.GetUserByUsername(username)
		if err == nil && order.UserID == user.ID {
			authorized = true
		}
	}

	// Session kontrolü (kayıt olmayan kullanıcılar için)
	if !authorized && sessionID != "" && order.SessionID == sessionID {
		authorized = true
	}

	if !authorized {
		c.JSON(http.StatusForbidden, gin.H{
			"success": false,
			"error":   "Bu siparişi görüntüleme yetkiniz yok",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"order":   order,
	})
}

// CustomerCancelOrder - Müşteri sipariş iptali (hem kayıtlı hem kayıt olmayan)
func (h *Handler) CustomerCancelOrder(c *gin.Context) {
	orderIDStr := c.Param("id")
	orderID, err := strconv.Atoi(orderIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Geçersiz sipariş ID"})
		return
	}

	order, err := h.db.GetOrderByID(orderID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "Sipariş bulunamadı"})
		return
	}

	// Yetki kontrolü
	sessionID, _ := c.Cookie("user_session")
	username, _ := c.Cookie("username")

	var authorized bool
	var user *models.User

	// Kayıtlı kullanıcı kontrolü
	if username != "" {
		user, err = h.db.GetUserByUsername(username)
		if err == nil && order.UserID == user.ID {
			authorized = true
		}
	}

	// Session kontrolü (kayıt olmayan kullanıcılar için)
	if !authorized && sessionID != "" && order.SessionID == sessionID {
		authorized = true
	}

	if !authorized {
		c.JSON(http.StatusForbidden, gin.H{
			"success": false,
			"error":   "Bu siparişi iptal etme yetkiniz yok",
		})
		return
	}

	// Sadece "pending" durumundaki siparişler iptal edilebilir
	if order.Status != "pending" {
		var errorMessage string
		switch order.Status {
		case "confirmed":
			errorMessage = "Sipariş onaylandığı için artık iptal edilemez"
		case "shipped":
			errorMessage = "Siparişiniz kargoya verildi. Artık iptal edilemez"
		case "delivered":
			errorMessage = "Sipariş teslim edildiği için iptal edilemez"
		case "cancelled":
			errorMessage = "Sipariş zaten iptal edilmiş"
		default:
			errorMessage = "Bu sipariş durumunda iptal işlemi yapılamaz"
		}

		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   errorMessage,
		})
		return
	}

	// Sipariş durumunu "cancelled" olarak güncelle
	err = h.db.UpdateOrderStatus(orderID, "cancelled")
	if err != nil {
		log.Printf("CustomerCancelOrder - Error updating order status: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Sipariş iptal edilemedi",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Sipariş başarıyla iptal edildi",
	})
}

// Support Chat Handlers

// SupportChatPage - Canlı destek sayfası
func (h *Handler) SupportChatPage(c *gin.Context) {
	username, _ := c.Cookie("username")
	sessionID, _ := c.Cookie("user_session")
	isLoggedIn := username != ""

	if sessionID == "" {
		sessionID = generateSessionID()
		c.SetCookie("user_session", sessionID, 3600*24*30, "/", "", false, false)
	}

	// MAIL GÖNDERİMİ EKLE - Destek sayfasına giriş
	if h.email != nil {
		subject := "Destek Sayfasına Giriş - " + username
		body := fmt.Sprintf(`
			<h3>Yeni Destek Sayfası Girişi</h3>
			<p><strong>Kullanıcı:</strong> %s</p>
			<p><strong>Session ID:</strong> %s</p>
			<p><strong>Tarih:</strong> %s</p>
			<br>
			<p>Kullanıcı destek sayfasına giriş yaptı.</p>
			<br>
					<p><strong>Admin Panel:</strong> <a href="https://irmaksuaritma.com/admin">https://irmaksuaritma.com/admin</a></p>
		<p><strong>Destek Yönetimi:</strong> <a href="https://irmaksuaritma.com/admin/support">https://irmaksuaritma.com/admin/support</a></p>
		`, username, sessionID, time.Now().Format("2006-01-02 15:04:05"))

		err := h.email.SendEmail("wbcenapoktay@gmail.com", subject, body)
		if err != nil {
			log.Printf("SupportChatPage - Mail gönderim hatası: %v", err)
			// Mail hatası olsa bile sayfa açılsın
		}
	}

	c.HTML(http.StatusOK, "support_chat.html", gin.H{
		"title":      "Canlı Destek",
		"isLoggedIn": isLoggedIn,
		"username":   username,
		"sessionID":  sessionID,
	})
}

// SendSupportMessage - Destek mesajı gönder
func (h *Handler) SendSupportMessage(c *gin.Context) {
	var request struct {
		Message string `json:"message"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Geçersiz mesaj"})
		return
	}

	if strings.TrimSpace(request.Message) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Mesaj boş olamaz"})
		return
	}

	// Spam kontrolü
	if h.spamDetector.IsSpam(request.Message) {
		clientIP := c.ClientIP()
		h.securityLog.LogSecurityEvent("SPAM_DETECTED", fmt.Sprintf("Support chat spam: %s", request.Message), clientIP)
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Mesajınız spam içerik kontrolünden geçemedi. Lütfen farklı bir mesaj yazın."})
		return
	}

	username, _ := c.Cookie("username")
	sessionID, _ := c.Cookie("user_session")

	if sessionID == "" {
		sessionID = generateSessionID()
		c.SetCookie("user_session", sessionID, 3600*24*30, "/", "", false, false)
	}

	var userID *int
	displayName := "Ziyaretçi"

	if username != "" {
		user, err := h.db.GetUserByUsername(username)
		if err == nil {
			userID = &user.ID
			displayName = user.Username
		}
	}

	// Create or get support session
	userAgent := c.GetHeader("User-Agent")
	if userAgent == "" {
		userAgent = "Unknown"
	}
	_, err := h.db.GetOrCreateSupportSession(sessionID, displayName, userID, userAgent)
	if err != nil {
		log.Printf("SendSupportMessage - Error creating session: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Oturum oluşturulamadı"})
		return
	}

	// Save message
	message := &models.Message{
		UserID:    userID,
		Username:  displayName,
		SessionID: sessionID,
		Message:   request.Message,
		IsAdmin:   false,
		IsRead:    false,
	}

	err = h.db.SaveMessage(message)
	if err != nil {
		log.Printf("SendSupportMessage - Error saving message: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Mesaj gönderilemedi"})
		return
	}

	// MAIL GÖNDERİMİ EKLE
	if h.email != nil {
		subject := "Yeni Destek Mesajı - " + displayName
		body := fmt.Sprintf(`
			<h3>Yeni Destek Mesajı</h3>
			<p><strong>Kullanıcı:</strong> %s</p>
			<p><strong>Mesaj:</strong> %s</p>
			<p><strong>Tarih:</strong> %s</p>
			<br>
			<p>Destek panelinden yanıtlayabilirsiniz.</p>
		`, displayName, request.Message, time.Now().Format("2006-01-02 15:04:05"))

		err = h.email.SendEmail("wbcenapoktay@gmail.com", subject, body)
		if err != nil {
			log.Printf("SendSupportMessage - Mail gönderim hatası: %v", err)
			// Mail hatası olsa bile mesaj başarılı sayılsın
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": message,
	})
}

// GetSupportMessages - Destek mesajlarını getir
func (h *Handler) GetSupportMessages(c *gin.Context) {
	sessionID, _ := c.Cookie("user_session")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Oturum bulunamadı"})
		return
	}

	messages, err := h.db.GetMessagesBySession(sessionID)
	if err != nil {
		log.Printf("GetSupportMessages - Error getting messages: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Mesajlar getirilemedi"})
		return
	}

	// Mark admin messages as read
	h.db.MarkMessagesAsRead(sessionID, false)

	c.JSON(http.StatusOK, gin.H{
		"success":  true,
		"messages": messages,
	})
}

// Admin Support Handlers

// AdminSupportPage - Admin destek paneli
func (h *Handler) AdminSupportPage(c *gin.Context) {
	sessions, err := h.db.GetActiveSupportSessions()
	if err != nil {
		log.Printf("AdminSupportPage - Error getting sessions: %v", err)
		sessions = []models.SupportSession{}
	}

	c.HTML(http.StatusOK, "admin_support.html", gin.H{
		"title":    "Canlı Destek Yönetimi",
		"sessions": sessions,
	})
}

// AdminGetSupportSessions - Admin için aktif oturumları getir
func (h *Handler) AdminGetSupportSessions(c *gin.Context) {
	sessions, err := h.db.GetActiveSupportSessions()
	if err != nil {
		log.Printf("AdminGetSupportSessions - Error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Oturumlar getirilemedi"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":  true,
		"sessions": sessions,
	})
}

// AdminGetSupportMessages - Admin için belirli oturumdaki mesajları getir
func (h *Handler) AdminGetSupportMessages(c *gin.Context) {
	sessionID := c.Param("sessionId")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Session ID gerekli"})
		return
	}

	messages, err := h.db.GetMessagesBySession(sessionID)
	if err != nil {
		log.Printf("AdminGetSupportMessages - Error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Mesajlar getirilemedi"})
		return
	}

	// Mark user messages as read
	h.db.MarkMessagesAsRead(sessionID, true)

	c.JSON(http.StatusOK, gin.H{
		"success":  true,
		"messages": messages,
	})
}

// AdminSendSupportMessage - Admin mesaj gönder
func (h *Handler) AdminSendSupportMessage(c *gin.Context) {
	sessionID := c.Param("sessionId")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Session ID gerekli"})
		return
	}

	var request struct {
		Message string `json:"message"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Geçersiz mesaj"})
		return
	}

	if strings.TrimSpace(request.Message) == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Mesaj boş olamaz"})
		return
	}

	// Save admin message
	message := &models.Message{
		UserID:    nil, // Admin mesajları için null
		Username:  "Admin",
		SessionID: sessionID,
		Message:   request.Message,
		IsAdmin:   true,
		IsRead:    false,
	}

	err := h.db.SaveMessage(message)
	if err != nil {
		log.Printf("AdminSendSupportMessage - Error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Mesaj gönderilemedi"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": message,
	})
}

// Video Call Request Handlers

// HandleVideoCallRequest - Video görüşme talebi işle
func (h *Handler) HandleVideoCallRequest(c *gin.Context) {
	var request struct {
		SessionID string `json:"session_id"`
		Action    string `json:"action"` // start, end
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Geçersiz istek"})
		return
	}

	if request.SessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Session ID gerekli"})
		return
	}

	switch request.Action {
	case "start":
		// Get user info
		username, _ := c.Cookie("username")
		var userID *int
		displayName := "Ziyaretçi"

		if username != "" {
			user, err := h.db.GetUserByUsername(username)
			if err == nil {
				userID = &user.ID
				displayName = user.Username
			}
		} else {
			// Generate guest number for anonymous users
			displayName = fmt.Sprintf("Misafir-%s", request.SessionID[:8])
		}

		// Create video call request
		err := h.db.CreateVideoCallRequest(request.SessionID, displayName, userID)
		if err != nil {
			log.Printf("HandleVideoCallRequest - Error creating request: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Video görüşme talebi oluşturulamadı"})
			return
		}

		// Send email notification to admin
		adminEmail := os.Getenv("ADMIN_EMAIL")
		if adminEmail == "" {
			adminEmail = "irmaksuaritmam@gmail.com" // Default admin email
		}

		go func() {
			if err := h.email.SendVideoCallNotification(adminEmail, displayName, request.SessionID); err != nil {
				log.Printf("HandleVideoCallRequest - Error sending email notification: %v", err)
			}
		}()

		c.JSON(http.StatusOK, gin.H{"success": true, "message": "Video görüşme talebi gönderildi"})

	case "end":
		// End video call request
		err := h.db.EndVideoCallRequest(request.SessionID)
		if err != nil {
			log.Printf("HandleVideoCallRequest - Error ending request: %v", err)
		}

		c.JSON(http.StatusOK, gin.H{"success": true, "message": "Video görüşme sonlandırıldı"})

	default:
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Geçersiz aksiyon"})
	}
}

// AdminVideoCallResponse - Admin video görüşme yanıtı
func (h *Handler) AdminVideoCallResponse(c *gin.Context) {
	var request struct {
		SessionID string `json:"session_id"`
		Action    string `json:"action"` // accept, reject, end
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Geçersiz istek"})
		return
	}

	if request.SessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Session ID gerekli"})
		return
	}

	switch request.Action {
	case "accept":
		err := h.db.UpdateVideoCallRequestStatus(request.SessionID, "accepted")
		if err != nil {
			log.Printf("AdminVideoCallResponse - Error accepting: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Video görüşme kabul edilemedi"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"success": true, "message": "Video görüşme kabul edildi"})

	case "reject":
		err := h.db.UpdateVideoCallRequestStatus(request.SessionID, "rejected")
		if err != nil {
			log.Printf("AdminVideoCallResponse - Error rejecting: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Video görüşme reddedilemedi"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"success": true, "message": "Video görüşme reddedildi"})

	case "end":
		err := h.db.EndVideoCallRequest(request.SessionID)
		if err != nil {
			log.Printf("AdminVideoCallResponse - Error ending: %v", err)
		}
		c.JSON(http.StatusOK, gin.H{"success": true, "message": "Video görüşme sonlandırıldı"})

	default:
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Geçersiz aksiyon"})
	}
}

// CheckVideoCallStatus - Video görüşme durumunu kontrol et
func (h *Handler) CheckVideoCallStatus(c *gin.Context) {
	sessionID := c.Param("sessionId")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Session ID gerekli"})
		return
	}

	request, err := h.db.GetVideoCallRequestBySession(sessionID)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"success": true, "has_request": false})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success":     true,
		"has_request": true,
		"request":     request,
	})
}

// AdminGetVideoCallRequests - Tüm aktif video görüşme taleplerini getir
func (h *Handler) AdminGetVideoCallRequests(c *gin.Context) {
	requests, err := h.db.GetAllActiveVideoCallRequests()
	if err != nil {
		log.Printf("AdminGetVideoCallRequests - Error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Video görüşme talepleri getirilemedi"})
		return
	}
	// Her request'e initiator ekle
	var result []map[string]interface{}
	for _, r := range requests {
		item := map[string]interface{}{
			"id":           r.ID,
			"session_id":   r.SessionID,
			"user_id":      r.UserID,
			"username":     r.Username,
			"status":       r.Status,
			"requested_at": r.RequestedAt,
			"responded_at": r.RespondedAt,
		}
		if r.Initiator != "" {
			item["initiator"] = r.Initiator
		} else if r.Username == "Admin" {
			item["initiator"] = "admin"
		} else {
			item["initiator"] = "user"
		}
		result = append(result, item)
	}
	c.JSON(http.StatusOK, gin.H{
		"success":  true,
		"requests": result,
	})
}

// WebRTC Signaling storage - In production, use Redis or database
var signalingMessages = make(map[string][]interface{})
var signalingMutex sync.RWMutex

// HandleWebRTCSignal - Müşteri WebRTC signaling mesajları
func (h *Handler) HandleWebRTCSignal(c *gin.Context) {
	var request struct {
		SessionID string      `json:"session_id"`
		Message   interface{} `json:"message"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Geçersiz istek"})
		return
	}

	if request.SessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Session ID gerekli"})
		return
	}

	// Store signaling message for admin to retrieve
	signalingMutex.Lock()
	key := "customer_to_admin_" + request.SessionID
	if signalingMessages[key] == nil {
		signalingMessages[key] = []interface{}{}
	}
	signalingMessages[key] = append(signalingMessages[key], request.Message)
	signalingMutex.Unlock()

	log.Printf("WebRTC Signal from customer %s: %+v", request.SessionID, request.Message)

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Signaling mesajı alındı"})
}

// HandleAdminWebRTCSignal - Admin WebRTC signaling mesajları
func (h *Handler) HandleAdminWebRTCSignal(c *gin.Context) {
	var request struct {
		SessionID string      `json:"session_id"`
		Message   interface{} `json:"message"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Geçersiz istek"})
		return
	}

	if request.SessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Session ID gerekli"})
		return
	}

	// Store signaling message for customer to retrieve
	signalingMutex.Lock()
	key := "admin_to_customer_" + request.SessionID
	if signalingMessages[key] == nil {
		signalingMessages[key] = []interface{}{}
	}
	signalingMessages[key] = append(signalingMessages[key], request.Message)
	signalingMutex.Unlock()

	log.Printf("WebRTC Signal from admin to %s: %+v", request.SessionID, request.Message)

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Admin signaling mesajı alındı"})
}

// GetWebRTCSignals - Müşteri için admin'den gelen signaling mesajlarını getir
func (h *Handler) GetWebRTCSignals(c *gin.Context) {
	sessionID := c.Param("sessionId")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Session ID gerekli"})
		return
	}

	signalingMutex.Lock()
	key := "admin_to_customer_" + sessionID
	messages := signalingMessages[key]
	// Clear messages after reading
	signalingMessages[key] = []interface{}{}
	signalingMutex.Unlock()

	c.JSON(http.StatusOK, gin.H{
		"success":  true,
		"messages": messages,
	})
}

// GetAdminWebRTCSignals - Admin için müşteriden gelen signaling mesajlarını getir
func (h *Handler) GetAdminWebRTCSignals(c *gin.Context) {
	sessionID := c.Param("sessionId")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Session ID gerekli"})
		return
	}

	signalingMutex.Lock()
	key := "customer_to_admin_" + sessionID
	messages := signalingMessages[key]
	// Clear messages after reading
	signalingMessages[key] = []interface{}{}
	signalingMutex.Unlock()

	c.JSON(http.StatusOK, gin.H{
		"success":  true,
		"messages": messages,
	})
}

// AdminStartVideoCall - Admin video call başlatma
func (h *Handler) AdminStartVideoCall(c *gin.Context) {
	var request struct {
		SessionID string `json:"session_id"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Geçersiz istek"})
		return
	}

	if request.SessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Session ID gerekli"})
		return
	}

	// Check if session exists
	userAgent := c.GetHeader("User-Agent")
	if userAgent == "" {
		userAgent = "Unknown"
	}
	session, err := h.db.GetOrCreateSupportSession(request.SessionID, "Admin", nil, userAgent)
	if err != nil {
		log.Printf("AdminStartVideoCall - Error getting session: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Session bulunamadı"})
		return
	}

	// Önce mevcut pending request'i sonlandır
	err = h.db.EndVideoCallRequest(request.SessionID)
	if err != nil {
		log.Printf("AdminStartVideoCall - Warning: Could not end existing request: %v", err)
	}

	// Create video call request (username 'Admin' ve initiator 'admin' olarak kaydet)
	err = h.db.CreateVideoCallRequestWithInitiator(request.SessionID, session.Username, session.UserID, "admin")
	if err != nil {
		log.Printf("AdminStartVideoCall - Error creating video call request: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Video call talebi oluşturulamadı"})
		return
	}

	// Send admin-call-request signal to customer
	signalingMutex.Lock()
	key := "admin_to_customer_" + request.SessionID
	if signalingMessages[key] == nil {
		signalingMessages[key] = []interface{}{}
	}
	signalingMessages[key] = append(signalingMessages[key], map[string]interface{}{
		"type":      "admin-call-request",
		"timestamp": time.Now().Unix(),
	})
	signalingMutex.Unlock()

	log.Printf("AdminStartVideoCall - Video call request sent to session %s", request.SessionID)

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Video call talebi gönderildi"})
}

// Kullanıcıdan ping al
func (h *Handler) SupportPing(c *gin.Context) {
	username, _ := c.Cookie("username")
	sessionID, _ := c.Cookie("user_session")

	if sessionID == "" {
		sessionID = generateSessionID()
		c.SetCookie("user_session", sessionID, 3600*24*30, "/", "", false, false)
	}

	var userID *int
	displayName := "Ziyaretçi"

	if username != "" {
		user, err := h.db.GetUserByUsername(username)
		if err == nil {
			userID = &user.ID
			displayName = user.Username
		}
	}

	// Create or get support session
	userAgent := c.GetHeader("User-Agent")
	if userAgent == "" {
		userAgent = "Unknown"
	}

	// Session'ı oluştur veya güncelle
	_, err := h.db.GetOrCreateSupportSession(sessionID, displayName, userID, userAgent)
	if err != nil {
		log.Printf("SupportPing - Error creating/updating session: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Session güncellenemedi"})
		return
	}

	// Session'ı aktif duruma getir
	err = h.db.UpdateSupportSessionLastActive(sessionID)
	if err != nil {
		log.Printf("SupportPing - Error updating session status: %v", err)
	}

	log.Printf("SupportPing - Session %s ping received from %s", sessionID, displayName)
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// Kullanıcı destek sayfasından ayrıldı
func (h *Handler) SupportLeave(c *gin.Context) {
	// Session ID'yi cookie'den al
	sessionID, _ := c.Cookie("session_id")
	if sessionID == "" {
		// Eğer cookie'de yoksa, form data'dan al
		sessionID = c.PostForm("session_id")
	}

	if sessionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Session ID gerekli"})
		return
	}

	// Session'ı offline olarak işaretle
	err := h.db.MarkSupportSessionOffline(sessionID)
	if err != nil {
		log.Printf("Session offline işaretlenirken hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Session offline işaretlenemedi"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Session başarıyla offline işaretlendi"})
}

// Address Management Handlers

// AddAddress, yeni adres ekleme
func (h *Handler) AddAddress(c *gin.Context) {
	username, _ := c.Cookie("username")
	if username == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Giriş yapmanız gerekiyor"})
		return
	}

	// Kullanıcı ID'sini al
	user, err := h.db.GetUserByUsername(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Kullanıcı bulunamadı"})
		return
	}

	// Form verilerini al
	recipientName := c.PostForm("recipientName")
	phoneNumber := c.PostForm("phoneNumber")
	title := c.PostForm("title")
	fullAddress := c.PostForm("fullAddress")
	province := c.PostForm("province")
	district := c.PostForm("district")
	neighborhood := c.PostForm("neighborhood")
	postalCode := c.PostForm("postalCode")
	isDefaultStr := c.PostForm("isDefault")

	// Validasyon
	if recipientName == "" || phoneNumber == "" || title == "" || fullAddress == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tüm alanlar doldurulmalıdır"})
		return
	}

	// Varsayılan adres kontrolü
	isDefault := isDefaultStr == "true"

	// Yeni adres oluştur
	address := &models.Address{
		UserID:        user.ID,
		RecipientName: recipientName,
		PhoneNumber:   phoneNumber,
		Title:         title,
		FullAddress:   fullAddress,
		Province:      province,
		District:      district,
		Neighborhood:  neighborhood,
		PostalCode:    postalCode,
		IsDefault:     isDefault,
	}

	// Adresi veritabanına ekle
	err = h.db.AddAddress(address)
	if err != nil {
		log.Printf("Adres eklenirken hata: %v", err)
		c.Redirect(http.StatusSeeOther, "/profile?error=Adres eklenemedi")
		return
	}

	// Başarılı olduğunda profile sayfasına yönlendir
	c.Redirect(http.StatusSeeOther, "/profile?success=Adres başarıyla eklendi")
}

// UpdateAddress, adres güncelleme
func (h *Handler) UpdateAddress(c *gin.Context) {
	username, _ := c.Cookie("username")
	if username == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Giriş yapmanız gerekiyor"})
		return
	}

	// Kullanıcı ID'sini al
	user, err := h.db.GetUserByUsername(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Kullanıcı bulunamadı"})
		return
	}

	// Form verilerini al
	addressIDStr := c.PostForm("addressId")
	recipientName := c.PostForm("recipientName")
	phoneNumber := c.PostForm("phoneNumber")
	title := c.PostForm("title")
	fullAddress := c.PostForm("fullAddress")
	province := c.PostForm("province")
	district := c.PostForm("district")
	neighborhood := c.PostForm("neighborhood")
	postalCode := c.PostForm("postalCode")
	isDefaultStr := c.PostForm("isDefault")

	// Address ID'yi dönüştür
	addressID, err := strconv.Atoi(addressIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Geçersiz adres ID"})
		return
	}

	// Validasyon
	if recipientName == "" || phoneNumber == "" || title == "" || fullAddress == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tüm alanlar doldurulmalıdır"})
		return
	}

	// Varsayılan adres kontrolü
	isDefault := isDefaultStr == "true"

	// Adresi güncelle
	address := &models.Address{
		ID:            addressID,
		UserID:        user.ID,
		RecipientName: recipientName,
		PhoneNumber:   phoneNumber,
		Title:         title,
		FullAddress:   fullAddress,
		Province:      province,
		District:      district,
		Neighborhood:  neighborhood,
		PostalCode:    postalCode,
		IsDefault:     isDefault,
	}

	err = h.db.UpdateAddress(address)
	if err != nil {
		log.Printf("Adres güncellenirken hata: %v", err)
		c.Redirect(http.StatusSeeOther, "/profile?error=Adres güncellenemedi")
		return
	}

	// Eğer bu adres varsayılan ise, bekleyen siparişleri güncelle
	if isDefault {
		// Bekleyen siparişleri güncelle
		orders, err := h.db.GetOrdersByUserID(user.ID)
		if err == nil {
			newAddress := fmt.Sprintf("%s\n%s\n%s, %s\n%s",
				recipientName,
				phoneNumber,
				fullAddress,
				province,
				district)

			for _, order := range orders {
				// Sadece bekleyen siparişleri güncelle
				if order.Status == "pending" {
					order.Address = newAddress
					order.CustomerName = recipientName
					order.Phone = phoneNumber

					err := h.db.SaveOrder(&order)
					if err != nil {
						log.Printf("Sipariş %d güncellenirken hata: %v", order.ID, err)
					} else {
						log.Printf("Sipariş %d adres bilgileri güncellendi", order.ID)
					}
				}
			}
		}
	}

	c.Redirect(http.StatusSeeOther, "/profile?success=Adres başarıyla güncellendi")
}

// DeleteAddress, adres silme
func (h *Handler) DeleteAddress(c *gin.Context) {
	username, _ := c.Cookie("username")
	if username == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Giriş yapmanız gerekiyor"})
		return
	}

	// Kullanıcı ID'sini al
	user, err := h.db.GetUserByUsername(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Kullanıcı bulunamadı"})
		return
	}

	// Address ID'yi al
	addressIDStr := c.Param("id")
	addressID, err := strconv.Atoi(addressIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Geçersiz adres ID"})
		return
	}

	// Adresi sil
	err = h.db.DeleteAddress(addressID, user.ID)
	if err != nil {
		log.Printf("Adres silinirken hata: %v", err)
		c.Redirect(http.StatusSeeOther, "/profile?error=Adres silinemedi")
		return
	}

	c.Redirect(http.StatusSeeOther, "/profile?success=Adres başarıyla silindi")
}

// MakeDefaultAddress, adresi varsayılan yapma
func (h *Handler) MakeDefaultAddress(c *gin.Context) {
	username, _ := c.Cookie("username")
	if username == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Giriş yapmanız gerekiyor"})
		return
	}

	// Kullanıcı ID'sini al
	user, err := h.db.GetUserByUsername(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Kullanıcı bulunamadı"})
		return
	}

	// Address ID'yi al
	addressIDStr := c.Param("id")
	addressID, err := strconv.Atoi(addressIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Geçersiz adres ID"})
		return
	}

	// Adresi varsayılan yap
	err = h.db.MakeDefaultAddress(addressID, user.ID)
	if err != nil {
		log.Printf("Adres varsayılan yapılırken hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Adres varsayılan yapılamadı"})
		return
	}

	// Yeni varsayılan adresi al
	addresses, err := h.db.GetUserAddresses(user.ID)
	if err != nil {
		log.Printf("Varsayılan adres alınırken hata: %v", err)
		c.JSON(http.StatusOK, gin.H{"message": "Adres başarıyla varsayılan yapıldı"})
		return
	}

	var defaultAddress *models.Address
	for _, addr := range addresses {
		if addr.IsDefault {
			defaultAddress = &addr
			break
		}
	}

	if defaultAddress != nil {
		// Bekleyen siparişleri güncelle
		orders, err := h.db.GetOrdersByUserID(user.ID)
		if err == nil {
			for _, order := range orders {
				// Sadece bekleyen siparişleri güncelle
				if order.Status == "pending" {
					newAddress := fmt.Sprintf("%s\n%s\n%s, %s\n%s",
						defaultAddress.RecipientName,
						defaultAddress.PhoneNumber,
						defaultAddress.FullAddress,
						defaultAddress.Province,
						defaultAddress.District)

					order.Address = newAddress
					order.CustomerName = defaultAddress.RecipientName
					order.Phone = defaultAddress.PhoneNumber

					err := h.db.SaveOrder(&order)
					if err != nil {
						log.Printf("Sipariş %d güncellenirken hata: %v", order.ID, err)
					} else {
						log.Printf("Sipariş %d adres bilgileri güncellendi", order.ID)
					}
				}
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Adres başarıyla varsayılan yapıldı ve bekleyen siparişler güncellendi"})
}

// DeleteOrderByUser, kullanıcının kendi siparişini silmesi
func (h *Handler) DeleteOrderByUser(c *gin.Context) {
	username, _ := c.Cookie("username")
	if username == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Giriş yapmanız gerekiyor"})
		return
	}

	// Kullanıcı ID'sini al
	user, err := h.db.GetUserByUsername(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Kullanıcı bulunamadı"})
		return
	}

	// Sipariş ID'sini al
	orderIDStr := c.Param("id")
	orderID, err := strconv.Atoi(orderIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Geçersiz sipariş ID"})
		return
	}

	// Siparişi getir ve kullanıcıya ait olduğunu kontrol et
	order, err := h.db.GetOrderByID(orderID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Sipariş bulunamadı"})
		return
	}

	// Siparişin bu kullanıcıya ait olduğunu kontrol et
	if order.UserID != user.ID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Bu siparişi silme yetkiniz yok"})
		return
	}

	// Sadece bekleyen veya iptal edilmiş siparişler silinebilir
	if order.Status != "pending" && order.Status != "cancelled" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Sadece bekleyen veya iptal edilmiş siparişler silinebilir"})
		return
	}

	// Siparişi sil
	err = h.db.DeleteOrder(orderID)
	if err != nil {
		log.Printf("Sipariş silinirken hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Sipariş silinemedi"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Sipariş başarıyla silindi"})
}

// DebugOrders - Sunucuda siparişleri debug etmek için (sadece geliştirme için)
func (h *Handler) DebugOrders(c *gin.Context) {
	orders, err := h.db.GetAllOrders()
	if err != nil {
		log.Printf("DebugOrders - Hata: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Siparişler alınamadı",
		})
		return
	}

	log.Printf("DebugOrders - Toplam %d sipariş bulundu", len(orders))

	var orderNumbers []string
	for _, order := range orders {
		orderNumbers = append(orderNumbers, order.OrderNumber)
		log.Printf("DebugOrders - Sipariş: ID=%d, OrderNumber=%s, Status=%s",
			order.ID, order.OrderNumber, order.Status)
	}

	c.JSON(http.StatusOK, gin.H{
		"success":       true,
		"total_orders":  len(orders),
		"order_numbers": orderNumbers,
		"orders":        orders,
	})
}

// HandleContactForm - İletişim formu gönderimi
func (h *Handler) HandleContactForm(c *gin.Context) {
	var request struct {
		Name     string   `json:"name" binding:"required"`
		Email    string   `json:"email" binding:"required,email"`
		Phone    string   `json:"phone" binding:"required"`
		Subject  string   `json:"subject" binding:"required"`
		Message  string   `json:"message" binding:"required,min=10"`
		Services []string `json:"services"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		log.Printf("Form verisi hatası: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Geçersiz form verisi",
		})
		return
	}

	// Spam koruması - basit kontroller
	if len(request.Message) < 10 {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Mesaj en az 10 karakter olmalıdır",
		})
		return
	}

	// Spam kelime kontrolü
	if h.spamDetector.IsSpam(request.Message) {
		clientIP := c.ClientIP()
		h.securityLog.LogSecurityEvent("SPAM_DETECTED", fmt.Sprintf("Contact form spam: %s", request.Subject), clientIP)

		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Mesajınız spam içerik kontrolünden geçemedi. Lütfen farklı bir mesaj yazın.",
		})
		return
	}

	// E-posta formatı kontrolü
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(request.Email) {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"message": "Geçersiz e-posta adresi",
		})
		return
	}

	// Rate limiting - IP bazlı basit kontrol
	clientIP := c.ClientIP()
	// Burada daha gelişmiş rate limiting eklenebilir

	// E-posta gönderimi
	servicesText := ""
	if len(request.Services) > 0 {
		servicesText = "İlgilendiği Hizmetler: " + strings.Join(request.Services, ", ")
	}

	emailBody := fmt.Sprintf(`
		<h2>Yeni İletişim Formu Mesajı</h2>
		<p><strong>Ad Soyad:</strong> %s</p>
		<p><strong>E-posta:</strong> %s</p>
		<p><strong>Telefon:</strong> %s</p>
		<p><strong>Konu:</strong> %s</p>
		<p><strong>Mesaj:</strong></p>
		<p>%s</p>
		<p><strong>%s</strong></p>
		<hr>
		<p><small>IP Adresi: %s | Tarih: %s</small></p>
	`, request.Name, request.Email, request.Phone, request.Subject, request.Message, servicesText, clientIP, time.Now().Format("02.01.2006 15:04:05"))

	err := h.email.SendEmail(
		"irmaksuaritmam@gmail.com",
		"Yeni İletişim Formu Mesajı - "+request.Subject,
		emailBody,
	)

	if err != nil {
		log.Printf("İletişim formu e-posta gönderimi hatası: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"message": "Mesaj gönderilirken bir hata oluştu. Lütfen daha sonra tekrar deneyin.",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Mesajınız başarıyla gönderildi. En kısa sürede size dönüş yapacağız.",
	})
}

// SecurityMiddleware, güvenlik kontrollerini yapar
func (h *Handler) SecurityMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		method := c.Request.Method

		// Public rotalar için güvenlik kontrollerini bypass et
		publicPaths := []string{
			"/login",
			"/register",
			"/forgot-password",
			"/reset-password",
			"/verify-email",
			"/about",
			"/contact",
			"/",
		}

		// Public path kontrolü
		for _, pp := range publicPaths {
			if strings.HasPrefix(path, pp) {
				log.Printf("� SecurityMiddleware - Public Path: %s", path)
				c.Next()
				return
			}
		}

		// Oturum kontrolü
		session, err := c.Cookie("user_session")
		if err != nil || session == "" {
			log.Printf("� SecurityMiddleware - Yetkisiz erişim engellendi: %s", path)
			if method == "GET" {
				c.Redirect(http.StatusSeeOther, "/login")
			} else {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			}
			c.Abort()
			return
		}

		// IP adresi loglama
		ip := c.ClientIP()
		h.securityLog.LogSecurityEvent("ACCESS", fmt.Sprintf("Path: %s, Method: %s", path, method), ip)

		// Spam kontrolü (POST istekleri için)
		if method == "POST" {
			rawData, _ := c.GetRawData()
			c.Request.Body = io.NopCloser(bytes.NewBuffer(rawData))

			if h.spamDetector.IsSpam(string(rawData)) {
				log.Printf("🚫 SecurityMiddleware - Spam detected from IP: %s", ip)
				h.securityLog.LogSecurityEvent("SPAM", "Spam content detected", ip)
				c.JSON(http.StatusBadRequest, gin.H{"error": "Spam content detected"})
				c.Abort()
				return
			}
		}

		log.Printf("✅ SecurityMiddleware - Authorized access: %s %s", method, path)
		c.Next()
	}
}

// VerifyEmailPage, e-posta doğrulama sayfasını gösterir
func (h *Handler) VerifyEmailPage(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.HTML(http.StatusOK, "verify_email.html", gin.H{
			"title": "E-posta Doğrulama",
			"info":  "E-posta doğrulaması için doğrulama linkine ihtiyacınız var.",
		})
		return
	}

	// Token'ın geçerli olup olmadığını kontrol et
	user, err := h.db.GetUserByEmailVerifyToken(token)
	if err != nil {
		c.HTML(http.StatusBadRequest, "verify_email.html", gin.H{
			"title": "E-posta Doğrulama",
			"error": "Geçersiz veya süresi dolmuş doğrulama bağlantısı.",
		})
		return
	}

	// E-postayı doğrula
	if err := h.db.VerifyUserEmail(user.ID); err != nil {
		c.HTML(http.StatusInternalServerError, "verify_email.html", gin.H{
			"title": "E-posta Doğrulama",
			"error": "E-posta doğrulanırken bir hata oluştu.",
		})
		return
	}

	c.HTML(http.StatusOK, "verify_email.html", gin.H{
		"title":   "E-posta Doğrulama",
		"success": "E-posta adresiniz başarıyla doğrulandı. Artık giriş yapabilirsiniz.",
	})
}

// ResendVerificationEmail, doğrulama e-postasını yeniden gönderir
func (h *Handler) ResendVerificationEmail(c *gin.Context) {
	email := c.PostForm("email")
	if email == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "E-posta adresi gerekli",
		})
		return
	}

	// Kullanıcıyı bul
	user, err := h.db.GetUserByEmail(email)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "Eğer bu e-posta adresi kayıtlıysa, doğrulama bağlantısı gönderilecektir.",
		})
		return
	}

	// Kullanıcı zaten doğrulanmış mı kontrol et
	if user.EmailVerified {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Bu e-posta adresi zaten doğrulanmış.",
		})
		return
	}

	// Yeni token oluştur
	token := uuid.New().String()
	user.EmailVerifyToken = token
	user.EmailVerifyExpiry = time.Now().Add(24 * time.Hour)

	// Kullanıcıyı güncelle
	if err := h.db.UpdateUser(user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Doğrulama bağlantısı oluşturulamadı.",
		})
		return
	}

	// Doğrulama e-postasını gönder
	if err := h.email.SendEmailVerification(user.Email, user.Username, token); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"success": false,
			"error":   "Doğrulama e-postası gönderilemedi.",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Doğrulama bağlantısı e-posta adresinize gönderildi.",
	})
}

// Register - Kullanıcı kaydı
func (h *Handler) Register(c *gin.Context) {
	log.Printf("🚨 Register fonksiyonu çağrıldı! Method: %s", c.Request.Method)
	if c.Request.Method == "GET" {
		c.HTML(http.StatusOK, "register.html", gin.H{
			"title": "Kayıt Ol - Su Arıtma Uzmanı",
		})
		return
	}

	var request struct {
		FullName string `json:"fullName" form:"fullName" binding:"required"`
		Email    string `json:"email" form:"email" binding:"required,email"`
		Password string `json:"password" form:"password" binding:"required,min=6"`
		Captcha  string `json:"captcha" form:"captcha" binding:"required"`
	}

	// Hem JSON hem form data kabul et
	contentType := c.GetHeader("Content-Type")
	var err error
	if strings.Contains(contentType, "application/json") {
		err = c.ShouldBindJSON(&request)
	} else {
		err = c.ShouldBind(&request)
	}

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Geçersiz veri formatı"})
		return
	}

	// Spam kontrolü - email ve fullname'de şüpheli kelimeler
	if h.spamDetector.IsSpam(request.Email) || h.spamDetector.IsSpam(request.FullName) {
		clientIP := c.ClientIP()
		h.securityLog.LogSecurityEvent("SPAM_REGISTRATION", fmt.Sprintf("Spam registration attempt: %s", request.Email), clientIP)
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Kayıt bilgileriniz spam kontrolünden geçemedi"})
		return
	}

	// Captcha kontrolü (basit kontrol)
	if request.Captcha != "1234" { // Gerçek captcha sistemi eklenebilir
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Captcha doğrulaması başarısız"})
		return
	}

	// Email format kontrolü - şüpheli domain'ler
	suspiciousDomains := []string{"omggreatfoods.com", "aol.com", "yahoo.com"}
	emailDomain := strings.Split(request.Email, "@")[1]
	for _, domain := range suspiciousDomains {
		if strings.Contains(emailDomain, domain) {
			clientIP := c.ClientIP()
			h.securityLog.LogSecurityEvent("SUSPICIOUS_DOMAIN", fmt.Sprintf("Suspicious email domain: %s", emailDomain), clientIP)
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Bu email domain'i kabul edilmiyor"})
			return
		}
	}

	// Rate limiting kontrolü
	clientIP := c.ClientIP()
	if h.isRateLimited(clientIP, "register", 5, time.Minute) {
		h.securityLog.LogSecurityEvent("RATE_LIMIT", "Registration rate limit exceeded", clientIP)
		c.JSON(http.StatusTooManyRequests, gin.H{"success": false, "message": "Çok fazla kayıt denemesi. Lütfen bekleyin."})
		return
	}

	// Şifre hash'leme
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Şifre hash'lenirken hata oluştu"})
		return
	}

	// Kullanıcı oluşturma
	token := uuid.New().String()
	user := models.User{
		Username:          request.FullName,
		Email:             request.Email,
		PasswordHash:      string(hashedPassword),
		EmailVerified:     false,
		EmailVerifyToken:  token,
		EmailVerifyExpiry: time.Now().Add(24 * time.Hour),
		CreatedAt:         time.Now(),
	}

	if err := h.db.CreateUser(&user); err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "Bu kullanıcı adı veya email zaten kullanılıyor"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"success": false, "message": "Kullanıcı oluşturulurken hata oluştu"})
		}
		return
	}

	// Başarılı kayıt log'u
	h.securityLog.LogSecurityEvent("SUCCESSFUL_REGISTRATION", fmt.Sprintf("New user registered: %s", request.Email), clientIP)

	// Doğrulama e-postası gönder
	if err := h.email.SendEmailVerification(user.Email, user.Username, token); err != nil {
		log.Printf("Error sending verification email: %v", err)
		// E-posta gönderilemese bile kayıt işlemi devam eder
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Kayıt başarılı! Lütfen e-posta adresinize gönderilen doğrulama bağlantısını tıklayın.",
	})
}

// isRateLimited, rate limiting kontrolü yapar
func (h *Handler) isRateLimited(ip, action string, maxAttempts int, window time.Duration) bool {
	key := fmt.Sprintf("%s:%s", ip, action)
	now := time.Now()

	if lastAttempt, exists := h.rateLimit[key]; exists {
		if now.Sub(lastAttempt) < window {
			return true
		}
	}

	h.rateLimit[key] = now
	return false
}
