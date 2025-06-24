package handlers

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"suaritamauzumani/internal/database"
	"suaritamauzumani/internal/models"
	"suaritamauzumani/internal/services"

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
	GetUserByID(userID int) (*models.User, error)
	GetAllUsers() ([]models.User, error)
	UpdateUser(user *models.User) error
	DeleteUser(userID int) error
	CreatePasswordResetToken(email string, token string) error
	GetUserByResetToken(token string) (*models.User, error)
	ClearResetToken(userID int) error
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
	GetOrdersBySessionID(sessionID string) ([]models.Order, error)
	GetOrCreateSupportSession(sessionID, displayName string, userID *int) (*models.SupportSession, error)
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
}

// Handler, HTTP isteklerini yönetir.
type Handler struct {
	db          DBInterface
	email       *services.EmailService
	cartService *services.CartService
}

// NewHandler, yeni bir Handler örneği oluşturur.
func NewHandler(db DBInterface) *Handler {
	return &Handler{
		db:          db,
		email:       services.NewEmailService(),
		cartService: services.NewCartService(),
	}
}

// Admin credentials (in production, these should be stored securely)
const (
	ADMIN_USERNAME = "admin"
	ADMIN_PASSWORD = "admin123"
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

	if !database.CheckPasswordHash(password, user.PasswordHash) {
		log.Printf("Incorrect password for user %s", username)
		c.HTML(http.StatusUnauthorized, "login.html", gin.H{
			"title": "Giriş Yap",
			"error": "Kullanıcı adı veya parola hatalı.",
		})
		return
	}

	sessionID := uuid.New().String()
	c.SetCookie("user_session", sessionID, 3600, "/", "", false, true)
	c.SetCookie("username", user.Username, 3600, "/", "", false, true)
	
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
	fullName := c.PostForm("fullName")
	username := c.PostForm("username")
	email := c.PostForm("email")
	password := c.PostForm("password")
	confirmPassword := c.PostForm("confirmPassword")

	// Validasyon
	if fullName == "" || username == "" || email == "" || password == "" {
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

	// Kullanıcıyı oluştur
	user := &models.User{
		FullName:     fullName,
		Username:     username,
		Email:        email,
		PasswordHash: string(hashedPassword),
	}

	if err := h.db.CreateUser(user); err != nil {
		log.Printf("Error creating user: %v", err)
		c.HTML(http.StatusInternalServerError, "register.html", gin.H{
			"title": "Kayıt Ol",
			"error": "Kullanıcı adı veya e-posta adresi zaten kullanımda.",
		})
		return
	}

	// Hoş geldin e-postası gönder
	if err := h.email.SendWelcomeEmail(email, username); err != nil {
		log.Printf("Error sending welcome email: %v", err)
		// E-posta gönderilemese bile kayıt işlemi devam eder
	}

	c.Redirect(http.StatusSeeOther, "/login")
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
	
	// Kullanıcı bilgilerini al
	user, err := h.db.GetUserByUsername(username)
	if err != nil {
		log.Printf("Error getting user: %v", err)
		c.HTML(http.StatusOK, "profile.html", gin.H{
			"title":    "Profilim",
			"username": username,
			"error":    "Kullanıcı bilgileri yüklenemedi",
		})
		return
	}
	
	c.HTML(http.StatusOK, "profile.html", gin.H{
		"title":    "Profilim",
		"username": username,
		"user":     user,
	})
}

// UpdateUserAddress, kullanıcı adres bilgilerini günceller.
func (h *Handler) UpdateUserAddress(c *gin.Context) {
	username, _ := c.Cookie("username")
	if username == "" {
		c.Redirect(http.StatusSeeOther, "/login")
		return
	}
	
	user, err := h.db.GetUserByUsername(username)
	if err != nil {
		log.Printf("Error getting user: %v", err)
		c.HTML(http.StatusOK, "profile.html", gin.H{
			"title":         "Profilim",
			"username":      username,
			"address_error": "Kullanıcı bilgileri yüklenemedi",
		})
		return
	}
	
	// Form verilerini al
	user.Phone = c.PostForm("phone")
	user.City = c.PostForm("city")
	user.District = c.PostForm("district")
	user.PostalCode = c.PostForm("postal_code")
	user.Address = c.PostForm("address")
	
	// Kullanıcı bilgilerini güncelle
	if err := h.db.UpdateUser(user); err != nil {
		log.Printf("Error updating user address: %v", err)
		c.HTML(http.StatusOK, "profile.html", gin.H{
			"title":         "Profilim",
			"username":      username,
			"user":          user,
			"address_error": "Adres bilgileri güncellenemedi",
		})
		return
	}
	
	c.HTML(http.StatusOK, "profile.html", gin.H{
		"title":           "Profilim",
		"username":        username,
		"user":            user,
		"address_success": "Adres bilgileriniz başarıyla güncellendi!",
	})
}

func (h *Handler) HomePage(c *gin.Context) {
	products, err := h.db.GetAllProducts()
	if err != nil {
		log.Printf("Error getting products: %v", err)
		products = []models.Product{}
	}
	
	username, _ := c.Cookie("username")
	isLoggedIn := username != ""

	c.HTML(http.StatusOK, "home.html", gin.H{
		"products":   products,
		"title":      "suarıtama uzmanı com - Ana Sayfa",
		"isLoggedIn": isLoggedIn,
		"username":   username,
	})
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

	product := &models.Product{
		Name:        form.Name,
		Description: form.Description,
		Price:       form.Price,
		Image:       imagePath,
		Category:    form.Category,
		Stock:       form.Stock,
	}

	if err := h.db.CreateProduct(product); err != nil {
		log.Printf("Error creating product: %v", err)
		c.HTML(http.StatusInternalServerError, "admin.html", gin.H{
			"error": "Ürün eklenirken hata oluştu",
		})
		return
	}

	c.Redirect(http.StatusSeeOther, "/admin")
}

func (h *Handler) DeleteProduct(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Geçersiz ürün ID'si"})
		return
	}

	product, err := h.db.GetProductByID(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Ürün bulunamadı"})
		return
	}

	if product.Image != "" {
		imagePath := filepath.Join(".", product.Image)
		if _, err := os.Stat(imagePath); err == nil {
			os.Remove(imagePath)
		}
	}

	if err := h.db.DeleteProduct(id); err != nil {
		log.Printf("Error deleting product: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Ürün silinirken hata oluştu"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Ürün başarıyla silindi"})
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

	// Sadece "pending" durumundaki siparişler iptal edilebilir
	if order.Status != "pending" {
		log.Printf("UserCancelOrder - Cannot cancel order %d with status %s", orderID, order.Status)
		
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
		
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": errorMessage})
		return
	}

	// Siparişi iptal et (status'u "cancelled" yap)
	err = h.db.UpdateOrderStatus(orderID, "cancelled")
	if err != nil {
		log.Printf("UserCancelOrder - Error updating order status: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Sipariş iptal edilemedi"})
		return
	}

	log.Printf("UserCancelOrder - Order %d successfully cancelled by user %s", orderID, username)
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "Sipariş başarıyla iptal edildi",
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
	}

	cart := h.cartService.GetCart(sessionID)

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
	}

	var req struct {
		ProductID int `json:"product_id"`
		Quantity  int `json:"quantity"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Geçersiz veri"})
		return
	}

	product, err := h.db.GetProductByID(req.ProductID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "Ürün bulunamadı"})
		return
	}

	err = h.cartService.AddToCart(sessionID, *product, req.Quantity)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Sepete eklenemedi"})
		return
	}

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
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Üründ sepetten çıkarılamadı"})
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

	// Kullanıcı giriş yapmış mı kontrol et
	username, _ := c.Cookie("username")
	isLoggedIn := username != ""
	
	var user *models.User
	if isLoggedIn {
		var err error
		user, err = h.db.GetUserByUsername(username)
		if err != nil {
			log.Printf("Error getting user for checkout: %v", err)
			// Kullanıcı bilgileri alınamadıysa boş user objesi oluştur
			user = &models.User{}
		}
	} else {
		// Giriş yapmamış kullanıcı için boş user objesi
		user = &models.User{}
	}

	c.HTML(http.StatusOK, "checkout.html", gin.H{
		"title":      "Sipariş Ver",
		"cart":       cart,
		"isLoggedIn": isLoggedIn,
		"user":       user,
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
	if username != "" {
		user, err := h.db.GetUserByUsername(username)
		if err == nil {
			userID = user.ID
		}
	}

	order := models.Order{
		UserID:        userID,
		SessionID:     sessionID,
		OrderNumber:   generateOrderNumber(),
		CustomerName:  form.CustomerName,
		Email:         form.Email,
		Phone:         form.Phone,
		Address:       form.Address,
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

	c.HTML(http.StatusOK, "order_success.html", gin.H{
		"title":        "Sipariş Başarılı",
		"order_id":     orderID,
		"order_number": orderNumber,
		"isLoggedIn":   true,
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

	// Eğer sipariş kayıtlı bir kullanıcıya aitse, kullanıcının tam adres bilgilerini al
	var userDetails *models.User
	if order.UserID > 0 {
		user, err := h.db.GetUserByID(order.UserID)
		if err == nil {
			userDetails = user
		}
	}

	response := gin.H{
		"success": true,
		"order":   order,
	}

	// Kullanıcı detayları varsa ekle
	if userDetails != nil {
		response["user_details"] = userDetails
	}

	c.JSON(http.StatusOK, response)
}

// Helper functions
func generateSessionID() string {
	return uuid.New().String()
}

func generateOrderNumber() string {
	return "ORD-" + uuid.New().String()[:8]
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

	// Admin notları ile birlikte sipariş durumunu güncelle
	if err := h.db.UpdateOrderWithNotes(orderID, req.Status, req.AdminNotes); err != nil {
		log.Printf("AdminUpdateOrder - Error updating order: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Sipariş güncellenemedi"})
		return
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

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"users":   users,
	})
}

func (h *Handler) AdminDeleteUser(c *gin.Context) {
	userIDStr := c.Param("id")
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		log.Printf("AdminDeleteUser - Invalid user ID: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Geçersiz kullanıcı ID"})
		return
	}

	log.Printf("AdminDeleteUser - Attempting to delete user ID: %d", userID)

	if err := h.db.DeleteUser(userID); err != nil {
		log.Printf("AdminDeleteUser - Error deleting user ID %d: %v", userID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": fmt.Sprintf("Kullanıcı silinemedi: %v", err)})
		return
	}

	log.Printf("AdminDeleteUser - Successfully deleted user ID: %d", userID)
	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Kullanıcı silindi"})
}

func (h *Handler) HandleChangePassword(c *gin.Context) {
	username, _ := c.Cookie("username")
	if username == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "error": "Oturum geçersiz"})
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Geçersiz veri"})
		return
	}

	user, err := h.db.GetUserByUsername(username)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"success": false, "error": "Kullanıcı bulunamadı"})
		return
	}

	// Mevcut parolayı kontrol et
	if !CheckPasswordHash(req.CurrentPassword, user.PasswordHash) {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "Mevcut parola yanlış"})
		return
	}

	// Yeni parolayı hashle
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Parola güncellenemedi"})
		return
	}

	user.PasswordHash = string(hashedPassword)
	if err := h.db.UpdateUser(user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"success": false, "error": "Parola güncellenemedi"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"success": true, "message": "Parola güncellendi"})
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
	email := c.PostForm("email")

	if orderNumber == "" || email == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"success": false,
			"error":   "Sipariş numarası ve e-posta adresi gerekli",
		})
		return
	}

	// Sipariş numarası ve e-posta ile sipariş bul
	order, err := h.db.GetOrderByNumberAndEmail(orderNumber, email)
	if err != nil {
		log.Printf("TrackOrderByNumber - Order not found: %v", err)
		c.JSON(http.StatusNotFound, gin.H{
			"success": false,
			"error":   "Sipariş bulunamadı. Sipariş numarası ve e-posta adresini kontrol edin.",
		})
		return
	}

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
	
	// Kayıtlı kullanıcı kontrolü
	if username != "" {
		user, err := h.db.GetUserByUsername(username)
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
	
	// Kayıtlı kullanıcı kontrolü
	if username != "" {
		user, err := h.db.GetUserByUsername(username)
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
	_, err := h.db.GetOrCreateSupportSession(sessionID, displayName, userID)
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
	
	c.JSON(http.StatusOK, gin.H{
		"success":  true,
		"requests": requests,
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