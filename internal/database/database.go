package database

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"cenap/internal/models"

	"golang.org/x/crypto/bcrypt"
)

// dbData, JSON dosyasındaki tüm verileri temsil eder.
type dbData struct {
	Products          []models.Product          `json:"products"`
	Users             []models.User             `json:"users"`
	Orders            []models.Order            `json:"orders"`
	Messages          []models.Message          `json:"messages"`
	SupportSessions   []models.SupportSession   `json:"support_sessions"`
	VideoCallRequests []models.VideoCallRequest `json:"video_call_requests"`
	Carts             []models.Cart             `json:"carts"`
	CartItems         []models.CartItem         `json:"cart_items"`
	Addresses         []models.Address          `json:"addresses"`
}

// JSONDatabase, veritabanı işlemlerini yönetir.
type JSONDatabase struct {
	mu       sync.RWMutex
	data     dbData
	filePath string
}

// NewDatabase, yeni bir JSONDatabase örneği oluşturur ve verileri yükler.
func NewDatabase() (*JSONDatabase, error) {
	db := &JSONDatabase{
		filePath: "./data.json",
	}
	if err := db.loadData(); err != nil {
		// Eğer dosya boşsa veya sadece ürünler varsa, kullanıcılar için başlat
		if _, ok := err.(*json.SyntaxError); ok || db.data.Users == nil {
			db.data.Users = []models.User{}
			db.data.Orders = []models.Order{}
			db.data.Messages = []models.Message{}
			db.data.SupportSessions = []models.SupportSession{}
			db.data.VideoCallRequests = []models.VideoCallRequest{}
			db.data.Addresses = []models.Address{}
			if saveErr := db.saveData(); saveErr != nil {
				return nil, saveErr
			}
		} else {
			return nil, err
		}
	}
	return db, nil
}

func (db *JSONDatabase) loadData() error {
	if _, err := os.Stat(db.filePath); os.IsNotExist(err) {
		db.data.Products = []models.Product{}
		db.data.Users = []models.User{}
		db.data.Orders = []models.Order{}
		db.data.Messages = []models.Message{}
		db.data.SupportSessions = []models.SupportSession{}
		db.data.VideoCallRequests = []models.VideoCallRequest{}
		db.data.Carts = []models.Cart{}
		db.data.CartItems = []models.CartItem{}
		db.data.Addresses = []models.Address{}
		return db.saveData()
	}

	fileData, err := os.ReadFile(db.filePath)
	if err != nil {
		return err
	}
	// Dosya boşsa hata vermemesi için kontrol
	if len(fileData) == 0 {
		db.data.Products = []models.Product{}
		db.data.Users = []models.User{}
		db.data.Orders = []models.Order{}
		db.data.Messages = []models.Message{}
		db.data.SupportSessions = []models.SupportSession{}
		db.data.VideoCallRequests = []models.VideoCallRequest{}
		db.data.Carts = []models.Cart{}
		db.data.CartItems = []models.CartItem{}
		db.data.Addresses = []models.Address{}
		return nil
	}

	return json.Unmarshal(fileData, &db.data)
}

func (db *JSONDatabase) saveData() error {
	data, err := json.MarshalIndent(db.data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(db.filePath, data, 0644)
}

// GetAllProducts, tüm ürünleri döndürür.
func (db *JSONDatabase) GetAllProducts() ([]models.Product, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	products := make([]models.Product, len(db.data.Products))
	copy(products, db.data.Products)
	return products, nil
}

// GetProductByID, belirli bir ID'ye sahip ürünü döndürür.
func (db *JSONDatabase) GetProductByID(id int) (*models.Product, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	for _, p := range db.data.Products {
		if p.ID == id {
			return &p, nil
		}
	}
	return nil, os.ErrNotExist
}

// CreateProduct, yeni bir ürün oluşturur.
func (db *JSONDatabase) CreateProduct(product *models.Product) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	maxID := 0
	for _, p := range db.data.Products {
		if p.ID > maxID {
			maxID = p.ID
		}
	}
	product.ID = maxID + 1
	product.CreatedAt = time.Now()
	product.UpdatedAt = time.Now()
	db.data.Products = append(db.data.Products, *product)
	return db.saveData()
}

// UpdateProduct, mevcut bir ürünü günceller.
func (db *JSONDatabase) UpdateProduct(product *models.Product) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	for i, p := range db.data.Products {
		if p.ID == product.ID {
			product.UpdatedAt = time.Now()
			db.data.Products[i] = *product
			return db.saveData()
		}
	}
	return os.ErrNotExist
}

// DeleteProduct, belirli bir ID'ye sahip ürünü siler.
func (db *JSONDatabase) DeleteProduct(id int) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	for i, p := range db.data.Products {
		if p.ID == id {
			db.data.Products = append(db.data.Products[:i], db.data.Products[i+1:]...)
			return db.saveData()
		}
	}
	return os.ErrNotExist
}

// --- User Functions ---

// CreateUser, yeni bir kullanıcı oluşturur ve parolasını hashler.
func (db *JSONDatabase) CreateUser(user *models.User) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	// Kullanıcı adı veya e-postanın zaten var olup olmadığını kontrol et
	for _, u := range db.data.Users {
		if u.Username == user.Username {
			return errors.New("username already exists")
		}
		if u.Email == user.Email {
			return errors.New("email already exists")
		}
	}

	// user.PasswordHash zaten hash'lenmiş durumda, tekrar hash'lemeye gerek yok

	// Yeni ID ata
	maxID := 0
	for _, u := range db.data.Users {
		if u.ID > maxID {
			maxID = u.ID
		}
	}
	user.ID = maxID + 1
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()

	db.data.Users = append(db.data.Users, *user)
	return db.saveData()
}

// GetUserByUsername, kullanıcı adına göre bir kullanıcıyı döndürür.
func (db *JSONDatabase) GetUserByUsername(username string) (*models.User, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	for _, u := range db.data.Users {
		if u.Username == username {
			return &u, nil
		}
	}
	return nil, errors.New("user not found")
}

// GetUserByEmail, e-posta adresine göre bir kullanıcıyı döndürür.
func (db *JSONDatabase) GetUserByEmail(email string) (*models.User, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	for _, u := range db.data.Users {
		if u.Email == email {
			return &u, nil
		}
	}
	return nil, errors.New("user not found")
}

// UpdateUser, kullanıcı bilgilerini günceller.
func (db *JSONDatabase) UpdateUser(user *models.User) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	for i, u := range db.data.Users {
		if u.ID == user.ID {
			user.UpdatedAt = time.Now()
			db.data.Users[i] = *user
			return db.saveData()
		}
	}
	return errors.New("user not found")
}

// CreatePasswordResetToken, şifre sıfırlama token'ı oluşturur.
func (db *JSONDatabase) CreatePasswordResetToken(email string, token string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	for i, u := range db.data.Users {
		if u.Email == email {
			db.data.Users[i].ResetToken = token
			db.data.Users[i].ResetExpiry = time.Now().Add(24 * time.Hour) // 24 saat geçerli
			db.data.Users[i].UpdatedAt = time.Now()
			return db.saveData()
		}
	}
	return errors.New("user not found")
}

// GetUserByResetToken, reset token'ına göre kullanıcıyı döndürür.
func (db *JSONDatabase) GetUserByResetToken(token string) (*models.User, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	for _, u := range db.data.Users {
		if u.ResetToken == token && time.Now().Before(u.ResetExpiry) {
			return &u, nil
		}
	}
	return nil, errors.New("invalid or expired reset token")
}

// ClearResetToken, kullanıcının reset token'ını temizler.
func (db *JSONDatabase) ClearResetToken(userID int) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	for i, u := range db.data.Users {
		if u.ID == userID {
			db.data.Users[i].ResetToken = ""
			db.data.Users[i].ResetExpiry = time.Time{}
			db.data.Users[i].UpdatedAt = time.Now()
			return db.saveData()
		}
	}
	return errors.New("user not found")
}

// CheckPasswordHash, verilen parola ile hash'i karşılaştırır.
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// CreateOrder, yeni bir sipariş oluşturur.
func (db *JSONDatabase) CreateOrder(order *models.Order) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	// Stok kontrolü (sadece kontrol, düşürme yok)
	for _, item := range order.Items {
		product, err := db.GetProductByID(item.ProductID)
		if err != nil {
			return fmt.Errorf("ürün bulunamadı: %d", item.ProductID)
		}

		if product.Stock < item.Quantity {
			return fmt.Errorf("yetersiz stok: %s (mevcut: %d, istenen: %d)", product.Name, product.Stock, item.Quantity)
		}
	}

	// Sipariş numarası oluştur
	order.OrderNumber = generateOrderNumber()
	order.Status = "pending"
	order.CreatedAt = time.Now()
	order.UpdatedAt = time.Now()

	// Yeni ID atama
	maxID := 0
	for _, o := range db.data.Orders {
		if o.ID > maxID {
			maxID = o.ID
		}
	}
	order.ID = maxID + 1

	// Siparişi data structure'a ekle
	db.data.Orders = append(db.data.Orders, *order)

	// Ana JSON dosyasına kaydet
	return db.saveData()
}

// SaveOrder, siparişi kaydeder (yeni oluşturur veya mevcut olanı günceller)
func (db *JSONDatabase) SaveOrder(order *models.Order) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	// Eğer order ID 0 ise, yeni sipariş oluştur
	if order.ID == 0 {
		maxID := 0
		for _, o := range db.data.Orders {
			if o.ID > maxID {
				maxID = o.ID
			}
		}
		order.ID = maxID + 1
		order.CreatedAt = time.Now()

		// Varsayılan değerler
		if order.Status == "" {
			order.Status = "pending"
		}
		if order.OrderNumber == "" {
			order.OrderNumber = generateOrderNumber()
		}
	}

	order.UpdatedAt = time.Now()

	// Mevcut siparişi güncelle veya yeni sipariş ekle
	found := false
	for i, o := range db.data.Orders {
		if o.ID == order.ID {
			db.data.Orders[i] = *order
			found = true
			break
		}
	}

	if !found {
		db.data.Orders = append(db.data.Orders, *order)
	}

	return db.saveData()
}

// GetOrdersByUserID, kullanıcının siparişlerini getirir.
func (db *JSONDatabase) GetOrdersByUserID(userID int) ([]models.Order, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var userOrders []models.Order
	for _, order := range db.data.Orders {
		if order.UserID == userID {
			userOrders = append(userOrders, order)
		}
	}

	// Tarihe göre sırala (en yeni önce)
	sort.Slice(userOrders, func(i, j int) bool {
		return userOrders[i].CreatedAt.After(userOrders[j].CreatedAt)
	})

	return userOrders, nil
}

// GetOrderByID, ID'ye göre sipariş getirir.
func (db *JSONDatabase) GetOrderByID(orderID int) (*models.Order, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	for _, order := range db.data.Orders {
		if order.ID == orderID {
			return &order, nil
		}
	}

	return nil, fmt.Errorf("sipariş bulunamadı")
}

// UpdateOrderStatus, sipariş durumunu günceller.
func (db *JSONDatabase) UpdateOrderStatus(orderID int, status string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	for i, order := range db.data.Orders {
		if order.ID == orderID {
			oldStatus := order.Status
			db.data.Orders[i].Status = status
			db.data.Orders[i].UpdatedAt = time.Now()

			// Admin onayladığında stokları düşür
			if oldStatus == "pending" && status == "confirmed" {
				log.Printf("Admin onayı: Sipariş %d için stok düşürülüyor (eski: %s, yeni: %s)", orderID, oldStatus, status)
				if err := db.deductStockFromOrder(&order); err != nil {
					log.Printf("Stok düşürme hatası: %v", err)
				} else {
					log.Printf("Stok düşürme başarılı: Sipariş %d", orderID)
				}
			}

			// Eğer sipariş iptal edildiyse stokları geri ekle
			if oldStatus != "cancelled" && status == "cancelled" {
				if err := db.restoreStockFromOrder(&order); err != nil {
					log.Printf("Stok geri ekleme hatası: %v", err)
				}
			}

			return db.saveData()
		}
	}

	return fmt.Errorf("sipariş bulunamadı")
}

// deductStockFromOrder, onaylanan siparişin stoklarını düşürür
func (db *JSONDatabase) deductStockFromOrder(order *models.Order) error {
	log.Printf("deductStockFromOrder başladı - Sipariş ID: %d, Ürün sayısı: %d", order.ID, len(order.Items))

	for _, item := range order.Items {
		log.Printf("Ürün işleniyor - ProductID: %d, Quantity: %d", item.ProductID, item.Quantity)

		// Ürünü bul ve stoku güncelle (lock kullanmadan)
		for i, product := range db.data.Products {
			if product.ID == item.ProductID {
				log.Printf("Ürün bulundu - Name: %s, Mevcut stok: %d", product.Name, product.Stock)

				// Stoku düşür
				db.data.Products[i].Stock -= item.Quantity
				log.Printf("Stok düşürüldü - Yeni stok: %d", db.data.Products[i].Stock)
				log.Printf("Stok düşürüldü: %s (-%d)", product.Name, item.Quantity)
				break
			}
		}
	}

	log.Printf("deductStockFromOrder tamamlandı")
	return nil
}

// restoreStockFromOrder, iptal edilen siparişin stoklarını geri ekler
func (db *JSONDatabase) restoreStockFromOrder(order *models.Order) error {
	for _, item := range order.Items {
		// Ürünü bul ve stoku güncelle (lock kullanmadan)
		for i, product := range db.data.Products {
			if product.ID == item.ProductID {
				// Stoku geri ekle
				db.data.Products[i].Stock += item.Quantity
				log.Printf("Stok geri eklendi: %s (+%d)", product.Name, item.Quantity)
				break
			}
		}
	}

	return nil
}

// generateOrderNumber, benzersiz sipariş numarası oluşturur.
func generateOrderNumber() string {
	return fmt.Sprintf("ORD-%s", time.Now().Format("20060102-150405"))
}

// --- Admin Order Functions ---

// GetAllOrders, tüm siparişleri döndürür (admin için)
func (db *JSONDatabase) GetAllOrders() ([]models.Order, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	orders := make([]models.Order, len(db.data.Orders))
	copy(orders, db.data.Orders)

	// Siparişleri tarihe göre sırala (en yeni önce)
	sort.Slice(orders, func(i, j int) bool {
		return orders[i].CreatedAt.After(orders[j].CreatedAt)
	})

	return orders, nil
}

// GetOrdersByStatus, belirli duruma sahip siparişleri döndürür
func (db *JSONDatabase) GetOrdersByStatus(status string) ([]models.Order, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var filteredOrders []models.Order
	for _, order := range db.data.Orders {
		if order.Status == status {
			filteredOrders = append(filteredOrders, order)
		}
	}

	// Siparişleri tarihe göre sırala (en yeni önce)
	sort.Slice(filteredOrders, func(i, j int) bool {
		return filteredOrders[i].CreatedAt.After(filteredOrders[j].CreatedAt)
	})

	return filteredOrders, nil
}

// UpdateOrderWithNotes, sipariş durumunu ve admin notlarını günceller
func (db *JSONDatabase) UpdateOrderWithNotes(orderID int, status string, adminNotes string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	for i, order := range db.data.Orders {
		if order.ID == orderID {
			oldStatus := order.Status
			db.data.Orders[i].Status = status
			db.data.Orders[i].AdminNotes = adminNotes
			db.data.Orders[i].UpdatedAt = time.Now()

			// Admin onayladığında stokları düşür
			if oldStatus == "pending" && status == "confirmed" {
				log.Printf("Admin onayı (notlar): Sipariş %d için stok düşürülüyor (eski: %s, yeni: %s)", orderID, oldStatus, status)
				if err := db.deductStockFromOrder(&order); err != nil {
					log.Printf("Stok düşürme hatası: %v", err)
				} else {
					log.Printf("Stok düşürme başarılı (notlar): Sipariş %d", orderID)
				}
			}

			// Eğer sipariş iptal edildiyse veya beklemeye alındıysa stokları geri ekle
			if oldStatus == "confirmed" && (status == "cancelled" || status == "pending") {
				log.Printf("Admin durum değişikliği: Sipariş %d için stoklar geri ekleniyor (eski: %s, yeni: %s)", orderID, oldStatus, status)
				if err := db.restoreStockFromOrder(&order); err != nil {
					log.Printf("Stok geri ekleme hatası: %v", err)
				} else {
					log.Printf("Stoklar geri eklendi: Sipariş %d", orderID)
				}
			}

			return db.saveData()
		}
	}

	return errors.New("order not found")
}

// DeleteOrder, siparişi siler (admin için)
func (db *JSONDatabase) DeleteOrder(orderID int) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	for i, order := range db.data.Orders {
		if order.ID == orderID {
			// Eğer sipariş onaylanmışsa stokları geri ekle
			if order.Status == "confirmed" {
				log.Printf("Admin sipariş silme: Sipariş %d onaylanmış, stoklar geri ekleniyor", orderID)
				if err := db.restoreStockFromOrder(&order); err != nil {
					log.Printf("Stok geri ekleme hatası (sipariş silme): %v", err)
				} else {
					log.Printf("Stoklar geri eklendi (sipariş silme): Sipariş %d", orderID)
				}
			}

			// Siparişi listeden çıkar
			db.data.Orders = append(db.data.Orders[:i], db.data.Orders[i+1:]...)
			return db.saveData()
		}
	}

	return errors.New("order not found")
}

// GetAllUsers, tüm kullanıcıları getirir
func (db *JSONDatabase) GetAllUsers() ([]models.User, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	return db.data.Users, nil
}

// DeleteUser, belirli bir kullanıcıyı siler
func (db *JSONDatabase) DeleteUser(userID int) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	// Admin kullanıcısını silmeyi engelle
	for _, user := range db.data.Users {
		if user.ID == userID && user.Username == "admin" {
			return errors.New("admin user cannot be deleted")
		}
	}

	for i, user := range db.data.Users {
		if user.ID == userID {
			// Kullanıcıyı slice'dan çıkar
			db.data.Users = append(db.data.Users[:i], db.data.Users[i+1:]...)
			return db.saveData()
		}
	}

	return errors.New("user not found")
}

// Order tracking methods

// GetOrderByNumberAndEmail, sipariş numarası ve e-posta ile sipariş getirir
func (db *JSONDatabase) GetOrderByNumberAndEmail(orderNumber, email string) (*models.Order, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	for _, order := range db.data.Orders {
		if order.OrderNumber == orderNumber && order.Email == email {
			return &order, nil
		}
	}

	return nil, errors.New("sipariş bulunamadı")
}

// GetOrderByNumber, sadece sipariş numarası ile sipariş getirir
func (db *JSONDatabase) GetOrderByNumber(orderNumber string) (*models.Order, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	for _, order := range db.data.Orders {
		if order.OrderNumber == orderNumber {
			return &order, nil
		}
	}

	return nil, errors.New("sipariş bulunamadı")
}

// GetOrdersBySessionID, session ID'ye göre siparişleri getirir (kayıt olmayan kullanıcılar için)
func (db *JSONDatabase) GetOrdersBySessionID(sessionID string) ([]models.Order, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var sessionOrders []models.Order
	for _, order := range db.data.Orders {
		if order.SessionID == sessionID {
			sessionOrders = append(sessionOrders, order)
		}
	}

	// Tarihe göre sırala (en yeni önce)
	sort.Slice(sessionOrders, func(i, j int) bool {
		return sessionOrders[i].CreatedAt.After(sessionOrders[j].CreatedAt)
	})

	return sessionOrders, nil
}

// GetActiveSupportSessions method interface uyumu için
func (db *JSONDatabase) GetActiveSupportSessions() ([]models.SupportSession, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var sessions []models.SupportSession
	// Son 5 dakika içinde aktif olan sessionları göster (admin hariç)
	fiveMinutesAgo := time.Now().Add(-5 * time.Minute)

	// Admin username'lerini tanımla
	adminUsernames := []string{"admin", "Admin", "ADMIN", "admın", "Admın", "ADMİN"}

	for _, session := range db.data.SupportSessions {
		// Admin session'larını filtrele (admin kullanıcısının session'larını gösterme)
		isAdmin := false
		for _, adminUsername := range adminUsernames {
			if session.Username == adminUsername {
				isAdmin = true
				break
			}
		}

		if session.Status == "active" && session.LastMessageAt.After(fiveMinutesAgo) && !isAdmin {
			sessions = append(sessions, session)
		}
	}

	// Sort by last_message_at DESC
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].LastMessageAt.After(sessions[j].LastMessageAt)
	})

	log.Printf("GetActiveSupportSessions - Found %d active sessions (last 5 minutes, admin excluded)", len(sessions))

	return sessions, nil
}

// Support message methods
func (db *JSONDatabase) SaveMessage(message *models.Message) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	// Generate new ID
	maxID := 0
	for _, m := range db.data.Messages {
		if m.ID > maxID {
			maxID = m.ID
		}
	}
	message.ID = maxID + 1
	message.CreatedAt = time.Now()

	db.data.Messages = append(db.data.Messages, *message)

	// Update session last message time
	db.updateSessionLastMessage(message.SessionID)

	return db.saveData()
}

func (db *JSONDatabase) GetMessagesBySession(sessionID string) ([]models.Message, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var messages []models.Message
	for _, msg := range db.data.Messages {
		if msg.SessionID == sessionID {
			messages = append(messages, msg)
		}
	}

	// Sort by created_at
	sort.Slice(messages, func(i, j int) bool {
		return messages[i].CreatedAt.Before(messages[j].CreatedAt)
	})

	return messages, nil
}

func (db *JSONDatabase) GetOrCreateSupportSession(sessionID, username string, userID *int, userAgent string) (*models.SupportSession, error) {
	db.mu.Lock()
	defer db.mu.Unlock()

	// Check if session exists with same sessionID and userAgent
	for _, session := range db.data.SupportSessions {
		if session.SessionID == sessionID && session.UserAgent == userAgent {
			// Session exists, update user info if userID is provided
			if userID != nil {
				for i, s := range db.data.SupportSessions {
					if s.SessionID == sessionID && s.UserAgent == userAgent {
						db.data.SupportSessions[i].UserID = userID
						db.data.SupportSessions[i].Username = username
						db.data.SupportSessions[i].LastMessageAt = time.Now()
						db.saveData()
						return &db.data.SupportSessions[i], nil
					}
				}
			}
			return &session, nil
		}
	}

	// Create new session
	maxID := 0
	for _, s := range db.data.SupportSessions {
		if s.ID > maxID {
			maxID = s.ID
		}
	}

	newSession := models.SupportSession{
		ID:            maxID + 1,
		SessionID:     sessionID,
		UserID:        userID,
		Username:      username,
		UserAgent:     userAgent,
		Status:        "active",
		LastMessageAt: time.Now(),
		CreatedAt:     time.Now(),
		UnreadCount:   0,
	}

	db.data.SupportSessions = append(db.data.SupportSessions, newSession)
	err := db.saveData()
	if err != nil {
		return nil, err
	}

	return &newSession, nil
}

func (db *JSONDatabase) updateSessionLastMessage(sessionID string) {
	for i, session := range db.data.SupportSessions {
		if session.SessionID == sessionID {
			db.data.SupportSessions[i].LastMessageAt = time.Now()
			break
		}
	}
}

func (db *JSONDatabase) MarkMessagesAsRead(sessionID string, isAdmin bool) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	for i, msg := range db.data.Messages {
		if msg.SessionID == sessionID && msg.IsAdmin != isAdmin {
			db.data.Messages[i].IsRead = true
		}
	}

	return db.saveData()
}

// Video Call Request methods

// CreateVideoCallRequest, yeni bir video görüşme talebi oluşturur
func (db *JSONDatabase) CreateVideoCallRequest(sessionID, username string, userID *int) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	// Check if there's already a pending request for this session
	for _, req := range db.data.VideoCallRequests {
		if req.SessionID == sessionID && req.Status == "pending" {
			return errors.New("pending video call request already exists")
		}
	}

	// Generate new ID
	maxID := 0
	for _, req := range db.data.VideoCallRequests {
		if req.ID > maxID {
			maxID = req.ID
		}
	}

	newRequest := models.VideoCallRequest{
		ID:          maxID + 1,
		SessionID:   sessionID,
		UserID:      userID,
		Username:    username,
		Status:      "pending",
		RequestedAt: time.Now(),
	}

	db.data.VideoCallRequests = append(db.data.VideoCallRequests, newRequest)
	return db.saveData()
}

// GetVideoCallRequestBySession, session ID'ye göre aktif video call request'i getirir
func (db *JSONDatabase) GetVideoCallRequestBySession(sessionID string) (*models.VideoCallRequest, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	for _, req := range db.data.VideoCallRequests {
		if req.SessionID == sessionID && req.Status == "pending" {
			return &req, nil
		}
	}

	return nil, errors.New("no pending video call request found")
}

// UpdateVideoCallRequestStatus, video call request durumunu günceller
func (db *JSONDatabase) UpdateVideoCallRequestStatus(sessionID, status string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	for i, req := range db.data.VideoCallRequests {
		if req.SessionID == sessionID && req.Status == "pending" {
			db.data.VideoCallRequests[i].Status = status
			now := time.Now()
			db.data.VideoCallRequests[i].RespondedAt = &now
			return db.saveData()
		}
	}

	return errors.New("no pending video call request found")
}

// EndVideoCallRequest, video call request'i sonlandırır
func (db *JSONDatabase) EndVideoCallRequest(sessionID string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	for i, req := range db.data.VideoCallRequests {
		if req.SessionID == sessionID && (req.Status == "pending" || req.Status == "accepted") {
			db.data.VideoCallRequests[i].Status = "ended"
			now := time.Now()
			db.data.VideoCallRequests[i].RespondedAt = &now
			return db.saveData()
		}
	}

	return nil // Don't return error if no request found, it might already be ended
}

// GetAllActiveVideoCallRequests, tüm aktif video call request'leri getirir
func (db *JSONDatabase) GetAllActiveVideoCallRequests() ([]models.VideoCallRequest, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var activeRequests []models.VideoCallRequest
	// Son 30 dakika içinde talep edilmiş ve pending durumunda olan request'leri göster
	thirtyMinutesAgo := time.Now().Add(-30 * time.Minute)

	for _, req := range db.data.VideoCallRequests {
		if req.Status == "pending" && req.RequestedAt.After(thirtyMinutesAgo) {
			activeRequests = append(activeRequests, req)
		}
	}

	// Sort by requested_at DESC (en yeni önce)
	sort.Slice(activeRequests, func(i, j int) bool {
		return activeRequests[i].RequestedAt.After(activeRequests[j].RequestedAt)
	})

	return activeRequests, nil
}

// Yeni bir video görüşme talebi oluşturur (initiator ile)
func (db *JSONDatabase) CreateVideoCallRequestWithInitiator(sessionID, username string, userID *int, initiator string) error {
	// Önce eski request'leri temizle
	db.CleanupOldVideoCallRequests()

	db.mu.Lock()
	defer db.mu.Unlock()

	// Check if there's already a pending request for this session
	for _, req := range db.data.VideoCallRequests {
		if req.SessionID == sessionID && req.Status == "pending" {
			return errors.New("pending video call request already exists")
		}
	}

	// Generate new ID
	maxID := 0
	for _, req := range db.data.VideoCallRequests {
		if req.ID > maxID {
			maxID = req.ID
		}
	}

	newRequest := models.VideoCallRequest{
		ID:          maxID + 1,
		SessionID:   sessionID,
		UserID:      userID,
		Username:    username,
		Status:      "pending",
		RequestedAt: time.Now(),
		Initiator:   initiator,
	}

	db.data.VideoCallRequests = append(db.data.VideoCallRequests, newRequest)
	return db.saveData()
}

// CleanupOldVideoCallRequests, eski video call request'lerini temizler
func (db *JSONDatabase) CleanupOldVideoCallRequests() error {
	db.mu.Lock()
	defer db.mu.Unlock()

	// 30 dakikadan eski pending request'leri ended olarak işaretle
	thirtyMinutesAgo := time.Now().Add(-30 * time.Minute)
	updated := false

	for i, req := range db.data.VideoCallRequests {
		if req.Status == "pending" && req.RequestedAt.Before(thirtyMinutesAgo) {
			db.data.VideoCallRequests[i].Status = "expired"
			now := time.Now()
			db.data.VideoCallRequests[i].RespondedAt = &now
			updated = true
			log.Printf("CleanupOldVideoCallRequests - Expired request for session %s", req.SessionID)
		}
	}

	if updated {
		return db.saveData()
	}
	return nil
}

func (db *JSONDatabase) UpdateSupportSessionLastActive(sessionID string) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	for i, session := range db.data.SupportSessions {
		if session.SessionID == sessionID {
			db.data.SupportSessions[i].LastMessageAt = time.Now()
			db.data.SupportSessions[i].Status = "active"
			log.Printf("UpdateSupportSessionLastActive - Session %s updated", sessionID)
			return db.saveData()
		}
	}
	log.Printf("UpdateSupportSessionLastActive - Session %s not found", sessionID)
	return nil
}

func (db *JSONDatabase) MarkSupportSessionOffline(sessionID string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	// Session'ı bul ve offline olarak işaretle
	for i, session := range db.data.SupportSessions {
		if session.SessionID == sessionID {
			// Status'u offline yap ve son aktif zamanını çok eski bir tarihe ayarla
			db.data.SupportSessions[i].Status = "offline"
			db.data.SupportSessions[i].LastMessageAt = time.Now().AddDate(-1, 0, 0)
			log.Printf("MarkSupportSessionOffline - Session %s marked as offline", sessionID)
			return db.saveData()
		}
	}

	log.Printf("MarkSupportSessionOffline - Session %s not found", sessionID)
	return nil
}

// --- Cart Functions ---

// GetCartBySessionID, session ID'ye göre sepeti döndürür
func (db *JSONDatabase) GetCartBySessionID(sessionID string) (*models.Cart, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	for _, cart := range db.data.Carts {
		if cart.SessionID == sessionID {
			// Sepet öğelerini de getir
			var items []models.CartItem
			for _, item := range db.data.CartItems {
				if item.CartID == cart.ID {
					items = append(items, item)
				}
			}
			cart.Items = items
			return &cart, nil
		}
	}
	return nil, os.ErrNotExist
}

// CreateCart, yeni bir sepet oluşturur
func (db *JSONDatabase) CreateCart(cart *models.Cart) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	// Yeni ID ata
	maxID := 0
	for _, c := range db.data.Carts {
		if c.ID > maxID {
			maxID = c.ID
		}
	}
	cart.ID = maxID + 1
	cart.CreatedAt = time.Now()
	cart.UpdatedAt = time.Now()

	db.data.Carts = append(db.data.Carts, *cart)
	if saveErr := db.saveData(); saveErr != nil {
		return saveErr
	}
	return nil
}

// UpdateCart, sepeti günceller
func (db *JSONDatabase) UpdateCart(cart *models.Cart) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	for i, c := range db.data.Carts {
		if c.ID == cart.ID {
			cart.UpdatedAt = time.Now()
			db.data.Carts[i] = *cart
			if saveErr := db.saveData(); saveErr != nil {
				return saveErr
			}
			return nil
		}
	}
	return os.ErrNotExist
}

// DeleteCart, sepeti siler
func (db *JSONDatabase) DeleteCart(cartID int) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	// Sepeti sil
	for i, cart := range db.data.Carts {
		if cart.ID == cartID {
			db.data.Carts = append(db.data.Carts[:i], db.data.Carts[i+1:]...)
			break
		}
	}

	// Sepet öğelerini de sil
	var newCartItems []models.CartItem
	for _, item := range db.data.CartItems {
		if item.CartID != cartID {
			newCartItems = append(newCartItems, item)
		}
	}
	db.data.CartItems = newCartItems

	if saveErr := db.saveData(); saveErr != nil {
		return saveErr
	}
	return nil
}

// AddCartItem, sepet öğesi ekler
func (db *JSONDatabase) AddCartItem(item *models.CartItem) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	// Yeni ID ata
	maxID := 0
	for _, i := range db.data.CartItems {
		if i.ID > maxID {
			maxID = i.ID
		}
	}
	item.ID = maxID + 1

	db.data.CartItems = append(db.data.CartItems, *item)
	if saveErr := db.saveData(); saveErr != nil {
		return saveErr
	}
	return nil
}

// UpdateCartItem, sepet öğesini günceller
func (db *JSONDatabase) UpdateCartItem(item *models.CartItem) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	for i, it := range db.data.CartItems {
		if it.ID == item.ID {
			db.data.CartItems[i] = *item
			if saveErr := db.saveData(); saveErr != nil {
				return saveErr
			}
			return nil
		}
	}
	return os.ErrNotExist
}

// DeleteCartItem, sepet öğesini siler
func (db *JSONDatabase) DeleteCartItem(itemID int) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	for i, item := range db.data.CartItems {
		if item.ID == itemID {
			db.data.CartItems = append(db.data.CartItems[:i], db.data.CartItems[i+1:]...)
			if saveErr := db.saveData(); saveErr != nil {
				return saveErr
			}
			return nil
		}
	}
	return os.ErrNotExist
}

// GetCartItemsByCartID, sepet ID'sine göre öğeleri döndürür
func (db *JSONDatabase) GetCartItemsByCartID(cartID int) ([]models.CartItem, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var items []models.CartItem
	for _, item := range db.data.CartItems {
		if item.CartID == cartID {
			items = append(items, item)
		}
	}
	return items, nil
}

// Address Management Methods

// AddAddress, yeni bir adres ekler
func (db *JSONDatabase) AddAddress(address *models.Address) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	// En yüksek ID'yi bul
	maxID := 0
	for _, addr := range db.data.Addresses {
		if addr.ID > maxID {
			maxID = addr.ID
		}
	}
	address.ID = maxID + 1
	address.CreatedAt = time.Now()
	address.UpdatedAt = time.Now()

	// Eğer bu adres varsayılan olarak işaretlenmişse, diğer adresleri varsayılan olmaktan çıkar
	if address.IsDefault {
		for i := range db.data.Addresses {
			if db.data.Addresses[i].UserID == address.UserID {
				db.data.Addresses[i].IsDefault = false
			}
		}
	}

	db.data.Addresses = append(db.data.Addresses, *address)
	return db.saveData()
}

// UpdateAddress, mevcut bir adresi günceller
func (db *JSONDatabase) UpdateAddress(address *models.Address) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	for i, addr := range db.data.Addresses {
		if addr.ID == address.ID && addr.UserID == address.UserID {
			address.UpdatedAt = time.Now()

			// Eğer bu adres varsayılan olarak işaretlenmişse, diğer adresleri varsayılan olmaktan çıkar
			if address.IsDefault {
				for j := range db.data.Addresses {
					if db.data.Addresses[j].UserID == address.UserID && db.data.Addresses[j].ID != address.ID {
						db.data.Addresses[j].IsDefault = false
					}
				}
			}

			db.data.Addresses[i] = *address
			return db.saveData()
		}
	}
	return os.ErrNotExist
}

// DeleteAddress, belirli bir ID'ye sahip adresi siler
func (db *JSONDatabase) DeleteAddress(addressID int, userID int) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	for i, addr := range db.data.Addresses {
		if addr.ID == addressID && addr.UserID == userID {
			// Eğer silinen adres varsayılan adres ise, başka bir adresi varsayılan yap
			if addr.IsDefault {
				for j, otherAddr := range db.data.Addresses {
					if otherAddr.UserID == userID && otherAddr.ID != addressID {
						db.data.Addresses[j].IsDefault = true
						break
					}
				}
			}

			db.data.Addresses = append(db.data.Addresses[:i], db.data.Addresses[i+1:]...)
			return db.saveData()
		}
	}
	return os.ErrNotExist
}

// MakeDefaultAddress, belirli bir adresi varsayılan yapar
func (db *JSONDatabase) MakeDefaultAddress(addressID int, userID int) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	// Önce tüm adresleri varsayılan olmaktan çıkar
	for i := range db.data.Addresses {
		if db.data.Addresses[i].UserID == userID {
			db.data.Addresses[i].IsDefault = false
		}
	}

	// Sonra belirtilen adresi varsayılan yap
	for i := range db.data.Addresses {
		if db.data.Addresses[i].ID == addressID && db.data.Addresses[i].UserID == userID {
			db.data.Addresses[i].IsDefault = true
			db.data.Addresses[i].UpdatedAt = time.Now()
			return db.saveData()
		}
	}
	return os.ErrNotExist
}

// GetUserAddresses, kullanıcının tüm adreslerini döndürür
func (db *JSONDatabase) GetUserAddresses(userID int) ([]models.Address, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var addresses []models.Address

	// Önce ayrı addresses array'inden kontrol et
	for _, addr := range db.data.Addresses {
		if addr.UserID == userID {
			addresses = append(addresses, addr)
		}
	}

	// Eğer ayrı addresses array'inde bulunamazsa, users içindeki addresses'den al
	if len(addresses) == 0 {
		for _, user := range db.data.Users {
			if user.ID == userID && len(user.Addresses) > 0 {
				addresses = append(addresses, user.Addresses...)
			}
		}
	}

	return addresses, nil
}

// FixOldOrderAddresses, eski siparişlerdeki bozuk adres bilgilerini düzeltir
func (db *JSONDatabase) FixOldOrderAddresses() error {
	db.mu.Lock()
	defer db.mu.Unlock()

	for i := range db.data.Orders {
		order := &db.data.Orders[i]

		// Eğer adres bilgisi \n karakterleri içeriyorsa düzelt
		if order.Address != "" {
			// \n karakterlerini virgül ile değiştir
			order.Address = strings.ReplaceAll(order.Address, "\n", ", ")

			// Fazla virgülleri temizle
			order.Address = strings.ReplaceAll(order.Address, ", , ", ", ")
			order.Address = strings.Trim(order.Address, ", ")
		}
	}

	return db.saveData()
}

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
