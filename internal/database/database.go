package database

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"

	"cenap/internal/models"
	"golang.org/x/crypto/bcrypt"
)

// dbData, JSON dosyasındaki tüm verileri temsil eder.
type dbData struct {
	Products         []models.Product         `json:"products"`
	Users            []models.User            `json:"users"`
	Orders           []models.Order           `json:"orders"`
	Messages         []models.Message         `json:"messages"`
	SupportSessions  []models.SupportSession  `json:"support_sessions"`
	VideoCallRequests []models.VideoCallRequest `json:"video_call_requests"`
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
			if err := db.saveData(); err != nil {
				return nil, err
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

	// Parolayı hashle
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.PasswordHash), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	user.PasswordHash = string(hashedPassword)

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
			db.data.Orders[i].Status = status
			db.data.Orders[i].UpdatedAt = time.Now()
			return db.saveData()
		}
	}

	return fmt.Errorf("sipariş bulunamadı")
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
			db.data.Orders[i].Status = status
			db.data.Orders[i].AdminNotes = adminNotes
			db.data.Orders[i].UpdatedAt = time.Now()
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
	// Son 30 dakika içinde mesaj alışverişi olan sessionları göster
	thirtyMinutesAgo := time.Now().Add(-30 * time.Minute)
	
	for _, session := range db.data.SupportSessions {
		if session.Status == "active" && session.LastMessageAt.After(thirtyMinutesAgo) {
			sessions = append(sessions, session)
		}
	}
	
	// Sort by last_message_at DESC
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].LastMessageAt.After(sessions[j].LastMessageAt)
	})
	
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

func (db *JSONDatabase) GetOrCreateSupportSession(sessionID, username string, userID *int) (*models.SupportSession, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	
	// Check if session exists
	for _, session := range db.data.SupportSessions {
		if session.SessionID == sessionID {
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

 