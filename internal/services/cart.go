package services

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"cenap/internal/models"
)

// CartService, sepet işlemlerini yönetir
type CartService struct {
	carts map[string]*models.Cart
	mutex sync.RWMutex
	db    interface {
		GetProductByID(id int) (*models.Product, error)
	}
}

// NewCartService, yeni bir CartService örneği oluşturur
func NewCartService(db interface {
	GetProductByID(id int) (*models.Product, error)
}) *CartService {
	return &CartService{
		carts: make(map[string]*models.Cart),
		db:    db,
	}
}

// GetCart, session ID'ye göre sepeti döndürür
func (cs *CartService) GetCart(sessionID string) *models.Cart {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()

	if cart, exists := cs.carts[sessionID]; exists {
		return cart
	}

	// Yeni sepet oluştur
	cart := &models.Cart{
		Items:      []models.CartItem{},
		TotalItems: 0,
		TotalPrice: 0,
		SessionID:  sessionID,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	cs.carts[sessionID] = cart
	return cart
}

// AddToCart, sepete ürün ekler
func (cs *CartService) AddToCart(sessionID string, product models.Product, quantity int) error {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()

	// Geçersiz quantity kontrolü
	if quantity <= 0 {
		return fmt.Errorf("geçersiz miktar: %d", quantity)
	}

	// Stok kontrolü (sadece sepete ekleme için)
	if cs.db != nil {
		currentProduct, err := cs.db.GetProductByID(product.ID)
		if err != nil {
			return fmt.Errorf("ürün bulunamadı: %v", err)
		}

		// Sepetteki mevcut miktarı hesapla
		existingQuantity := 0
		if existingCart, exists := cs.carts[sessionID]; exists {
			for _, item := range existingCart.Items {
				if item.ProductID == product.ID {
					existingQuantity = item.Quantity
					break
				}
			}
		}

		// Toplam istenen miktar stoktan fazla mı?
		totalRequested := existingQuantity + quantity
		if totalRequested > currentProduct.Stock {
			return fmt.Errorf("yetersiz stok: %s (mevcut: %d, istenen: %d)", currentProduct.Name, currentProduct.Stock, totalRequested)
		}
	}

	// Sepeti al (GetCart fonksiyonu zaten mutex kullanıyor, bu yüzden buradan çağırmayalım)
	var cart *models.Cart
	if existingCart, exists := cs.carts[sessionID]; exists {
		cart = existingCart
	} else {
		// Yeni sepet oluştur
		cart = &models.Cart{
			Items:      []models.CartItem{},
			TotalItems: 0,
			TotalPrice: 0,
			SessionID:  sessionID,
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		}
		cs.carts[sessionID] = cart
	}

	// Ürün zaten sepette var mı kontrol et
	for i, item := range cart.Items {
		if item.ProductID == product.ID {
			cart.Items[i].Quantity += quantity
			cart.Items[i].TotalPrice = float64(cart.Items[i].Quantity) * cart.Items[i].Price
			cs.updateCartTotals(cart)
			return nil
		}
	}

	// Yeni ürün ekle
	cartItem := models.CartItem{
		ProductID:  product.ID,
		Name:       product.Name,
		Price:      product.Price,
		Image:      product.Image,
		Quantity:   quantity,
		TotalPrice: product.Price * float64(quantity),
	}

	cart.Items = append(cart.Items, cartItem)
	cs.updateCartTotals(cart)
	return nil
}

// UpdateCartItem, sepet öğesini günceller
func (cs *CartService) UpdateCartItem(sessionID string, productID int, quantity int) error {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()

	fmt.Printf("CartService.UpdateCartItem - SessionID: %s, ProductID: %d, Quantity: %d\n", sessionID, productID, quantity)

	// Sepeti al
	cart, exists := cs.carts[sessionID]
	if !exists {
		fmt.Printf("CartService.UpdateCartItem - Cart not found for session: %s\n", sessionID)
		return fmt.Errorf("sepet bulunamadı")
	}

	fmt.Printf("CartService.UpdateCartItem - Cart found with %d items\n", len(cart.Items))

	for i, item := range cart.Items {
		fmt.Printf("CartService.UpdateCartItem - Checking item %d: ProductID=%d\n", i, item.ProductID)
		if item.ProductID == productID {
			fmt.Printf("CartService.UpdateCartItem - Found matching product, updating quantity from %d to %d\n", item.Quantity, quantity)
			if quantity <= 0 {
				// Ürünü sepetten kaldır
				fmt.Printf("CartService.UpdateCartItem - Removing item from cart\n")
				cart.Items = append(cart.Items[:i], cart.Items[i+1:]...)
			} else {
				cart.Items[i].Quantity = quantity
				cart.Items[i].TotalPrice = float64(quantity) * cart.Items[i].Price
				fmt.Printf("CartService.UpdateCartItem - Updated item: Quantity=%d, TotalPrice=%.2f\n", cart.Items[i].Quantity, cart.Items[i].TotalPrice)
			}
			cs.updateCartTotals(cart)
			fmt.Printf("CartService.UpdateCartItem - Cart totals updated: TotalItems=%d, TotalPrice=%.2f\n", cart.TotalItems, cart.TotalPrice)
			return nil
		}
	}

	fmt.Printf("CartService.UpdateCartItem - Product %d not found in cart\n", productID)
	return fmt.Errorf("ürün sepette bulunamadı")
}

// RemoveFromCart, sepetten ürün kaldırır
// RemoveFromCart, sepetten ürün kaldırır
func (cs *CartService) RemoveFromCart(sessionID string, productID int) error {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()

	// Sepeti al
	cart, exists := cs.carts[sessionID]
	if !exists {
		return fmt.Errorf("sepet bulunamadı")
	}

	for i, item := range cart.Items {
		if item.ProductID == productID {
			cart.Items = append(cart.Items[:i], cart.Items[i+1:]...)
			cs.updateCartTotals(cart)
			return nil
		}
	}

	return fmt.Errorf("ürün sepette bulunamadı")
}

// ClearCart, sepeti temizler
func (cs *CartService) ClearCart(sessionID string) {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()

	if cart, exists := cs.carts[sessionID]; exists {
		cart.Items = []models.CartItem{}
		cs.updateCartTotals(cart)
	}
}

// updateCartTotals, sepet toplamlarını günceller
func (cs *CartService) updateCartTotals(cart *models.Cart) {
	totalItems := 0
	totalPrice := 0.0

	for _, item := range cart.Items {
		totalItems += item.Quantity
		totalPrice += item.TotalPrice
	}

	cart.TotalItems = totalItems
	cart.TotalPrice = totalPrice
	cart.UpdatedAt = time.Now()
}

// GetCartCount, sepetteki toplam ürün sayısını döndürür
func (cs *CartService) GetCartCount(sessionID string) int {
	cart := cs.GetCart(sessionID)
	return cart.TotalItems
}

// GetCartJSON, sepeti JSON formatında döndürür
func (cs *CartService) GetCartJSON(sessionID string) (string, error) {
	cart := cs.GetCart(sessionID)
	cartJSON, err := json.Marshal(cart)
	if err != nil {
		return "", err
	}
	return string(cartJSON), nil
}
