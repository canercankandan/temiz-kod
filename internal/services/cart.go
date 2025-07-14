package services

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"cenap/internal/database"
	"cenap/internal/models"
)

// CartService, sepet işlemlerini yönetir
type CartService struct {
	db database.DBInterface
}

// NewCartService, yeni bir CartService örneği oluşturur
func NewCartService(db database.DBInterface) *CartService {
	return &CartService{
		db: db,
	}
}

// GetCart, session ID'ye göre sepeti döndürür
func (cs *CartService) GetCart(sessionID string) *models.Cart {
	log.Printf("CartService.GetCart - SessionID: %s", sessionID)

	cart, err := cs.db.GetCartBySessionID(sessionID)
	if err != nil {
		log.Printf("CartService.GetCart - Creating new cart for session: %s", sessionID)
		// Yeni sepet oluştur
		cart = &models.Cart{
			Items:      []models.CartItem{},
			TotalItems: 0,
			TotalPrice: 0,
			SessionID:  sessionID,
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		}

		// Veritabanına kaydet
		if err := cs.db.CreateCart(cart); err != nil {
			log.Printf("CartService.GetCart - Error creating cart: %v", err)
			return cart
		}
	} else {
		log.Printf("CartService.GetCart - Found existing cart with %d items", len(cart.Items))
	}

	return cart
}

// AddToCart, sepete ürün ekler
func (cs *CartService) AddToCart(sessionID string, product models.Product, quantity int) error {
	log.Printf("CartService.AddToCart - SessionID: %s, ProductID: %d, Quantity: %d", sessionID, product.ID, quantity)

	// Geçersiz quantity kontrolü
	if quantity <= 0 {
		return fmt.Errorf("geçersiz miktar: %d", quantity)
	}

	// Sepeti al
	cart, err := cs.db.GetCartBySessionID(sessionID)
	if err != nil {
		log.Printf("CartService.AddToCart - Creating new cart for session: %s", sessionID)
		// Yeni sepet oluştur
		cart = &models.Cart{
			Items:      []models.CartItem{},
			TotalItems: 0,
			TotalPrice: 0,
			SessionID:  sessionID,
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		}

		if err := cs.db.CreateCart(cart); err != nil {
			log.Printf("CartService.AddToCart - Error creating cart: %v", err)
			return err
		}
	} else {
		log.Printf("CartService.AddToCart - Found existing cart with %d items", len(cart.Items))
	}

	// Ürün zaten sepette var mı kontrol et
	for i, item := range cart.Items {
		if item.ProductID == product.ID {
			log.Printf("CartService.AddToCart - Product already in cart, updating quantity from %d to %d", item.Quantity, item.Quantity+quantity)
			cart.Items[i].Quantity += quantity
			cart.Items[i].TotalPrice = float64(cart.Items[i].Quantity) * cart.Items[i].Price

			// Veritabanında güncelle
			if err := cs.db.UpdateCartItem(&cart.Items[i]); err != nil {
				log.Printf("CartService.AddToCart - Error updating cart item: %v", err)
				return err
			}

			cs.updateCartTotals(cart)
			log.Printf("CartService.AddToCart - Updated cart totals: TotalItems=%d, TotalPrice=%.2f", cart.TotalItems, cart.TotalPrice)
			return nil
		}
	}

	// Yeni ürün ekle
	log.Printf("CartService.AddToCart - Adding new product to cart")
	cartItem := models.CartItem{
		CartID:     cart.ID,
		ProductID:  product.ID,
		Name:       product.Name,
		Price:      product.Price,
		Image:      product.Image,
		Quantity:   quantity,
		TotalPrice: product.Price * float64(quantity),
	}

	// Veritabanına ekle
	if err := cs.db.AddCartItem(&cartItem); err != nil {
		log.Printf("CartService.AddToCart - Error adding cart item: %v", err)
		return err
	}

	cart.Items = append(cart.Items, cartItem)
	cs.updateCartTotals(cart)
	log.Printf("CartService.AddToCart - Added new product, cart totals: TotalItems=%d, TotalPrice=%.2f", cart.TotalItems, cart.TotalPrice)
	return nil
}

// UpdateCartItem, sepet öğesini günceller
func (cs *CartService) UpdateCartItem(sessionID string, productID int, quantity int) error {
	log.Printf("CartService.UpdateCartItem - SessionID: %s, ProductID: %d, Quantity: %d", sessionID, productID, quantity)

	// Sepeti al
	cart, err := cs.db.GetCartBySessionID(sessionID)
	if err != nil {
		log.Printf("CartService.UpdateCartItem - Cart not found for session: %s", sessionID)
		return fmt.Errorf("sepet bulunamadı")
	}

	log.Printf("CartService.UpdateCartItem - Cart found with %d items", len(cart.Items))

	for i, item := range cart.Items {
		log.Printf("CartService.UpdateCartItem - Checking item %d: ProductID=%d", i, item.ProductID)
		if item.ProductID == productID {
			log.Printf("CartService.UpdateCartItem - Found matching product, updating quantity from %d to %d", item.Quantity, quantity)
			if quantity <= 0 {
				// Ürünü sepetten kaldır
				log.Printf("CartService.UpdateCartItem - Removing item from cart")
				if err := cs.db.DeleteCartItem(item.ID); err != nil {
					log.Printf("CartService.UpdateCartItem - Error deleting cart item: %v", err)
					return err
				}
				cart.Items = append(cart.Items[:i], cart.Items[i+1:]...)
			} else {
				cart.Items[i].Quantity = quantity
				cart.Items[i].TotalPrice = float64(quantity) * cart.Items[i].Price
				log.Printf("CartService.UpdateCartItem - Updated item: Quantity=%d, TotalPrice=%.2f", cart.Items[i].Quantity, cart.Items[i].TotalPrice)

				// Veritabanında güncelle
				if err := cs.db.UpdateCartItem(&cart.Items[i]); err != nil {
					log.Printf("CartService.UpdateCartItem - Error updating cart item: %v", err)
					return err
				}
			}
			cs.updateCartTotals(cart)
			log.Printf("CartService.UpdateCartItem - Cart totals updated: TotalItems=%d, TotalPrice=%.2f", cart.TotalItems, cart.TotalPrice)
			return nil
		}
	}

	log.Printf("CartService.UpdateCartItem - Product %d not found in cart", productID)
	return fmt.Errorf("ürün sepette bulunamadı")
}

// RemoveFromCart, sepetten ürün kaldırır
func (cs *CartService) RemoveFromCart(sessionID string, productID int) error {
	log.Printf("CartService.RemoveFromCart - SessionID: %s, ProductID: %d", sessionID, productID)

	// Sepeti al
	cart, err := cs.db.GetCartBySessionID(sessionID)
	if err != nil {
		log.Printf("CartService.RemoveFromCart - Cart not found for session: %s", sessionID)
		return fmt.Errorf("sepet bulunamadı")
	}

	for i, item := range cart.Items {
		if item.ProductID == productID {
			log.Printf("CartService.RemoveFromCart - Removing item %d from cart", item.ID)
			if err := cs.db.DeleteCartItem(item.ID); err != nil {
				log.Printf("CartService.RemoveFromCart - Error deleting cart item: %v", err)
				return err
			}
			cart.Items = append(cart.Items[:i], cart.Items[i+1:]...)
			cs.updateCartTotals(cart)
			return nil
		}
	}

	return fmt.Errorf("ürün sepette bulunamadı")
}

// ClearCart, sepeti temizler
func (cs *CartService) ClearCart(sessionID string) {
	log.Printf("CartService.ClearCart - SessionID: %s", sessionID)

	cart, err := cs.db.GetCartBySessionID(sessionID)
	if err != nil {
		log.Printf("CartService.ClearCart - Cart not found for session: %s", sessionID)
		return
	}

	// Tüm sepet öğelerini sil
	for _, item := range cart.Items {
		if err := cs.db.DeleteCartItem(item.ID); err != nil {
			log.Printf("CartService.ClearCart - Error deleting cart item: %v", err)
		}
	}

	cart.Items = []models.CartItem{}
	cs.updateCartTotals(cart)
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

	// Veritabanında güncelle
	if err := cs.db.UpdateCart(cart); err != nil {
		log.Printf("CartService.updateCartTotals - Error updating cart: %v", err)
	}
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
