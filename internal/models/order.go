package models

import "time"

// Order, siparişi temsil eder
type Order struct {
	ID            int        `json:"id"`
	UserID        int        `json:"user_id"`
	SessionID     string     `json:"session_id"`
	OrderNumber   string     `json:"order_number"`
	CustomerName  string     `json:"customer_name"`
	Email         string     `json:"email"`
	Phone         string     `json:"phone"`
	Address       string     `json:"address"`
	Items         []CartItem `json:"items"`
	TotalPrice    float64    `json:"total_price"`
	Status        string     `json:"status"` // "pending", "confirmed", "shipped", "delivered", "cancelled"
	PaymentMethod string     `json:"payment_method"`
	Notes         string     `json:"notes"`
	AdminNotes    string     `json:"admin_notes"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// OrderItem, sipariş öğesini temsil eder
type OrderItem struct {
	ID         int     `json:"id"`
	OrderID    int     `json:"order_id"`
	ProductID  int     `json:"product_id"`
	Name       string  `json:"name"`
	Price      float64 `json:"price"`
	Image      string  `json:"image"`
	Quantity   int     `json:"quantity"`
	TotalPrice float64 `json:"total_price"`
}

// OrderForm, sipariş formu verilerini temsil eder
type OrderForm struct {
	CustomerName  string `form:"customerName" binding:"required"`
	Email         string `form:"email" binding:"required,email"`
	Phone         string `form:"phone" binding:"required"`
	Address       string `form:"address" binding:"required"`
	PaymentMethod string `form:"paymentMethod"`
	Notes         string `form:"notes"`
}
