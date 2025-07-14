package models

import (
	"time"
)

// Cart, sepet modelini temsil eder
type Cart struct {
	ID         int        `json:"id" db:"id"`
	SessionID  string     `json:"session_id" db:"session_id"`
	Items      []CartItem `json:"items"`
	TotalItems int        `json:"total_items" db:"total_items"`
	TotalPrice float64    `json:"total_price" db:"total_price"`
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at" db:"updated_at"`
}

// CartItem, sepet öğesini temsil eder
type CartItem struct {
	ID         int     `json:"id" db:"id"`
	CartID     int     `json:"cart_id" db:"cart_id"`
	ProductID  int     `json:"product_id" db:"product_id"`
	Name       string  `json:"name" db:"name"`
	Price      float64 `json:"price" db:"price"`
	Image      string  `json:"image" db:"image"`
	Quantity   int     `json:"quantity" db:"quantity"`
	TotalPrice float64 `json:"total_price" db:"total_price"`
}
