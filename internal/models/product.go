package models

import (
	"time"
)

type Product struct {
	ID          int       `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Description string    `json:"description" db:"description"`
	Price       float64   `json:"price" db:"price"`
	Image       string    `json:"image" db:"image"`
	Category    string    `json:"category" db:"category"`
	Stock       int       `json:"stock" db:"stock"`
	Features    string    `json:"features" db:"features"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

type ProductForm struct {
	Name        string            `form:"name" binding:"required"`
	Description string            `form:"description" binding:"required"`
	Price       float64           `form:"price" binding:"required"`
	Category    string            `form:"category" binding:"required"`
	Stock       int               `form:"stock" binding:"required"`
	Features    map[string]string `form:"features"`
}

type ProductFeature struct {
	Key   string `json:"key"`
	Value string `json:"value"`
} 