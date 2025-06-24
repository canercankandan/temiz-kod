package models

import "time"

// User, kullanıcı bilgilerini temsil eder.
type User struct {
	ID           int       `json:"id"`
	FullName     string    `json:"full_name"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	Phone        string    `json:"phone"`
	Address      string    `json:"address"`
	City         string    `json:"city"`
	District     string    `json:"district"`
	PostalCode   string    `json:"postal_code"`
	PasswordHash string    `json:"password_hash"`
	ResetToken   string    `json:"reset_token,omitempty"`
	ResetExpiry  time.Time `json:"reset_expiry,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
} 