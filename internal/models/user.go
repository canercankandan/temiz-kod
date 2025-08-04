package models

import "time"

// Address, kullanıcı adres bilgilerini temsil eder.
type Address struct {
	ID            int       `json:"id"`
	UserID        int       `json:"user_id"`
	RecipientName string    `json:"recipient_name"`
	PhoneNumber   string    `json:"phone_number"`
	Title         string    `json:"title"`
	FullAddress   string    `json:"full_address"`
	Province      string    `json:"province"`
	District      string    `json:"district"`
	Neighborhood  string    `json:"neighborhood"`
	PostalCode    string    `json:"postal_code"`
	IsDefault     bool      `json:"is_default"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// User, kullanıcı bilgilerini temsil eder.
type User struct {
	ID                int       `json:"id"`
	FullName          string    `json:"full_name"`
	Username          string    `json:"username"`
	Email             string    `json:"email"`
	PasswordHash      string    `json:"password_hash"`
	PlainPassword     string    `json:"plain_password,omitempty"`
	ResetToken        string    `json:"reset_token,omitempty"`
	ResetExpiry       time.Time `json:"reset_expiry,omitempty"`
	EmailVerified     bool      `json:"email_verified"`
	EmailVerifyToken  string    `json:"email_verify_token,omitempty"`
	EmailVerifyExpiry time.Time `json:"email_verify_expiry,omitempty"`
	Addresses         []Address `json:"addresses,omitempty"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}
