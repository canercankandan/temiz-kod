package models

import "time"

// Message - Canlı destek mesajları için model
type Message struct {
	ID        int       `json:"id" db:"id"`
	UserID    *int      `json:"user_id" db:"user_id"`    // Null olabilir (anonim kullanıcılar için)
	Username  string    `json:"username" db:"username"`   // Kullanıcı adı
	SessionID string    `json:"session_id" db:"session_id"` // Session ID
	Message   string    `json:"message" db:"message"`
	Content   string    `json:"content" db:"content"`     // Mesaj içeriği (alternatif alan)
	IsAdmin   bool      `json:"is_admin" db:"is_admin"`   // Admin mesajı mı?
	IsUser    bool      `json:"is_user" db:"is_user"`     // Kullanıcı mesajı mı?
	IsRead    bool      `json:"is_read" db:"is_read"`     // Okundu mu?
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	Timestamp time.Time `json:"timestamp" db:"timestamp"` // Zaman damgası
}

// SupportSession - Destek oturumu
type SupportSession struct {
	ID            int       `json:"id" db:"id"`
	SessionID     string    `json:"session_id" db:"session_id"`
	UserID        *int      `json:"user_id" db:"user_id"`
	Username      string    `json:"username" db:"username"`
	Status        string    `json:"status" db:"status"` // active, closed
	LastMessageAt time.Time `json:"last_message_at" db:"last_message_at"`
	CreatedAt     time.Time `json:"created_at" db:"created_at"`
	UnreadCount   int       `json:"unread_count" db:"unread_count"`
}

// VideoCallRequest - Video görüşme talebi
type VideoCallRequest struct {
	ID           int       `json:"id" db:"id"`
	SessionID    string    `json:"session_id" db:"session_id"`
	UserID       *int      `json:"user_id" db:"user_id"`
	Username     string    `json:"username" db:"username"`
	Status       string    `json:"status" db:"status"` // pending, accepted, rejected, ended
	RequestedAt  time.Time `json:"requested_at" db:"requested_at"`
	RespondedAt  *time.Time `json:"responded_at" db:"responded_at"`
	Initiator    string    `json:"initiator" db:"initiator"`
} 