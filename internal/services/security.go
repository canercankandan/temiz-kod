package services

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

// SecurityLogger, güvenlik olaylarını loglar
type SecurityLogger struct {
	file *os.File
}

// NewSecurityLogger, yeni bir güvenlik logger'ı oluşturur
func NewSecurityLogger() *SecurityLogger {
	file, err := os.OpenFile("security.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Güvenlik log dosyası oluşturulamadı: %v", err)
		return nil
	}

	return &SecurityLogger{file: file}
}

// LogSecurityEvent, güvenlik olayını loglar
func (sl *SecurityLogger) LogSecurityEvent(eventType, details, ipAddress string) {
	if sl.file == nil {
		return
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	logEntry := fmt.Sprintf("[%s] %s - %s - IP: %s\n", timestamp, eventType, details, ipAddress)

	_, err := sl.file.WriteString(logEntry)
	if err != nil {
		log.Printf("Güvenlik log yazma hatası: %v", err)
	}
}

// Close, log dosyasını kapatır
func (sl *SecurityLogger) Close() {
	if sl.file != nil {
		sl.file.Close()
	}
}

// SpamDetector, spam içerik tespiti yapar
type SpamDetector struct {
	spamWords []string
}

// NewSpamDetector, yeni bir spam detector oluşturur
func NewSpamDetector() *SpamDetector {
	return &SpamDetector{
		spamWords: []string{
			"bitcoin", "btc", "crypto", "wallet", "deposit", "withdraw",
			"investment", "profit", "earn money", "make money", "get rich",
			"quick money", "urgent", "limited time", "exclusive offer",
			"free money", "lottery", "prize", "winner", "claim", "verify",
			"account suspended", "security alert", "bank transfer",
			"western union", "moneygram", "nigerian prince", "inheritance",
			"lottery winner", "bank account", "credit card", "ssn",
			"social security", "passport", "driver license", "id card",
			"incoming", "pending", "transaction", "transfer", "redeem",
			"graph.org", "external sender", "unknown sender", "review?",
			"accept?", "approve?", "📃", "📩", "🔑", "🔷", "🗂", "✉️",
		},
	}
}

// IsSpam, mesajın spam olup olmadığını kontrol eder
func (sd *SpamDetector) IsSpam(message string) bool {
	messageLower := strings.ToLower(message)
	for _, word := range sd.spamWords {
		if strings.Contains(messageLower, word) {
			return true
		}
	}
	return false
}
