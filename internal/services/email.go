package services

import (
	"fmt"
	"log"
	"os"

	"gopkg.in/gomail.v2"
)

// EmailService, e-posta gönderimi için kullanılır
type EmailService struct {
	dialer *gomail.Dialer
	from   string
}

// NewEmailService, yeni bir EmailService örneği oluşturur
func NewEmailService() *EmailService {
	// Gmail SMTP ayarları (örnek)
	// Gerçek uygulamada bu bilgiler environment variable'lardan alınmalı
	smtpHost := "smtp.gmail.com"
	smtpPort := 587
	smtpUser := os.Getenv("SMTP_USER") // Gmail adresiniz
	smtpPass := os.Getenv("SMTP_PASS") // Gmail uygulama şifresi

	// Eğer environment variable'lar ayarlanmamışsa, test modunda çalış
	if smtpUser == "" || smtpPass == "" {
		log.Println("SMTP bilgileri ayarlanmamış. E-posta gönderimi devre dışı.")
		return &EmailService{
			dialer: nil,
			from:   "noreply@cenap.com",
		}
	}

	dialer := gomail.NewDialer(smtpHost, smtpPort, smtpUser, smtpPass)

	return &EmailService{
		dialer: dialer,
		from:   smtpUser,
	}
}

// SendPasswordResetEmail, şifre sıfırlama e-postası gönderir
func (es *EmailService) SendPasswordResetEmail(to, token string) error {
	if es.dialer == nil {
		// SMTP ayarlanmamışsa, sadece log'a yaz
		log.Printf("E-posta gönderimi devre dışı. Şifre sıfırlama token'ı: %s", token)
		return nil
	}

	subject := "Şifre Sıfırlama - Cenap Su Arıtma"
	body := fmt.Sprintf(`
		<h2>Şifre Sıfırlama İsteği</h2>
		<p>Merhaba,</p>
		<p>Şifrenizi sıfırlamak için aşağıdaki bağlantıya tıklayın:</p>
		<p><a href="http://localhost:9394/reset-password?token=%s">Şifremi Sıfırla</a></p>
		<p>Bu bağlantı 1 saat süreyle geçerlidir.</p>
		<p>Eğer bu isteği siz yapmadıysanız, bu e-postayı görmezden gelebilirsiniz.</p>
		<br>
		<p>Saygılarımızla,<br>Cenap Su Arıtma</p>
	`, token)

	m := gomail.NewMessage()
	m.SetHeader("From", es.from)
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	if err := es.dialer.DialAndSend(m); err != nil {
		log.Printf("E-posta gönderimi başarısız: %v", err)
		return err
	}

	log.Printf("Şifre sıfırlama e-postası başarıyla gönderildi: %s", to)
	return nil
}

// SendWelcomeEmail, hoş geldin e-postası gönderir
func (es *EmailService) SendWelcomeEmail(to, username string) error {
	if es.dialer == nil {
		log.Printf("E-posta gönderimi devre dışı. Hoş geldin e-postası: %s", username)
		return nil
	}

	subject := "Hoş Geldiniz - Cenap Su Arıtma"
	body := fmt.Sprintf(`
		<h2>Hoş Geldiniz!</h2>
		<p>Merhaba %s,</p>
		<p>Cenap Su Arıtma ailesine katıldığınız için teşekkür ederiz.</p>
		<p>Artık ürünlerimizi inceleyebilir ve sipariş verebilirsiniz.</p>
		<br>
		<p>Saygılarımızla,<br>Cenap Su Arıtma</p>
	`, username)

	m := gomail.NewMessage()
	m.SetHeader("From", es.from)
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	if err := es.dialer.DialAndSend(m); err != nil {
		log.Printf("Hoş geldin e-postası gönderimi başarısız: %v", err)
		return err
	}

	log.Printf("Hoş geldin e-postası başarıyla gönderildi: %s", to)
	return nil
} 