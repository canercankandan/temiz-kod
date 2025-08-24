package services

import (
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"time"

	"cenap/internal/models"

	"gopkg.in/gomail.v2"
)

// EmailService, e-posta gönderimi için kullanılır
type EmailService struct {
	dialer *gomail.Dialer
	from   string
}

// NewEmailService, yeni bir EmailService örneği oluşturur
func NewEmailService() *EmailService {
	// Gmail SMTP ayarları
	smtpHost := "smtp.gmail.com"
	smtpPort := 587
	smtpUser := "irmaksuaritmam@gmail.com"
	smtpPass := "opmo faai pxds svsb"  // App Password

	// Log SMTP configuration
	log.Printf("📧 SMTP Yapılandırması:")
	log.Printf("📧 Host: %s", smtpHost)
	log.Printf("📧 Port: %d", smtpPort)
	log.Printf("📧 User: %s", smtpUser)
	log.Printf("📧 Pass: ***************")
	
	// Log SMTP configuration (without password)
	log.Printf("SMTP Configuration - Host: %s, Port: %d, User: %s", smtpHost, smtpPort, smtpUser)

	// SMTP bilgileri kontrol et
	if smtpUser == "" || smtpPass == "" {
		log.Println("SMTP bilgileri ayarlanmamış. E-posta gönderimi devre dışı.")
		return &EmailService{
			dialer: nil,
			from:   "noreply@cenap.com",
		}
	}

	dialer := gomail.NewDialer(smtpHost, smtpPort, smtpUser, smtpPass)

	// TLS güvenlik ayarları
	dialer.TLSConfig = &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         "smtp.gmail.com",
	}

	// Test bağlantısı
	if d, err := dialer.Dial(); err != nil {
		log.Printf("SMTP bağlantı hatası: %v", err)
	} else {
		d.Close()
		log.Println("SMTP bağlantısı başarılı")
	}

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
		<p>Şifrenizi sıfırlamak için aşağıdaki bağlantılardan birini kullanın:</p>
		
		<div style="text-align: center; margin: 20px 0;">
			<a href="https://xn--suartmauzman-44bi.com/reset-password?token=%s" style="display: inline-block; background-color: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold; margin: 10px;">🔐 Şifremi Sıfırla</a>
		</div>
		
		<p><strong>Alternatif Link:</strong></p>
		<p><a href="https://xn--suartmauzman-44bi.com/reset-password?token=%s">https://xn--suartmauzman-44bi.com/reset-password?token=%s</a></p>
		
		<p>Bu bağlantı 1 saat süreyle geçerlidir.</p>
		<p>Eğer bu isteği siz yapmadıysanız, bu e-postayı görmezden gelebilirsiniz.</p>
		<br>
		<p>Saygılarımızla,<br>Cenap Su Arıtma</p>
	`, token, token, token)

	m := gomail.NewMessage()
	m.SetHeader("From", es.from)
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	return es.dialer.DialAndSend(m)
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
		<p>Merhaba <strong>%s</strong>,</p>
		<p>Cenap Su Arıtma ailesine hoş geldiniz! Hesabınız başarıyla oluşturuldu.</p>
		<br>
		<p>Artık aşağıdaki hizmetlerimizden yararlanabilirsiniz:</p>
		<ul>
			<li>✅ Kaliteli su arıtma cihazları</li>
			<li>✅ 7/24 canlı destek</li>
			<li>✅ Ücretsiz kurulum</li>
			<li>✅ 5 yıl garanti</li>
		</ul>
		<br>
		<div style="text-align: center; margin: 20px 0;">
			<a href="https://xn--suartmauzman-44bi.com" style="display: inline-block; background-color: #28a745; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold;">🏠 Ana Sayfaya Git</a>
		</div>
		<br>
		<p>Herhangi bir sorunuz olursa <a href="https://xn--suartmauzman-44bi.com/contact">iletişim</a> sayfamızdan bize ulaşabilirsiniz.</p>
		<br>
		<p>Saygılarımızla,<br>Cenap Su Arıtma</p>
	`, username)

	m := gomail.NewMessage()
	m.SetHeader("From", es.from)
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	return es.dialer.DialAndSend(m)
}

// SendVideoCallNotification, video call talebi bildirimi gönderir
func (es *EmailService) SendVideoCallNotification(adminEmail, customerName, sessionID string) error {
	if es.dialer == nil {
		log.Printf("E-posta gönderimi devre dışı. Video call bildirimi: %s - %s", customerName, sessionID)
		return nil
	}

	subject := "Video Görüşme Talebi - Cenap Su Arıtma"
	body := fmt.Sprintf(`
		<h2>Video Görüşme Talebi</h2>
		<p>Merhaba,</p>
		<p><strong>%s</strong> adlı müşteri canlı destek üzerinden video görüşme talebinde bulundu.</p>
		<p><strong>Session ID:</strong> %s</p>
		<p><strong>Tarih:</strong> %s</p>
		<br>
		<p>Video görüşme talebini yanıtlamak için admin panelini kontrol edin.</p>
		
		<div style="text-align: center; margin: 20px 0;">
			<a href="https://xn--suartmauzman-44bi.com/admin/support" style="display: inline-block; background-color: #28a745; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold; margin: 10px;">📱 Admin Destek Paneli</a>
		</div>
		
		<p><strong>Alternatif Linkler:</strong></p>
		<ul>
			<li><a href="https://xn--suartmauzman-44bi.com/admin">Ana Admin Paneli</a></li>
			<li><a href="https://xn--suartmauzman-44bi.com/admin/support">Destek Paneli</a></li>
		</ul>
		
		<br>
		<p>Saygılarımızla,<br>Cenap Su Arıtma</p>
	`, customerName, sessionID, time.Now().Format("02.01.2006 15:04:05"))

	m := gomail.NewMessage()
	m.SetHeader("From", es.from)
	m.SetHeader("To", adminEmail)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	return es.dialer.DialAndSend(m)
}

// SendSupportChatNotification, yeni ziyaretçi canlı desteğe geldiğinde mail bildirimi gönderir
func (es *EmailService) SendSupportChatNotification(adminEmail, visitorName, sessionID, userAgent string) error {
	if es.dialer == nil {
		log.Printf("E-posta gönderimi devre dışı. Support chat bildirimi: %s - %s", visitorName, sessionID)
		return nil
	}

	subject := "Yeni Canlı Destek Ziyaretçisi - Cenap Su Arıtma"
	body := fmt.Sprintf(`
		<h2>🔔 Yeni Canlı Destek Ziyaretçisi</h2>
		<p>Merhaba,</p>
		<p><strong>%s</strong> adlı ziyaretçi canlı destek sayfasına girdi ve sizi bekliyor.</p>
		<br>
		<p><strong>Ziyaretçi Bilgileri:</strong></p>
		<ul>
			<li><strong>Ad:</strong> %s</li>
			<li><strong>Session ID:</strong> %s</li>
			<li><strong>Tarih:</strong> %s</li>
			<li><strong>Tarayıcı:</strong> %s</li>
		</ul>
		<br>
		<p>Ziyaretçiye yardımcı olmak için admin panelini kontrol edin.</p>
		
		<div style="text-align: center; margin: 20px 0;">
			<a href="https://xn--suartmauzman-44bi.com/admin" style="display: inline-block; background-color: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold; margin: 10px;">📱 Admin Paneli</a>
			<a href="https://xn--suartmauzman-44bi.com/admin/support" style="display: inline-block; background-color: #28a745; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold; margin: 10px;">💬 Canlı Destek</a>
		</div>
		
		<p><strong>Hızlı Erişim Linkleri:</strong></p>
		<ul>
			<li><a href="https://xn--suartmauzman-44bi.com/admin">Ana Admin Paneli</a></li>
			<li><a href="https://xn--suartmauzman-44bi.com/admin/support">Canlı Destek Paneli</a></li>
		</ul>
		
		<br>
		<p><em>Bu bildirim, ziyaretçi canlı destek sayfasına girdiğinde otomatik olarak gönderilmiştir.</em></p>
		<br>
		<p>Saygılarımızla,<br>Cenap Su Arıtma</p>
	`, visitorName, visitorName, sessionID, time.Now().Format("02.01.2006 15:04:05"), userAgent)

	m := gomail.NewMessage()
	m.SetHeader("From", es.from)
	m.SetHeader("To", adminEmail)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	return es.dialer.DialAndSend(m)
}

// SendAdminOrderNotification, yeni sipariş geldiğinde admin'e bildirim gönderir
func (es *EmailService) SendAdminOrderNotification(adminEmail string, order *models.Order) error {
	if es.dialer == nil {
		log.Printf("E-posta gönderimi devre dışı. Admin sipariş bildirimi: %s", order.OrderNumber)
		return nil
	}

	// Sipariş ürünlerini formatla
	var itemsHTML string
	for _, item := range order.Items {
		itemsHTML += fmt.Sprintf(`
			<tr>
				<td style="padding: 10px; border-bottom: 1px solid #eee;">%s</td>
				<td style="padding: 10px; border-bottom: 1px solid #eee;">%.2f TL</td>
				<td style="padding: 10px; border-bottom: 1px solid #eee;">%d</td>
				<td style="padding: 10px; border-bottom: 1px solid #eee;">%.2f TL</td>
			</tr>
		`, item.Name, item.Price, item.Quantity, item.Price*float64(item.Quantity))
	}

	subject := "Yeni Sipariş Bildirimi - Cenap Su Arıtma"
	body := fmt.Sprintf(`
		<h2>🛒 Yeni Sipariş Alındı!</h2>
		<p>Merhaba,</p>
		<p>Yeni bir sipariş alındı ve işleme hazır.</p>
		<br>
		<p><strong>Sipariş Detayları:</strong></p>
		<ul>
			<li><strong>Sipariş Numarası:</strong> %s</li>
			<li><strong>Müşteri Adı:</strong> %s</li>
			<li><strong>E-posta:</strong> %s</li>
			<li><strong>Telefon:</strong> %s</li>
			<li><strong>Adres:</strong> %s</li>
			<li><strong>Ödeme Yöntemi:</strong> %s</li>
			<li><strong>Toplam Tutar:</strong> %.2f TL</li>
			<li><strong>Tarih:</strong> %s</li>
		</ul>
		<br>
		<p><strong>Sipariş Ürünleri:</strong></p>
		<table style="width: 100%%; border-collapse: collapse; margin: 20px 0;">
			<thead>
				<tr style="background-color: #f8f9fa;">
					<th style="padding: 10px; text-align: left; border-bottom: 2px solid #dee2e6;">Ürün</th>
					<th style="padding: 10px; text-align: left; border-bottom: 2px solid #dee2e6;">Fiyat</th>
					<th style="padding: 10px; text-align: left; border-bottom: 2px solid #dee2e6;">Adet</th>
					<th style="padding: 10px; text-align: left; border-bottom: 2px solid #dee2e6;">Toplam</th>
				</tr>
			</thead>
			<tbody>
				%s
			</tbody>
		</table>
		<br>
		<p><strong>Müşteri Notları:</strong></p>
		<p style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #007bff;">%s</p>
		<br>
		<div style="text-align: center; margin: 20px 0;">
			<a href="https://xn--suartmauzman-44bi.com/admin" style="display: inline-block; background-color: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold; margin: 10px;">📱 Admin Paneli</a>
		</div>
		<br>
		<p><strong>Hızlı Erişim Linkleri:</strong></p>
		<ul>
			<li><a href="https://xn--suartmauzman-44bi.com/admin">Ana Admin Paneli</a></li>
		</ul>
		<br>
		<p><em>Bu bildirim, müşteri siparişi tamamladığında otomatik olarak gönderilmiştir.</em></p>
		<br>
		<p>Saygılarımızla,<br>Cenap Su Arıtma</p>
	`, order.OrderNumber, order.CustomerName, order.Email, order.Phone, order.Address, order.PaymentMethod, order.TotalPrice, order.CreatedAt.Format("02.01.2006 15:04:05"), itemsHTML, order.Notes)

	m := gomail.NewMessage()
	m.SetHeader("From", es.from)
	m.SetHeader("To", adminEmail)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	return es.dialer.DialAndSend(m)
}

// SendCustomerOrderConfirmation, müşteriye sipariş onay e-postası gönderir
func (es *EmailService) SendCustomerOrderConfirmation(customerEmail string, order *models.Order) error {
	if es.dialer == nil {
		log.Printf("E-posta gönderimi devre dışı. Müşteri sipariş onayı: %s", order.OrderNumber)
		return nil
	}

	// Sipariş ürünlerini formatla
	var itemsHTML string
	for _, item := range order.Items {
		itemsHTML += fmt.Sprintf(`
			<tr>
				<td style="padding: 10px; border-bottom: 1px solid #eee;">%s</td>
				<td style="padding: 10px; border-bottom: 1px solid #eee;">%.2f TL</td>
				<td style="padding: 10px; border-bottom: 1px solid #eee;">%d</td>
				<td style="padding: 10px; border-bottom: 1px solid #eee;">%.2f TL</td>
			</tr>
		`, item.Name, item.Price, item.Quantity, item.Price*float64(item.Quantity))
	}

	subject := "Sipariş Onayı - Cenap Su Arıtma"
	body := fmt.Sprintf(`
		<h2>✅ Siparişiniz Alındı!</h2>
		<p>Merhaba <strong>%s</strong>,</p>
		<p>Siparişiniz başarıyla alındı ve işleme alındı. Sipariş detaylarınız aşağıdadır:</p>
		<br>
		<p><strong>Sipariş Bilgileri:</strong></p>
		<ul>
			<li><strong>Sipariş Numarası:</strong> %s</li>
			<li><strong>Sipariş Tarihi:</strong> %s</li>
			<li><strong>Toplam Tutar:</strong> %.2f TL</li>
			<li><strong>Ödeme Yöntemi:</strong> %s</li>
		</ul>
		<br>
		<p><strong>Teslimat Bilgileri:</strong></p>
		<ul>
			<li><strong>Ad Soyad:</strong> %s</li>
			<li><strong>Telefon:</strong> %s</li>
			<li><strong>Adres:</strong> %s</li>
		</ul>
		<br>
		<p><strong>Sipariş Ürünleri:</strong></p>
		<table style="width: 100%%; border-collapse: collapse; margin: 20px 0;">
			<thead>
				<tr style="background-color: #f8f9fa;">
					<th style="padding: 10px; text-align: left; border-bottom: 2px solid #dee2e6;">Ürün</th>
					<th style="padding: 10px; text-align: left; border-bottom: 2px solid #dee2e6;">Fiyat</th>
					<th style="padding: 10px; text-align: left; border-bottom: 2px solid #dee2e6;">Adet</th>
					<th style="padding: 10px; text-align: left; border-bottom: 2px solid #dee2e6;">Toplam</th>
				</tr>
			</thead>
			<tbody>
				%s
			</tbody>
		</table>
		<br>
		<p><strong>Sipariş Notlarınız:</strong></p>
		<p style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #007bff;">%s</p>
		<br>
		<p><strong>Sipariş Takibi:</strong></p>
		<p>Siparişinizin durumunu takip etmek için aşağıdaki linki kullanabilirsiniz:</p>
		<div style="text-align: center; margin: 20px 0;">
			<a href="https://xn--suartmauzman-44bi.com/track?order_number=%s&email=%s" style="display: inline-block; background-color: #28a745; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold; margin: 10px;">📦 Siparişimi Takip Et</a>
		</div>
		<br>
		<p><strong>Önemli Bilgiler:</strong></p>
		<ul>
			<li>✅ Siparişiniz 24 saat içinde işleme alınacak</li>
			<li>✅ Kargo bilgileri email ile bildirilecek</li>
			<li>✅ 7/24 canlı destek hizmetimiz mevcuttur</li>
			<li>✅ 2 yıl garanti kapsamındadır</li>
			<li>✅ 1 yıl parça garantisi</li>
		</ul>
		<br>
		<p><strong>İletişim:</strong></p>
		<p>Herhangi bir sorunuz olursa:</p>
		<ul>
			<li>📞 <a href="tel:+905448113105">0544 811 31 05</a></li>
			<li>💬 <a href="https://xn--suartmauzman-44bi.com/support">Canlı Destek</a></li>
			<li>📧 <a href="mailto:irmaksuaritmam.com">irmaksuaritmam.com</a></li>
		</ul>
		<br>
		<p>Teşekkür ederiz,<br><strong>Cenap Su Arıtma</strong></p>
	`, order.CustomerName, order.OrderNumber, order.CreatedAt.Format("02.01.2006 15:04:05"), order.TotalPrice, order.PaymentMethod, order.CustomerName, order.Phone, order.Address, itemsHTML, order.Notes, order.OrderNumber, order.Email)

	m := gomail.NewMessage()
	m.SetHeader("From", es.from)
	m.SetHeader("To", customerEmail)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	return es.dialer.DialAndSend(m)
}

// SendAdminOrderConfirmationEmail, admin siparişi onayladığında müşteriye gönderilen email
func (es *EmailService) SendAdminOrderConfirmationEmail(customerEmail string, order *models.Order) error {
	if es.dialer == nil {
		log.Printf("E-posta gönderimi devre dışı. Admin sipariş onayı: %s", order.OrderNumber)
		return nil
	}

	// Sipariş ürünlerini formatla
	var itemsHTML string
	for _, item := range order.Items {
		itemsHTML += fmt.Sprintf(`
			<tr>
				<td style="padding: 10px; border-bottom: 1px solid #eee;">%s</td>
				<td style="padding: 10px; border-bottom: 1px solid #eee;">%.2f TL</td>
				<td style="padding: 10px; border-bottom: 1px solid #eee;">%d</td>
				<td style="padding: 10px; border-bottom: 1px solid #eee;">%.2f TL</td>
			</tr>
		`, item.Name, item.Price, item.Quantity, item.Price*float64(item.Quantity))
	}

	subject := "Siparişiniz Onaylandı - Cenap Su Arıtma"
	body := fmt.Sprintf(`
		<h2>✅ Siparişiniz Onaylandı!</h2>
		<p>Merhaba <strong>%s</strong>,</p>
		<p>Siparişiniz yöneticimiz tarafından onaylandı ve kargoya verilmek üzere hazırlanıyor.</p>
		<br>
		<p><strong>Sipariş Bilgileri:</strong></p>
		<ul>
			<li><strong>Sipariş Numarası:</strong> %s</li>
			<li><strong>Sipariş Tarihi:</strong> %s</li>
			<li><strong>Onay Tarihi:</strong> %s</li>
			<li><strong>Toplam Tutar:</strong> %.2f TL</li>
			<li><strong>Ödeme Yöntemi:</strong> %s</li>
		</ul>
		<br>
		<p><strong>Teslimat Bilgileri:</strong></p>
		<ul>
			<li><strong>Ad Soyad:</strong> %s</li>
			<li><strong>Telefon:</strong> %s</li>
			<li><strong>Adres:</strong> %s</li>
		</ul>
		<br>
		<p><strong>Sipariş Ürünleri:</strong></p>
		<table style="width: 100%%; border-collapse: collapse; margin: 20px 0;">
			<thead>
				<tr style="background-color: #f8f9fa;">
					<th style="padding: 10px; text-align: left; border-bottom: 2px solid #dee2e6;">Ürün</th>
					<th style="padding: 10px; text-align: left; border-bottom: 2px solid #dee2e6;">Fiyat</th>
					<th style="padding: 10px; text-align: left; border-bottom: 2px solid #dee2e6;">Adet</th>
					<th style="padding: 10px; text-align: left; border-bottom: 2px solid #dee2e6;">Toplam</th>
				</tr>
			</thead>
			<tbody>
				%s
			</tbody>
		</table>
		<br>
		<p><strong>Sipariş Notlarınız:</strong></p>
		<p style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #007bff;">%s</p>
		<br>
		<p><strong>Sonraki Adımlar:</strong></p>
		<ul>
			<li>✅ Siparişiniz kargoya verilecek</li>
			<li>✅ Kargo takip numarası email ile bildirilecek</li>
			<li>✅ Teslimat 1-3 iş günü içinde yapılacak</li>
			<li>✅ Kurulum ekibimiz sizinle iletişime geçecek</li>
		</ul>
		<br>
		<p><strong>Sipariş Takibi:</strong></p>
		<p>Siparişinizin durumunu takip etmek için aşağıdaki linki kullanabilirsiniz:</p>
		<div style="text-align: center; margin: 20px 0;">
			<a href="https://xn--suartmauzman-44bi.com/track?order_number=%s&email=%s" style="display: inline-block; background-color: #28a745; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold; margin: 10px;">📦 Siparişimi Takip Et</a>
		</div>
		<br>
		<p><strong>Önemli Bilgiler:</strong></p>
		<ul>
			<li>✅ 2 yıl garanti kapsamındadır</li>
			<li>✅ 1 yıl parça garantisi</li>
			<li>✅ Ücretsiz kurulum hizmeti</li>
			<li>✅ 7/24 canlı destek hizmetimiz mevcuttur</li>
			<li>✅ Teknik servis desteği</li>
		</ul>
		<br>
		<p><strong>İletişim:</strong></p>
		<p>Herhangi bir sorunuz olursa:</p>
		<ul>
			<li>📞 <a href="tel:+905448113105">0544 811 31 05</a></li>
			<li>💬 <a href="https://xn--suartmauzman-44bi.com/support">Canlı Destek</a></li>
			<li>📧 <a href="mailto:irmaksuaritmam.com">irmaksuaritmam.com</a></li>
		</ul>
		<br>
		<p>Teşekkür ederiz,<br><strong>Cenap Su Arıtma</strong></p>
	`, order.CustomerName, order.OrderNumber, order.CreatedAt.Format("02.01.2006 15:04:05"), time.Now().Format("02.01.2006 15:04:05"), order.TotalPrice, order.PaymentMethod, order.CustomerName, order.Phone, order.Address, itemsHTML, order.Notes, order.OrderNumber, order.Email)

	m := gomail.NewMessage()
	m.SetHeader("From", es.from)
	m.SetHeader("To", customerEmail)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	return es.dialer.DialAndSend(m)
}

// SendEmailVerification, e-posta doğrulama linki gönderir
func (es *EmailService) SendEmailVerification(to, username, token string) error {
	if es.dialer == nil {
		log.Printf("E-posta gönderimi devre dışı. E-posta doğrulama: %s - %s", to, token)
		return nil
	}

	subject := "E-posta Doğrulama - Cenap Su Arıtma"

	// Base URL'i ortam değişkeninden oku; yoksa irmaksuaritma.com'u kullan
	baseURL := os.Getenv("PUBLIC_BASE_URL")
	if baseURL == "" {
		baseURL = "https://irmaksuaritma.com"
	}

	body := fmt.Sprintf(`
		<h2>E-posta Adresinizi Doğrulayın</h2>
		<p>Merhaba <strong>%s</strong>,</p>
		<p>Cenap Su Arıtma hesabınızı aktifleştirmek için lütfen e-posta adresinizi doğrulayın.</p>
		<br>
		<div style="text-align: center; margin: 20px 0;">
            <a href="%s/verify-email?token=%s" style="display: inline-block; background-color: #28a745; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold; margin: 10px;">✉️ E-postamı Doğrula</a>
		</div>
		<br>
		<p><strong>Alternatif Link:</strong></p>
        <p><a href="%s/verify-email?token=%s">%s/verify-email?token=%s</a></p>
		<br>
		<p>Bu link 24 saat süreyle geçerlidir.</p>
		<p>Eğer bu hesabı siz oluşturmadıysanız, bu e-postayı görmezden gelebilirsiniz.</p>
		<br>
		<p>Saygılarımızla,<br>Cenap Su Arıtma</p>
    `, username, baseURL, token, baseURL, token, baseURL, token)

	m := gomail.NewMessage()
	m.SetHeader("From", es.from)
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	return es.dialer.DialAndSend(m)
}

// SendEmail, genel e-posta gönderimi için kullanılır
func (es *EmailService) SendEmail(to, subject, body string) error {
	if es.dialer == nil {
		log.Printf("E-posta gönderimi devre dışı. Gönderilecek e-posta: %s - %s", to, subject)
		return nil
	}

	m := gomail.NewMessage()
	m.SetHeader("From", es.from)
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	return es.dialer.DialAndSend(m)
}

// TestEmail, test e-postası gönderir
func (es *EmailService) TestEmail(to string) error {
	if es.dialer == nil {
		log.Printf("E-posta gönderimi devre dışı. Test e-postası: %s", to)
		return nil
	}

	subject := "Test E-postası - Cenap Su Arıtma"
	body := `
		<h2>Test E-postası</h2>
		<p>Bu bir test e-postasıdır.</p>
		<p>Mail servisi çalışıyor!</p>
		<br>
		<p>Saygılarımızla,<br>Cenap Su Arıtma</p>
	`

	m := gomail.NewMessage()
	m.SetHeader("From", es.from)
	m.SetHeader("To", to)
	m.SetHeader("Subject", subject)
	m.SetBody("text/html", body)

	log.Printf("Test mail gönderiliyor: %s -> %s", es.from, to)

	err := es.dialer.DialAndSend(m)
	if err != nil {
		log.Printf("Test mail hatası: %v", err)
		return err
	}

	log.Printf("Test mail başarıyla gönderildi!")
	return nil
}
