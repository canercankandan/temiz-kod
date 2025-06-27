package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

func main() {
	// RSA private key oluştur
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Private key oluşturulamadı: %v", err)
	}

	// Sertifika template'i oluştur
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{"TR"},
			Organization: []string{"Cenap Water Filters"},
			CommonName:   "192.168.1.133",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("192.168.1.133")},
	}

	// Sertifikayı oluştur
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		log.Fatalf("Sertifika oluşturulamadı: %v", err)
	}

	// Sertifikayı dosyaya yaz
	certOut, err := os.Create("cert.pem")
	if err != nil {
		log.Fatalf("cert.pem oluşturulamadı: %v", err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	certOut.Close()

	// Private key'i dosyaya yaz
	keyOut, err := os.Create("key.pem")
	if err != nil {
		log.Fatalf("key.pem oluşturulamadı: %v", err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	keyOut.Close()

	log.Println("SSL sertifikası oluşturuldu: cert.pem ve key.pem")
} 