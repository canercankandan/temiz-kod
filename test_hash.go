package main

import (
    " fmt\
 \golang.org/x/crypto/bcrypt\
)

func main() {
 // Mevcut hash'i test et
 hash := \.HWoiZOXnrtWmigoAHRkwkih.EYQBc5ZyP4WsO\
 password := \123456\
 
 err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
 if err != nil {
 fmt.Println(\Hash yanlış:\, err)
 
 // Yeni hash oluştur
 newHash, _ := bcrypt.GenerateFromPassword([]byte(\123456\), bcrypt.DefaultCost)
 fmt.Println(\Yeni hash:\, string(newHash))
 } else {
 fmt.Println(\Hash doğru!\)
 }
}
