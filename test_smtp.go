package main

import (
    " fmt\
 \gopkg.in/gomail.v2\
)

func main() {
 d := gomail.NewDialer(\smtp.gmail.com\, 587, \wbcenapoktay@gmail.com\, \ltpw igvm rsui nfss\)
 
 if err := d.Dial(); err != nil {
 fmt.Printf(\SMTP Bağlantı hatası: %v\n\, err)
 return
 }
 fmt.Println(\SMTP Bağlantısı başarılı!\)
}
