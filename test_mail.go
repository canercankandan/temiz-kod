package main

import (
    " fmt\
 \gopkg.in/gomail.v2\
)

func main() {
 m := gomail.NewMessage()
 m.SetHeader(\From\, \wbcenapoktay@gmail.com\)
 m.SetHeader(\To\, \wbcenapoktay@gmail.com\)
 m.SetHeader(\Subject\, \Test Mail\)
 m.SetBody(\text/plain\, \Bu bir test mailidir.\)

 d := gomail.NewDialer(\smtp.gmail.com\, 587, \wbcenapoktay@gmail.com\, \ltpw igvm rsui nfss\)

 if err := d.DialAndSend(m); err != nil {
 fmt.Printf(\Hata: %v\n\, err)
 } else {
 fmt.Println(\Mail başarıyla gönderildi!\)
 }
}
