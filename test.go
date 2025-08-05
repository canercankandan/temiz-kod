package main
import " golang.org/x/crypto/bcrypt\
import \fmt\
func main() {
 newHash, _ := bcrypt.GenerateFromPassword([]byte(\123456\), bcrypt.DefaultCost)
 fmt.Println(string(newHash))
}
