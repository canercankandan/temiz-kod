# suarıtama uzmanı com Web Sitesi

Go ile geliştirilmiş modern web sitesi ve admin paneli.

## Özellikler

- 🏠 **Ana Sayfa**: Hoş geldin mesajı ve öne çıkan ürünler
- 📦 **Ürünler Sayfası**: Tüm ürünlerin listelendiği sayfa
- ⚙️ **Admin Paneli**: Ürün ekleme, silme ve yönetim
- 📸 **Resim Yükleme**: Ürünlere resim ekleme özelliği
- 📱 **Responsive Tasarım**: Mobil uyumlu modern arayüz
- 🗄️ **JSON Veritabanı**: Harici bağımlılık gerektirmeyen, dosya tabanlı veritabanı

## Teknolojiler

- **Backend**: Go (Gin Framework)
- **Veritabanı**: JSON Dosyası
- **Frontend**: HTML5, CSS3, JavaScript
- **Template Engine**: Go HTML templates

## Kurulum ve Çalıştırma

Proje sizin için derlendi ve çalıştırılmaya hazır hale getirildi.

1.  Proje dizinine gidin (eğer zaten orada değilseniz):
    ```powershell
    cd cenap
    ```

2.  Uygulamayı çalıştırın. Bunun için oluşturulan `suaritamauzumani.exe` dosyasını çalıştırmanız yeterlidir:
    ```powershell
    ./suaritamauzumani.exe
    ```

3.  Tarayıcınızda `http://localhost:9394` adresine gidin.

Eğer projede değişiklik yapıp yeniden derlemek isterseniz, aşağıdaki komutu kullanabilirsiniz:
```powershell
go build -o suaritamauzumani.exe cmd/web/main.go
```

### Geliştirme Ortamı İçin
Eğer `go run` komutu ile çalışmak isterseniz, aşağıdaki komutu kullanabilirsiniz:
```powershell
$env:GOPATH = "C:\temp\go"; $env:GOCACHE = "C:\temp\go\cache"; go run cmd/web/main.go
```

## Kullanım

### Admin Paneli

1.  `/admin` sayfasına gidin (`http://localhost:9394/admin`)
2.  Yeni ürün eklemek için formu doldurun:
    -   Ürün adı
    -   Kategori
    -   Açıklama
    -   Fiyat
    -   Stok miktarı
    -   Ürün resmi
3.  "Ürün Ekle" butonuna tıklayın

### Ürün Yönetimi

-   **Ekleme**: Admin panelinden form ile
-   **Silme**: Admin panelindeki tabloda silme butonu ile
-   **Görüntüleme**: Ana sayfa ve ürünler sayfasında

## Proje Yapısı

```
cenap/
├── cmd/
│   └── web/
│       └── main.go          # Ana uygulama dosyası
├── internal/
│   ├── database/
│   │   └── database.go      # Veritabanı işlemleri (JSON)
│   ├── handlers/
│   │   └── handlers.go      # HTTP handler'ları
│   └── models/
│       └── product.go       # Veri modelleri
├── static/
│   ├── css/
│   │   └── style.css        # Özel CSS stilleri
│   ├── js/
│   │   └── app.js           # JavaScript fonksiyonları
│   └── uploads/             # Yüklenen ürün resimleri
├── templates/
│   ├── base.html            # Temel template
│   ├── home.html            # Ana sayfa
│   ├── products.html        # Ürünler sayfası
│   ├── admin.html           # Admin paneli
│   ├── about.html           # Hakkımızda
│   └── contact.html         # İletişim
├── go.mod                   # Go modül dosyası
├── data.json                # Ürün verilerinin saklandığı dosya
└── README.md                # Bu dosya
```

## API Endpoints

-   `GET /` - Ana sayfa
-   `GET /products` - Ürünler sayfası
-   `GET /about` - Hakkımızda sayfası
-   `GET /contact` - İletişim sayfası
-   `GET /admin` - Admin paneli
-   `POST /admin/add-product` - Ürün ekleme
-   `DELETE /admin/delete-product/:id` - Ürün silme

## Veri Yapısı (data.json)

`data.json` dosyası, ürünlerin bir dizisini içerir. Her ürün aşağıdaki alanlara sahiptir:

| Alan | Tip | Açıklama |
| --- | --- | --- |
| id | number | Benzersiz ID |
| name | string | Ürün adı |
| description | string | Ürün açıklaması |
| price | number | Fiyat |
| image | string | Resim dosya yolu |
| category | string | Kategori |
| stock | number | Stok miktarı |
| created_at | string | Oluşturulma tarihi (ISO 8601) |
| updated_at | string | Güncellenme tarihi (ISO 8601) |

## Lisans

Bu proje MIT lisansı altında lisanslanmıştır.

## İletişim

-   E-posta: info@suaritamauzamani.com
-   Telefon: +90 555 123 4567 