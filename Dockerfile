# Build stage
FROM golang:1.21-alpine AS builder

# Gerekli paketleri yükle
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

# Modülleri önceden kopyala ve indir
COPY go.mod go.sum ./
RUN go mod download

# Tüm kaynak kodunu kopyala
COPY . .

# Uygulamayı derle
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main ./cmd/web

# Run stage
FROM alpine:latest

# Gerekli paketleri yükle
RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# Gerekli dosyaları kopyala
COPY --from=builder /app/main .
COPY --from=builder /app/static ./static
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/data.json .
COPY --from=builder /app/orders.json .

# Portu belirt
EXPOSE 8080

# Uygulamayı başlat
CMD ["./main"] 