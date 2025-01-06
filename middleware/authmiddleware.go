package middleware

import (
    "fmt"
    "log"
    "net/http"
    "strings"

    "github.com/dgrijalva/jwt-go"
    "proyek3/config"
)

// AuthMiddleware adalah middleware untuk memeriksa token JWT
func AuthMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Ambil token dari header Authorization
        tokenString := r.Header.Get("Authorization")
        if tokenString == "" {
            http.Error(w, "Token is required", http.StatusUnauthorized)
            return
        }

        // Jika token diawali dengan "Bearer ", hapus bagian tersebut
        if strings.HasPrefix(tokenString, "Bearer ") {
            tokenString = strings.TrimPrefix(tokenString, "Bearer ")
        } else {
            http.Error(w, "Invalid token format", http.StatusUnauthorized)
            return
        }

        // Verifikasi token
        token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
            // Pastikan metode signing adalah HS256
            if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
                return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
            }
            return []byte(config.JwtSecret), nil
        })

        if err != nil {
            log.Printf("Error parsing token: %v", err)
            http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
            return
        }

        // Validasi klaim jika diperlukan (misalnya, email)
        if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
            log.Printf("Token valid for user: %v", claims["email"])
            // Anda bisa menyimpan informasi pengguna di context untuk digunakan di handler selanjutnya
            next.ServeHTTP(w, r)
        } else {
            http.Error(w, "Invalid token claims", http.StatusUnauthorized)
        }
    })
}
