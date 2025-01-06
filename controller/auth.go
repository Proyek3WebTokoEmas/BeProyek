package controller

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"proyek3/config"
	"proyek3/database"
	"proyek3/model"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"golang.org/x/crypto/bcrypt"
)

// Struktur untuk menyimpan email dan password yang diterima dalam request
type Credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Claims untuk JWT
type Claims struct {
	Email string `json:"email"`
	jwt.StandardClaims
}

func CreateToken(user model.User) (string, error) {
	claims := jwt.MapClaims{
		"email": user.Email,
		"exp":   time.Now().Add(time.Hour * 72).Unix(),
	}

	// Buat token menggunakan signing method HMAC dan secret key
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Tanda tangani token dengan secret key
	tokenString, err := token.SignedString([]byte(config.JwtSecret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// Fungsi untuk mengirim email konfirmasi menggunakan SendGrid
func sendVerificationEmail(toEmail, verificationToken string) error {
	apiKey := config.SendGridAPIKey
	verificationLink := fmt.Sprintf("http://localhost:8080/verify?token=%s", verificationToken)

	from := mail.NewEmail("Your App", "fathir080604@gmail.com")
	to := mail.NewEmail("User", toEmail)
	subject := "Konfirmasi Registrasi"

	htmlContent := `
		<html>
		<head>
			<style>
				body { font-family: Arial, sans-serif; background-color: #f4f4f4; color: #333; margin: 0; padding: 0; }
				.container { max-width: 600px; margin: 30px auto; padding: 20px; background-color: #ffffff; border-radius: 8px; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1); }
				.header { text-align: center; padding-bottom: 20px; }
				.header h2 { color: #007BFF; }
				.content p { font-size: 16px; }
				.button { display: inline-block; padding: 10px 20px; background-color: #28a745; color: #fff; border-radius: 5px; text-decoration: none; font-size: 16px; }
				.footer { margin-top: 20px; font-size: 14px; color: #888; text-align: center; }
			</style>
		</head>
		<body>
			<div class="container">
				<div class="header">
					<h2>Terima kasih telah mendaftar !</h2>
				</div>
				<div class="content">
					<p>Hi,</p>
					<p>Terima kasih telah mendaftar ! Untuk melanjutkan, silakan klik tombol di bawah ini untuk memverifikasi akun Anda:</p>
					<p><a href="` + verificationLink + `" class="button">Verifikasi Akun</a></p>
					<p>Jika Anda tidak mendaftar di website kami, abaikan email ini.</p>
				</div>
				<div class="footer">
					<p>&copy; 2024 OurApp. All rights reserved.</p>
				</div>
			</div>
		</body>
		</html>
	`

	message := mail.NewSingleEmail(from, subject, to, "", htmlContent)
	client := sendgrid.NewSendClient(apiKey)
	_, err := client.Send(message)
	return err
}

// Fungsi untuk memverifikasi email dengan token
func VerifyEmail(w http.ResponseWriter, r *http.Request) {
	// Ambil token dari query parameter
	tokenStr := r.URL.Query().Get("token")
	if tokenStr == "" {
		http.Error(w, "Token is missing", http.StatusBadRequest)
		return
	}

	// Parse token untuk memverifikasi keabsahannya
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		// Pastikan signing method sesuai
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// Kembalikan kunci rahasia untuk validasi
		return []byte(config.JwtSecret), nil
	})
	if err != nil || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		log.Println("Error parsing/validating token:", err)
		return
	}

	// Ambil klaim dari token
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		http.Error(w, "Invalid token claims", http.StatusUnauthorized)
		return
	}

	// Ambil email dari klaim
	email := claims["email"].(string)

	// Verifikasi email pengguna dalam database
	var user model.User
	err = database.DB.QueryRow(`SELECT email FROM "user" WHERE email=$1`, email).Scan(&user.Email)
	if err != nil {
		log.Printf("User not found: %v", err)
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Set status verifikasi di database
	_, err = database.DB.Exec(`UPDATE "user" SET verified = $1 WHERE email = $2`, true, email)
	if err != nil {
		log.Printf("Error updating user verification: %v", err)
		http.Error(w, "Error verifying email", http.StatusInternalServerError)
		return
	}

	// Tanggapan sukses
	w.Header().Set("Content-Type", "application/json")
	response := map[string]string{"message": "Email successfully verified"}
	json.NewEncoder(w).Encode(response)
}



// Fungsi untuk register pengguna baru
func Register(w http.ResponseWriter, r *http.Request) {
	var user model.User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Enkripsi password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Internal server error during password encryption", http.StatusInternalServerError)
		return
	}

	// Simpan user ke database
	_, err = database.DB.Exec(`INSERT INTO "user" (name, email, password, verified) VALUES ($1, $2, $3, $4)`, user.Name, user.Email, hashedPassword, false)
	if err != nil {
		log.Printf("Error inserting user: %v", err)
		http.Error(w, "Internal server error during user insertion", http.StatusInternalServerError)
		return
	}

	// Buat token verifikasi
	verificationToken, err := CreateToken(user) // Gunakan token yang sama dengan JWT untuk login
	if err != nil {
		http.Error(w, "Failed to create verification token", http.StatusInternalServerError)
		return
	}

	// Kirim email verifikasi
	err = sendVerificationEmail(user.Email, verificationToken)
	if err != nil {
		http.Error(w, "Failed to send verification email", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{"message": "User registered successfully. Please verify your email."}
	json.NewEncoder(w).Encode(response)
}

// Fungsi untuk login pengguna
func Login(w http.ResponseWriter, r *http.Request) {
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	var user model.User
	err = database.DB.QueryRow(`SELECT email, password FROM "user" WHERE email=$1`, creds.Email).Scan(&user.Email, &user.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "User not found", http.StatusUnauthorized)
			return
		}
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Verifikasi password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(creds.Password))
	if err != nil {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	// Generate token JWT
	expirationTime := time.Now().Add(60 * time.Minute)
	claims := &Claims{
		Email: creds.Email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(config.JwtSecret))
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Kirim token ke client
	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{"message": "Login successful", "token": tokenString}
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		log.Printf("Error encoding response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// Fungsi untuk memverifikasi token JWT
func Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ambil token dari header Authorization
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Missing token", http.StatusUnauthorized)
			return
		}

		// Verifikasi token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, http.ErrNoLocation
			}
			return []byte(config.JwtSecret), nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Token valid, lanjutkan ke handler berikutnya
		next.ServeHTTP(w, r)
	})
}
