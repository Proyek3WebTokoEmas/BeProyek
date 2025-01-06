package main

import (
	"fmt"
	"log"
	"net/http"
	"proyek3/config"
	"proyek3/database"
	"proyek3/routes"

	"github.com/rs/cors"
)

func main() {
	// Inisialisasi konfigurasi dan muat JWT secret dari .env
	config.InitConfig()

	// Inisialisasi database
	database.InitDB()
	fmt.Println("Database initialized")

	// Inisialisasi router dari routes.go
	router := routes.InitRoutes()

	// Tambahkan middleware CORS
	corsHandler := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000"}, // Ganti dengan alamat frontend Anda
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
	}).Handler(router)

	// Mulai server
	log.Println("Server started at :8080")
	err := http.ListenAndServe(":8080", corsHandler)
	if err != nil {
		log.Fatal("Server failed to start:", err)
	}
}
