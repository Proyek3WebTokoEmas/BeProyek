package routes

import (
	"proyek3/controller"
	"proyek3/middleware"
	"github.com/gorilla/mux"
)

// InitRoutes menginisialisasi semua route
func InitRoutes() *mux.Router {
	router := mux.NewRouter()

	// Route untuk register dan login tanpa autentikasi
	router.HandleFunc("/register", controller.Register).Methods("POST")
	router.HandleFunc("/login", controller.Login).Methods("POST")
	router.HandleFunc("/verify", controller.VerifyEmail).Methods("GET")

	// Subrouter untuk endpoint yang dilindungi
	protected := router.PathPrefix("/protected").Subrouter()
	protected.Use(middleware.AuthMiddleware) // Middleware autentikasi

	// Endpoint yang memerlukan autentikasi
	protected.HandleFunc("/tambah-emas", controller.TambahEmas).Methods("POST")
	protected.HandleFunc("/emas", controller.GetAllEmas).Methods("GET")
	protected.HandleFunc("/emas/update/", controller.UpdateEmas).Methods("PUT")

	return router
}
