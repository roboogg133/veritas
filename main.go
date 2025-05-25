package main

import (
	"context"
	"log"
	"net/http"
	"veritas/config"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
)

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func Encrypt() {

}

func GetUserAndPassword(user string) (string, string) {
	config.InitDB()

	var username, password string

	err := config.DB.QueryRow(context.Background(),
		"SELECT username, password FROM users WHERE username = $1", user).Scan(&username, &password)

	if err != nil {
		if err == pgx.ErrNoRows {
			return "fuck ", "me"
		} else {
			log.Panic(err)
		}
	}

	return username, password

}

func main() {

	r := gin.Default()
	r.POST("/api/login", func(back *gin.Context) {

		var req LoginRequest

		if err := back.ShouldBindJSON(&req); err != nil {
			back.JSON(http.StatusBadRequest, gin.H{"response": "badrequest"})
			return
		}

		if req.Username == "arrombado" && req.Password == "arrombado1" {
			back.JSON(http.StatusOK, gin.H{"response": "authenticated"})
		} else {

			back.JSON(http.StatusFound, gin.H{"response": Authenticate(req.Username)})

			//	back.JSON(http.StatusUnauthorized, gin.H{"response": "invalid"})
		}
	})
	r.Run()

}
