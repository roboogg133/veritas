package main

import (
	"context"
	"log"
	"net/http"
	"strings"
	"veritas/config"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	return string(bytes), err
}

func Authenticate(user string, rawpass string) bool {
	config.InitDB()

	var password string

	// Search for the username
	err := config.DB.QueryRow(context.Background(),
		"SELECT password FROM users WHERE username = $1", user).Scan(&password)

	if err != nil {
		if err == pgx.ErrNoRows {
			return false
		} else {
			log.Panic(err)
		}
	}

	err = bcrypt.CompareHashAndPassword([]byte(password), []byte(rawpass))
	if err != nil {
		return false
	} else {
		return true
	}

}

func Register(username string, password string) error {

	config.InitDB()

	_, err := config.DB.Exec(context.Background(),
		"INSERT INTO users (username, password) VALUES ($1, $2)", username, password)
	if err != nil {
		return err
	}

	return nil
}

func Auth() gin.HandlerFunc {
	return func(back *gin.Context) {
		tokenString := back.GetHeader("Authorization")

		if tokenString == "" {
			back.AbortWithStatusJSON(http.StatusForbidden, gin.H{"response": "invalid token"})
			return
		}

		claims, err := config.TokenAuthenticate(tokenString)
		if err != nil {
			back.AbortWithStatusJSON(http.StatusForbidden, gin.H{"response": "invalid token"})
			return
		}

		back.Set("username", claims.Username)
		back.Next()
	}
}

func main() {

	r := gin.Default()
	r.POST("/api/login", func(back *gin.Context) {

		var req LoginRequest

		if err := back.ShouldBindJSON(&req); err != nil {
			back.JSON(http.StatusBadRequest, gin.H{"response": "badrequest"})
			return
		}

		value := Authenticate(req.Username, req.Password)

		if value == true {
			token, err := config.GenerateJWT(req.Username)
			if err != nil {
				back.JSON(http.StatusInternalServerError, gin.H{"response": "failed to generate session token"})
				return
			}

			back.JSON(http.StatusOK, gin.H{"response": token})
			return
		}
		if value == false {
			back.JSON(http.StatusUnauthorized, gin.H{"response": "Unauthorized"})
			return
		}

	})

	r.POST("/api/register", func(back *gin.Context) {

		var req LoginRequest

		if err := back.ShouldBindJSON(&req); err != nil {
			back.JSON(http.StatusBadRequest, gin.H{"response": "badrequest"})
			return
		}

		if strings.ContainsAny(req.Username, " ") || strings.ContainsAny(req.Password, " ") || req.Password == "" || req.Username == "" {
			back.JSON(http.StatusBadRequest, gin.H{"response": "invalid username or password"})
		}

		password, _ := HashPassword(req.Password)

		err := Register(req.Username, password)
		if err != nil {
			back.JSON(http.StatusBadRequest, gin.H{"response": "username alredy been taken"})
			return
		} else {
			back.JSON(http.StatusCreated, gin.H{"response": "suceffuly registered"})
			return
		}

	})

	r.Run()

}
