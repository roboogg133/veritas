package main

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"
	"veritas/config"

	"github.com/gin-contrib/cors"
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

func AuthAcess() gin.HandlerFunc {
	return func(back *gin.Context) {
		tokenString, err := back.Cookie("AcessToken")

		if err != nil {
			back.AbortWithStatus(http.StatusForbidden)
			return
		}

		if tokenString == "" {
			back.AbortWithStatus(http.StatusForbidden)
			return
		}

		claims, err := config.TokenAuthenticate(tokenString)
		if claims == nil {
			back.AbortWithStatus(http.StatusForbidden)
			return
		}
		if err != nil {
			back.AbortWithStatus(http.StatusForbidden)
			return
		}
		if claims.TokenType != "access" {
			back.AbortWithStatus(http.StatusForbidden)
			return
		}

		back.Set("username", claims.Username)
		back.Next()
	}
}

func AuthRefresh() gin.HandlerFunc {
	return func(back *gin.Context) {
		tokenString, err := back.Cookie("RefreshToken")

		if err != nil {
			back.AbortWithStatus(http.StatusForbidden)
			return
		}

		claims, err := config.TokenAuthenticate(tokenString)
		if claims == nil {
			back.AbortWithStatus(http.StatusForbidden)
			return
		}
		if err != nil {
			back.AbortWithStatus(http.StatusForbidden)
			return
		}
		if claims.TokenType != "refresh" {
			back.AbortWithStatus(http.StatusForbidden)
			return
		}

		back.Set("username", claims.Username)
		back.Next()
	}
}

func main() {

	r := gin.Default()
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"https://servidordomal.fun", "*://31.97.20.160"},
		AllowMethods:     []string{"GET", "POST", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Authorization", "Content-Type"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: false,
		MaxAge:           12 * time.Hour,
	}))
	r.POST("/service/login", func(back *gin.Context) {

		var req LoginRequest

		if err := back.ShouldBindJSON(&req); err != nil {
			back.JSON(http.StatusBadRequest, gin.H{"response": "badrequest"})
			return
		}

		value := Authenticate(req.Username, req.Password)

		if value == true {
			token, err := config.GenerateJWTAcessToken(req.Username)
			if err != nil {
				back.JSON(http.StatusInternalServerError, gin.H{"response": "failed to generate tokens"})
				return
			}
			refresh, err := config.GenerateJWTRefreshToken(req.Username)
			if err != nil {
				back.JSON(http.StatusInternalServerError, gin.H{"response": "failed to generate tokens"})
				return
			}

			back.SetSameSite(http.SameSiteStrictMode)
			back.SetCookie("AccessToken", token, 900, "/", "servidordomal.fun", true, true)
			back.SetSameSite(http.SameSiteStrictMode)
			back.SetCookie("RefreshToken", refresh, 345600, "/", "servidordomal.fun", true, true)

			back.Status(http.StatusOK)
			return
		}
		if value == false {
			back.Status(http.StatusUnauthorized)
			return
		}

	})

	r.POST("/service/register", func(back *gin.Context) {

		var req LoginRequest

		if err := back.ShouldBindJSON(&req); err != nil {
			back.Status(http.StatusBadRequest)
			return
		}

		if strings.ContainsAny(req.Username, " ") || strings.ContainsAny(req.Password, " ") || req.Password == "" || req.Username == "" {
			back.JSON(http.StatusBadRequest, gin.H{"response": "invalid username or password"})
			return
		}

		password, _ := HashPassword(req.Password)

		err := Register(req.Username, password)
		if err != nil {
			back.JSON(http.StatusConflict, gin.H{"response": "username alredy been taken"})
			return
		} else {
			back.Status(http.StatusCreated)
			return
		}

	})

	r.GET("/service/validate", AuthAcess(), func(c *gin.Context) {

		c.Status(http.StatusOK)
	})

	r.GET("/service/refresh", AuthRefresh(), func(back *gin.Context) {

		usernameRaw, _ := back.Get("username")

		username := usernameRaw.(string)

		token, err := config.GenerateJWTAcessToken(username)
		if err != nil {
			back.JSON(http.StatusInternalServerError, gin.H{"response": "error generating token"})
			return
		}
		refresh, err := config.GenerateJWTRefreshToken(username)
		if err != nil {
			back.JSON(http.StatusInternalServerError, gin.H{"response": "error generating refresh token"})
			return
		}

		http.SetCookie(back.Writer, &http.Cookie{
			Name:     "AccessToken",
			Value:    token,
			MaxAge:   900,
			Path:     "/",
			Domain:   "servidordomal.fun",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})

		http.SetCookie(back.Writer, &http.Cookie{
			Name:     "RefreshToken",
			Value:    refresh,
			MaxAge:   345600,
			Path:     "/",
			Domain:   "servidordomal.fun",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
		back.Status(http.StatusOK)

	})

	r.Run(":8080")

}
