package config

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
)

var Dsn string
var DB *pgxpool.Pool

func InitDB() {

	godotenv.Load()

	var host = os.Getenv("DB_HOST")
	var port = os.Getenv("DB_PORT")
	var user = os.Getenv("DB_USER")
	var passwordnotgood = os.Getenv("DB_PASSWORD")
	var dbname = os.Getenv("DB_NAME")

	var password = url.QueryEscape(passwordnotgood)

	var Dsn = fmt.Sprintf("postgres://%s:%s@%s:%s/%s", user, password, host, port, dbname)

	dbpool, err := pgxpool.New(context.Background(), Dsn)
	if err != nil {
		log.Panic("Error connecting to DATABASE : ", err)
	}

	err = dbpool.Ping(context.Background())
	if err != nil {
		log.Panic("Database isn't reachable : ", err)
	}

	DB = dbpool

}
