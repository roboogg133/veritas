package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
)

func main() {

	prompt := "Qual a cor do céu?"

	payload := []byte(fmt.Sprintf(`{"model": "gemma3:1b",
		"prompt" : "%s",
		"stream": false}`, prompt))

	body := bytes.NewBuffer(payload)

	response, err := http.Post("http://localhost:11434/api/generate", "application/json", body)
	if err != nil {
		log.Fatal("error doing POST request : ", err)
	}

	responseBody, err := io.ReadAll(response.Body)

	if response.StatusCode == 200 {
		log.Println(string(responseBody))
	}
}
