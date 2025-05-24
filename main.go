package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
)

func main() {

	prompt := `Você é uma inteligência artificial chamada Anfitrião. Sua missão é criar histórias de mistério para um jogo de dedução.

Formato da resposta:
--TITULO--
[Título da história]
--TITULO--

--DESFECHO--
[Resumo do que acontece no fim da história, sem explicar como chegou lá]
--DESFECHO--

--HISTORIA--
[A história completa, com todos os eventos que levam ao desfecho. Seja criativo, mas consistente. O jogador não verá esta parte.]
--HISTORIA--
Não adicione nada fora desse formato.`

	payload := map[string]interface{}{
		"model":  "gemma3:1b",
		"prompt": prompt,
		"stream": false,
	}

	payloadJson, err := json.Marshal(payload)
	if err != nil {
		log.Fatal("Error creating json : ", err)
	}

	body := bytes.NewBuffer(payloadJson)

	response, err := http.Post("http://localhost:11434/api/generate", "application/json", body)
	if err != nil {
		log.Fatal("error doing POST request : ", err)
	}

	responseBody, err := io.ReadAll(response.Body)

	if response.StatusCode == 200 {
		log.Println(string(responseBody))
	}
	if response.StatusCode != 200 {
		log.Fatal(response.Status + "\n" + string(responseBody))
	}
}
