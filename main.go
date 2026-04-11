/*
'sprout' es una base para el desarrollo de prácticas en clase con Go.

Se puede compilar con "go build" en el directorio donde resida main.go
o "go build -o nombre" para que el ejecutable tenga un nombre distinto

curso: 			**rellenar**
asignatura: 	**antes de**
estudiantes: 	**entregar**
*/
package main

import (
	"log"
	"os"
	"time"

	"sprout/pkg/certgen"
	"sprout/pkg/client"
	"sprout/pkg/server"
	"sprout/pkg/ui"
)

func main() {

	// Creamos un logger con prefijo 'main' para identificar
	// los mensajes en la consola.
	logger := log.New(os.Stdout, "[main] ", log.LstdFlags)

	// Generamos el certificado TLS autofirmado en memoria.
	// El mismo cert se pasa al servidor (para arrancar TLS) y al cliente
	// (para hacer pinning y rechazar cualquier otro certificado).
	certPEM, keyPEM, err := certgen.Generate()
	if err != nil {
		logger.Fatalf("Error generando certificado TLS: %v", err)
	}
	logger.Println("Certificado TLS generado correctamente.")

	// Inicia servidor HTTPS en goroutine.
	logger.Println("Iniciando servidor HTTPS...")
	go func() {
		if err := server.Run(certPEM, keyPEM); err != nil {
			logger.Fatalf("Error del servidor: %v\n", err)
		}
	}()

	// Esperamos un tiempo prudencial a que arranque el servidor.
	const totalSteps = 20
	for i := 1; i <= totalSteps; i++ {
		ui.PrintProgressBar(i, totalSteps, 30)
		time.Sleep(100 * time.Millisecond)
	}

	// Inicia cliente con el cert del servidor para cert pinning.
	logger.Println("Iniciando cliente...")
	client.Run(certPEM)
}
