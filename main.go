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
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"sprout/pkg/certgen"
	"sprout/pkg/client"
	"sprout/pkg/server"
	"sprout/pkg/store"
	"sprout/pkg/ui"
)

func main() {
	//Obtenemos parametros de entrada
	var basePath, dbName, fileName, port string
	var dump bool
	flag.StringVar(&basePath, "base", "data", "Ruta base para la base de datos y archivos (default: data)")
	flag.StringVar(&dbName, "db", "server.db", "Nombre de la base de datos (default: server.db)")
	flag.StringVar(&fileName, "files", "files", "Nombre del directorio donde se almacenarán los archivos (default: files)")
	flag.StringVar(&port, "port", "8080", "Puerto en el que el servidor escuchará (default: 8080)")
	flag.BoolVar(&dump, "dump", false, "Si se establece, se hará un volcado de la base de datos al entrar, debe existir (default: false)")

	flag.Parse()

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

	if dump {
		// Abrimos la base de datos usando el motor bbolt
		logger.Println("Abriendo base de datos para volcado...")
		db, err := store.NewStore("bbolt", fmt.Sprintf("%s/server.db", basePath))
		if err != nil {
			logger.Fatalf("error abriendo base de datos: %v", err)
		}
		logger.Println("Base de datos abierta correctamente, realizando volcado...")
		err = db.Dump()
		if err != nil {
			logger.Fatalf("error dump database: %v", err)
		}
		time.Sleep(1000 * time.Millisecond)
		db.Close()
		logger.Println("Volcado de base de datos completado.")
	}

	// Inicia servidor HTTPS en goroutine.
	logger.Println("Iniciando servidor HTTPS...")
	go func() {
		if err := server.Run(certPEM, keyPEM, basePath, dbName, fileName, port); err != nil {
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
	cliente := client.NewClient("https://localhost:8080/api", certPEM)
	logger.Println("Cliente iniciado correctamente.")
	client.RunTUI(cliente)
}
