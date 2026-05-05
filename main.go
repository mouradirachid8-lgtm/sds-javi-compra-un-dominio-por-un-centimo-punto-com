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
	"strings"
	"time"

	"sprout/pkg/backup"
	"sprout/pkg/certgen"
	"sprout/pkg/client"
	"sprout/pkg/server"
	"sprout/pkg/store"
	"sprout/pkg/ui"
)

func main() {
	//Obtenemos parametros de entrada
	var basePath, dbName, fileName, port string
	var backupBasePath, dbNameBackup, fileNameBackup, backupPort string
	var dump bool
	flag.StringVar(&basePath, "base", "data", "Ruta base para la base de datos y archivos (default: data)")
	flag.StringVar(&dbName, "db", "server.db", "Nombre de la base de datos (default: server.db)")
	flag.StringVar(&fileName, "files", "files", "Nombre del directorio donde se almacenarán los archivos (default: files)")
	flag.StringVar(&port, "port", "8080", "Puerto en el que el servidor escuchará (default: 8080)")
	flag.StringVar(&backupPort, "backup-port", "8081", "Puerto en el que el servidor de backups escuchará (default: 8081)")
	flag.StringVar(&backupBasePath, "backup-base", "backup", "Ruta base para las copias de seguridad (default: backup)")
	flag.StringVar(&dbNameBackup, "backup-db", "backup.db", "Nombre de la base de datos de backups (default: backup.db)")
	flag.StringVar(&fileNameBackup, "backup-files", "backup_files", "Nombre del directorio donde se almacenarán las copias de seguridad (default: backup_files)")
	flag.BoolVar(&dump, "dump", false, "Si se establece, se hará un volcado de la base de datos al entrar, debe existir (default: false)")

	flag.Parse()

	// Creamos un logger con prefijo 'main' para identificar
	// los mensajes en la consola.
	logger := log.New(os.Stdout, "[main] ", log.LstdFlags)

	// Generamos el certificado TLS autofirmado y lo guardamos en disco.
	// El certificado se pasa al servidor (para arrancar TLS) mediante sus rutas
	// y se carga para el cliente (para hacer pinning y rechazar cualquier otro certificado).
	if err := os.MkdirAll("certs", 0755); err != nil {
		logger.Fatalf("Error creando carpeta certs: %v", err)
	}
	certFile := "certs/cert.pem"
	keyFile := "certs/key.pem"
	err := certgen.Generate(certFile, keyFile)
	if err != nil {
		logger.Fatalf("Error generando certificado TLS: %v", err)
	}
	logger.Println("Certificado TLS generado y guardado en disco correctamente.")

	// He movido la lectura del certificado por parte del cliente para comprobar que es correcto el https
	// y funciona correctamente con cert pinning.
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		logger.Fatalf("Error leyendo el certificado TLS para el cliente: %v", err)
	}

	if dump {
		// Abrimos la base de datos usando el motor bbolt
		logger.Println("Abriendo base de datos para volcado...")
		db, err := store.NewStore("bbolt", fmt.Sprintf("%s/%s", basePath, dbName))
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
	//Inicia servidor de backups
	logger.Println("Iniciando servidor de backups...")
	go func() {
		if err := server.Run(certFile, keyFile, backupBasePath, dbNameBackup, fileNameBackup, backupPort, nil, "backup"); err != nil {
			logger.Fatalf("Error del servidor: %v\n", err)
		}
	}()
	time.Sleep(1000 * time.Millisecond)
	const totalBackupSteps = 20
	for i := 1; i <= totalBackupSteps; i++ {
		ui.PrintProgressBar(i, totalBackupSteps, 30)
		time.Sleep(100 * time.Millisecond)
	}
	// Generamos un cliente de backup para interactuar con el servidor de backups.
	logger.Println("Creando cliente de backup...")

	backupClient := crearBackupClient(backupPort, certPEM)

	// Inicia servidor HTTPS en goroutine.
	logger.Println("Iniciando servidor HTTPS...")
	go func() {
		if err := server.Run(certFile, keyFile, basePath, dbName, fileName, port, backupClient, "srv"); err != nil {
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
	cliente := client.NewClient(fmt.Sprintf("https://localhost:%s/api", port), certPEM)
	logger.Println("Cliente iniciado correctamente.")
	client.RunTUI(cliente)
}

func crearBackupClient(backupPort string, certPEM []byte) *backup.BackupClient {
	// Generamos un cliente de backup para interactuar con el servidor de backups.
	url := fmt.Sprintf("https://localhost:%s/api", backupPort)

	username := ui.ReadInput("Nombre de usuario")
	password, err := ui.ReadPassword("Contraseña")
	if err != nil {
		fmt.Printf("Error leyendo contraseña: %v\n", err)
		return nil
	}

	backupClient := backup.NewBackupClient(username, password, url, certPEM)
	if backupClient == nil {
		fmt.Println("No se pudo crear el cliente de backup. Verifica las credenciales y la conexión al servidor de backups.")
		fmt.Println("Quieres registrarte con estas credenciales?")
		registrarse := ui.ReadInput("Si/No")
		if strings.ToLower(registrarse) == "si" || strings.ToLower(registrarse) == "s" {
			err := client.NewClient(url, certPEM).Register(username, password)
			if err != nil {
				fmt.Printf("Error registrando en el servidor de backup: %v\n", err)
				return nil
			}
			fmt.Println("Registro exitoso. Intenta iniciar sesión nuevamente.")
			backupClient = backup.NewBackupClient(username, password, url, certPEM)
			if backupClient == nil {
				fmt.Println("No se pudo crear el cliente de backup después del registro. Verifica las credenciales y la conexión al servidor de backups.")
				return nil
			}
			return backupClient
		}
	}
	return backupClient
}
