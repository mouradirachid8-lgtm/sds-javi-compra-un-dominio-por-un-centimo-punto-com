// El paquete client contiene la lógica de interacción con el usuario
// así como de comunicación con el servidor.
package client

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sprout/pkg/api"
	"sprout/pkg/ui"
	"strings"
	"time"
)

// client estructura interna no exportada que controla
// el estado de la sesión (usuario, token) y logger.
type client struct {
	log         *log.Logger
	currentUser string
	authToken   string
	httpClient  *http.Client
	server      string
	encode      []byte
}

// Run es la única función exportada de este paquete.
// Recibe el certificado TLS del servidor en formato PEM para establecer
// una conexión HTTPS de confianza sin depender de una CA pública.
func Run(certPEM []byte) {
	// Construimos un pool de CAs que solo contiene el certificado del servidor.
	// Así el cliente acepta únicamente ese cert y rechaza cualquier otro.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		log.Fatal("No se ha podido cargar el certificado TLS del servidor")
	}

	tlsConfig := &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig

	c := &client{
		log: log.New(os.Stdout, "[cli] ", log.LstdFlags),
		httpClient: &http.Client{
			Timeout:   5 * time.Second,
			Transport: transport,
		},
		server: "https://localhost:8080/api",
	}
	c.runLoop()
}

// runLoop maneja la lógica del menú principal.
// Se muestran distintas opciones en función de si hay un usuario con sesión activa
func (c *client) runLoop() {
	for {
		ui.ClearScreen()

		// Construimos un título que muestre el usuario activo, si lo hubiera.
		var title string
		if c.currentUser == "" {
			title = "Menú"
		} else {
			title = fmt.Sprintf("Menú (%s)", c.currentUser)
		}

		// Generamos las opciones dinámicamente, según si hay un login activo.
		var options []string
		if c.currentUser == "" {
			// Usuario NO logueado: Registro, Login, Salir
			options = []string{
				"Registrar usuario",
				"Iniciar sesión",
				"Salir",
			}
		} else {
			// Usuario activo: Listar archivos, Descargar datos, Actualizar datos, Borrar datos, Cerrar sesión, Salir
			options = []string{
				"Listar archivos",
				"Descargar datos",
				"Actualizar datos",
				"Borrar datos",
				"Cerrar sesión",
				"Salir",
			}
		}

		// Mostramos el menú y obtenemos la elección del usuario.
		choice := ui.PrintMenu(title, options)

		// Hay que mapear la opción elegida según si está logueado o no.
		if c.currentUser == "" {
			// Caso NO logueado
			switch choice {
			case 1:
				c.registerUser()
			case 2:
				c.loginUser()
			case 3:
				// Opción Salir
				c.log.Println("Saliendo del cliente...")
				return
			}
		} else {
			// Caso logueado
			switch choice {
			case 1:
				c.lookup()
			case 2:
				c.fetchData()
			case 3:
				c.updateData()
			case 4:
				c.deleteData()
			case 5:
				c.logoutUser()
			case 6:
				// Opción Salir
				c.log.Println("Saliendo del cliente...")
				return
			}
		}

		// Pausa para que el usuario vea resultados.
		ui.Pause("Pulsa [Enter] para continuar...")
	}
}

// hashPassword es una función auxiliar para hashear contraseñas antes de enviarlas al servidor.
func (c *client) hashPassword(password string) [64]byte { // En un caso real, se debería usar un algoritmo de hashing fuerte como bcrypt o Argon2.
	// Aquí usaremos SHA512 por simplicidad, aunque no es recomendado para contraseñas.
	// Además, en un caso real se debería usar un salt único por usuario.
	return sha512.Sum512([]byte(password + c.currentUser))
}

// registerUser pide credenciales y las envía al servidor para un registro.
// Si el registro es exitoso, se intenta el login automático.
func (c *client) registerUser() {
	ui.ClearScreen()
	fmt.Println("** Registro de usuario **")

	username := ui.ReadInput("Nombre de usuario")
	password, err := ui.ReadPassword("Contraseña")

	if err != nil {
		c.log.Println("No se ha podido obtener la contraseña, registro cancelado: ", err)
		return
	}

	hashedPassword := c.hashPassword(password)
	c.encode = hashedPassword[:32]       // Usamos solo los primeros 32 bytes del hash para el cifrado.
	loginPassword := hashedPassword[32:] // Usamos solo los últimos 32 bytes del hash para la contraseña.

	body, _ := json.Marshal(api.RegisterRequest{
		Username: username,
		Password: string(loginPassword),
	})
	// Enviamos la acción al servidor
	res := c.sendRequest(api.Request{
		Body: body,
	}, nil, api.ActionRegister)

	// Mostramos resultado
	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

	// Si fue exitoso, probamos loguear automáticamente.
	if res.Success {
		c.log.Println("Registro exitoso; intentando login automático...")

		loginRes := c.sendRequest(api.Request{
			Body: body,
		}, nil, api.ActionLogin)
		if loginRes.Success {
			c.currentUser = username
			c.authToken = loginRes.Token
			fmt.Println("Login automático exitoso. Token guardado.")
		} else {
			fmt.Println("No se ha podido hacer login automático:", loginRes.Message)
		}
	}
}

// loginUser pide credenciales y realiza un login en el servidor.
func (c *client) loginUser() {
	ui.ClearScreen()
	fmt.Println("** Inicio de sesión **")

	username := ui.ReadInput("Nombre de usuario")
	password, err := ui.ReadPassword("Contraseña")

	if err != nil {
		c.log.Println("No se ha podido obtener la contraseña, registro cancelado: ", err)
		return
	}

	hashedPassword := c.hashPassword(password)
	c.encode = hashedPassword[:32]       // Usamos solo los primeros 32 bytes del hash para el cifrado.
	loginPassword := hashedPassword[32:] // Usamos solo los últimos 32 bytes del hash para la contraseña.

	body, _ := json.Marshal(api.LoginRequest{
		Username: username,
		Password: string(loginPassword),
	})

	res := c.sendRequest(api.Request{
		Body: body,
	}, nil, api.ActionLogin)

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)
	fmt.Println("Token:", res.Token)

	// Si login fue exitoso, guardamos currentUser y el token.
	if res.Success {
		c.currentUser = username
		c.authToken = res.Token
		fmt.Println("Sesión iniciada con éxito. Token guardado.")
	}
}

// lookup pide un listado de los archivos de un directorio.
// El servidor devuelve el listado asociado al usuario logueado.
func (c *client) lookup() {
	ui.ClearScreen()
	fmt.Println("** Listar archivos del servidor **")

	if c.currentUser == "" || c.authToken == "" {
		fmt.Println("No estás logueado. Inicia sesión primero.")
		return
	}

	remotePath := ui.ReadInput("Ruta del directorio en el servidor (ej: dir/docs/)")
	recursive := ui.ReadInput("¿Quieres que se muestren los archivos de forma recursiva? (s/n)")

	body, _ := json.Marshal(api.LookupRequest{Path: remotePath, Recursive: recursive == "s"})
	res := c.sendRequest(api.Request{Body: body}, nil, api.ActionLookup)

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)
	if res.Success {
		var files []api.File
		if err := json.Unmarshal([]byte(res.Data), &files); err == nil {
			fmt.Println("Archivos:")
			for _, f := range files {
				if f.IsDirectory {
					fmt.Printf("- %s (directorio)\n", f.Name)
				} else {
					fmt.Printf("- %s (%d bytes, modificado: %s)\n", f.Name, f.Size, f.Modified.Format("2006-01-02 15:04:05"))
				}
			}
		} else {
			fmt.Println("Error al procesar la lista de archivos:", err)
		}
	}
}

func encryptFile(reader io.Reader, key []byte) (io.Reader, error) {
	iv := make([]byte, 16)

	_, err := rand.Read(iv) // crear un iv aleatorio
	if err != nil {
		return nil, err
	}

	// Crear el bloque AES
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Crear CTR
	ctr := cipher.NewCTR(block, iv)

	var enc cipher.StreamReader // enc es un stream de cifrado que utiliza CTR para cifrar los datos que se leen de reader
	enc.S = ctr
	enc.R = reader

	encWithIV := io.MultiReader(strings.NewReader(string(iv)), enc) // readerWithIV es un reader que primero devuelve el iv y luego el contenido del reader original. Esto es necesario para que el servidor pueda leer el iv al inicio del stream y usarlo para descifrar el resto de datos.

	return encWithIV, nil
}

func decryptFile(reader io.Reader, key []byte) (io.Reader, error) {
	iv := make([]byte, 16)

	_, err := io.ReadFull(reader, iv) // leer el iv del inicio del fichero de entrada
	if err != nil {
		return nil, err
	}

	// Crear el bloque AES
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Crear CTR
	ctr := cipher.NewCTR(block, iv)

	var enc cipher.StreamReader // enc es un stream de cifrado que utiliza CTR para descifrar los datos que se leen de reader
	enc.S = ctr
	enc.R = reader

	return enc, nil
}

// fetchData pide datos privados al servidor.
// El servidor devuelve la data asociada al usuario logueado.
func (c *client) fetchData() {
	ui.ClearScreen()
	fmt.Println("** Descargar archivo del servidor **")

	if c.currentUser == "" || c.authToken == "" {
		fmt.Println("No estás logueado. Inicia sesión primero.")
		return
	}

	remotePath := ui.ReadInput("Ruta del archivo en el servidor (ej: archivo.txt)")
	localPath := ui.ReadInput("Dónde guardarlo en tu PC (ej: ./descargado.txt)")

	// Preparamos el JSON pidiendo el archivo que queremos descargar
	reqBody, _ := json.Marshal(api.FetchDataRequest{Path: remotePath})
	req := api.Request{Body: reqBody}
	jsonData, _ := json.Marshal(req)

	// Conectamos la tubería hacia el servidor
	httpReq, err := http.NewRequest(http.MethodPost, c.server, bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("Error creando la petición:", err)
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Action", api.ActionFetchData)
	httpReq.Header.Set("X-Token", c.authToken)

	// Enviamos la petición
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		fmt.Println("Error conectando con el servidor:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Error del servidor (Código %d). Puede que el archivo no exista.\n", resp.StatusCode)
		return
	}

	// Creamos un archivo en el disco duro del cliente para ir recibiendo la información
	file, err := os.Create(localPath)
	if err != nil {
		fmt.Println("Error creando el archivo local:", err)
		return
	}
	defer file.Close()

	encBody, err := decryptFile(resp.Body, c.encode) // Envolvemos el archivo con un reader de descifrado para que se guarde descifrado en el disco
	if err != nil {
		fmt.Println("Error desencriptando el archivo remoto:", err)
		return
	}

	// Vamos almacenando en el archivo creado los datos que vamos recibiendo del servidor
	_, err = io.Copy(file, encBody)
	if err != nil {
		fmt.Println("Error guardando los datos:", err)
		return
	}

	fmt.Println("Archivo descargado correctamente y guardado en:", localPath)
}

// updateData pide nuevo texto y lo envía al servidor con ActionUpdateData.
func (c *client) updateData() {
	ui.ClearScreen()
	fmt.Println("** Actualizar datos del usuario **")

	if c.currentUser == "" || c.authToken == "" {
		fmt.Println("No estás logueado. Inicia sesión primero.")
		return
	}

	// Leemos la nueva Data
	filePathVar := ui.ReadInput("Introduce el fichero que desees almacenar")
	fileStat, err := os.Stat(filePathVar)
	if err != nil {
		c.log.Println("No se ha podido acceder al fichero:", err)
		return
	}
	if fileStat.IsDir() { // De momento solo se permiten ficheros
		fmt.Println("La ruta introducida es un directorio, todo el contenido se subirá y remplazara al existente, continuar (S/n)?")
		response := ui.ReadInput("")
		response = strings.ToLower(response)
		if response != "s" {
			return
		}
	}

	destBasePath := ui.ReadInput("Introduce la ruta donde quieres almacenar el fichero en el servidor (ej: /docs/miarchivo.txt)")

	if fileStat.IsDir() {
		fmt.Println("Subiendo directorio de forma recursiva...")
		startTime := time.Now()
		if count, total, err := c.recursiveUpload(filePathVar, destBasePath); err != nil {
			endTime := time.Now()
			duration := endTime.Sub(startTime)
			fmt.Printf("Tiempo transcurrido: %s\n", duration)
			c.log.Println("Error al subir el directorio:", err)
			return
		} else {
			endTime := time.Now()
			duration := endTime.Sub(startTime)
			fmt.Printf("Tiempo transcurrido: %s\n", duration)
			fmt.Printf("Se han subido %d archivos de un total de %d.\n", count, total)
		}
		return
	}

	res, err := c.uploadFile(filePathVar, destBasePath, false)
	if err != nil {
		c.log.Println("Error al subir el fichero", filePathVar, " :", err)
		return
	}

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)
	if !res.Success {
		if strings.Contains(res.Message, "archivo ya existe") {
			response := ui.ReadInput("Desea actualizar el archivo (S/n)")
			response = strings.ToLower(response)
			if response == "s" {
				res, err = c.uploadFile(filePathVar, destBasePath, true)
				if err != nil {
					c.log.Println("Error al subir el fichero", filePathVar, " :", err)
					return
				}
				fmt.Println("Éxito:", res.Success)
				fmt.Println("Mensaje:", res.Message)
			}
		}
	}
}

func (c *client) recursiveUpload(localPath string, destBasePath string) (int, int, error) {
	// Enviamos la solicitud de actualización
	if !strings.HasSuffix(localPath, string(os.PathSeparator)) {
		localPath += string(os.PathSeparator)
	}
	count := 0
	total := 0
	fmt.Println("localPath: ", localPath)
	//Imprimimos un mensaje con todo el contenido del directorio
	filepath.Walk(localPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil //No se sube el directorio no es necesario
		}
		destpath := destBasePath + strings.TrimPrefix(path, localPath)
		fmt.Println(path, " - ", info.Size(), " bytes a ", destpath)
		total++
		if destpath != "" {
			res, err := c.uploadFile(path, destpath, false)
			if err != nil {
				c.log.Println("Error al subir el fichero :", err)
			}
			if !res.Success {
				c.log.Println("Error al subir el fichero :", res.Message)
			} else {
				count++
			}
		}
		return nil
	})
	return count, total, nil
}

// logoutUser llama a la acción logout en el servidor, y si es exitosa,
// borra la sesión local (currentUser/authToken).
func (c *client) logoutUser() {
	ui.ClearScreen()
	fmt.Println("** Cerrar sesión **")

	if c.currentUser == "" || c.authToken == "" {
		fmt.Println("No estás logueado.")
		return
	}

	// Llamamos al servidor con la acción ActionLogout
	res := c.sendRequest(api.Request{}, nil, api.ActionLogout)

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

	// Si fue exitoso, limpiamos la sesión local.
	if res.Success {
		c.currentUser = ""
		c.authToken = ""
		c.encode = nil

	}
}

// sendStreamingRequest es una función especializada para enviar datos binarios (ficheros) al servidor.
func (c *client) sendStreamingRequest(file io.Reader, headers []http.Header, action string, path string) api.Response {
	valid := api.IsValidAction(action)
	if !valid {
		c.log.Println("Acción no válida:", action)
		return api.Response{Success: false, Message: "Acción no válida"}
	}
	httpReq, err := http.NewRequest(http.MethodPost, c.server, file)
	if err != nil {
		c.log.Println("No se ha podido construir la petición HTTP:", err)
		return api.Response{Success: false, Message: "Error interno del cliente"}
	}
	httpReq.Header.Set("Content-Type", "application/octet-stream")
	httpReq.Header.Set("X-Action", action)
	if c.authToken != "" {
		httpReq.Header.Set("X-Token", c.authToken)
	}
	httpReq.Header.Set("X-Path", path)

	for _, h := range headers {
		for k, v := range h {
			for _, vv := range v {
				httpReq.Header.Set(k, vv)
			}
		}
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		fmt.Println("Error al contactar con el servidor:", err)
		return api.Response{Success: false, Message: "Error de conexión"}
	}
	defer resp.Body.Close()

	// Leemos el body de respuesta y lo desempaquetamos en un api.Response.
	// Si el servidor ha respondido con un error HTTP, intentamos igualmente
	// descodificar un api.Response para mostrar el mensaje.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.log.Println("No se ha podido leer la respuesta:", err)
		return api.Response{Success: false, Message: "Respuesta inválida del servidor"}
	}
	var res api.Response
	if err := json.Unmarshal(body, &res); err != nil {
		c.log.Println("No se ha podido descodificar la respuesta JSON:", err)
		return api.Response{Success: false, Message: "Respuesta inválida del servidor"}
	}
	return res

}

// sendRequest envía un POST JSON a la URL del servidor y
// devuelve la respuesta decodificada. Se usa para todas las acciones.
func (c *client) sendRequest(req api.Request, headers []http.Header, action string) api.Response {
	valid := api.IsValidAction(action)
	if !valid {
		c.log.Println("Acción no válida:", action)
		return api.Response{Success: false, Message: "Acción no válida"}
	}

	jsonData, err := json.Marshal(req)
	if err != nil {
		c.log.Println("No se ha podido serializar la petición JSON:", err)
		return api.Response{Success: false, Message: "Error interno del cliente"}
	}

	httpReq, err := http.NewRequest(http.MethodPost, c.server, bytes.NewBuffer(jsonData))
	if err != nil {
		c.log.Println("No se ha podido construir la petición HTTP:", err)
		return api.Response{Success: false, Message: "Error interno del cliente"}
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Action", action)
	if c.authToken != "" {
		httpReq.Header.Set("X-Token", c.authToken)
	}

	for _, h := range headers {
		for k, v := range h {
			for _, vv := range v {
				httpReq.Header.Set(k, vv)
			}
		}
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		fmt.Println("Error al contactar con el servidor:", err)
		return api.Response{Success: false, Message: "Error de conexión"}
	}
	defer resp.Body.Close()

	// Leemos el body de respuesta y lo desempaquetamos en un api.Response.
	// Si el servidor ha respondido con un error HTTP, intentamos igualmente
	// descodificar un api.Response para mostrar el mensaje.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		c.log.Println("No se ha podido leer la respuesta:", err)
		return api.Response{Success: false, Message: "Respuesta inválida del servidor"}
	}
	var res api.Response
	if err := json.Unmarshal(body, &res); err != nil {
		c.log.Println("No se ha podido descodificar la respuesta JSON:", err)
		return api.Response{Success: false, Message: "Respuesta inválida del servidor"}
	}
	return res
}

func (c *client) uploadFile(filePath string, destPath string, force bool) (api.Response, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return api.Response{Success: false, Message: "No se ha podido abrir el fichero"}, fmt.Errorf("no se ha podido abrir el fichero: %w", err)
	}

	defer file.Close()

	encFile, err := encryptFile(file, c.encode)
	if err != nil {
		return api.Response{Success: false, Message: "Error al cifrar el fichero"}, fmt.Errorf("error al cifrar el fichero: %w", err)
	}

	headers := []http.Header{{"X-Force": []string{fmt.Sprintf("%v", force)}}}

	res := c.sendStreamingRequest(encFile, headers, api.ActionUpdateData, destPath)
	return res, nil
}

func (c *client) deleteData() {
	ui.ClearScreen()
	fmt.Println("** Borrar datos del usuario **")

	if c.currentUser == "" || c.authToken == "" {
		fmt.Println("No estás logueado. Inicia sesión primero.")
		return
	}

	targetPath := ui.ReadInput("Introduce la ruta del fichero o carpeta que quieres borrar (ej: /docs/miarchivo.txt o /docs)")

	body, _ := json.Marshal(api.DeleteDataRequest{
		Path: targetPath,
	})

	res := c.sendRequest(api.Request{
		Body: body,
	}, nil, api.ActionDeleteData)

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)
}
