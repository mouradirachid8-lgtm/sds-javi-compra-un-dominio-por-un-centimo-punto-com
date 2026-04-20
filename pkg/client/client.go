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

func NewClient(serverAddr string, certPem []byte) *client {
	// Aseguramos que la URL del servidor apunta al endpoint /api que maneja
	// las peticiones JSON/stream en el servidor. Evitamos duplicar barras.
	//Ponemos https, quitamos la barra final y añadimos /api si no está presente.
	if !strings.HasPrefix(serverAddr, "http://") && !strings.HasPrefix(serverAddr, "https://") {
		serverAddr = "https://" + serverAddr
	}
	if strings.HasSuffix(serverAddr, "/") {
		serverAddr = strings.TrimRight(serverAddr, "/")
	}
	if !strings.HasSuffix(serverAddr, "/api") {
		serverAddr = strings.TrimRight(serverAddr, "/") + "/api"
	}
	// Construimos un pool de CAs que solo contiene el certificado del servidor.
	// Así el cliente acepta únicamente ese cert y rechaza cualquier otro.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPem) {
		log.Fatal("No se ha podido cargar el certificado TLS del servidor")
	}

	tlsConfig := &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig

	return &client{
		log: log.New(os.Stdout, "[cli] ", log.LstdFlags),
		httpClient: &http.Client{
			Timeout:   5 * time.Second,
			Transport: transport,
		},
		server: serverAddr,
	}
}

// hashPassword es una función auxiliar para hashear contraseñas antes de enviarlas al servidor.
func (c *client) hashPassword(password string) [64]byte { // En un caso real, se debería usar un algoritmo de hashing fuerte como bcrypt o Argon2.
	// Aquí usaremos SHA512 por simplicidad, aunque no es recomendado para contraseñas.
	// Además, en un caso real se debería usar un salt único por usuario.
	return sha512.Sum512([]byte(password + c.currentUser))
}

func (c *client) Login(username, password string) error {
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

	if res.Success {
		c.currentUser = username
		c.authToken = res.Token
		return nil
	} else {
		return fmt.Errorf("login fallido: %s", res.Message)
	}
}

func (c *client) Register(username, password string) error {
	hashedPassword := c.hashPassword(password)
	c.encode = hashedPassword[:32]          // Usamos solo los primeros 32 bytes del hash para el cifrado.
	registerPassword := hashedPassword[32:] // Usamos solo los últimos 32 bytes del hash para la contraseña.

	body, _ := json.Marshal(api.RegisterRequest{
		Username: username,
		Password: string(registerPassword),
	})

	res := c.sendRequest(api.Request{
		Body: body,
	}, nil, api.ActionRegister)

	if res.Success {
		c.log.Println("Registro exitoso")
		return nil
	} else {
		return fmt.Errorf("registro fallido: %s", res.Message)
	}
}

// lookup pide un listado de los archivos de un directorio.
// El servidor devuelve el listado asociado al usuario logueado.
func (c *client) Lookup(remotePath string, recursive bool) ([]api.File, error) {
	if c.currentUser == "" || c.authToken == "" {
		return nil, fmt.Errorf("no estás logueado")
	}

	body, _ := json.Marshal(api.LookupRequest{Path: remotePath, Recursive: recursive})
	res := c.sendRequest(api.Request{Body: body}, nil, api.ActionLookup)

	if !res.Success {
		return nil, fmt.Errorf("Error del servidor: %s", res.Message)
	}

	var files []api.File
	if err := json.Unmarshal([]byte(res.Data), &files); err != nil {
		return nil, fmt.Errorf("Error al decodificar la lista de archivos: %w", err)
	}

	for i := range files {
		timeStr := files[i].Modified.Format(time.RFC3339)
		normalizedTime, _ := time.Parse(time.RFC3339, timeStr)
		files[i].Modified = normalizedTime
	}

	return files, nil
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
func (c *client) FetchData(remotePath, localPath string) error {

	if c.currentUser == "" || c.authToken == "" {
		return fmt.Errorf("no estás logueado")
	}

	// Preparamos el JSON pidiendo el archivo que queremos descargar
	reqBody, _ := json.Marshal(api.FetchDataRequest{Path: remotePath})
	req := api.Request{Body: reqBody}
	jsonData, _ := json.Marshal(req)

	// Conectamos la tubería hacia el servidor
	httpReq, err := http.NewRequest(http.MethodPost, c.server, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("no se ha podido construir la petición HTTP: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Action", api.ActionFetchData)
	httpReq.Header.Set("X-Token", c.authToken)

	// Enviamos la petición
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("error de conexión: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("error del servidor: código %d", resp.StatusCode)
	}

	// Creamos un archivo en el disco duro del cliente para ir recibiendo la información
	file, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("Error creando el archivo local: %w", err)
	}
	defer file.Close()

	encBody, err := decryptFile(resp.Body, c.encode) // Envolvemos el archivo con un reader de descifrado para que se guarde descifrado en el disco
	if err != nil {
		return fmt.Errorf("Error desencriptando el archivo remoto: %w", err)
	}

	// Vamos almacenando en el archivo creado los datos que vamos recibiendo del servidor
	_, err = io.Copy(file, encBody)
	if err != nil {

		return fmt.Errorf("Error guardando los datos: %w", err)
	}

	return nil
}

// updateData pide nuevo texto y lo envía al servidor con ActionUpdateData.
func (c *client) UploadData(filePathVar string, destBasePath string, recursive bool, force bool) (int, int, error) {

	if c.currentUser == "" || c.authToken == "" {
		return 0, 0, fmt.Errorf("no estás logueado")
	}

	// Leemos la nueva Data
	fileStat, err := os.Stat(filePathVar)
	if err != nil {
		c.log.Println("No se ha podido acceder al fichero:", err)
		return 0, 0, fmt.Errorf("no se ha podido acceder al fichero: %w", err)
	}
	if fileStat.IsDir() && !recursive {
		return 0, 0, fmt.Errorf("solo se permiten ficheros")
	}

	if fileStat.IsDir() && recursive {
		if count, total, err := c.recursiveUpload(filePathVar, destBasePath); err != nil {
			return 0, 0, fmt.Errorf("error al subir el directorio: %w", err)
		} else {
			return count, total, nil
		}
	}

	res, err := c.uploadFile(filePathVar, destBasePath, force)
	if err != nil {
		return 0, 0, fmt.Errorf("error al subir el fichero: %w", err)
	}

	if !res.Success {
		return 0, 0, fmt.Errorf("error del servidor: %s", res.Message)
	}

	return 1, 1, nil
}

func (c *client) recursiveUpload(localPath string, destBasePath string) (int, int, error) {
	// Enviamos la solicitud de actualización
	if !strings.HasSuffix(localPath, string(os.PathSeparator)) {
		localPath += string(os.PathSeparator)
	}
	count := 0
	total := 0
	//Imprimimos un mensaje con todo el contenido del directorio
	filepath.Walk(localPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			c.log.Println("Error al acceder al fichero:", err)
			return err
		}
		if info.IsDir() {
			return nil //No se sube el directorio no es necesario
		}
		destpath := destBasePath + strings.TrimPrefix(path, localPath)
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
func (c *client) LogoutUser() error {

	if c.currentUser == "" || c.authToken == "" {
		return fmt.Errorf("no estás logueado")
	}

	// Llamamos al servidor con la acción ActionLogout
	res := c.sendRequest(api.Request{}, nil, api.ActionLogout)

	// Si fue exitoso, limpiamos la sesión local.
	if res.Success {
		c.currentUser = ""
		c.authToken = ""
		c.encode = nil
		return nil
	} else {
		return fmt.Errorf("error del servidor: %s", res.Message)
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
		c.log.Println("Error al contactar con el servidor:", err)
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
		// Logueamos el cuerpo crudo para facilitar el debug cuando el servidor
		// devuelve texto no-JSON (p.ej. errores en texto plano o panics).
		c.log.Printf("Cuerpo de respuesta bruto: %q\n", string(body))
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
		c.log.Println("Error al contactar con el servidor:", err)
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
		c.log.Printf("Cuerpo de respuesta bruto: %q\n", string(body))
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

	// Extraer metadatos del archivo original
	stat, err := file.Stat()
	if err != nil {
		return api.Response{Success: false, Message: "Error leyendo metadatos"}, err
	}
	perms := fmt.Sprintf("%04o", stat.Mode().Perm())
	modTime := stat.ModTime().Format(time.RFC3339)

	encFile, err := encryptFile(file, c.encode)
	if err != nil {
		return api.Response{Success: false, Message: "Error al cifrar el fichero"}, fmt.Errorf("error al cifrar el fichero: %w", err)
	}

	headers := []http.Header{{
		"X-Force":       []string{fmt.Sprintf("%v", force)},
		"X-Permissions": []string{perms},
		"X-Modified":    []string{modTime},
	}}

	res := c.sendStreamingRequest(encFile, headers, api.ActionUpdateData, destPath)
	return res, nil
}

func (c *client) DeleteData(targetPath string) error {
	if c.currentUser == "" || c.authToken == "" {
		return fmt.Errorf("no estás logueado")
	}

	body, _ := json.Marshal(api.DeleteDataRequest{
		Path: targetPath,
	})

	res := c.sendRequest(api.Request{
		Body: body,
	}, nil, api.ActionDeleteData)

	if !res.Success {
		return fmt.Errorf("error del servidor: %s", res.Message)
	}

	c.log.Println("Datos borrados correctamente.")
	return nil
}
