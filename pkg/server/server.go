// El paquete server contiene el código del servidor.
// Interactúa con el cliente mediante una API JSON/HTTP
package server

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"sprout/pkg/api"
	"sprout/pkg/external_logger"
	"sprout/pkg/store"
	"strconv"
	"strings"
	"time"
	"net"
)

// server encapsula el estado de nuestro servidor
type server struct {
	db       store.Store // base de datos
	log      *log.Logger // logger para mensajes de error e información
	basePath string      // ruta base para almacenar archivos (opcional)
}

var INT64_MAX = big.NewInt(0).SetInt64(1<<63 - 1)

const maxUploadSize = 1000 << 20 // 1000 MiB por defecto

// Run inicia la base de datos y arranca el servidor HTTPS con el certificado TLS proporcionado.
// certPEM y keyPEM son el certificado y la clave privada en formato PEM,
// generados por el paquete certgen.
func Run(certPEM, keyPEM []byte) error {

	// Crear la carpeta 'data' en caso de que no exista.
	if err := os.MkdirAll("data", 0755); err != nil {
		return fmt.Errorf("error creando la carpeta 'data': %w", err)
	}

	// Abrimos la base de datos usando el motor bbolt
	db, err := store.NewStore("bbolt", "data/server.db")
	if err != nil {
		return fmt.Errorf("error abriendo base de datos: %v", err)
	}

	// Configuramos el logger asíncrono si está definido por variables de entorno
	loggerPrefix := "[srv] "
	var srvLog *log.Logger
	var closeLog func()

	logEndpoint := os.Getenv("LOG_SERVER_ENDPOINT")
	logAuthEndpoint := os.Getenv("LOG_SERVER_AUTH_ENDPOINT")

	if logEndpoint != "" {
		extLog, closeFn, extErr := external_logger.NewExternalLogger(logEndpoint, logAuthEndpoint)
		if extErr == nil {
			srvLog = extLog
			closeLog = closeFn
		} else {
			// Fallback silencioso a consola estándar si falla el logger
			srvLog = log.New(os.Stdout, loggerPrefix, log.LstdFlags)
			closeLog = func() {}
		}
	} else {
		srvLog = log.New(os.Stdout, loggerPrefix, log.LstdFlags)
		closeLog = func() {}
	}

	// Creamos nuestro servidor con su logger
	srv := &server{
		db:       db,
		log:      srvLog,
		basePath: "data/files", // carpeta para almacenar archivos (opcional)
	}

	// Al terminar, cerramos la base de datos y flusheamos el logger
	defer func() {
		closeLog()
		srv.db.Close()
	}()

	// Construimos un mux y asociamos /api a nuestro apiHandler,
	mux := http.NewServeMux()
	mux.Handle("/api", http.HandlerFunc(srv.apiHandler))

	// Cargamos el certificado TLS desde los PEM en memoria
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("error cargando certificado TLS: %w", err)
	}

	// Iniciamos el servidor HTTPS.
	httpSrv := &http.Server{
		Addr:    ":8080",
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			MinVersion:   tls.VersionTLS12,
		},
		ReadHeaderTimeout: 5 * time.Second,
	}
	// Pasamos strings vacíos porque ya configuramos TLSConfig.Certificates
	return httpSrv.ListenAndServeTLS("", "")
}

// apiHandler decodifica la solicitud JSON, la despacha
// a la función correspondiente y devuelve la respuesta JSON.
func (s *server) apiHandler(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	if r.Method != http.MethodPost {
		s.log.Printf("RECHAZO MÉTODO: %s desde %s", r.Method, clientIP)
		http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		return
	}
	actionHeader := r.Header.Get("X-Action")
	if actionHeader == "" {
		s.log.Printf("ERROR CABECERA: X-Action faltante desde %s", clientIP)
		http.Error(w, "Falta la cabecera X-Action", http.StatusBadRequest)
		return
	}
	if !api.IsValidAction(actionHeader) {
		s.log.Printf("ALERTA SEGURIDAD: Acción inválida '%s' desde %s", actionHeader, clientIP)
		http.Error(w, "Acción no válida", http.StatusBadRequest)
		return
	}
	ContentType := r.Header.Get("Content-Type")
	if ContentType == "" {
		s.log.Printf("ERROR CABECERA: Content-Type faltante desde %s", clientIP)
		http.Error(w, "Falta la cabecera Content-Type", http.StatusBadRequest)
		return
	}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		s.jsonHandler(w, r, clientIP)
		return
	} else if strings.HasPrefix(r.Header.Get("Content-Type"), "application/octet-stream") {
		s.fileHandler(w, r, clientIP)
		return
	} else {
		s.log.Printf("ERROR CONTENT-TYPE: Tipo no soportado '%s' desde %s", ContentType, clientIP)
		http.Error(w, "Content-Type no soportado", http.StatusUnsupportedMediaType)
		return
	}
}

func (s *server) jsonHandler(w http.ResponseWriter, r *http.Request, clientIP string) {
	// Limitamos el tamaño del body para evitar sorpresas.
	// (No es una medida de seguridad "de verdad"; sólo robustez.)
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MiB

	// Decodificamos la solicitud en una estructura api.Request
	var req api.Request
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		s.log.Printf("ERROR JSON: Formato inválido desde %s: %v", clientIP, err)
		http.Error(w, "Error en el formato JSON", http.StatusBadRequest)
		return
	}
	// Evitamos que se envíen múltiples objetos JSON concatenados.
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		s.log.Printf("ALERTA SEGURIDAD: Múltiples JSON concatenados desde %s", clientIP)
		http.Error(w, "Error en el formato JSON", http.StatusBadRequest)
		return
	}
	action := r.Header.Get("X-Action")
	token := r.Header.Get("X-Token")
	// Despacho según la acción solicitada
	var res api.Response
	switch action {
	case api.ActionRegister:
		res = s.registerUser(req, clientIP)
	case api.ActionLogin:
		res = s.loginUser(req, clientIP)
	case api.ActionFetchData:
		s.streamFetchData(w, req, token, clientIP)
		return
	case api.ActionDeleteData:
		res = s.deleteData(req, token, clientIP)
	case api.ActionLogout:
		res = s.logoutUser(req, token, clientIP)
	default:
		s.log.Printf("ALERTA: Acción desconocida '%s' desde %s", action, clientIP)
		res = api.Response{Success: false, Message: "Acción desconocida"}
	}

	// Enviamos la respuesta en formato JSON
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

func (s *server) fileHandler(w http.ResponseWriter, r *http.Request, clientIP string) {
	// Limitar el tamaño del body usando el ResponseWriter para que
	// http.MaxBytesReader pueda escribir el error en caso de exceder.
	if r.ContentLength > 0 && r.ContentLength > maxUploadSize {
		s.log.Printf("ERROR TAMAÑO: Archivo demasiado grande (%d bytes) desde %s", r.ContentLength, clientIP)
		http.Error(w, "Archivo demasiado grande", http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadSize)
	defer r.Body.Close()

	action := r.Header.Get("X-Action")
	token := r.Header.Get("X-Token")
	var res api.Response
	switch action {
	case api.ActionUpdateData:
		res = s.updateData(r.Body, token, r.Header.Get("X-Path"), r.Header.Get("X-Force") == "true", clientIP)
	default:
		s.log.Printf("ALERTA: Acción desconocida en fileHandler '%s' desde %s", action, clientIP)
		res = api.Response{Success: false, Message: "Acción desconocida"}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

// generateToken crea un token único incrementando un contador interno (inseguro)
func (s *server) generateToken(username string) string {
	// atomic es necesario al haber paralelismo en las peticiones HTTP.
	n, err := rand.Int(rand.Reader, INT64_MAX)
	if err != nil {
		panic(err)
	}
	id := n.Int64()
	//id := atomic.AddInt64(&s.tokenCounter, 1)
	return fmt.Sprintf("token_%d+%s", id, username)
}

// registerUser registra un nuevo usuario, si no existe.
// - Guardamos la contraseña en el namespace 'auth'
// - Creamos entrada vacía en 'userdata' para el usuario
func (s *server) registerUser(req api.Request, clientIP string) api.Response {
	var regReq api.RegisterRequest
	if err := json.Unmarshal(req.Body, &regReq); err != nil {
		s.log.Printf("FALLO REGISTRO: JSON inválido desde %s: %v", clientIP, err)
		return api.Response{Success: false, Message: "Error al procesar la solicitud"}
	}

	// Validación básica
	if regReq.Username == "" || regReq.Password == "" {
		s.log.Printf("FALLO REGISTRO: Credenciales vacías desde %s", clientIP)
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}

	// Validar longitud
	if len(regReq.Username) > 50 {
		s.log.Printf("FALLO REGISTRO: Username demasiado largo desde %s", clientIP)
		return api.Response{Success: false, Message: "Username demasiado largo"}
	}

	if len(regReq.Password) < 6 {
		s.log.Printf("FALLO REGISTRO: Password demasiado corta desde %s", clientIP)
		return api.Response{Success: false, Message: "Password debe tener al menos 6 caracteres"}
	}

	// Verificamos si ya existe el usuario en 'auth'
	exists, err := s.userExists(regReq.Username)
	if err != nil {
		s.log.Printf("FALLO REGISTRO: Error BD verificando '%s' desde %s: %v", regReq.Username, clientIP, err)
		return api.Response{Success: false, Message: "Error al verificar usuario"}
	}
	if exists {
		s.log.Printf("FALLO REGISTRO: Usuario '%s' ya existe, intento desde %s", regReq.Username, clientIP)
		return api.Response{Success: false, Message: "El usuario ya existe"}
	}

	// Almacenamos la contraseña en el namespace 'auth' (clave=nombre, valor=contraseña)
	if err := s.db.Put("auth", []byte(regReq.Username), []byte(regReq.Password)); err != nil {
		s.log.Printf("FALLO REGISTRO: Error guardando credenciales para '%s' desde %s: %v", regReq.Username, clientIP, err)
		return api.Response{Success: false, Message: "Error al guardar credenciales"}
	}

	// Creamos una entrada vacía para los datos en 'userdata'
	if err := s.db.Put("userdata", []byte(regReq.Username), []byte("")); err != nil {
		s.log.Printf("FALLO REGISTRO: Error inicializando datos para '%s' desde %s: %v", regReq.Username, clientIP, err)
		return api.Response{Success: false, Message: "Error al inicializar datos de usuario"}
	}

	s.log.Printf("ÉXITO REGISTRO: Usuario '%s' registrado desde %s", regReq.Username, clientIP)
	return api.Response{Success: true, Message: "Usuario registrado"}
}

// loginUser valida credenciales en el namespace 'auth' y genera un token en 'sessions'.
func (s *server) loginUser(req api.Request, clientIP string) api.Response {
	var loginReq api.LoginRequest
	if err := json.Unmarshal(req.Body, &loginReq); err != nil {
		s.log.Printf("FALLO LOGIN: JSON inválido desde %s: %v", clientIP, err)
		return api.Response{Success: false, Message: "Error al procesar la solicitud"}
	}

	if loginReq.Username == "" || loginReq.Password == "" {
		s.log.Printf("FALLO LOGIN: Credenciales vacías desde %s", clientIP)
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}

	// Recogemos la contraseña guardada en 'auth'
	storedPass, err := s.db.Get("auth", []byte(loginReq.Username))
	if err != nil {
		s.log.Printf("FALLO LOGIN: Usuario no encontrado '%s' desde %s", loginReq.Username, clientIP)
		return api.Response{Success: false, Message: "Usuario no encontrado"}
	}

	// Comparamos
	if string(storedPass) != loginReq.Password {
		s.log.Printf("FALLO AUTENTICACIÓN: Usuario '%s' contraseña incorrecta desde %s", loginReq.Username, clientIP)
		return api.Response{Success: false, Message: "Credenciales inválidas"}
	}

	// Generamos un nuevo token, lo guardamos en 'sessions'
	token := s.generateToken(loginReq.Username)
	if err := s.db.Put("sessions", []byte(token), []byte(loginReq.Username)); err != nil {
		s.log.Printf("FALLO LOGIN: Error creando sesión para '%s' desde %s: %v", loginReq.Username, clientIP, err)
		return api.Response{Success: false, Message: "Error al crear sesión"}
	}

	s.log.Printf("ÉXITO LOGIN: Usuario '%s' autenticado desde %s", loginReq.Username, clientIP)
	return api.Response{Success: true, Message: "Login exitoso", Token: token}
}

// fetchData verifica el token y retorna el contenido del namespace 'userdata'.
func (s *server) fetchData(req api.Request, token string) api.Response {
	// Chequeo de credenciales
	if token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	valid, username := s.isTokenValid(token)
	if !valid {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	// Obtenemos los datos asociados al usuario desde 'userdata'
	rawData, err := s.db.Get("userdata", []byte(username))
	if err != nil {
		return api.Response{Success: false, Message: "Error al obtener datos del usuario"}
	}

	return api.Response{
		Success: true,
		Message: "Datos privados de " + username,
		Data:    string(rawData),
	}
}

// updateData cambia el contenido de 'userdata' (los "datos" del usuario)
// después de validar el token.
func (s *server) updateData(body io.ReadCloser, token string, path string, force bool, clientIP string) api.Response {
	// Chequeo de credenciales
	if token == "" {
		s.log.Printf("FALLO SUBIDA: Token vacío desde %s", clientIP)
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	valid, username := s.isTokenValid(token)
	if !valid {
		s.log.Printf("FALLO SUBIDA: Token inválido desde %s", clientIP)
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	if err := s.saveFile(body, username, force, path, clientIP); err != nil {
		s.log.Printf("FALLO SUBIDA: Error guardando '%s' para '%s' desde %s: %s", path, username, clientIP, err.Error())
		return api.Response{Success: false, Message: "Error al guardar datos: " + err.Error()}
	}

	s.log.Printf("ÉXITO SUBIDA: Usuario '%s' subió '%s' desde %s", username, path, clientIP)
	return api.Response{Success: true, Message: "Datos de usuario actualizados"}
}

// logoutUser borra la sesión en 'sessions', invalidando el token.
func (s *server) logoutUser(req api.Request, token string, clientIP string) api.Response {
	// Chequeo de credenciales
	if token == "" {
		s.log.Printf("FALLO LOGOUT: Token vacío desde %s", clientIP)
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	valid, username := s.isTokenValid(token)
	if !valid {
		s.log.Printf("FALLO LOGOUT: Token inválido desde %s", clientIP)
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	// Borramos la entrada en 'sessions'
	if err := s.db.Delete("sessions", []byte(token)); err != nil {
		s.log.Printf("FALLO LOGOUT: Error borrando sesión para '%s' desde %s: %v", username, clientIP, err)
		return api.Response{Success: false, Message: "Error al cerrar sesión"}
	}

	s.log.Printf("ÉXITO LOGOUT: Usuario '%s' cerró sesión desde %s", username, clientIP)
	return api.Response{Success: true, Message: "Sesión cerrada correctamente"}
}

// userExists comprueba si existe un usuario con la clave 'username'
// en 'auth'. Si no se encuentra, retorna false.
func (s *server) userExists(username string) (bool, error) {
	_, err := s.db.Get("auth", []byte(username))
	if err != nil {
		// Si no existe namespace o la clave, no es un error "real".
		if errors.Is(err, store.ErrNamespaceNotFound) || errors.Is(err, store.ErrKeyNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// isTokenValid comprueba que el token almacenado en 'sessions'
// coincida con el token proporcionado.
func (s *server) isTokenValid(token string) (bool, string) {
	codePart, extractedUsername, ok := strings.Cut(token, "+")
	if !ok {
		return false, ""
	}

	idStr := strings.TrimPrefix(codePart, "token_")
	_, errParse := strconv.ParseInt(idStr, 10, 64)
	if errParse != nil {
		return false, ""
	}
	username, err := s.db.Get("sessions", []byte(token))
	if err != nil {
		return false, ""
	}
	if string(username) == extractedUsername {
		return true, extractedUsername
	} else {
		return false, ""
	}
}

// getClientIP extrae la IP del cliente de la petición HTTP
func getClientIP(r *http.Request) string {
	// Intentar obtener de X-Forwarded-For primero (proxies)
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		// X-Forwarded-For puede contener múltiples IPs, tomar la primera
		ips := strings.Split(forwarded, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}
	
	// Alternativa: X-Real-IP
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}
	
	// Si no hay proxies, usar RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func (s *server) saveFile(body io.ReadCloser, username string, force bool, path string, clientIP string) error {
	path = strings.ReplaceAll(path, "\\", "/") // Evitamos barras invertidas
	path = strings.TrimSpace(path)
	if strings.Contains(path, "..") {
		return fmt.Errorf("No se admite '..'")
	}

	// Si el cliente envía una ruta absoluta (Windows/Linux), nos quedamos con el nombre.
	if filepath.IsAbs(path) || (len(path) >= 2 && path[1] == ':') {
		path = filepath.Base(path)
	}

	path = strings.TrimPrefix(path, "/")
	path = "/" + username + "/" + path
	path = strings.ReplaceAll(path, "//", "/") // Evitamos dobles barras
	var creationTime int64
	data, err := s.db.Get("userdata", []byte(path))
	if err != nil {
		// Si no existe la clave/namespace, lo tratamos como alta nueva.
		if !errors.Is(err, store.ErrKeyNotFound) && !errors.Is(err, store.ErrNamespaceNotFound) {
			return fmt.Errorf("error al leer datos: %w", err)
		}
	} else if data != nil && !force {
		s.log.Printf("FALLO SUBIDA: Archivo existe '%s' usuario '%s' desde %s (sin force)", path, username, clientIP)
		return fmt.Errorf("archivo ya existe")
	}

	if data != nil {
		var existingFile api.File
		if err := json.Unmarshal(data, &existingFile); err != nil {
			s.log.Printf("ERROR METADATOS: Error parsing para '%s' usuario '%s': %v", path, username, err)
			return fmt.Errorf("error al procesar datos existentes: %w", err)
		}
		creationTime = existingFile.Created.Unix()
	}

	s.log.Printf("Guardando archivo para usuario '%s' en path '%s'", username, path)
	if err := os.MkdirAll(filepath.Dir(s.basePath+path), 0755); err != nil {
		s.log.Printf("ERROR DIRECTORIO: Error creando directorios '%s' usuario '%s': %v", path, username, err)
		return fmt.Errorf("error al crear directorios: %w", err)
	}
	file, err := os.Create(s.basePath + path) // Creamos el fichero en el sistema de archivos
	if err != nil {
		s.log.Printf("ERROR ARCHIVO: Error creando '%s' usuario '%s': %v", path, username, err)
		return fmt.Errorf("error al crear archivo: %w", err)
	}
	defer file.Close()
	_, err = io.Copy(file, body) // Copiamos el contenido del body al fichero
	if err != nil {
		s.log.Printf("ERROR COPIA: Error copiando datos '%s' usuario '%s': %v", path, username, err)
		return fmt.Errorf("error al copiar datos: %w", err)
	}
	stats, err := file.Stat()
	if err != nil {
		s.log.Printf("ERROR COPIA: Error al obtener información de '%s' usuario '%s': %v", path, username, err)
		return fmt.Errorf("error al obtener información del archivo: %w", err)
	}
	fileBytes, err := json.Marshal(api.File{
		Name:        filepath.Base(path),
		Modified:    time.Now(),
		Created:     time.Unix(creationTime, 0),
		Size:        stats.Size(),
		Path:        path,
		IsDirectory: false,
	})
	if err != nil {
		s.log.Printf("ERROR COPIA: Error al serializar '%s' usuario '%s': %v", path, username, err)
		return fmt.Errorf("error al serializar metadatos: %w", err)
	}

	if err := s.db.Put("userdata", []byte(path), fileBytes); err != nil {
		s.log.Printf("ERROR BD: Error guardando metadatos '%s' usuario '%s': %v", path, username, err)
		return fmt.Errorf("error al guardar archivo: %w", err)
	}

	return nil
}

func (s *server) deleteData(req api.Request, token string, clientIP string) api.Response {
	// 1. Chequeo de credenciales
	if token == "" {
		s.log.Printf("FALLO BORRADO: Token vacío desde %s", clientIP)
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	valid, username := s.isTokenValid(token)
	if !valid {
		s.log.Printf("FALLO BORRADO: Token inválido desde %s", clientIP)
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	var delReq api.DeleteDataRequest
	if err := json.Unmarshal(req.Body, &delReq); err != nil {
		s.log.Printf("FALLO BORRADO: JSON inválido usuario '%s' desde %s: %v", username, clientIP, err)
		return api.Response{Success: false, Message: "Error al procesar la solicitud"}
	}

	// 2. Saneamiento de la ruta (Seguridad)
	target := strings.ReplaceAll(delReq.Path, "\\", "/")
	target = strings.TrimSpace(target)

	// Prevenir Path Traversal (evitar que suban niveles fuera de su carpeta)
	if strings.Contains(target, "..") {
		s.log.Printf("ALERTA SEGURIDAD: INTENTO PATH TRAVERSAL borrado '%s' usuario '%s' desde %s", target, username, clientIP)
		return api.Response{Success: false, Message: "No se admite '..' en la ruta"}
	}

	if filepath.IsAbs(target) || (len(target) >= 2 && target[1] == ':') {
		s.log.Printf("ALERTA SEGURIDAD: RUTA ABSOLUTA borrado '%s' usuario '%s' desde %s", target, username, clientIP)
		target = filepath.Base(target)
	}

	// copidoa de saveFile
	target = strings.TrimPrefix(target, "/")
	dbPath := "/" + username + "/" + target
	dbPath = strings.ReplaceAll(dbPath, "//", "/")

	// Seguridad: Evitar que el usuario borre su carpeta raíz completa
	if dbPath == "/"+username || dbPath == "/"+username+"/" {
		s.log.Printf("ALERTA SEGURIDAD: INTENTO BORRAR RAÍZ usuario '%s' desde %s", username, clientIP)
		return api.Response{Success: false, Message: "No tienes permiso para borrar tu directorio raíz completo"}
	}

	fullSystemPath := s.basePath + dbPath

	// Comprobar si existe
	stat, err := os.Stat(fullSystemPath)
	if err != nil {
		if os.IsNotExist(err) {
			s.log.Printf("FALLO BORRADO: Archivo no existe '%s' usuario '%s' desde %s", dbPath, username, clientIP)
			return api.Response{Success: false, Message: "El archivo o carpeta no existe"}
		}
		s.log.Printf("ERROR ACCESO: Error accediendo '%s' usuario '%s': %v", dbPath, username, err)
		return api.Response{Success: false, Message: "Error al acceder a la ruta"}
	}

	// Recopilar las rutas para limpiar la base de datos
	pathsToDelete := []string{dbPath}
	isDir := stat.IsDir()
	fileCount := 1

	if stat.IsDir() {
		// Si es carpeta, buscamos todos los archivos de dentro para limpiarlos de la BD
		filepath.Walk(fullSystemPath, func(fsPath string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				fileCount++
				// Convertimos la ruta física a la ruta relativa de la BD
				relPath, _ := filepath.Rel(s.basePath, fsPath)
				relPath = filepath.ToSlash(relPath)
				pathsToDelete = append(pathsToDelete, "/"+relPath)
			}
			return nil
		})
	}

	// Borramos del disco
	if err := os.RemoveAll(fullSystemPath); err != nil {
		s.log.Printf("ERROR FÍSICO: Error borrando '%s' usuario '%s': %v", fullSystemPath, username, err)
		return api.Response{Success: false, Message: "Error interno al borrar en el disco"}
	}

	// Borramos los registros de la db
	for _, p := range pathsToDelete {
		_ = s.db.Delete("userdata", []byte(p))
	}

	tipoBorrado := "archivo"
	if isDir {
		tipoBorrado = "directorio"
	}

	s.log.Printf("ÉXITO BORRADO: Usuario '%s' borró %s '%s' (%d items) desde %s", username, tipoBorrado, dbPath, fileCount, clientIP)
	return api.Response{Success: true, Message: "Borrado completado correctamente"}
}
func (s *server) streamFetchData(w http.ResponseWriter, req api.Request, token string, clientIP string) {
	if token == "" {
		s.log.Printf("FALLO DESCARGA: Token vacío desde %s", clientIP)
		http.Error(w, "Faltan credenciales", http.StatusUnauthorized)
		return
	}
	valid, username := s.isTokenValid(token)
	if !valid {
		s.log.Printf("FALLO DESCARGA: Token inválido desde %s", clientIP)
		http.Error(w, "Token inválido o expirado", http.StatusUnauthorized)
		return
	}

	// Busca el archivo que solicita descargar el cliente
	var fetchReq api.FetchDataRequest
	if err := json.Unmarshal(req.Body, &fetchReq); err != nil {
		s.log.Printf("FALLO DESCARGA: JSON inválido para '%s' desde %s: %v", username, clientIP, err)
		http.Error(w, "Error leyendo la petición", http.StatusBadRequest)
		return
	}

	path := strings.ReplaceAll(fetchReq.Path, "\\", "/")
	path = strings.TrimSpace(path)

	if strings.Contains(path, "..") {
		s.log.Printf("ALERTA SEGURIDAD: INTENTO PATH TRAVERSAL descarga '%s' usuario '%s' desde %s", path, username, clientIP)
		http.Error(w, "Ruta no permitida (no se admite '..')", http.StatusBadRequest)
		return
	}

	if filepath.IsAbs(path) || (len(path) >= 2 && path[1] == ':') {
		s.log.Printf("ALERTA SEGURIDAD: RUTA ABSOLUTA descarga '%s' usuario '%s' desde %s", path, username, clientIP)
		path = filepath.Base(path)
	}

	path = strings.TrimPrefix(path, "/")
	dbPath := "/" + username + "/" + path
	dbPath = strings.ReplaceAll(dbPath, "//", "/")

	// Buscar archivo en base de datos
	_, err := s.db.Get("userdata", []byte(dbPath))
	if err != nil {
		s.log.Printf("FALLO DESCARGA: Archivo no encontrado '%s' usuario '%s' desde %s", dbPath, username, clientIP)
		http.Error(w, "Archivo no encontrado o sin permisos", http.StatusNotFound)
		return
	}

	// Preparar transferencia del archivo
	physicalPath := s.basePath + dbPath
	file, err := os.Open(physicalPath)
	if err != nil {
		s.log.Printf("FALLO DESCARGA: Error abriendo archivo '%s' usuario '%s' desde %s: %v", dbPath, username, clientIP, err)
		http.Error(w, "Error interno al abrir el archivo físico", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	fileInfo, _ := file.Stat()
	s.log.Printf("ÉXITO DESCARGA: Usuario '%s' descargó '%s' (%d bytes) desde %s", username, dbPath, fileInfo.Size(), clientIP)
	w.Header().Set("Content-Type", "application/octet-stream") // Porque estamos pasando un archivo binario
	io.Copy(w, file)                                           // Pasamos poco a poco la información del archivo
}
