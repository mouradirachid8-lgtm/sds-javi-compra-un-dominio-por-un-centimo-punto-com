// El paquete server contiene el código del servidor.
// Interactúa con el cliente mediante una API JSON/HTTP
package server

import (
	"crypto/rand"
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
	"sprout/pkg/store"
	"strconv"
	"strings"
	"time"
)

// server encapsula el estado de nuestro servidor
type server struct {
	db       store.Store // base de datos
	log      *log.Logger // logger para mensajes de error e información
	basePath string      // ruta base para almacenar archivos (opcional)
}

var INT64_MAX = big.NewInt(0).SetInt64(1<<63 - 1)

const maxUploadSize = 1000 << 20 // 1000 MiB por defecto

// Run inicia la base de datos y arranca el servidor HTTP.
func Run() error {

	// Crear la carpeta 'data' en caso de que no exista.
	if err := os.MkdirAll("data", 0755); err != nil {
		return fmt.Errorf("error creando la carpeta 'data': %w", err)
	}

	// Abrimos la base de datos usando el motor bbolt
	db, err := store.NewStore("bbolt", "data/server.db")
	if err != nil {
		return fmt.Errorf("error abriendo base de datos: %v", err)
	}

	// Creamos nuestro servidor con su logger con prefijo 'srv'
	srv := &server{
		db:       db,
		log:      log.New(os.Stdout, "[srv] ", log.LstdFlags),
		basePath: "data/files", // carpeta para almacenar archivos (opcional)
	}

	// Al terminar, cerramos la base de datos
	defer srv.db.Close()

	// Construimos un mux y asociamos /api a nuestro apiHandler,
	mux := http.NewServeMux()
	mux.Handle("/api", http.HandlerFunc(srv.apiHandler))

	// Iniciamos el servidor HTTP.
	httpSrv := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return httpSrv.ListenAndServe()
}

// apiHandler decodifica la solicitud JSON, la despacha
// a la función correspondiente y devuelve la respuesta JSON.
func (s *server) apiHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Método no permitido", http.StatusMethodNotAllowed)
		return
	}
	actionHeader := r.Header.Get("X-Action")
	if actionHeader == "" {
		http.Error(w, "Falta la cabecera X-Action", http.StatusBadRequest)
		return
	}
	if !api.IsValidAction(actionHeader) {
		http.Error(w, "Acción no válida", http.StatusBadRequest)
		return
	}
	ContentType := r.Header.Get("Content-Type")
	if ContentType == "" {
		http.Error(w, "Falta la cabecera Content-Type", http.StatusBadRequest)
		return
	}
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		s.jsonHandler(w, r)
		return
	} else if strings.HasPrefix(r.Header.Get("Content-Type"), "application/octet-stream") {
		s.fileHandler(w, r)
		return
	} else {
		http.Error(w, "Content-Type no soportado", http.StatusUnsupportedMediaType)
		return
	}
}

func (s *server) jsonHandler(w http.ResponseWriter, r *http.Request) {
	// Limitamos el tamaño del body para evitar sorpresas.
	// (No es una medida de seguridad "de verdad"; sólo robustez.)
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MiB

	// Decodificamos la solicitud en una estructura api.Request
	var req api.Request
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "Error en el formato JSON", http.StatusBadRequest)
		return
	}
	// Evitamos que se envíen múltiples objetos JSON concatenados.
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		http.Error(w, "Error en el formato JSON", http.StatusBadRequest)
		return
	}
	action := r.Header.Get("X-Action")
	token := r.Header.Get("X-Token")
	// Despacho según la acción solicitada
	var res api.Response
	switch action {
	case api.ActionRegister:
		res = s.registerUser(req)
	case api.ActionLogin:
		res = s.loginUser(req)
	case api.ActionFetchData:
		s.streamFetchData(w, req, token)
		return
	case api.ActionDeleteData:
		res = s.deleteData(req, token)
	case api.ActionLogout:
		res = s.logoutUser(req, token)
	default:
		res = api.Response{Success: false, Message: "Acción desconocida"}
	}

	// Enviamos la respuesta en formato JSON
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

func (s *server) fileHandler(w http.ResponseWriter, r *http.Request) {
	// Limitar el tamaño del body usando el ResponseWriter para que
	// http.MaxBytesReader pueda escribir el error en caso de exceder.
	if r.ContentLength > 0 && r.ContentLength > maxUploadSize {
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
		res = s.updateData(r.Body, token, r.Header.Get("X-Path"), r.Header.Get("X-Force") == "true")
	default:
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
func (s *server) registerUser(req api.Request) api.Response {
	var regReq api.RegisterRequest
	if err := json.Unmarshal(req.Body, &regReq); err != nil {
		return api.Response{Success: false, Message: "Error al procesar la solicitud"}
	}

	// Validación básica
	if regReq.Username == "" || regReq.Password == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}

	// Verificamos si ya existe el usuario en 'auth'
	exists, err := s.userExists(regReq.Username)
	if err != nil {
		return api.Response{Success: false, Message: "Error al verificar usuario"}
	}
	if exists {
		return api.Response{Success: false, Message: "El usuario ya existe"}
	}

	// Almacenamos la contraseña en el namespace 'auth' (clave=nombre, valor=contraseña)
	if err := s.db.Put("auth", []byte(regReq.Username), []byte(regReq.Password)); err != nil {
		return api.Response{Success: false, Message: "Error al guardar credenciales"}
	}

	// Creamos una entrada vacía para los datos en 'userdata'
	if err := s.db.Put("userdata", []byte(regReq.Username), []byte("")); err != nil {
		return api.Response{Success: false, Message: "Error al inicializar datos de usuario"}
	}

	return api.Response{Success: true, Message: "Usuario registrado"}
}

// loginUser valida credenciales en el namespace 'auth' y genera un token en 'sessions'.
func (s *server) loginUser(req api.Request) api.Response {
	var loginReq api.LoginRequest
	if err := json.Unmarshal(req.Body, &loginReq); err != nil {
		return api.Response{Success: false, Message: "Error al procesar la solicitud"}
	}

	if loginReq.Username == "" || loginReq.Password == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}

	// Recogemos la contraseña guardada en 'auth'
	storedPass, err := s.db.Get("auth", []byte(loginReq.Username))
	if err != nil {
		return api.Response{Success: false, Message: "Usuario no encontrado"}
	}

	// Comparamos
	if string(storedPass) != loginReq.Password {
		return api.Response{Success: false, Message: "Credenciales inválidas"}
	}

	// Generamos un nuevo token, lo guardamos en 'sessions'
	token := s.generateToken(loginReq.Username)
	if err := s.db.Put("sessions", []byte(token), []byte(loginReq.Username)); err != nil {
		return api.Response{Success: false, Message: "Error al crear sesión"}
	}

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
func (s *server) updateData(body io.ReadCloser, token string, path string, force bool) api.Response {
	// Chequeo de credenciales
	if token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	valid, username := s.isTokenValid(token)
	if !valid {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	if err := s.saveFile(body, username, force, path); err != nil {
		return api.Response{Success: false, Message: "Error al guardar datos: " + err.Error()}
	}

	return api.Response{Success: true, Message: "Datos de usuario actualizados"}
}

// logoutUser borra la sesión en 'sessions', invalidando el token.
func (s *server) logoutUser(req api.Request, token string) api.Response {
	// Chequeo de credenciales
	if token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	valid, _ := s.isTokenValid(token)
	if !valid {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	// Borramos la entrada en 'sessions'
	if err := s.db.Delete("sessions", []byte(token)); err != nil {
		return api.Response{Success: false, Message: "Error al cerrar sesión"}
	}

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

func (s *server) saveFile(body io.ReadCloser, username string, force bool, path string) error {
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
		return fmt.Errorf("archivo ya existe")
	}

	if data != nil {
		var existingFile api.File
		if err := json.Unmarshal(data, &existingFile); err != nil {
			return fmt.Errorf("error al procesar datos existentes: %w", err)
		}
		creationTime = existingFile.Created.Unix()
	}

	s.log.Printf("Guardando archivo para usuario '%s' en path '%s'", username, path)
	if err := os.MkdirAll(filepath.Dir(s.basePath+path), 0755); err != nil {
		return fmt.Errorf("error al crear directorios: %w", err)
	}
	file, err := os.Create(s.basePath + path) // Creamos el fichero en el sistema de archivos
	if err != nil {
		return fmt.Errorf("error al crear archivo: %w", err)
	}
	defer file.Close()
	_, err = io.Copy(file, body) // Copiamos el contenido del body al fichero
	if err != nil {
		return fmt.Errorf("error al copiar datos: %w", err)
	}
	stats, err := file.Stat()
	if err != nil {
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
		return fmt.Errorf("error al serializar metadatos: %w", err)
	}

	if err := s.db.Put("userdata", []byte(path), fileBytes); err != nil {
		return fmt.Errorf("error al guardar archivo: %w", err)
	}

	return nil
}

func (s *server) deleteData(req api.Request, token string) api.Response {
	// 1. Chequeo de credenciales
	if token == "" {
		return api.Response{Success: false, Message: "Faltan credenciales"}
	}
	valid, username := s.isTokenValid(token)
	if !valid {
		return api.Response{Success: false, Message: "Token inválido o sesión expirada"}
	}

	var delReq api.DeleteDataRequest
	if err := json.Unmarshal(req.Body, &delReq); err != nil {
		return api.Response{Success: false, Message: "Error al procesar la solicitud"}
	}

	// 2. Saneamiento de la ruta (Seguridad)
	target := strings.ReplaceAll(delReq.Path, "\\", "/")
	target = strings.TrimSpace(target)

	// Prevenir Path Traversal (evitar que suban niveles fuera de su carpeta)
	if strings.Contains(target, "..") {
		return api.Response{Success: false, Message: "No se admite '..' en la ruta"}
	}

	if filepath.IsAbs(target) || (len(target) >= 2 && target[1] == ':') {
		target = filepath.Base(target)
	}

	// copidoa de saveFile
	target = strings.TrimPrefix(target, "/")
	dbPath := "/" + username + "/" + target
	dbPath = strings.ReplaceAll(dbPath, "//", "/")

	// Seguridad: Evitar que el usuario borre su carpeta raíz completa
	if dbPath == "/"+username || dbPath == "/"+username+"/" {
		return api.Response{Success: false, Message: "No tienes permiso para borrar tu directorio raíz completo"}
	}

	fullSystemPath := s.basePath + dbPath

	// Comprobar si existe
	stat, err := os.Stat(fullSystemPath)
	if err != nil {
		if os.IsNotExist(err) {
			return api.Response{Success: false, Message: "El archivo o carpeta no existe"}
		}
		return api.Response{Success: false, Message: "Error al acceder a la ruta"}
	}

	// Recopilar las rutas para limpiar la base de datos
	pathsToDelete := []string{dbPath}

	if stat.IsDir() {
		// Si es carpeta, buscamos todos los archivos de dentro para limpiarlos de la BD
		filepath.Walk(fullSystemPath, func(fsPath string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
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
		s.log.Printf("Error al borrar físico %s: %v", fullSystemPath, err)
		return api.Response{Success: false, Message: "Error interno al borrar en el disco"}
	}

	// Borramos los registros de la db
	for _, p := range pathsToDelete {
		_ = s.db.Delete("userdata", []byte(p))
	}

	s.log.Printf("Borrado completado para usuario '%s' en path '%s' (Es dir: %v)", username, dbPath, stat.IsDir())
	return api.Response{Success: true, Message: "Borrado completado correctamente"}
}
func (s *server) streamFetchData(w http.ResponseWriter, req api.Request, token string) {
	if token == "" {
		http.Error(w, "Faltan credenciales", http.StatusUnauthorized)
		return
	}
	valid, username := s.isTokenValid(token)
	if !valid {
		http.Error(w, "Token inválido o expirado", http.StatusUnauthorized)
		return
	}

	// Busca el archivo que solicita descargar el cliente
	var fetchReq api.FetchDataRequest
	if err := json.Unmarshal(req.Body, &fetchReq); err != nil {
		http.Error(w, "Error leyendo la petición", http.StatusBadRequest)
		return
	}

	path := strings.ReplaceAll(fetchReq.Path, "\\", "/")
	path = strings.TrimSpace(path)

	if strings.Contains(path, "..") {
		http.Error(w, "Ruta no permitida (no se admite '..')", http.StatusBadRequest)
		return
	}

	if filepath.IsAbs(path) || (len(path) >= 2 && path[1] == ':') {
		path = filepath.Base(path)
	}

	path = strings.TrimPrefix(path, "/")
	dbPath := "/" + username + "/" + path
	dbPath = strings.ReplaceAll(dbPath, "//", "/")

	// Buscar archivo en base de datos
	_, err := s.db.Get("userdata", []byte(dbPath))
	if err != nil {
		http.Error(w, "Archivo no encontrado o sin permisos", http.StatusNotFound)
		return
	}

	// Preparar transferencia del archivo
	physicalPath := s.basePath + dbPath
	file, err := os.Open(physicalPath)
	if err != nil {
		http.Error(w, "Error interno al abrir el archivo físico", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	w.Header().Set("Content-Type", "application/octet-stream") // Porque estamos pasando un archivo binario
	io.Copy(w, file)                                           // Pasamos poco a poco la información del archivo
}
