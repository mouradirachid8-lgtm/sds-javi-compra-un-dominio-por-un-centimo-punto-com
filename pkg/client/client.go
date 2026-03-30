// El paquete client contiene la lógica de interacción con el usuario
// así como de comunicación con el servidor.
package client

import (
	"bytes"
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
}

// Run es la única función exportada de este paquete.
// Crea un client interno y ejecuta el bucle principal.
func Run() {
	// Creamos un logger con prefijo 'cli' para identificar
	// los mensajes en la consola.
	c := &client{
		log: log.New(os.Stdout, "[cli] ", log.LstdFlags),
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
		server: "http://localhost:8080/api",
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
			// Usuario activo: Ver datos, Actualizar datos, Logout, Salir
			options = []string{
				"Ver datos",
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
				c.fetchData()
			case 2:
				c.updateData()
			case 3:
				c.deleteData()
			case 4:
				c.logoutUser()
			case 5:
				// Opción Salir
				c.log.Println("Saliendo del cliente...")
				return
			}
		}

		// Pausa para que el usuario vea resultados.
		ui.Pause("Pulsa [Enter] para continuar...")
	}
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
	body, _ := json.Marshal(api.RegisterRequest{
		Username: username,
		Password: password,
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

	body, _ := json.Marshal(api.LoginRequest{
		Username: username,
		Password: password,
	})

	res := c.sendRequest(api.Request{
		Body: body,
	}, nil, api.ActionLogin)

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

	// Si login fue exitoso, guardamos currentUser y el token.
	if res.Success {
		c.currentUser = username
		c.authToken = res.Token
		fmt.Println("Sesión iniciada con éxito. Token guardado.")
	}
}

// fetchData pide datos privados al servidor.
// El servidor devuelve la data asociada al usuario logueado.
func (c *client) fetchData() {
	ui.ClearScreen()
	fmt.Println("** Obtener datos del usuario **")

	// Chequeo básico de que haya sesión
	if c.currentUser == "" || c.authToken == "" {
		fmt.Println("No estás logueado. Inicia sesión primero.")
		return
	}

	// Hacemos la request con ActionFetchData
	res := c.sendRequest(api.Request{}, nil, api.ActionFetchData)

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)

	// Si fue exitoso, mostramos la data recibida
	if res.Success {
		fmt.Println("Tus datos:", res.Data)
	}
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
		c.log.Println("La ruta introducida es un directorio, todo el contenido se subirá y remplazara al existente, continuar (S/n)?")
		response := ui.ReadInput("")
		response = strings.ToLower(response)
		if response != "s" {
			return
		}
	}

	destBasePath := ui.ReadInput("Introduce la ruta donde quieres almacenar el fichero en el servidor (ej: /docs/miarchivo.txt)")

	// Enviamos la solicitud de actualización
	if fileStat.IsDir() {
		fmt.Println("Subiendo archivos: ")
		//Como detecto el SO?
		if !strings.HasSuffix(filePathVar, "\\") { // Añadimos \ (windows)
			filePathVar += "\\"
		}
		fmt.Println("filePathVar: ", filePathVar)
		//Imprimimos un mensaje con todo el contenido del directorio
		filepath.Walk(filePathVar, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			destpath := destBasePath + strings.TrimPrefix(path, filePathVar)
			fmt.Println(path, " - ", info.Size(), " bytes a ", destpath)
			if destpath != "" {
				res, err := c.uploadFile(path, destpath, false)
				if err != nil {
					fmt.Println("Error al subir el fichero :", err)
					fmt.Println("Continua...")
				}
				if !res.Success {
					fmt.Println("Error al subir el fichero :", res.Message)
					fmt.Println("Continua...")
				} else {
					fmt.Println("Subido archivo  con exito", path, " a ", destpath)
				}
			}
			return nil
		})
		fmt.Println("Subido directorio completo")
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
	headers := []http.Header{{"X-Force": []string{fmt.Sprintf("%v", force)}}}

	res := c.sendStreamingRequest(file, headers, api.ActionUpdateData, destPath)
	return res, nil
}

func (c *client) deleteData() {
	ui.ClearScreen()
	fmt.Println("** Borrar datos del usuario **")

	if c.currentUser == "" || c.authToken == "" {
		fmt.Println("No estás logueado. Inicia sesión primero.")
		return
	}

	targetPath := ui.ReadInput("Introduce la ruta del fichero que quieres borrar en el servidor (ej: /docs/miarchivo.txt)")

	body, _ := json.Marshal(api.DeleteDataRequest{
		Path: targetPath,
	})

	res := c.sendRequest(api.Request{
		Body: body,
	}, nil, api.ActionDeleteData)

	fmt.Println("Éxito:", res.Success)
	fmt.Println("Mensaje:", res.Message)
}