package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sprout/pkg/api"
	"sprout/pkg/ui"
	"strings"
	"time"
)

type TUI struct {
	client *client.Client
}

// runLoop maneja la lógica del menú principal.
// Se muestran distintas opciones en función de si hay un usuario con sesión activa
func (t *TUI) runLoop() {
	for {
		ui.ClearScreen()

		// Construimos un título que muestre el usuario activo, si lo hubiera.
		var title string
		if t.client.currentUser == "" {
			title = "Menú"
		} else {
			title = fmt.Sprintf("Menú (%s)", t.client.currentUser)
		}

		// Generamos las opciones dinámicamente, según si hay un login activo.
		var options []string
		if t.client.currentUser == "" {
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
		if t.client.currentUser == "" {
			// Caso NO logueado
			switch choice {
			case 1:
				t.registerUser()
			case 2:
				t.loginUser()
			case 3:
				// Opción Salir
				t.client.log.Println("Saliendo del cliente...")
				return
			}
		} else {
			// Caso logueado
			switch choice {
			case 1:
				t.lookupUI()
			case 2:
				t.fetchData()
			case 3:
				t.updateData()
			case 4:
				t.deleteData()
			case 5:
				t.logoutUser()
			case 6:
				// Opción Salir
				t.client.log.Println("Saliendo del cliente...")
				return
			}
		}

		// Pausa para que el usuario vea resultados.
		ui.Pause("Pulsa [Enter] para continuar...")
	}
}

// loginUser pide credenciales y realiza un login en el servidor.
func (t *TUI) loginUser() {
	ui.ClearScreen()
	fmt.Println("** Inicio de sesión **")

	username := ui.ReadInput("Nombre de usuario")
	password, err := ui.ReadPassword("Contraseña")

	if err != nil {
		t.client.log.Println("No se ha podido obtener la contraseña, registro cancelado: ", err)
		return
	}

	err = t.client.login(username, password)
	if err != nil {
		t.client.log.Println("Error durante el login:", err)
	}
}

// registerUser pide credenciales y las envía al servidor para un registro.
// Si el registro es exitoso, se intenta el login automático.
func (t *TUI) registerUser() {
	ui.ClearScreen()
	fmt.Println("** Registro de usuario **")

	username := ui.ReadInput("Nombre de usuario")
	password, err := ui.ReadPassword("Contraseña")

	if err != nil {
		t.client.log.Println("No se ha podido obtener la contraseña, registro cancelado: ", err)
		return
	}

	err = t.client.register(username, password)
	if err != nil {
		t.client.log.Println("Error durante el registro:", err)
		return
	}

	fmt.Println("Registro exitoso. Intentando iniciar sesión automáticamente...")
	err = t.client.login(username, password)
	if err != nil {
		t.client.log.Println("Error durante el login automático:", err)
	}
}

// lookup pide un listado de los archivos de un directorio.
// El servidor devuelve el listado asociado al usuario logueado.
func (t *TUI) lookupUI() {
	ui.ClearScreen()
	fmt.Println("** Listar archivos del servidor **")

	if t.client.currentUser == "" || t.client.authToken == "" {
		fmt.Println("No estás logueado. Inicia sesión primero.")
		return
	}

	remotePath := ui.ReadInput("Ruta del directorio en el servidor (ej: dir/docs/)")
	recursive := ui.ReadInput("¿Quieres que se muestren los archivos de forma recursiva? (s/n)")

	files, err := t.client.lookup(remotePath, recursive == "s")
	if err != nil {
		fmt.Println("Error al obtener el listado de archivos:", err)
		return
	}

	fmt.Println("Archivos:")
	for _, f := range files {
		if f.IsDirectory {
			fmt.Printf("- %s (directorio)\n", f.Name)
		} else {
			fmt.Printf("- %s (%d bytes, modificado: %s)\n", f.Name, f.Size, f.Modified.Format("2006-01-02 15:04:05"))
		}
	}
}

// fetchData pide datos privados al servidor.
// El servidor devuelve la data asociada al usuario logueado.
func (t *TUI) fetchDataUI() {
	ui.ClearScreen()
	fmt.Println("** Descargar archivo del servidor **")

	if t.client.currentUser == "" || t.client.authToken == "" {
		fmt.Println("No estás logueado. Inicia sesión primero.")
		return
	}

	remotePath := ui.ReadInput("Ruta del archivo en el servidor (ej: archivo.txt)")
	localPath := ui.ReadInput("Dónde guardarlo en tu PC (ej: ./descargado.txt)")

	err := t.client.fetchData(remotePath, localPath)
	if err != nil {
		fmt.Println("Error al descargar el archivo:", err)
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
