package client

import (
	"fmt"
	"os"
	"sprout/pkg/ui"
	"strings"
	"time"
)

type tui struct {
	Client *Client
}

// RunTUI maneja la lógica del menú principal.
// Se muestran distintas opciones en función de si hay un usuario con sesión activa
func RunTUI(client *Client) {
	t := &tui{Client: client}

	for {
		ui.ClearScreen()

		// Construimos un título que muestre el usuario activo, si lo hubiera.
		var title string
		if t.Client.currentUser == "" {
			title = "Menú"
		} else {
			title = fmt.Sprintf("Menú (%s)", t.Client.currentUser)
		}

		// Generamos las opciones dinámicamente, según si hay un login activo.
		var options []string
		if t.Client.currentUser == "" {
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
		if t.Client.currentUser == "" {
			// Caso NO logueado
			switch choice {
			case 1:
				t.registerUser()
			case 2:
				t.loginUser()
			case 3:
				// Opción Salir
				t.Client.log.Println("Saliendo del cliente...")
				return
			}
		} else {
			// Caso logueado
			switch choice {
			case 1:
				t.lookupUI()
			case 2:
				t.fetchDataUI()
			case 3:
				t.updateDataUI()
			case 4:
				t.deleteDataUI()
			case 5:
				t.logoutUserUI()
			case 6:
				// Opción Salir
				t.Client.log.Println("Saliendo del cliente...")
				return
			}
		}

		// Pausa para que el usuario vea resultados.
		ui.Pause("Pulsa [Enter] para continuar...")
	}
}

// loginUser pide credenciales y realiza un login en el servidor.
func (t *tui) loginUser() {
	ui.ClearScreen()
	fmt.Println("** Inicio de sesión **")

	username := ui.ReadInput("Nombre de usuario")
	password, err := ui.ReadPassword("Contraseña")

	if err != nil {
		t.Client.log.Println("No se ha podido obtener la contraseña, inicio de sesión cancelado: ", err)
		return
	}

	err = t.Client.Login(username, password)
	if err != nil {
		t.Client.log.Println("Error durante el login:", err)
	}
}

// registerUser pide credenciales y las envía al servidor para un registro.
// Si el registro es exitoso, se intenta el login automático.
func (t *tui) registerUser() {
	ui.ClearScreen()
	fmt.Println("** Registro de usuario **")

	username := ui.ReadInput("Nombre de usuario")
	password, err := ui.ReadPassword("Contraseña")

	if err != nil {
		t.Client.log.Println("No se ha podido obtener la contraseña, registro cancelado: ", err)
		return
	}

	err = t.Client.Register(username, password)
	if err != nil {
		t.Client.log.Println("Error durante el registro:", err)
		return
	}

	fmt.Println("Registro exitoso. Intentando iniciar sesión automáticamente...")
	err = t.Client.Login(username, password)
	if err != nil {
		t.Client.log.Println("Error durante el login automático:", err)
	}
}

// lookup pide un listado de los archivos de un directorio.
// El servidor devuelve el listado asociado al usuario logueado.
func (t *tui) lookupUI() {
	ui.ClearScreen()
	fmt.Println("** Listar archivos del servidor **")

	if t.Client.currentUser == "" || t.Client.authToken == "" {
		fmt.Println("No estás logueado. Inicia sesión primero.")
		return
	}

	remotePath := ui.ReadInput("Ruta del directorio en el servidor (ej: dir/docs/)")
	recursive := ui.ReadInput("¿Quieres que se muestren los archivos de forma recursiva? (s/n)")
	isRecursive := strings.ToLower(strings.TrimSpace(recursive)) == "s"

	files, err := t.Client.Lookup(remotePath, isRecursive)
	if err != nil {
		fmt.Println("Error al obtener el listado de archivos:", err)
		return
	}

	fmt.Println("Archivos:")
	for _, f := range files {
		if f.IsDirectory {
			fmt.Printf("- %s (directorio)\n", f.Name)
		} else {
			fmt.Printf("- %s (%d bytes, modificado: %s, permisos: %s)\n", f.Name, f.Size, f.Modified.Format("2006-01-02 15:04:05"), f.Permissions)
		}
	}
}

// fetchData pide datos privados al servidor.
// El servidor devuelve la data asociada al usuario logueado.
func (t *tui) fetchDataUI() {
	ui.ClearScreen()
	fmt.Println("** Descargar archivo del servidor **")

	if t.Client.currentUser == "" || t.Client.authToken == "" {
		fmt.Println("No estás logueado. Inicia sesión primero.")
		return
	}

	remotePath := ui.ReadInput("Ruta del archivo en el servidor (ej: archivo.txt)")
	localPath := ui.ReadInput("Dónde guardarlo en tu PC (ej: ./descargado.txt)")

	err := t.Client.FetchData(remotePath, localPath)
	if err != nil {
		fmt.Println("Error al descargar el archivo:", err)
	} else {
		fmt.Println("Archivo descargado correctamente y guardado en:", localPath)
	}
}

// updateData pide nuevo texto y lo envía al servidor con ActionUpdateData.
func (t *tui) updateDataUI() {
	ui.ClearScreen()
	fmt.Println("** Actualizar datos del usuario **")

	if t.Client.currentUser == "" || t.Client.authToken == "" {
		fmt.Println("No estás logueado. Inicia sesión primero.")
		return
	}

	// Leemos la nueva Data
	filePathVar := ui.ReadInput("Introduce el fichero que desees almacenar")

	fileStat, err := os.Stat(filePathVar)
	if err != nil {
		t.Client.log.Println("No se ha podido acceder al fichero:", err)
		return
	}
	recursive := false
	if fileStat.IsDir() { // De momento solo se permiten ficheros
		fmt.Println("La ruta introducida es un directorio, todo el contenido se subirá y reemplazará al existente, continuar (S/n)?")
		response := ui.ReadInput("")
		response = strings.ToLower(response)
		if response != "s" {
			return
		}
		recursive = true
	}

	destBasePath := ui.ReadInput("Introduce la ruta donde quieres almacenar el fichero en el servidor (ej: /docs/miarchivo.txt)")

	startTime := time.Now()
	count, total, err := t.Client.UploadData(filePathVar, destBasePath, recursive, false)
	if err != nil {
		endTime := time.Now()
		duration := endTime.Sub(startTime)
		fmt.Printf("Tiempo transcurrido: %s\n", duration)
		t.Client.log.Println("Error al subir el fichero:", err)
		//Si ya existe el archivo, preguntamos si se quiere actualizar
		if strings.Contains(err.Error(), "archivo ya existe") {
			response := ui.ReadInput("Desea actualizar el archivo (S/n)")
			response = strings.ToLower(response)
			if response == "s" {
				count, total, err = t.Client.UploadData(filePathVar, destBasePath, recursive, true)
				if err != nil {
					t.Client.log.Println("Error al subir el fichero", filePathVar, " :", err)
					return
				}
			} else {
				fmt.Println("Subida cancelada por el usuario.")
				return
			}
		} else {
			endTime := time.Now()
			duration := endTime.Sub(startTime)
			fmt.Printf("Tiempo transcurrido: %s\n", duration)
			return
		}
	}
	endTime := time.Now()
	duration := endTime.Sub(startTime)
	fmt.Printf("Tiempo transcurrido: %s\n", duration)
	fmt.Printf("Se han subido %d archivos de un total de %d.\n", count, total)
}

// logoutUser llama a la acción logout en el servidor, y si es exitosa,
// borra la sesión local (currentUser/authToken).
func (t *tui) logoutUserUI() {
	ui.ClearScreen()
	fmt.Println("** Cerrar sesión **")

	if t.Client.currentUser == "" || t.Client.authToken == "" {
		fmt.Println("No estás logueado.")
		return
	}

	// Llamamos al servidor con la acción ActionLogout
	err := t.Client.LogoutUser()
	if err != nil {
		fmt.Println("Error al cerrar sesión:", err)
		return
	}

}

func (t *tui) deleteDataUI() {
	ui.ClearScreen()
	fmt.Println("** Borrar datos del usuario **")

	if t.Client.currentUser == "" || t.Client.authToken == "" {
		fmt.Println("No estás logueado. Inicia sesión primero.")
		return
	}

	targetPath := ui.ReadInput("Introduce la ruta del fichero o carpeta que quieres borrar (ej: /docs/miarchivo.txt o /docs)")

	err := t.Client.DeleteData(targetPath)
	if err != nil {
		fmt.Println("Error al borrar los datos:", err)
		return
	}

	fmt.Println("Datos borrados correctamente.")
}
