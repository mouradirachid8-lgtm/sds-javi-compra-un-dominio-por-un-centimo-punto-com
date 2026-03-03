// El paquete ui proporciona un conjunto de funciones sencillas
// para la interacción con el usuario mediante terminal
package ui

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/term"
)

// reader es el único lector global sobre stdin.
// Usar un único bufio.Reader evita comportamientos inesperados al mezclar Scan/Scanln
// con otras lecturas, especialmente en Windows.
var reader = bufio.NewReader(os.Stdin)

// readLine lee una línea completa (incluyendo espacios) y elimina el salto final.
func readLine() (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		// Si no hay \n pero sí datos, los devolvemos igualmente.
		if err == io.EOF && len(line) > 0 {
			return strings.TrimSpace(line), nil
		}
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// PrintMenu muestra un menú y solicita al usuario que seleccione una opción.
func PrintMenu(title string, options []string) int {
	fmt.Print(title, "\n\n")
	for i, option := range options {
		fmt.Printf("%d. %s\n", i+1, option)
	}
	for {
		fmt.Print("\nSelecciona una opción: ")
		line, err := readLine()
		if err == nil {
			choice, convErr := strconv.Atoi(strings.TrimSpace(line))
			if convErr == nil && choice >= 1 && choice <= len(options) {
				return choice
			}
		}
		fmt.Println("Opción no válida, inténtalo de nuevo.")
	}
}

// ReadInput solicita un texto al usuario y lo devuelve como string.
func ReadInput(prompt string) string {
	fmt.Print(prompt + ": ")
	line, err := readLine()
	if err != nil {
		return ""
	}
	return line
}

// ReadPassword muestra un mensaje y lee una contraseña sin mostrarla en la terminal.
func ReadPassword(prompt string) (string, error) {
	fmt.Print(prompt + ": ")

	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println() // Para evitar que el siguiente mensaje se imprima en la misma línea
	return string(bytePassword), err
}

// Confirm solicita una confirmación Sí/No al usuario.
func Confirm(message string) bool {
	for {
		fmt.Print(message + " (S/N): ")
		line, err := readLine()
		if err != nil {
			fmt.Println("Error leyendo entrada.")
			return false
		}
		response := strings.ToUpper(strings.TrimSpace(line))

		switch response {
		case "S":
			return true
		case "N":
			return false
		default:
			fmt.Println("Respuesta no válida, introduce S o N.")
		}
	}
}

// ClearScreen limpia la pantalla de la terminal.
func ClearScreen() {
	// Solución simple y multiplataforma.
	// - En macOS/Linux, ANSI suele funcionar.
	// - En Windows, usamos 'cls' para evitar problemas en consolas antiguas.
	if runtime.GOOS == "windows" {
		cmd := exec.Command("cmd", "/c", "cls")
		cmd.Stdout = os.Stdout
		_ = cmd.Run()
		return
	}
	fmt.Print("\033[H\033[2J")
}

// Pause muestra un mensaje y espera a que el usuario presione Enter.
func Pause(prompt string) {
	fmt.Println(prompt)
	_, _ = readLine()
}

// ReadInt solicita al usuario un entero y valida la entrada.
func ReadInt(prompt string) int {
	for {
		fmt.Print(prompt + ": ")
		line, err := readLine()
		if err == nil {
			value, convErr := strconv.Atoi(strings.TrimSpace(line))
			if convErr == nil {
				return value
			}
		}
		fmt.Println("Valor no válido, introduce un número entero.")
	}
}

// ReadFloat solicita al usuario un número real y valida la entrada.
func ReadFloat(prompt string) float64 {
	for {
		fmt.Print(prompt + ": ")
		line, err := readLine()
		if err == nil {
			value, convErr := strconv.ParseFloat(strings.TrimSpace(line), 64)
			if convErr == nil {
				return value
			}
		}
		fmt.Println("Valor no válido, introduce un número real.")
	}
}

// ReadMultiline lee varias líneas hasta que el usuario introduzca línea vacía.
func ReadMultiline(prompt string) string {
	fmt.Println(prompt + " (deja una línea en blanco para terminar):")
	var lines []string
	for {
		line, err := readLine()
		if err != nil {
			break
		}
		if line == "" {
			break
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

// PrintProgressBar muestra una barra de progreso en la terminal.
func PrintProgressBar(progress, total int, width int) {
	percent := float64(progress) / float64(total) * 100.0
	filled := int(float64(width) * (float64(progress) / float64(total)))
	bar := strings.Repeat("#", filled) + strings.Repeat("-", width-filled)
	fmt.Printf("\r[%s] %.2f%%", bar, percent)
	if progress == total {
		fmt.Println()
	}
}
