package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

/*
Argon2id está pensado para almacenamiento seguro de contraseñas.
En lugar de guardar la contraseña original, se guarda una sal aleatoria
junto con el hash derivado.

Este ejemplo usa parámetros pequeños para que la demo sea rápida,
pero suficientes para ilustrar el proceso.
*/
const (
	argonTime    uint32 = 1
	argonMemory  uint32 = 64 * 1024
	argonThreads uint8  = 4
	argonKeyLen  uint32 = 32
	saltLen             = 16
	size         int    = 32
)

/*
DummyHash es un hash Argon2id ficticio con los mismos parámetros que usa
HashPassword. Se pasa a VerifyPassword cuando el usuario no existe para que
el tiempo de respuesta sea similar al de un usuario válido con contraseña
incorrecta, evitando así un timing oracle de enumeración de usuarios.
*/
const DummyHash = "argon2id$AAAAAAAAAAAAAAAAAAAAAA$FZ0Ztb19yPBpiSv0AvbnELtsZdrZT8ciUZn/DhZW2o0"

/*
HashPassword devuelve el hash en el formato simplificado "argon2id$sal$hash".
*/
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("no se pudo generar la sal: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	return fmt.Sprintf("argon2id$%s$%s",
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

func VerifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 3 || parts[0] != "argon2id" {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}

	expected, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}

	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, uint32(len(expected)))

	return subtle.ConstantTimeCompare(hash, expected) == 1
}

/*
Para generar tokens aleatorios
*/
func NewRandomToken() (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("no se pudo generar un token aleatorio: %w", err)
	}
	// Se codifica en hexadecimal solo para poder imprimir y transportar el token
	// fácilmente en la demo sin perder aleatoriedad.
	return hex.EncodeToString(buf), nil
}
