// El paquete store provee una interfaz genérica de almacenamiento.
// Cada motor (en nuestro caso bbolt) se implementa en un archivo separado
// que debe cumplir la interfaz Store.
package store

import (
	"errors"
	"fmt"
)

// Store define los métodos comunes que deben implementar
// los diferentes motores de almacenamiento.
type Store interface {
	// Put almacena (o actualiza) el valor 'value' bajo la clave 'key'
	// dentro del 'namespace' indicado.
	Put(namespace string, key, value []byte) error

	// Get recupera el valor asociado a la clave 'key'
	// dentro del 'namespace' especificado.
	Get(namespace string, key []byte) ([]byte, error)

	// Delete elimina la clave 'key' dentro del 'namespace' especificado.
	Delete(namespace string, key []byte) error

	// ListKeys devuelve todas las claves existentes en el namespace.
	ListKeys(namespace string) ([][]byte, error)

	// KeysByPrefix devuelve las claves que empiecen con 'prefix' dentro
	// del namespace especificado.
	KeysByPrefix(namespace string, prefix []byte) ([][]byte, error)

	// Close cierra cualquier recurso abierto (por ej. cerrar la base de datos).
	Close() error

	// Dump imprime todo el contenido de la base de datos para depuración de errores.
	Dump() error
}

// NewStore permite instanciar diferentes tipos de Store
// dependiendo del motor solicitado (sólo se soporta "bbolt").
func NewStore(engine, path string) (Store, error) {
	switch engine {
	case "bbolt":
		return NewBboltStore(path)
	default:
		return nil, fmt.Errorf("motor de almacenamiento desconocido: %s", engine)
	}
}

// Errores centinela para poder distinguir fallos típicos sin depender de strings.
//
// Nota: esto NO pretende ser un sistema de errores completo; es lo mínimo para
// que el servidor pueda decidir si algo "no existe" o si es un error real.
var (
	ErrNamespaceNotFound = errors.New("namespace no encontrado")
	ErrKeyNotFound       = errors.New("clave no encontrada")
)
