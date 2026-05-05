package filemap

// Mapa de archivos para el cliente, con la ruta del archivo en el servidor, su hash, sus metadatos y una clave
// El cliente mantiene este mapa en memoria y lo sube encriptado al servidor cada vez que realiza un cambio
// File map no encripta unicamente permite guardar la clave

import (
	"bytes"
	"encoding/json"
	"io"
	"sprout/pkg/api"
)

// FileMeta contiene la ruta del archivo en el servidor y su hash (para verificar integridad)
type FileMeta struct {
	Hash     string   `json:"hash"`     // Hash del archivo para verificar integridad
	Metadata api.File `json:"metadata"` // Metadatos del archivo (nombre, fecha de modificación, etc.)
	Key      string   `json:"key"`
}

type FileMap struct {
	Files map[string]FileMeta `json:"files"` // Mapa de archivos, con la ruta del server como clave
}

// NewFileMap crea un nuevo FileMap con la clave dada y un mapa vacío de archivos
func NewFileMap() *FileMap {
	return &FileMap{
		Files: make(map[string]FileMeta),
	}
}

// AddFile añade un nuevo archivo al mapa, con su ruta en el servidor, hash y metadatos
func (fm *FileMap) AddFile(serverPath, hash string, metadata api.File, key string) {
	fm.Files[serverPath] = FileMeta{
		Hash:     hash,
		Metadata: metadata,
		Key:      key,
	}
}

// FileExists verifica si un archivo existe en el mapa por su ruta en el servidor
func (fm *FileMap) FileExists(serverPath string) bool {
	_, exists := fm.Files[serverPath]
	return exists
}

// RemoveFile elimina un archivo del mapa por su ruta en el servidor
func (fm *FileMap) RemoveFile(serverPath string) {
	delete(fm.Files, serverPath)
}

// GetFileMeta devuelve los metadatos de un archivo por su ruta en el servidor, o nil si no existe
func (fm *FileMap) GetFileMeta(serverPath string) *FileMeta {
	if meta, ok := fm.Files[serverPath]; ok {
		return &meta
	}
	return nil
}

// ListFiles devuelve una lista de las rutas de los archivos en el mapa
func (fm *FileMap) ListFiles() []string {
	paths := make([]string, 0, len(fm.Files))
	for path := range fm.Files {
		paths = append(paths, path)
	}
	return paths
}

// FilterFiles devuelve una lista de las rutas de los archivos que cumplen la función de filtro dada
func (fm *FileMap) FilterFiles(filter func(FileMeta) bool) []string {
	paths := make([]string, 0)
	for path, meta := range fm.Files {
		if filter(meta) {
			paths = append(paths, path)
		}
	}
	return paths
}

// UpdateFile actualiza los datos de un archivo en el mapa por su ruta en el servidor
func (fm *FileMap) UpdateFile(serverPath, hash string, metadata api.File, key string) {
	if _, ok := fm.Files[serverPath]; ok {
		fm.Files[serverPath] = FileMeta{
			Hash:     hash,
			Metadata: metadata,
			Key:      key,
		}
	}
}

// SaveFileMap retorna una io.reader con el contenido del FileMap en formato JSON, para subirlo al servidor
func (fm *FileMap) SaveFileMap() (io.Reader, error) {
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(fm); err != nil {
		return nil, err
	}
	return &buf, nil
}

// LoadFileMap carga un FileMap desde un io.Reader con el contenido en formato JSON, para descargarlo del servidor
func LoadFileMap(r io.Reader) (*FileMap, error) {
	var fm FileMap
	if err := json.NewDecoder(r).Decode(&fm); err != nil {
		return nil, err
	}
	return &fm, nil
}
