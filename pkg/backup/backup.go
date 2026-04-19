package backup

import (
	"fmt"
	"os"
	"path/filepath"
	"sprout/pkg/client"
	"strings"
	"time"
)

// Usa server de sprout como servidor de backup

type backupClient struct {
	token      string
	backupPath string
	client     *client.Client
}

// El username y token(password) se usan para autentica en el servidor de backups
func NewBackupClient(username, token, srvAddr string, certPerm []byte) *backupClient {
	if token == "" || srvAddr == "" {
		return nil
	}
	client := client.NewClient(srvAddr, certPerm)
	// Ya se hara mas seguro en el futuro
	client.Login(username, token)

	return &backupClient{
		token:      token,
		client:     client,
		backupPath: "backups",
	}
}

func (c *backupClient) setToken(token string) { //Por si queremos cambiar el token después de crear el cliente
	c.token = token
}

// Backup completo de la ruta dada, con el nombre dado (si no se da, se usará el nombre de la carpeta)
// Guarda la fecha y hora en el nombre del backup, con formato RFC3339 (ejemplo: backup-2026-01-01T00:00:00Z.tar.gz)
func (c *backupClient) Backup(Path string, name string) error { //Hace backup de los datos en la ruta dada
	if Path == "" {
		return fmt.Errorf("Ruta vacía")
	}
	if name == "" {
		name = filepath.Base(Path)
	}
	// Comprobamos que existe
	ostat, err := os.Stat(Path)
	if err != nil {
		return err
	}

	if !ostat.IsDir() {
		return os.ErrInvalid
	}

	// Ahora comprimimos la carpeta y obtenemos un fichero temporal .tar.gz
	compressedPath, err := CompressDirectoryTemp(Path)
	if err != nil {
		return err
	}
	defer os.Remove(compressedPath)

	// Subimos el backup al servidor
	// (nombre)2026-01-01T00:00:00Z.tar.gz
	backupName := fmt.Sprintf("%s-%s.tar.gz", strings.TrimSpace(time.Now().UTC().Format(time.RFC3339)), strings.TrimSuffix(name, string(filepath.Separator)))

	if err := c.uploadBackup(compressedPath, backupName); err != nil {
		return err
	}

	return nil
}

// Lista los backups disponibles en el servidor, devolviendo sus nombres
func (c *backupClient) ListBackups() ([]string, error) {
	if c.token == "" {
		return nil, fmt.Errorf("token vacío")
	}
	fileMetada, err := c.client.Lookup(c.backupPath, false) //No hace falta que sea recursivo
	if err != nil {
		return nil, err
	}
	list := make([]string, len(fileMetada))
	for i, meta := range fileMetada {
		list[i] = meta.Name
	}
	return list, nil
}

func (c *backupClient) uploadBackup(origin, name string) error {
	if c.token == "" {
		return fmt.Errorf("token vacío")
	}
	destiny := fmt.Sprintf("%s/%s", c.backupPath, name)
	_, _, err := c.client.UploadData(origin, destiny, false, true)
	return err
}

func (c *backupClient) DownloadBackup(name, dest string) error {
	if c.token == "" {
		return fmt.Errorf("token vacío")
	}
	origin := fmt.Sprintf("%s/%s", c.backupPath, name)
	return c.client.FetchData(origin, dest)
}
