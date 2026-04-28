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

type BackupClient struct {
	backupPath string
	client     *client.Client
}

// El username y token(password) se usan para autentica en el servidor de backups
func NewBackupClient(username, token, srvAddr string, certPerm []byte) *BackupClient {
	if token == "" || srvAddr == "" {
		return nil
	}
	client := client.NewClient(srvAddr, certPerm)
	// Ya se hara mas seguro en el futuro
	err := client.Login(username, token)
	if err != nil {
		fmt.Printf("Error autenticando en el servidor de backup: %v\n", err)
		return nil
	}
	return &BackupClient{
		client:     client,
		backupPath: "backups",
	}
}

func (bc *BackupClient) login(username, token string) error {
	if token == "" {
		return fmt.Errorf("token vacío")
	}
	return bc.client.Login(username, token)
}

// Backup completo de la ruta dada, con el nombre dado (si no se da, se usará el nombre de la carpeta)
// Guarda la fecha y hora en el nombre del backup, con formato RFC3339 (ejemplo: backup-2026-01-01T00:00:00Z.tar.gz)
func (bc *BackupClient) Backup(Path string, name string) error { //Hace backup de los datos en la ruta dada
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
	t := time.Now().UTC().Format(time.RFC3339)
	t = strings.ReplaceAll(t, ":", "-")
	t = strings.ReplaceAll(t, "/", "-") // opcional
	t = strings.TrimSpace(t)
	backupName := fmt.Sprintf("%s-%s.tar.gz", t, strings.TrimSuffix(name, string(filepath.Separator)))

	if err := bc.uploadBackup(compressedPath, backupName); err != nil {
		return err
	}

	return nil
}

// Lista los backups disponibles en el servidor, devolviendo sus nombres
func (bc *BackupClient) ListBackups() ([]string, error) {
	fileMetada, err := bc.client.Lookup(bc.backupPath, false) //No hace falta que sea recursivo
	if err != nil {
		return nil, err
	}
	list := make([]string, len(fileMetada))
	for i, meta := range fileMetada {
		list[i] = meta.Name
	}
	return list, nil
}

func (bc *BackupClient) uploadBackup(origin, name string) error {

	destiny := fmt.Sprintf("%s/%s", bc.backupPath, name)
	_, _, err := bc.client.UploadData(origin, destiny, false, true)
	return err
}

func (bc *BackupClient) DownloadBackup(name, dest string) error {

	origin := fmt.Sprintf("%s/%s", bc.backupPath, name)
	return bc.client.FetchData(origin, dest)
}
