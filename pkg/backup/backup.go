package backup

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sprout/pkg/api"
	"strings"
	"time"
)

// Usa server de sprut como servidor de backup

type backupClient struct {
	token   string
	srvAddr string
}

func NewBackupClient(token, srvAddr string) *backupClient {
	if token == "" || srvAddr == "" {
		return nil
	}

	return &backupClient{
		token:   token,
		srvAddr: srvAddr,
	}
}

func (c *backupClient) setToken(token string) { //Por si queremos cambiar el token después de crear el cliente
	c.token = token
}

func (c *backupClient) setServerAddress(addr string) { //Por si queremos cambiar la dirección del servidor después de crear el cliente
	c.srvAddr = addr
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
	compressedPath, err := compressDirectory(Path)
	if err != nil {
		return err
	}
	defer os.Remove(compressedPath)

	readData, err := os.Open(compressedPath)
	if err != nil {
		return err
	}
	defer readData.Close()

	// Subimos el backup al servidor
	// (nombre)2026-01-01T00:00:00Z.tar.gz
	backupName := fmt.Sprintf("%s-%s.tar.gz", strings.TrimSuffix(name, string(filepath.Separator)), time.Now().UTC().Format(time.RFC3339))

	if err := c.UploadBackup(readData, backupName); err != nil {
		return err
	}

	return nil
}

func compressDirectory(Path string) (string, error) {
	tmpFile, err := os.CreateTemp("", "backup-*.tar.gz")
	if err != nil {
		return "", fmt.Errorf("crear temporal: %w", err)
	}

	gw := gzip.NewWriter(tmpFile)
	tw := tar.NewWriter(gw)

	err = filepath.Walk(Path, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(Path, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = rel
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			if _, err := io.Copy(tw, f); err != nil {
				f.Close()
				return err
			}
			f.Close()
		}
		return nil
	})

	// Cerramos writers
	if cerr := tw.Close(); cerr != nil && err == nil {
		err = cerr
	}
	if cerr := gw.Close(); cerr != nil && err == nil {
		err = cerr
	}

	if err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return "", err
	}

	if _, err := tmpFile.Seek(0, 0); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return "", err
	}

	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpFile.Name())
		return "", err
	}

	return tmpFile.Name(), nil
}

func (c *backupClient) UploadBackup(backupData io.Reader, name string) error {
	if c == nil {
		return fmt.Errorf("Backup client nil")
	}
	if backupData == nil {
		return fmt.Errorf("No hay datos de backup")
	}
	// Preparamos la petición
	req, err := http.NewRequest(http.MethodPost, c.srvAddr, backupData)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if c.token != "" {
		req.Header.Set("X-Token", c.token)
	}
	req.Header.Set("X-Action", api.ActionUpdateData)
	req.Header.Set("X-Path", "/backups/"+name)

	// Enviamos la petición
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	// Falló la lectura de la respuesta
	if err != nil {
		return fmt.Errorf("leer respuesta: %w", err)
	}
	// Decodificamos la respuesta
	var res api.Response
	if err := json.Unmarshal(body, &res); err != nil {
		return fmt.Errorf("descodificar respuesta: %w", err)
	}
	// Ha falldo por parte del servidor
	if !res.Success {
		return fmt.Errorf("backup fallido: %s", res.Message)
	}

	return nil
}
