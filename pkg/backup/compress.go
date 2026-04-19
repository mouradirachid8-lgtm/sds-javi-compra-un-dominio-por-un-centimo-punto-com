package backup

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Comprime la carpeta dada en un fichero temporal .tar.gz y devuelve la ruta del fichero temporal
func CompressDirectoryTemp(Path string) (string, error) {
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

// Descomprime un fichero .tar.gz en la ruta dada
func UncompressTarGz(src, dest string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		target := filepath.Join(dest, hdr.Name)

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(hdr.Mode)); err != nil {
				return err
			}
		case tar.TypeReg:
			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(hdr.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			f.Close()
		default:
			return fmt.Errorf("tipo de archivo no soportado: %c", hdr.Typeflag)
		}
	}

	return nil
}
