package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func newTestBboltStore(t *testing.T) *BboltStore {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	s, err := NewBboltStore(path)
	if err != nil {
		t.Fatalf("no se ha podido crear la store de pruebas: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	return s
}

func TestBboltStore_GetCopiesValue(t *testing.T) {
	s := newTestBboltStore(t)

	key := []byte("k")
	orig := []byte("hola")
	if err := s.Put("ns", key, orig); err != nil {
		t.Fatalf("Put falló: %v", err)
	}

	v1, err := s.Get("ns", key)
	if err != nil {
		t.Fatalf("Get falló: %v", err)
	}

	// Mutamos el valor devuelto: si Get devuelve un alias interno de bbolt,
	// esto podría corromper datos o fallar de forma no determinista.
	if len(v1) == 0 {
		t.Fatalf("valor inesperado: vacío")
	}
	v1[0] = 'X'

	v2, err := s.Get("ns", key)
	if err != nil {
		t.Fatalf("Get (2) falló: %v", err)
	}
	if string(v2) != string(orig) {
		t.Fatalf("Get debería devolver una copia; esperado %q, obtenido %q", string(orig), string(v2))
	}
}

func TestBboltStore_NotFoundErrors(t *testing.T) {
	s := newTestBboltStore(t)

	_, err := s.Get("noexiste", []byte("k"))
	if err == nil || !errors.Is(err, ErrNamespaceNotFound) {
		t.Fatalf("esperado ErrNamespaceNotFound, obtenido: %v", err)
	}

	if err := s.Put("ns", []byte("k"), []byte("v")); err != nil {
		t.Fatalf("Put falló: %v", err)
	}

	_, err = s.Get("ns", []byte("otra"))
	if err == nil || !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("esperado ErrKeyNotFound, obtenido: %v", err)
	}
}

func TestBboltStore_PersistsOnDisk(t *testing.T) {
	// Prueba de humo: abre/cierra y vuelve a abrir.
	dir := t.TempDir()
	path := filepath.Join(dir, "persist.db")

	{
		s, err := NewBboltStore(path)
		if err != nil {
			t.Fatalf("open falló: %v", err)
		}
		if err := s.Put("ns", []byte("k"), []byte("v")); err != nil {
			_ = s.Close()
			t.Fatalf("Put falló: %v", err)
		}
		_ = s.Close()
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("esperado fichero DB en disco: %v", err)
	}

	{
		s, err := NewBboltStore(path)
		if err != nil {
			t.Fatalf("re-open falló: %v", err)
		}
		defer s.Close()

		v, err := s.Get("ns", []byte("k"))
		if err != nil {
			t.Fatalf("Get tras re-open falló: %v", err)
		}
		if string(v) != "v" {
			t.Fatalf("valor inesperado: %q", string(v))
		}
	}
}

func FuzzBboltStore_KeysByPrefix(f *testing.F) {
	// Seeds para que el fuzz tenga casos iniciales razonables.
	f.Add([]byte("pre"), []byte("pre1"), []byte("otra"))
	f.Add([]byte(""), []byte("k1"), []byte("k2"))
	f.Add([]byte("a"), []byte("b"), []byte("a"))

	f.Fuzz(func(t *testing.T, prefix, k1, k2 []byte) {
		s := newTestBboltStore(t)

		// Insertamos dos claves. No nos interesa el valor para esta propiedad.
		if err := s.Put("ns", k1, []byte("v1")); err != nil {
			t.Fatalf("Put(k1) falló: %v", err)
		}
		if err := s.Put("ns", k2, []byte("v2")); err != nil {
			t.Fatalf("Put(k2) falló: %v", err)
		}

		got, err := s.KeysByPrefix("ns", prefix)
		if err != nil {
			t.Fatalf("KeysByPrefix falló: %v", err)
		}

		// Propiedad 1: todo lo devuelto debe tener el prefijo.
		seen := make(map[string]struct{}, len(got))
		for _, k := range got {
			if !bytes.HasPrefix(k, prefix) {
				t.Fatalf("clave %q no tiene prefijo %q", string(k), string(prefix))
			}
			seen[string(k)] = struct{}{}
		}

		// Propiedad 2: cualquier clave insertada que cumpla el prefijo debe aparecer.
		if bytes.HasPrefix(k1, prefix) {
			if _, ok := seen[string(k1)]; !ok {
				t.Fatalf("se esperaba k1=%q en el resultado para prefijo %q", string(k1), string(prefix))
			}
		}
		if bytes.HasPrefix(k2, prefix) {
			if _, ok := seen[string(k2)]; !ok {
				t.Fatalf("se esperaba k2=%q en el resultado para prefijo %q", string(k2), string(prefix))
			}
		}
	})
}
