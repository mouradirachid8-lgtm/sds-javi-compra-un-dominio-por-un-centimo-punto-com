package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"sprout/pkg/api"
	"sprout/pkg/store"
)

func newTestHTTPServer(t *testing.T) *httptest.Server {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "server.db")
	db, err := store.NewStore("bbolt", path)
	if err != nil {
		t.Fatalf("no se ha podido crear la store: %v", err)
	}

	srv := &server{db: db}
	t.Cleanup(func() { _ = db.Close() })

	mux := http.NewServeMux()
	mux.Handle("/api", http.HandlerFunc(srv.apiHandler))

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func postJSON(t *testing.T, url string, v any) (*http.Response, api.Response) {
	t.Helper()

	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal falló: %v", err)
	}

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("POST falló: %v", err)
	}
	defer resp.Body.Close()

	var ar api.Response
	_ = json.NewDecoder(resp.Body).Decode(&ar)
	return resp, ar
}

func TestServer_RegisterLoginUpdateFetchLogout(t *testing.T) {
	ts := newTestHTTPServer(t)
	apiURL := ts.URL + "/api"

	// Register
	body, _ := json.Marshal(api.RegisterRequest{
		Username: "alice",
		Password: "pw",
	})
	_, r1 := postJSON(t, apiURL, api.Request{
		Action: api.ActionRegister,
		Body:   body,
	})
	if !r1.Success {
		t.Fatalf("register falló: %s", r1.Message)
	}

	// Login
	_, r2 := postJSON(t, apiURL, api.Request{
		Action: api.ActionLogin,
		Body:   body,
	})
	if !r2.Success || r2.Token == "" {
		t.Fatalf("login falló: success=%v msg=%q token=%q", r2.Success, r2.Message, r2.Token)
	}

	// Update
	_, r3 := postJSON(t, apiURL, api.Request{
		Action: api.ActionUpdateData,
		Token:  r2.Token,
		Data:   "secreto",
	})
	if !r3.Success {
		t.Fatalf("update falló: %s", r3.Message)
	}

	// Fetch
	_, r4 := postJSON(t, apiURL, api.Request{
		Action: api.ActionFetchData,
		Token:  r2.Token,
	})
	if !r4.Success || r4.Data != "secreto" {
		t.Fatalf("fetch falló: success=%v msg=%q data=%q", r4.Success, r4.Message, r4.Data)
	}

	// Logout
	_, r5 := postJSON(t, apiURL, api.Request{
		Action: api.ActionLogout,
		Token:  r2.Token,
	})
	if !r5.Success {
		t.Fatalf("logout falló: %s", r5.Message)
	}

	// Token ya no vale
	_, r6 := postJSON(t, apiURL, api.Request{
		Action: api.ActionFetchData,
		Token:  r2.Token,
	})
	if r6.Success {
		t.Fatalf("esperado fallo tras logout")
	}
}

func TestServer_UnknownFieldRejected(t *testing.T) {
	ts := newTestHTTPServer(t)
	apiURL := ts.URL + "/api"

	// Enviamos un JSON con un campo desconocido, debe dar 400.
	raw := []byte(`{"action":"register","username":"u","password":"p","nope":123}`)
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Post(apiURL, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("POST falló: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status esperado 400, obtenido %d", resp.StatusCode)
	}
}

func TestServer_RejectsTrailingJSON(t *testing.T) {
	ts := newTestHTTPServer(t)
	apiURL := ts.URL + "/api"

	// Dos objetos concatenados (o trailing garbage): por robustez lo rechazamos.
	raw := []byte(`{"action":"register","username":"u","password":"p"} {"action":"login"}`)
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Post(apiURL, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("POST falló: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status esperado 400, obtenido %d", resp.StatusCode)
	}
}
