package server

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
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

	srv := &server{
		db:       db,
		log:      log.New(io.Discard, "", 0),
		basePath: filepath.Join(dir, "files"),
	}
	t.Cleanup(func() { _ = db.Close() })

	mux := http.NewServeMux()
	mux.Handle("/api", http.HandlerFunc(srv.apiHandler))

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func postJSONAction(t *testing.T, url string, action string, token string, body any) (*http.Response, api.Response) {
	t.Helper()

	inner, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body falló: %v", err)
	}

	reqBody, err := json.Marshal(api.Request{Body: inner})
	if err != nil {
		t.Fatalf("marshal falló: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("NewRequest falló: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Action", action)
	if token != "" {
		req.Header.Set("X-Token", token)
	}

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST falló: %v", err)
	}
	defer resp.Body.Close()

	var ar api.Response
	_ = json.NewDecoder(resp.Body).Decode(&ar)
	return resp, ar
}

func postBinaryUpdate(t *testing.T, url string, token string, path string, content []byte, force bool) (*http.Response, api.Response) {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(content))
	if err != nil {
		t.Fatalf("NewRequest falló: %v", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Action", api.ActionUpdateData)
	req.Header.Set("X-Token", token)
	req.Header.Set("X-Path", path)
	if force {
		req.Header.Set("X-Force", "true")
	} else {
		req.Header.Set("X-Force", "false")
	}

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST binario falló: %v", err)
	}
	defer resp.Body.Close()

	var ar api.Response
	_ = json.NewDecoder(resp.Body).Decode(&ar)
	return resp, ar
}

func postFetch(t *testing.T, url string, token string, path string) (*http.Response, []byte) {
	t.Helper()

	inner, err := json.Marshal(api.FetchDataRequest{Path: path})
	if err != nil {
		t.Fatalf("marshal fetch body falló: %v", err)
	}
	reqBody, err := json.Marshal(api.Request{Body: inner})
	if err != nil {
		t.Fatalf("marshal request falló: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("NewRequest falló: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Action", api.ActionFetchData)
	if token != "" {
		req.Header.Set("X-Token", token)
	}

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("fetch POST falló: %v", err)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		resp.Body.Close()
		t.Fatalf("ReadAll falló: %v", err)
	}
	resp.Body.Close()

	return resp, data
}

func TestServer_RegisterLoginUpdateFetchLogout(t *testing.T) {
	ts := newTestHTTPServer(t)
	apiURL := ts.URL + "/api"

	// Register
	register := api.RegisterRequest{
		Username: "alice",
		Password: "pw",
	}
	_, r1 := postJSONAction(t, apiURL, api.ActionRegister, "", register)
	if !r1.Success {
		t.Fatalf("register falló: %s", r1.Message)
	}

	// Login
	login := api.LoginRequest{Username: "alice", Password: "pw"}
	_, r2 := postJSONAction(t, apiURL, api.ActionLogin, "", login)
	if !r2.Success || r2.Token == "" {
		t.Fatalf("login falló: success=%v msg=%q token=%q", r2.Success, r2.Message, r2.Token)
	}

	// Update (flujo binario)
	_, r3 := postBinaryUpdate(t, apiURL, r2.Token, "nota.txt", []byte("secreto"), false)
	if !r3.Success {
		t.Fatalf("update falló: %s", r3.Message)
	}

	// Fetch (stream binario)
	resp4, data4 := postFetch(t, apiURL, r2.Token, "nota.txt")
	if resp4.StatusCode != http.StatusOK {
		t.Fatalf("fetch falló: status=%d body=%q", resp4.StatusCode, string(data4))
	}
	if string(data4) != "secreto" {
		t.Fatalf("fetch contenido inesperado: %q", string(data4))
	}

	// Logout
	_, r5 := postJSONAction(t, apiURL, api.ActionLogout, r2.Token, struct{}{})
	if !r5.Success {
		t.Fatalf("logout falló: %s", r5.Message)
	}

	// Token ya no vale
	resp6, _ := postFetch(t, apiURL, r2.Token, "nota.txt")
	if resp6.StatusCode != http.StatusUnauthorized {
		t.Fatalf("esperado 401 tras logout, obtenido %d", resp6.StatusCode)
	}
}

func TestServer_UnknownFieldRejected(t *testing.T) {
	ts := newTestHTTPServer(t)
	apiURL := ts.URL + "/api"

	// Enviamos un Request válido en forma pero con campo top-level desconocido: debe dar 400.
	raw := []byte(`{"body":{"username":"u","password":"p"},"nope":123}`)
	req, err := http.NewRequest(http.MethodPost, apiURL, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("NewRequest falló: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Action", api.ActionRegister)

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
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
	raw := []byte(`{"body":{"username":"u","password":"p"}} {"body":{"username":"u","password":"p"}}`)
	req, err := http.NewRequest(http.MethodPost, apiURL, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("NewRequest falló: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Action", api.ActionRegister)

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST falló: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status esperado 400, obtenido %d", resp.StatusCode)
	}
}
