package external_logger

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// httpLogWriter envía logs al servidor externo de forma asíncrona y autenticada.
type httpLogWriter struct {
	endpoint     string
	authEndpoint string
	client       *http.Client
	ch           chan string
	wg           sync.WaitGroup

	// auth
	authMu    sync.RWMutex
	authToken string
	username  string
	password  string

	// config
	maxAttempts int

	// monitoring - campos adicionales para estadísticas
	droppedLogs   int64     // logs descartados por cola llena
	failedSends   int64     // intentos fallidos de envío
	successSends  int64     // envíos exitosos
	lastAuthTime  time.Time // última autenticación exitosa
	queueSize     int32     // tamaño actual del canal
	authFailCount int64     // contador de fallos de autenticación consecutivos
}

// NewExternalLogger crea un *log.Logger que envía entradas a endpoint.
// Si authEndpoint no está vacío, intentará autenticarse allí usando las
// credenciales tomadas de las variables de entorno LOG_SERVER_USER / LOG_SERVER_PASS.
// Devuelve también una función Close() para cerrar el worker y flushear pendientes.
func NewExternalLogger(endpoint, authEndpoint string) (*log.Logger, func(), error) {
	if endpoint == "" {
		return nil, nil, fmt.Errorf("endpoint vacío")
	}

	w := &httpLogWriter{
		endpoint:     endpoint,
		authEndpoint: authEndpoint,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		ch:           make(chan string, 100),
		lastAuthTime: time.Now(),
	}

	// Si nos piden autenticación, leemos credenciales y autenticamos.
	if authEndpoint != "" {
		w.username = os.Getenv("LOG_SERVER_USER")
		w.password = os.Getenv("LOG_SERVER_PASS")
		if w.username == "" || w.password == "" {
			return nil, nil, fmt.Errorf("auth required but LOG_SERVER_USER/LOG_SERVER_PASS not set")
		}
		if err := w.authenticate(); err != nil {
			return nil, nil, fmt.Errorf("error authenticating to log server: %w", err)
		}
	}
	w.maxAttempts = 3
	if maxAttemptsStr := os.Getenv("LOG_SERVER_MAX_ATTEMPTS"); maxAttemptsStr != "" {
		if n, err := fmt.Sscanf(maxAttemptsStr, "%d", &w.maxAttempts); err != nil || n != 1 {
			return nil, nil, fmt.Errorf("invalid LOG_SERVER_MAX_ATTEMPTS value: %s", maxAttemptsStr)
		}
	}

	// worker que envía logs en background (drena el canal hasta cerrarlo)
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		for line := range w.ch {
			w.sendLine(line)
		}
	}()

	logger := log.New(w, "[srv] ", log.LstdFlags)
	closeFn := func() {
		// Mostrar estadísticas antes de cerrar
		dropped := atomic.LoadInt64(&w.droppedLogs)
		failed := atomic.LoadInt64(&w.failedSends)
		success := atomic.LoadInt64(&w.successSends)
		if dropped > 0 || failed > 0 {
			fmt.Fprintf(os.Stderr, "[LOGGER STATS] Success: %d, Failed: %d, Dropped: %d\n",
				success, failed, dropped)
		}

		// cerrar el canal para que el worker lo drene y termine
		close(w.ch)
		w.wg.Wait()
	}
	return logger, closeFn, nil
}

// NewSlogExternalLogger crea un *slog.Logger estructurado que envía sus entradas (en JSON) al endpoint.
func NewSlogExternalLogger(endpoint, authEndpoint string) (*slog.Logger, func(), error) {
	if endpoint == "" {
		return nil, nil, fmt.Errorf("endpoint vacío")
	}

	w := &httpLogWriter{
		endpoint:     endpoint,
		authEndpoint: authEndpoint,
		client: &http.Client{
			Timeout: 5 * time.Second,
		},
		ch:           make(chan string, 100),
		lastAuthTime: time.Now(),
	}

	// Si nos piden autenticación, leemos credenciales y autenticamos.
	if authEndpoint != "" {
		w.username = os.Getenv("LOG_SERVER_USER")
		w.password = os.Getenv("LOG_SERVER_PASS")
		if w.username == "" || w.password == "" {
			return nil, nil, fmt.Errorf("auth required but LOG_SERVER_USER/LOG_SERVER_PASS not set")
		}
		if err := w.authenticate(); err != nil {
			return nil, nil, fmt.Errorf("error authenticating to log server: %w", err)
		}
	}
	w.maxAttempts = 3
	if maxAttemptsStr := os.Getenv("LOG_SERVER_MAX_ATTEMPTS"); maxAttemptsStr != "" {
		if n, err := fmt.Sscanf(maxAttemptsStr, "%d", &w.maxAttempts); err != nil || n != 1 {
			return nil, nil, fmt.Errorf("invalid LOG_SERVER_MAX_ATTEMPTS value: %s", maxAttemptsStr)
		}
	}

	// worker que envía logs en background (drena el canal hasta cerrarlo)
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		for line := range w.ch {
			w.sendLine(line)
		}
	}()

	// Usamos el handler JSON de slog que escribirá directamente a nuestro writer asíncrono
	jsonHandler := slog.NewJSONHandler(w, nil)
	logger := slog.New(jsonHandler)

	closeFn := func() {
		// Mostrar estadísticas antes de cerrar
		dropped := atomic.LoadInt64(&w.droppedLogs)
		failed := atomic.LoadInt64(&w.failedSends)
		success := atomic.LoadInt64(&w.successSends)
		if dropped > 0 || failed > 0 {
			fmt.Fprintf(os.Stderr, "[LOGGER STATS] Success: %d, Failed: %d, Dropped: %d\n",
				success, failed, dropped)
		}

		// cerrar el canal para que el worker lo drene y termine
		close(w.ch)
		w.wg.Wait()
	}
	return logger, closeFn, nil
}

// authenticate obtiene un token desde authEndpoint (se asume respuesta JSON {"token":"..."}).
func (w *httpLogWriter) authenticate() error {
	payload := map[string]string{"username": w.username, "password": w.password}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", w.authEndpoint, bytes.NewReader(body))
	if err != nil {
		atomic.AddInt64(&w.authFailCount, 1)
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := w.client.Do(req)
	if err != nil {
		atomic.AddInt64(&w.authFailCount, 1)
		return err
	}
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		atomic.AddInt64(&w.authFailCount, 1)
		return fmt.Errorf("auth failed: %s", resp.Status)
	}

	var res struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		atomic.AddInt64(&w.authFailCount, 1)
		return err
	}

	w.authMu.Lock()
	w.authToken = res.Token
	w.authMu.Unlock()

	// Reset contador de fallos si la auth fue exitosa
	atomic.StoreInt64(&w.authFailCount, 0)
	w.lastAuthTime = time.Now()
	return nil
}

// sendLine intenta enviar la línea al endpoint, reautenticando si recibe 401.
// Tiene un pequeño reintento y backoff.
func (w *httpLogWriter) sendLine(line string) {
	payload := map[string]string{"log": line}
	body, _ := json.Marshal(payload)

	maxAttempts := w.maxAttempts
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		req, err := http.NewRequest("POST", w.endpoint, bytes.NewReader(body))
		if err != nil {
			atomic.AddInt64(&w.failedSends, 1)
			return
		}
		req.Header.Set("Content-Type", "application/json")

		w.authMu.RLock()
		token := w.authToken
		w.authMu.RUnlock()
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}

		resp, err := w.client.Do(req)
		if err != nil {
			// fallo de red: reintentar
			atomic.AddInt64(&w.failedSends, 1)
			time.Sleep(150 * time.Millisecond)
			continue
		}

		// siempre cerrar body para evitar fugas
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusNoContent {
			atomic.AddInt64(&w.successSends, 1)
			return
		}

		if resp.StatusCode == http.StatusUnauthorized && w.authEndpoint != "" && attempt < maxAttempts {
			// reautenticar y reintentar
			if err := w.authenticate(); err != nil {
				atomic.AddInt64(&w.failedSends, 1)
				return
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}

		// para otros códigos no hacemos más reintentos
		atomic.AddInt64(&w.failedSends, 1)
		return
	}
}

// Write satisface io.Writer. Envía la línea al canal (sin bloquear indefinidamente).
// Usa recover para evitar panic si el canal se cierra concurrentemente.
func (w *httpLogWriter) Write(p []byte) (n int, err error) {
	line := string(bytes.TrimRight(p, "\n"))
	// proteger ante posible send en canal cerrado (race al cerrar)
	defer func() {
		_ = recover()
	}()
	select {
	case w.ch <- line:
		// Log encolado exitosamente
		atomic.AddInt32(&w.queueSize, 1)
	default:
		// cola llena: descartamos para no bloquear la aplicación.
		atomic.AddInt64(&w.droppedLogs, 1)
		// Intentar registrar en stderr como fallback
		fmt.Fprintf(os.Stderr, "[LOGGER QUEUE FULL] Discarding log: %s\n", line)
	}
	return len(p), nil
}

// GetStats retorna estadísticas actuales del logger
func (w *httpLogWriter) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"successSends":      atomic.LoadInt64(&w.successSends),
		"failedSends":       atomic.LoadInt64(&w.failedSends),
		"droppedLogs":       atomic.LoadInt64(&w.droppedLogs),
		"authFailCount":     atomic.LoadInt64(&w.authFailCount),
		"queueSize":         atomic.LoadInt32(&w.queueSize),
		"lastAuthTime":      w.lastAuthTime,
		"timeSinceLastAuth": time.Since(w.lastAuthTime),
	}
}

// HealthCheck verifica la salud del logger
func (w *httpLogWriter) HealthCheck() (healthy bool, message string) {
	authFails := atomic.LoadInt64(&w.authFailCount)
	dropped := atomic.LoadInt64(&w.droppedLogs)

	if authFails > 5 {
		return false, fmt.Sprintf("Too many auth failures: %d", authFails)
	}

	if dropped > 1000 {
		return false, fmt.Sprintf("Too many dropped logs: %d", dropped)
	}

	if time.Since(w.lastAuthTime) > 1*time.Hour {
		return false, "Last auth was more than 1 hour ago"
	}

	return true, "Logger is healthy"
}
