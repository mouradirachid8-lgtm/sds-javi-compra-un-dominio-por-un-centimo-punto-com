package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	logDir       = "logs"
	logFile      = filepath.Join(logDir, "auditoria.log")
	errorLog     = filepath.Join(logDir, "errores.log")
	securityLog  = filepath.Join(logDir, "seguridad.log")

	validUser    = getEnv("LOG_SERVER_USER", "admin")
	validPass    = getEnv("LOG_SERVER_PASS", "1234")
	secretToken  = getEnv("LOG_SERVER_TOKEN", "token-secreto")
	port         = getEnv("LOG_SERVER_PORT", "3000")

	// Fail2Ban
	failedAttempts = make(map[string]*Attempt)
	attemptMu      sync.Mutex
	maxAttempts    = 5
	blockDuration  = time.Hour

	// File writing mutex
	logMu sync.Mutex
)

type Attempt struct {
	Count        int
	BlockedUntil time.Time
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func main() {
	if err := os.MkdirAll(logDir, 0755); err != nil {
		log.Fatalf("Error creando directorio de logs: %v", err)
	}

	go cleanupFailedAttempts()

	mux := http.NewServeMux()
	mux.HandleFunc("/login", handleLogin)
	mux.HandleFunc("/logs", handleLogs)
	mux.HandleFunc("/health", handleHealth)

	// Wrap con CORS y method check
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)
		timestamp := time.Now().Format(time.RFC3339)

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		if r.Method != http.MethodPost && r.URL.Path != "/health" {
			logToFile(securityLog, fmt.Sprintf("[%s] RECHAZO MÉTODO: %s desde %s", timestamp, r.Method, clientIP))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)
			json.NewEncoder(w).Encode(map[string]string{"error": "Method not allowed"})
			return
		}

		mux.ServeHTTP(w, r)
	})

	fmt.Println("=====================================")
	fmt.Printf("🚀 Servidor de Logs iniciado\n")
	fmt.Printf("   Puerto: %s\n", port)
	fmt.Printf("   Endpoints:\n")
	fmt.Printf("   - POST /login (autenticación)\n")
	fmt.Printf("   - POST /logs (recibir eventos)\n")
	fmt.Printf("   - GET  /health (estado del servidor)\n")
	fmt.Printf("   Log Directory: %s\n", logDir)
	fmt.Println("=====================================")

	logToFile(logFile, fmt.Sprintf("[%s] [STARTUP] Servidor de logs iniciado en puerto %s", time.Now().Format(time.RFC3339), port))

	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatalf("Error iniciando servidor: %v", err)
	}
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	timestamp := time.Now().Format(time.RFC3339)

	attemptMu.Lock()
	attempt, exists := failedAttempts[clientIP]
	if !exists {
		attempt = &Attempt{}
		failedAttempts[clientIP] = attempt
	}
	attemptMu.Unlock()

	if time.Now().Before(attempt.BlockedUntil) {
		minutesLeft := int(time.Until(attempt.BlockedUntil).Minutes())
		if minutesLeft < 1 {
			minutesLeft = 1
		}
		logToFile(securityLog, fmt.Sprintf("[%s] IP BLOQUEADA: %s (%d minutos restantes)", timestamp, clientIP, minutesLeft))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]string{"error": fmt.Sprintf("Too many attempts. Blocked for %d minutes", minutesLeft)})
		return
	}

	var payload struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	r.Body = http.MaxBytesReader(w, r.Body, 50000)
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		logToFile(securityLog, fmt.Sprintf("[%s] JSON INVÁLIDO: %v desde %s", timestamp, err, clientIP))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}

	if payload.Username == validUser && payload.Password == validPass {
		attemptMu.Lock()
		attempt.Count = 0
		attemptMu.Unlock()

		logToFile(securityLog, fmt.Sprintf("[%s] LOGIN EXITOSO: Usuario '%s' desde %s", timestamp, payload.Username, clientIP))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"token": secretToken})
	} else {
		attemptMu.Lock()
		attempt.Count++
		if attempt.Count >= maxAttempts {
			attempt.BlockedUntil = time.Now().Add(blockDuration)
			logToFile(securityLog, fmt.Sprintf("[%s] IP BLOQUEADA: %s después de %d intentos fallidos", timestamp, clientIP, attempt.Count))
		} else {
			logToFile(securityLog, fmt.Sprintf("[%s] LOGIN FALLIDO: Intento %d/%d desde %s", timestamp, attempt.Count, maxAttempts, clientIP))
		}
		attemptMu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid credentials"})
	}
}

func handleLogs(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	timestamp := time.Now().Format(time.RFC3339)

	authHeader := r.Header.Get("Authorization")
	if authHeader != "Bearer "+secretToken {
		logToFile(securityLog, fmt.Sprintf("[%s] ACCESO DENEGADO: Token inválido desde %s", timestamp, clientIP))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
		return
	}

	var payload struct {
		Log string `json:"log"`
	}

	r.Body = http.MaxBytesReader(w, r.Body, 50000)
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		logToFile(securityLog, fmt.Sprintf("[%s] JSON INVÁLIDO: %v desde %s", timestamp, err, clientIP))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}

	logMessageString := payload.Log
	if logMessageString == "" {
		logToFile(securityLog, fmt.Sprintf("[%s] LOG VACÍO: Intento desde %s", timestamp, clientIP))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Log message required"})
		return
	}

	targetFile := logFile
	logType := "INFO"
	finalMessage := logMessageString

	// Intentar parsear el JSON de slog
	var parsedLog map[string]interface{}
	if err := json.Unmarshal([]byte(logMessageString), &parsedLog); err == nil {
		if lvl, ok := parsedLog["level"].(string); ok {
			logType = lvl
			if logType == "ERROR" {
				targetFile = errorLog
			} else if logType == "WARN" {
				targetFile = securityLog
			}
			finalMessageBytes, _ := json.Marshal(parsedLog)
			finalMessage = string(finalMessageBytes)
		}
	} else {
		// Fallback para mensajes que no son de slog estructurado
		if strings.Contains(logMessageString, "FALLO") || strings.Contains(logMessageString, "ERROR") {
			targetFile = errorLog
			logType = "ERROR"
		} else if strings.Contains(logMessageString, "ALERTA") || strings.Contains(logMessageString, "SEGURIDAD") || strings.Contains(logMessageString, "INTENTO") || strings.Contains(logMessageString, "ATAQUE") {
			targetFile = securityLog
			logType = "SECURITY"
		}
	}

	fullLog := fmt.Sprintf("[%s] [%s] %s", timestamp, logType, finalMessage)
	logToFile(targetFile, fullLog)

	if logType != "INFO" {
		fmt.Println(fullLog)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "timestamp": timestamp})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"status":    "OK",
		"timestamp": time.Now().Format(time.RFC3339),
		"logs": map[string]bool{
			"general":  fileExists(logFile),
			"errors":   fileExists(errorLog),
			"security": fileExists(securityLog),
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

func logToFile(filePath, message string) {
	logMu.Lock()
	defer logMu.Unlock()
	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Error abriendo %s: %v\n", filePath, err)
		return
	}
	defer f.Close()
	f.WriteString(message + "\n")
}

func getClientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		ips := strings.Split(forwarded, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}
	// Limpiar puerto
	ip := r.RemoteAddr
	if strings.Contains(ip, ":") {
		ip = ip[:strings.LastIndex(ip, ":")]
	}
	return ip
}

func cleanupFailedAttempts() {
	ticker := time.NewTicker(1 * time.Hour)
	for range ticker.C {
		attemptMu.Lock()
		cleaned := 0
		now := time.Now()
		for ip, attempt := range failedAttempts {
			if attempt.BlockedUntil.Before(now) {
				delete(failedAttempts, ip)
				cleaned++
			}
		}
		attemptMu.Unlock()
		if cleaned > 0 {
			fmt.Printf("[CLEANUP] Eliminadas %d entradas de intentos fallidos\n", cleaned)
		}
	}
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
