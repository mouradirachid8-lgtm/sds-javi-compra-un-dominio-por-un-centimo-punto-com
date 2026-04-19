const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.LOG_SERVER_PORT || 3000;
const LOG_DIR = path.join(__dirname, 'logs');
const LOG_FILE = path.join(LOG_DIR, 'auditoria.log');
const ERROR_LOG = path.join(LOG_DIR, 'errores.log');
const SECURITY_LOG = path.join(LOG_DIR, 'seguridad.log');

// Credenciales desde variables de entorno
const VALID_USER = process.env.LOG_SERVER_USER || 'admin';
const VALID_PASS = process.env.LOG_SERVER_PASS || '1234';
const SECRET_TOKEN = process.env.LOG_SERVER_TOKEN || 'token-secreto';

// Crear directorio de logs si no existe
if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
}

// Contador de intentos fallidos para detectar ataques
const failedAttempts = {};
const MAX_FAILED_ATTEMPTS = 5;
const BLOCK_DURATION = 3600000; // 1 hora en ms

function createServer() {
    return http.createServer((req, res) => {
        const clientIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        const timestamp = new Date().toISOString();

        // Establecer CORS básico
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

        if (req.method === 'OPTIONS') {
            res.writeHead(200);
            res.end();
            return;
        }

        if (req.method !== 'POST' && req.url !== '/health') {
            logToFile(SECURITY_LOG, `[${timestamp}] RECHAZO MÉTODO: ${req.method} desde ${clientIP}`);
            res.writeHead(405, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Method not allowed' }));
            return;
        }

        let body = '';

        req.on('data', chunk => {
            body += chunk.toString();
            // Limitar tamaño del body
            if (body.length > 50000) {
                logToFile(SECURITY_LOG, `[${timestamp}] PAYLOAD EXCESIVO: ${body.length} bytes desde ${clientIP}`);
                res.writeHead(413, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Payload too large' }));
                req.socket.destroy();
            }
        });

        req.on('error', err => {
            logToFile(ERROR_LOG, `[${timestamp}] ERROR PETICIÓN: ${err.message} desde ${clientIP}`);
        });

        req.on('end', () => {
            let payload;
            try {
                payload = JSON.parse(body);
            } catch (e) {
                logToFile(SECURITY_LOG, `[${timestamp}] JSON INVÁLIDO: ${e.message} desde ${clientIP}`);
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Invalid JSON' }));
                return;
            }

            // Rutas disponibles
            if (req.url === '/login') {
                handleLogin(req, res, payload, clientIP, timestamp);
            } else if (req.url === '/logs') {
                handleLogs(req, res, payload, clientIP, timestamp);
            } else if (req.url === '/health') {
                handleHealth(res, timestamp);
            } else {
                logToFile(SECURITY_LOG, `[${timestamp}] RUTA NO ENCONTRADA: ${req.url} desde ${clientIP}`);
                res.writeHead(404, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Not found' }));
            }
        });
    });
}

/**
 * Maneja el endpoint /login
 */
function handleLogin(req, res, payload, clientIP, timestamp) {
    const username = payload.username || '';
    const password = payload.password || '';

    // Inicializar contador para esta IP
    if (!failedAttempts[clientIP]) {
        failedAttempts[clientIP] = { count: 0, blockedUntil: 0 };
    }

    const attempt = failedAttempts[clientIP];

    // Verificar si la IP está bloqueada
    if (attempt.blockedUntil > Date.now()) {
        const minutesLeft = Math.ceil((attempt.blockedUntil - Date.now()) / 60000);
        logToFile(SECURITY_LOG, `[${timestamp}] IP BLOQUEADA: ${clientIP} (${minutesLeft} minutos restantes)`);
        res.writeHead(429, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: `Too many attempts. Blocked for ${minutesLeft} minutes` }));
        return;
    }

    // Validar credenciales
    if (username === VALID_USER && password === VALID_PASS) {
        // Reset contador en login exitoso
        failedAttempts[clientIP].count = 0;
        logToFile(SECURITY_LOG, `[${timestamp}] LOGIN EXITOSO: Usuario '${username}' desde ${clientIP}`);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ token: SECRET_TOKEN }));
    } else {
        // Incrementar contador de fallos
        attempt.count++;
        logToFile(SECURITY_LOG, `[${timestamp}] LOGIN FALLIDO: Intento ${attempt.count}/${MAX_FAILED_ATTEMPTS} desde ${clientIP}`);

        // Si se alcanza el límite, bloquear
        if (attempt.count >= MAX_FAILED_ATTEMPTS) {
            attempt.blockedUntil = Date.now() + BLOCK_DURATION;
            logToFile(SECURITY_LOG, `[${timestamp}] IP BLOQUEADA: ${clientIP} después de ${attempt.count} intentos fallidos`);
        }

        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid credentials' }));
    }
}

/**
 * Maneja el endpoint /logs
 */
function handleLogs(req, res, payload, clientIP, timestamp) {
    const authHeader = req.headers['authorization'] || '';

    // Verificar token
    if (authHeader !== `Bearer ${SECRET_TOKEN}`) {
        logToFile(SECURITY_LOG, `[${timestamp}] ACCESO DENEGADO: Token inválido desde ${clientIP}`);
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized' }));
        return;
    }

    const logMessage = payload.log || '';

    if (!logMessage) {
        logToFile(SECURITY_LOG, `[${timestamp}] LOG VACÍO: Intento desde ${clientIP}`);
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Log message required' }));
        return;
    }

    // Clasificar el tipo de log
    let logFile = LOG_FILE;
    let logType = 'INFO';

    if (logMessage.includes('FALLO') || logMessage.includes('ERROR')) {
        logFile = ERROR_LOG;
        logType = 'ERROR';
    } else if (logMessage.includes('ALERTA') || logMessage.includes('SEGURIDAD') || 
               logMessage.includes('INTENTO') || logMessage.includes('ATAQUE')) {
        logFile = SECURITY_LOG;
        logType = 'SECURITY';
    }

    // Registrar en archivo apropiado
    const fullLog = `[${timestamp}] [${logType}] ${logMessage}`;
    logToFile(logFile, fullLog);

    // También mostrar en consola eventos importantes
    if (logType !== 'INFO') {
        console.log(fullLog);
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', timestamp }));
}

/**
 * Maneja el endpoint /health
 */
function handleHealth(res, timestamp) {
    const uptime = process.uptime();
    const health = {
        status: 'OK',
        timestamp: timestamp,
        uptime: uptime,
        logs: {
            general: fs.existsSync(LOG_FILE),
            errors: fs.existsSync(ERROR_LOG),
            security: fs.existsSync(SECURITY_LOG)
        }
    };
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(health));
}

/**
 * Escribe un log en archivo con sincronización
 */
function logToFile(filePath, message) {
    try {
        fs.appendFileSync(filePath, message + '\n', { encoding: 'utf-8' });
    } catch (err) {
        console.error(`Error escribiendo en ${filePath}:`, err.message);
    }
}

/**
 * Limpiar intentos fallidos cada hora
 */
function cleanupFailedAttempts() {
    setInterval(() => {
        const now = Date.now();
        let cleaned = 0;
        for (const ip in failedAttempts) {
            // Mantener solo si está bloqueado actualmente
            if (failedAttempts[ip].blockedUntil < now) {
                delete failedAttempts[ip];
                cleaned++;
            }
        }
        if (cleaned > 0) {
            console.log(`[CLEANUP] Eliminadas ${cleaned} entradas de intentos fallidos`);
        }
    }, 3600000); // Cada hora
}

// Iniciar servidor
const server = createServer();
server.listen(PORT, () => {
    console.log(`\n=====================================`);
    console.log(`🚀 Servidor de Logs iniciado`);
    console.log(`   Puerto: ${PORT}`);
    console.log(`   Endpoints:`);
    console.log(`   - POST /login (autenticación)`);
    console.log(`   - POST /logs (recibir eventos)`);
    console.log(`   - GET  /health (estado del servidor)`);
    console.log(`   Log Directory: ${LOG_DIR}`);
    console.log(`=====================================\n`);

    logToFile(LOG_FILE, `[${new Date().toISOString()}] [STARTUP] Servidor de logs iniciado en puerto ${PORT}`);
});

// Manejo de señales para cerrar gracefully
process.on('SIGINT', () => {
    console.log('\n[SHUTDOWN] Cerrando servidor de logs...');
    server.close(() => {
        logToFile(LOG_FILE, `[${new Date().toISOString()}] [SHUTDOWN] Servidor cerrado`);
        process.exit(0);
    });
});

process.on('SIGTERM', () => {
    server.close(() => {
        logToFile(LOG_FILE, `[${new Date().toISOString()}] [SHUTDOWN] Servidor terminado`);
        process.exit(0);
    });
});

// Iniciar limpieza periódica
cleanupFailedAttempts();