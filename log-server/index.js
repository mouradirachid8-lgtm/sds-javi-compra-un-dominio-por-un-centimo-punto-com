const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = 3000;
const SECRET_TOKEN = 'mi-token-super-seguro';
const LOG_FILE = path.join(__dirname, 'auditoria.txt');

// Usuarios permitidos
const VALID_USER = 'admin';
const VALID_PASS = '1234';

const server = http.createServer((req, res) => {
    // Solo permitimos POST en las rutas
    if (req.method !== 'POST') {
        res.writeHead(405);
        return res.end('Method Not Allowed');
    }

    let body = '';
    req.on('data', chunk => {
        body += chunk.toString();
    });

    req.on('end', () => {
        let payload;
        try {
            payload = JSON.parse(body);
        } catch (e) {
            res.writeHead(400);
            return res.end('Invalid JSON');
        }

        // Endpoint de autenticación
        if (req.url === '/login') {
            if (payload.username === VALID_USER && payload.password === VALID_PASS) {
                console.log(`[AUTH] Usuario ${VALID_USER} autenticado.`);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ token: SECRET_TOKEN }));
            } else {
                console.log(`[AUTH] Intento fallido con usuario: ${payload.username}`);
                res.writeHead(401);
                res.end(JSON.stringify({ error: 'Credenciales inválidas' }));
            }
            return;
        }

        // Endpoint para recibir los logs
        if (req.url === '/logs') {
            // Verificar Autorización
            const authHeader = req.headers['authorization'];
            if (authHeader !== `Bearer ${SECRET_TOKEN}`) {
                console.log('[LOGS] Petición rechazada: Token inválido o ausente');
                res.writeHead(401);
                return res.end(JSON.stringify({ error: 'No autorizado' }));
            }

            // Procesar el evento
            const logMessage = payload.log;
            const time = new Date().toISOString();
            
            // Mostrar por consola del servidor Node
            console.log(`[NUEVO EVENTO | ${time}] ${logMessage}`);

            // Guardar en fichero de texto
            fs.appendFileSync(LOG_FILE, `[${time}] ${logMessage}\n`);

            res.writeHead(200);
            return res.end(JSON.stringify({ status: 'ok' }));
        }

        // Ruta no encontrada
        res.writeHead(404);
        res.end('Not Found');
    });
});

server.listen(PORT, () => {
    console.log(`=====================================`);
    console.log(`🚀 Servidor de Logs iniciado en el puerto ${PORT}`);
    console.log(`   Rutas habilitadas:`);
    console.log(`   - POST http://localhost:3000/login`);
    console.log(`   - POST http://localhost:3000/logs`);
    console.log(`=====================================\n`);
});
