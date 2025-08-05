const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const { Client } = require('ssh2');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const { z, ZodError } = require('zod');
// const url = require('url'); // 旧的、已废弃的模块，不再需要，予以移除

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ noServer: true });

const PORT = process.env.PORT || 3000;

// --- Zod Schemas for Validation ---
const AuthTypeSchema = z.enum(['password', 'key']);
const NodeSchema = z.object({
    name: z.string().min(1, "Node name is required"),
    host: z.string().min(1, "Hostname or IP address is required"),
    port: z.number().int().positive().default(22),
    username: z.string().min(1, "SSH username is required"),
    auth_type: AuthTypeSchema,
    auth_value: z.string().min(1, "Password or private key content is required"),
});

// --- Dynamic CORS Configuration ---
const allowedOrigins = [
    'https://ssh.arksec.net',
    'http://localhost:5173'
];

const corsOptions = {
    origin: (origin, callback) => {
        if (!origin || allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
            callback(new Error(msg), false);
        }
    }
};

// --- Middleware ---
app.use(helmet());
app.use(cors(corsOptions));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'static')));

// --- Shared SSH Connection Logic (Promise-based) ---
function connectSsh(nodeInput) {
    return new Promise((resolve, reject) => {
        const conn = new Client();
        const connectionConfig = {
            host: nodeInput.host,
            port: nodeInput.port,
            username: nodeInput.username,
            readyTimeout: 15000,
            [nodeInput.auth_type === 'password' ? 'password' : 'privateKey']: nodeInput.auth_value,
        };

        conn.on('ready', () => resolve(conn))
            .on('error', (err) => reject(new Error(`SSH Connection Error: ${err.message}`)))
            .on('timeout', () => reject(new Error('SSH Connection Timeout')))
            .connect(connectionConfig);
    });
}

// --- Frontend Route ---
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'static', 'index.html'));
});

// --- API Root Endpoint (Health Check) ---
app.get('/api', (req, res) => {
    res.json({
        status: 'ok',
        message: 'SSH WebSocket Gateway is running',
        available_endpoints: {
            api_health_check: 'GET /api',
            ssh_test: 'POST /api/ssh/test',
            ssh_websocket: 'WebSocket /ws/ssh'
        }
    });
});

// --- SSH Test API (Refactored with Async/Await) ---
app.post('/api/ssh/test', async (req, res) => {
    const startTime = Date.now();
    let conn = null;

    try {
        const nodeInput = NodeSchema.parse(req.body.node);
        const cmds = req.body.cmds && Array.isArray(req.body.cmds) && req.body.cmds.length > 0
            ? req.body.cmds
            : ["echo 'Connection successful' && uname -a"];
        const combinedCommand = cmds.join('\n');

        conn = await connectSsh(nodeInput);

        const execResult = await new Promise((resolve, reject) => {
            let execOutput = [];
            let execError = [];
            conn.exec(combinedCommand, { pty: true }, (err, stream) => {
                if (err) return reject(new Error(`EXEC error: ${err.message}`));

                stream.on('data', (data) => {
                    execOutput.push(...data.toString('utf-8').split('\n').map(line => line.trim()));
                }).stderr.on('data', (data) => {
                    execError.push(...data.toString('utf-8').split('\n').map(line => line.trim()));
                });

                stream.on('close', (code) => {
                    resolve({
                        success: code === 0 && execError.length === 0,
                        output: execOutput.filter(Boolean),
                        error: execError.filter(Boolean),
                    });
                });
            });
        });

        res.json({
            time_elapsed: parseFloat(((Date.now() - startTime) / 1000).toFixed(3)),
            success: execResult.success,
            output: execResult.output,
            error: execResult.error,
            node: { ...nodeInput, auth_value: '***' },
            cmds: combinedCommand,
        });

    } catch (error) {
        const timeElapsed = parseFloat(((Date.now() - startTime) / 1000).toFixed(3));
        const status = (error instanceof ZodError) ? 400 : 500;
        const errors = (error instanceof ZodError) ? error.errors : [error.message];
        
        res.status(status).json({
            time_elapsed,
            success: false,
            output: [],
            error: errors,
        });
    } finally {
        if (conn) conn.end();
    }
});

// --- WebSocket SSH Shell Handler ---
function handleWebSocketConnection(ws, req) {
    console.log(`WebSocket client connected from ${req.headers['x-forwarded-for'] || req.socket.remoteAddress}`);
    let sshConn = null;
    let sshStream = null;

    const sendWsError = (message) => {
        ws.send(`\r\n\u001b[31mError: ${message}\u001b[0m\r\n`);
    };
    
    const cleanup = () => {
        if (sshStream) sshStream.end();
        if (sshConn) sshConn.end();
        sshStream = null;
        sshConn = null;
    };

    ws.on('message', async (message) => {
        if (!sshConn) {
            try {
                const nodeInfo = JSON.parse(message.toString());
                const nodeInput = NodeSchema.parse(nodeInfo);

                ws.send(`\r\nConnecting to ${nodeInput.name} (${nodeInput.host})...\r\n`);
                sshConn = await connectSsh(nodeInput);
                ws.send('SSH connection established. Opening shell...\r\n');

                sshConn.shell({ term: 'xterm-color', pty: true }, (err, stream) => {
                    if (err) {
                        sendWsError(`Shell creation failed: ${err.message}`);
                        ws.close();
                        return;
                    }
                    sshStream = stream;
                    ws.send('Shell ready.\r\n');
                    
                    sshStream.on('data', (data) => ws.send(data.toString('utf-8')));
                    sshStream.on('close', () => {
                        ws.send('\r\nSSH shell session ended.\r\n');
                        ws.close();
                    });
                });

            } catch (error) {
                const errorMessage = (error instanceof ZodError)
                    ? error.errors.map(e => e.message).join(', ')
                    : error.message;
                sendWsError(errorMessage);
                ws.close();
            }
        } else {
            if (sshStream && sshStream.writable) {
                sshStream.write(message);
            }
        }
    });

    ws.on('close', () => {
        console.log('WebSocket client disconnected.');
        cleanup();
    });

    ws.on('error', (error) => {
        console.error('WebSocket error:', error);
        cleanup();
    });
}

// Bind the handler to the wss instance
wss.on('connection', handleWebSocketConnection);

// Manually handle HTTP Upgrade requests for WebSocket path routing
server.on('upgrade', (request, socket, head) => {
    // --- 关键修复：使用 WHATWG URL API 替代 url.parse() ---
    // 这种方法更现代、更安全，并且消除了废弃警告。
    const { pathname } = new URL(request.url, `http://${request.headers.host}`);

    if (pathname === '/ws/ssh') {
        wss.handleUpgrade(request, socket, head, (ws) => {
            wss.emit('connection', ws, request);
        });
    } else {
        socket.destroy();
    }
});


// --- Start Server ---
server.listen(PORT, () => {
    console.log(`Server is running robustly on port: ${PORT}`);
    console.log(`Allowed Origins for CORS: ${allowedOrigins.join(', ')}`);
});
