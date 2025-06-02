const express = require('express');
const http = require('http'); // 改回使用 http 模块
const WebSocket = require('ws');
const { Client } = require('ssh2');
const path = require('path');
const cors = require('cors'); // 引入 cors 模块
const { z, ZodError } = require('zod');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = process.env.PORT || 3000;

// --- Zod Schemas (类似 Pydantic 模型) ---
const AuthTypeSchema = z.enum(['password', 'key']);

const NodeSchema = z.object({
    name: z.string().min(1, "Node name is required"),
    host: z.string().min(1, "Hostname or IP address is required"),
    port: z.number().int().positive().default(22),
    username: z.string().min(1, "SSH username is required"),
    auth_type: AuthTypeSchema,
    auth_value: z.string().min(1, "Password or private key content is required"),
});

// --- 中间件 ---
// 配置 CORS，仅允许 https://ssh.arksec.net 访问
app.use(cors({ origin: 'https://ssh.arksec.net' }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'static')));

// --- 根路径提供前端 ---
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'static', 'index.html'));
});

// --- SSH 测试 API ---
app.post('/api/ssh/test', async (req, res) => {
    const startTime = Date.now();
    let nodeInput;
    try {
        nodeInput = NodeSchema.parse(req.body.node);
    } catch (error) {
        if (error instanceof ZodError) {
            return res.status(400).json({ success: false, errors: error.errors });
        }
        return res.status(400).json({ success: false, message: "Invalid node data format." });
    }

    const cmds = req.body.cmds && Array.isArray(req.body.cmds) && req.body.cmds.length > 0
        ? req.body.cmds
        : ["echo 'Connection successful' && uname -a"];
    const combinedCommand = cmds.join('\n');

    const conn = new Client();
    let connectionError = null;
    let execOutput = [];
    let execError = [];
    let success = false;

    conn.on('ready', () => {
        conn.exec(combinedCommand, { pty: true }, (err, stream) => {
            if (err) {
                execError.push(`EXEC error: ${err.message}`);
                finishRequest();
                return;
            }
            stream.on('close', (code, signal) => {
                success = (code === 0 && execError.length === 0);
                finishRequest();
            }).on('data', (data) => {
                execOutput.push(...data.toString('utf-8').split('\n').map(line => line.replace(/\r$/, '')));
            }).stderr.on('data', (data) => {
                execError.push(...data.toString('utf-8').split('\n').map(line => line.replace(/\r$/, '')));
            });
        });
    }).on('error', (err) => {
        connectionError = `SSH Connection error: ${err.message}`;
        execError.push(connectionError);
        finishRequest();
    }).on('timeout', () => {
        connectionError = 'SSH Connection timeout';
        execError.push(connectionError);
        finishRequest();
    });

    const connectionConfig = {
        host: nodeInput.host,
        port: nodeInput.port,
        username: nodeInput.username,
        readyTimeout: 10000,
        [nodeInput.auth_type === 'password' ? 'password' : 'privateKey']: nodeInput.auth_value,
    };

    try {
        conn.connect(connectionConfig);
    } catch (e) {
        execError.push(`Connection setup error: ${e.message}`);
        finishRequest();
    }

    function finishRequest() {
        if (conn) conn.end();
        
        const timeElapsed = (Date.now() - startTime) / 1000;
        const nodeResponse = { ...nodeInput, auth_value: '***' };

        if (!res.headersSent) {
            if (connectionError && success) {
                success = false;
            }
            res.json({
                time_elapsed: parseFloat(timeElapsed.toFixed(3)),
                success: success,
                output: execOutput.filter(line => line),
                error: execError.filter(line => line),
                node: nodeResponse,
                cmds: combinedCommand,
            });
        }
    }
});

// --- WebSocket SSH Shell ---
wss.on('connection', (ws, req) => {
    console.log(`WebSocket client connected from ${req.headers['x-forwarded-for'] || req.socket.remoteAddress} to ${req.url}`);
    let sshConn = new Client();
    let sshStream = null;

    ws.on('message', async (message) => {
        if (!sshStream) {
            let nodeInput;
            try {
                const nodeInfo = JSON.parse(message.toString());
                nodeInput = NodeSchema.parse(nodeInfo);
            } catch (error) {
                console.error("Invalid Node info from WebSocket:", error);
                ws.send(`\r\nInvalid connection data: ${error instanceof ZodError ? error.errors.map(e=>e.message).join(', ') : error.message}\r\n`);
                ws.close();
                return;
            }

            ws.send(`\r\nConnecting to ${nodeInput.name} (${nodeInput.host})...\r\n`);

            sshConn.on('ready', () => {
                ws.send('SSH connection established. Opening shell...\r\n');
                sshConn.shell({ term: 'xterm-color', pty: true }, (err, stream) => {
                    if (err) {
                        ws.send(`\r\nSSH Shell error: ${err.message}\r\n`);
                        sshConn.end();
                        ws.close();
                        return;
                    }
                    sshStream = stream;
                    ws.send('Shell ready.\r\n');

                    sshStream.on('data', (data) => {
                        ws.send(data.toString('utf-8'));
                    });

                    sshStream.on('close', () => {
                        ws.send('\r\nSSH shell session ended.\r\n');
                        sshConn.end();
                        ws.close();
                    });
                    
                    sshStream.on('error', (shellErr) => {
                        ws.send(`\r\nSSH Shell Stream error: ${shellErr.message}\r\n`);
                    });
                });
            }).on('error', (err) => {
                ws.send(`\r\nSSH Connection error: ${err.message}\r\n`);
                if (sshConn) sshConn.end();
                ws.close();
            }).on('timeout', () => {
                ws.send('\r\nSSH Connection timeout.\r\n');
                if (sshConn) sshConn.end();
                ws.close();
            });
            
            const connectionConfig = {
                host: nodeInput.host,
                port: nodeInput.port,
                username: nodeInput.username,
                readyTimeout: 20000,
                [nodeInput.auth_type === 'password' ? 'password' : 'privateKey']: nodeInput.auth_value,
            };
            try {
                sshConn.connect(connectionConfig);
            } catch(e) {
                ws.send(`\r\nConnection setup error: ${e.message}\r\n`);
                if (sshConn) sshConn.end();
                ws.close();
            }

        } else {
            if (sshStream && sshStream.writable) {
                sshStream.write(message.toString());
            }
        }
    });

    ws.on('close', () => {
        console.log('WebSocket client disconnected.');
        if (sshStream) {
            sshStream.end();
        }
        if (sshConn) {
            sshConn.end();
        }
    });

    ws.on('error', (error) => {
        console.error('WebSocket error:', error);
        if (sshStream) {
            sshStream.destroy();
        }
        if (sshConn) {
            sshConn.end();
        }
    });
});

// --- 启动服务器 ---
server.listen(PORT, () => {
    console.log(`Server is listening on internal port: ${PORT}`);
    console.log(`To access the app on Koyeb, use your Koyeb service URL (e.g., https://your-app-name.koyeb.app)`);
    console.log(`Frontend (if static/index.html exists): accessible via your Koyeb URL /`);
    console.log(`API endpoint for SSH test: POST to your Koyeb URL /api/ssh/test`);
    console.log(`WebSocket endpoint for SSH shell: connect to wss://your-koyeb-url (path might be /ws/ssh/ or just / depending on proxy)`);
});
