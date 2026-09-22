'use strict';

const express = require('express');
const http = require('http');
const net = require('net');
const dns = require('dns').promises;
const crypto = require('crypto');
const WebSocket = require('ws');
const { Client } = require('ssh2');
const cors = require('cors');
const helmet = require('helmet');
const { z, ZodError } = require('zod');

// =====================================================================
// 配置（全部来自环境变量）
// =====================================================================
//   API_TOKEN               必填。访问 API / WebSocket 的令牌（≥16 字符，建议 openssl rand -hex 32）
//   ALLOWED_ORIGINS         强烈建议设置。逗号分隔的允许来源，例如前端部署在 Vercel 后的域名
//                           （https://your-app.vercel.app）。前后端分离部署后不再有"默认可信来源"，
//                           不设置时仅在非生产环境放行 http://localhost:5173 方便本地调试。
//   TRUST_PROXY_HOPS        可选。前面有几层可信反向代理（Render 的边缘代理等），默认 0
//   ALLOW_PRIVATE_TARGETS   可选。设为 true 才允许连接内网/回环/链路本地地址，默认禁止
//   REQUIRE_HOST_FINGERPRINT可选。设为 true 则强制客户端提供 host_fingerprint（防中间人）
const PORT = process.env.PORT || 3000;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

const csv = (value) => (value || '').split(',').map((s) => s.trim()).filter(Boolean);

const API_TOKEN = process.env.API_TOKEN || '';
if (API_TOKEN.length < 16) {
    console.error('FATAL: 必须设置 API_TOKEN 环境变量（至少 16 个字符，例如: openssl rand -hex 32）');
    process.exit(1);
}
const API_TOKEN_HASH = crypto.createHash('sha256').update(API_TOKEN).digest();

const TRUST_PROXY_HOPS = Math.max(0, parseInt(process.env.TRUST_PROXY_HOPS || '0', 10) || 0);
const ALLOW_PRIVATE_TARGETS = process.env.ALLOW_PRIVATE_TARGETS === 'true';
const REQUIRE_HOST_FINGERPRINT = process.env.REQUIRE_HOST_FINGERPRINT === 'true';

const allowedOrigins = process.env.ALLOWED_ORIGINS
    ? csv(process.env.ALLOWED_ORIGINS)
    : (IS_PRODUCTION ? [] : ['http://localhost:5173']);
if (allowedOrigins.length === 0) {
    console.warn('WARNING: ALLOWED_ORIGINS 未设置——生产环境下将拒绝所有浏览器来源的请求。' +
        '请将其设为前端域名，例如 https://your-app.vercel.app');
}

const LIMITS = {
    JSON_BODY: '128kb',
    WS_MAX_PAYLOAD: 64 * 1024,
    PTY_MIN_COLS: 2, PTY_MAX_COLS: 1000,
    PTY_MIN_ROWS: 1, PTY_MAX_ROWS: 500,
    WS_AUTH_TIMEOUT_MS: 10_000,
    WS_IDLE_TIMEOUT_MS: 30 * 60_000,
    WS_MAX_BUFFERED_BYTES: 4 * 1024 * 1024,
    WS_MAX_TOTAL: 200,
    WS_MAX_PER_IP: 5,
    HTTP_RATE: { windowMs: 60_000, max: 30 },
    WS_RATE: { windowMs: 60_000, max: 20 },
};

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({
    noServer: true,
    maxPayload: LIMITS.WS_MAX_PAYLOAD, // ws 默认 100MiB，必须收紧
    perMessageDeflate: false,
});

// 缓解 slowloris 类慢速连接攻击
server.headersTimeout = 15_000;
server.requestTimeout = 30_000;

// =====================================================================
// 工具函数
// =====================================================================

/** 可以安全返回给客户端的错误（其他错误一律只返回通用信息，详情仅写日志） */
class PublicError extends Error {
    constructor(message, status = 502) {
        super(message);
        this.name = 'PublicError';
        this.status = status;
    }
}

/** 获取客户端 IP：仅在配置了可信代理层数时才读取 X-Forwarded-For，且必须是合法 IP（防伪造/日志注入） */
function getClientIp(req) {
    const socketIp = req.socket.remoteAddress || 'unknown';
    if (TRUST_PROXY_HOPS > 0) {
        const forwarded = String(req.headers['x-forwarded-for'] || '')
            .split(',')
            .map((s) => s.trim())
            .filter(Boolean);
        const candidate = forwarded[forwarded.length - TRUST_PROXY_HOPS];
        if (candidate && net.isIP(candidate)) return candidate;
    }
    return socketIp;
}

/** 固定窗口限流（进程内，按 key 计数） */
function createRateLimiter({ windowMs, max }) {
    const hits = new Map();
    setInterval(() => {
        const now = Date.now();
        for (const [key, entry] of hits) if (entry.resetAt <= now) hits.delete(key);
    }, windowMs).unref();

    return (key) => {
        const now = Date.now();
        let entry = hits.get(key);
        if (!entry || entry.resetAt <= now) {
            entry = { count: 0, resetAt: now + windowMs };
            hits.set(key, entry);
        }
        entry.count += 1;
        return entry.count <= max;
    };
}

const httpRateLimit = createRateLimiter(LIMITS.HTTP_RATE);
const wsRateLimit = createRateLimiter(LIMITS.WS_RATE);

/** 常量时间比较令牌 */
function isValidToken(candidate) {
    if (typeof candidate !== 'string' || candidate.length === 0 || candidate.length > 512) return false;
    const hash = crypto.createHash('sha256').update(candidate).digest();
    return crypto.timingSafeEqual(hash, API_TOKEN_HASH);
}

function formatZodIssues(error) {
    return error.issues.map((i) => ({ path: i.path.join('.'), message: i.message }));
}

// =====================================================================
// Zod Schemas
// =====================================================================
const noControlChars = /^[^\u0000-\u001f\u007f]*$/; // 禁止控制字符（防终端转义序列注入）

const AuthTypeSchema = z.enum(['password', 'key']);
const NodeSchema = z.object({
    name: z.string().min(1, 'Node name is required').max(100)
        .regex(noControlChars, 'Node name contains invalid characters'),
    host: z.string().min(1, 'Hostname or IP address is required').max(253)
        .regex(/^[A-Za-z0-9._:-]+$/, 'Invalid hostname or IP address'),
    port: z.number().int().min(1).max(65535).default(22),
    username: z.string().min(1, 'SSH username is required').max(128)
        .regex(noControlChars, 'SSH username contains invalid characters'),
    auth_type: AuthTypeSchema,
    auth_value: z.string().min(1, 'Password or private key content is required').max(16384),
    // 可选：OpenSSH 格式的主机密钥指纹，例如 SHA256:xxxxxxxx...（用于防中间人）
    host_fingerprint: z.string()
        .regex(/^SHA256:[A-Za-z0-9+/]{43}$/, 'host_fingerprint must look like SHA256:<base64>')
        .optional(),
});

// PTY 初始尺寸（握手消息里携带）与后续 resize 控制帧共用同一套边界校验
const PtySizeSchema = z.object({
    cols: z.number().int().min(LIMITS.PTY_MIN_COLS).max(LIMITS.PTY_MAX_COLS),
    rows: z.number().int().min(LIMITS.PTY_MIN_ROWS).max(LIMITS.PTY_MAX_ROWS),
});
const ResizeFrameSchema = z.object({
    type: z.literal('resize'),
    cols: PtySizeSchema.shape.cols,
    rows: PtySizeSchema.shape.rows,
});

// =====================================================================
// SSRF 防护：目标地址校验
// =====================================================================
const blockedRanges = new net.BlockList();
[
    ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
    ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.168.0.0', 16],
    ['198.18.0.0', 15], ['224.0.0.0', 4], ['240.0.0.0', 4],
].forEach(([addr, prefix]) => blockedRanges.addSubnet(addr, prefix, 'ipv4'));
[
    ['::', 128], ['::1', 128], ['::ffff:0:0', 96], ['64:ff9b::', 96],
    ['fc00::', 7], ['fe80::', 10], ['ff00::', 8],
].forEach(([addr, prefix]) => blockedRanges.addSubnet(addr, prefix, 'ipv6'));

/**
 * 解析并校验目标主机，返回“已校验过的 IP”。
 * 后续直接用该 IP 建立连接，避免 DNS rebinding（校验时和连接时解析结果不一致）。
 */
async function resolveTarget(host) {
    if (ALLOWED_TARGET_HOSTS.length > 0 && !ALLOWED_TARGET_HOSTS.includes(host.toLowerCase())) {
        throw new PublicError('Target host is not allowed', 403);
    }

    let addresses;
    const ipFamily = net.isIP(host);
    if (ipFamily) {
        addresses = [{ address: host, family: ipFamily }];
    } else {
        try {
            addresses = await dns.lookup(host, { all: true });
        } catch {
            throw new PublicError('Unable to resolve host', 502);
        }
    }

    if (!ALLOW_PRIVATE_TARGETS) {
        for (const { address, family } of addresses) {
            if (blockedRanges.check(address, family === 6 ? 'ipv6' : 'ipv4')) {
                throw new PublicError('Target host is not allowed', 403);
            }
        }
    }
    return addresses[0].address;
}

// =====================================================================
// SSH 连接
// =====================================================================
const sshFingerprint = (keyBuffer) =>
    'SHA256:' + crypto.createHash('sha256').update(keyBuffer).digest('base64').replace(/=+$/, '');

function toPublicSshError(err, hostKeyMismatch) {
    if (hostKeyMismatch) return new PublicError('Host key fingerprint mismatch', 502);
    if (err && err.level === 'client-authentication') return new PublicError('SSH authentication failed', 502);
    if (err && err.level === 'client-timeout') return new PublicError('SSH connection timed out', 504);
    if (err && /privateKey/i.test(err.message || '')) return new PublicError('Invalid private key or unsupported key format', 400);
    return new PublicError('SSH connection failed', 502);
}

async function connectSsh(nodeInput) {
    if (REQUIRE_HOST_FINGERPRINT && !nodeInput.host_fingerprint) {
        throw new PublicError('host_fingerprint is required', 400);
    }
    const address = await resolveTarget(nodeInput.host);

    return new Promise((resolve, reject) => {
        const conn = new Client();
        let settled = false;
        let hostKeyMismatch = false;

        const fail = (err) => {
            if (settled) return;
            settled = true;
            conn.end();
            reject(err);
        };

        conn.on('ready', () => {
            if (settled) return;
            settled = true;
            resolve(conn);
        })
            .on('error', (err) => {
                if (!settled) {
                    console.warn(`[ssh] connect failed: ${err.message}`);
                    fail(toPublicSshError(err, hostKeyMismatch));
                } else {
                    console.error(`[ssh] connection error: ${err.message}`);
                }
            })
            .on('timeout', () => fail(new PublicError('SSH connection timed out', 504)))
            .on('close', () => fail(new PublicError('SSH connection closed unexpectedly', 502)));

        const connectionConfig = {
            host: address, // 已校验的 IP
            port: nodeInput.port,
            username: nodeInput.username,
            readyTimeout: 15000,
            keepaliveInterval: 20000,
            hostVerifier: (key) => {
                if (!nodeInput.host_fingerprint) return true; // 未提供指纹：无法校验（存在中间人风险）
                const ok = Buffer.isBuffer(key) && sshFingerprint(key) === nodeInput.host_fingerprint;
                if (!ok) hostKeyMismatch = true;
                return ok;
            },
            [nodeInput.auth_type === 'password' ? 'password' : 'privateKey']: nodeInput.auth_value,
        };

        try {
            conn.connect(connectionConfig);
        } catch (err) {
            fail(toPublicSshError(err, false));
        }
    });
}

// =====================================================================
// HTTP 中间件
// =====================================================================
// 前后端分离部署：本服务只输出 JSON 和 WebSocket，不再提供任何 HTML/静态资源
// （前端是独立部署在别处的静态站点，例如 Vercel）。CSP 仍然收紧到最严格的默认值。
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'none'"],
            frameAncestors: ["'none'"],
            baseUri: ["'none'"],
        },
    },
}));

const corsOptions = {
    // 不再抛出 Error（会产生 500 + 堆栈），未允许的来源只是不返回 CORS 头
    origin: (origin, callback) => callback(null, !origin || allowedOrigins.includes(origin)),
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    maxAge: 600,
};
app.use(cors(corsOptions));

const apiGuards = {
    /** CORS 只约束浏览器读取响应，服务端仍需主动拒绝非法来源 */
    origin(req, res, next) {
        const origin = req.headers.origin;
        if (origin && !allowedOrigins.includes(origin)) {
            return res.status(403).json({ success: false, error: ['Origin not allowed'] });
        }
        next();
    },
    noStore(req, res, next) {
        res.set('Cache-Control', 'no-store');
        next();
    },
    rateLimit(req, res, next) {
        if (!httpRateLimit(getClientIp(req))) {
            res.set('Retry-After', String(Math.ceil(LIMITS.HTTP_RATE.windowMs / 1000)));
            return res.status(429).json({ success: false, error: ['Too many requests'] });
        }
        next();
    },
    auth(req, res, next) {
        const match = /^Bearer\s+(.+)$/i.exec(req.headers.authorization || '');
        if (!match || !isValidToken(match[1])) {
            res.set('WWW-Authenticate', 'Bearer');
            return res.status(401).json({ success: false, error: ['Unauthorized'] });
        }
        next();
    },
};

app.use('/api', apiGuards.origin, apiGuards.noStore, apiGuards.rateLimit);

// --- Health check (used by Render, uptime monitors, etc.) ---
// Deliberately not under /api so it isn't subject to apiGuards.auth — it leaks
// no information beyond "the process is up".
app.get('/', (req, res) => {
    res.json({ status: 'ok', service: 'ssh-gateway-backend' });
});

app.get('/api', (req, res) => {
    res.json({
        status: 'ok',
        message: 'SSH WebSocket Gateway is running',
        available_endpoints: {
            api_health_check: 'GET /api',
            ssh_websocket: 'WebSocket /ws/ssh',
        },
    });
});

// 说明：此前存在的 POST /api/ssh/test（用于在打开交互式 shell 前，
// 先执行一批任意命令做连通性测试）已按要求整体移除，以缩小攻击面——
// 现在服务端唯一能对目标主机执行操作的入口是交互式 WebSocket shell。

// --- 404 & 统一错误处理（不向客户端泄露堆栈/内部信息） ---
app.use((req, res) => {
    res.status(404).json({ success: false, error: ['Not found'] });
});
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);
    if (err && err.type === 'entity.too.large') {
        return res.status(413).json({ success: false, error: ['Request body too large'] });
    }
    if (err instanceof SyntaxError && err.status === 400) {
        return res.status(400).json({ success: false, error: ['Invalid JSON body'] });
    }
    console.error('[http] unhandled error:', err);
    res.status(500).json({ success: false, error: ['Internal server error'] });
});

// =====================================================================
// WebSocket SSH Shell
// =====================================================================
const safeSend = (ws, data) => {
    if (ws.readyState === WebSocket.OPEN) ws.send(data);
};

/**
 * 协议：第一条消息必须是 JSON：{ token, name, host, port, username, auth_type, auth_value, host_fingerprint? }
 * 之后的所有消息原样写入 SSH shell。
 * 令牌放在首条消息而不是 URL 里，避免出现在访问日志/浏览器历史中。
 */
function handleWebSocketConnection(ws, req, clientIp) {
    console.log(`[ws] client connected: ${clientIp}`);

    // awaiting_auth -> connecting -> ready -> closed
    let state = 'awaiting_auth';
    let sshConn = null;
    let sshStream = null;
    let idleTimer = null;

    const sendWsError = (message) => safeSend(ws, `\r\n\u001b[31mError: ${message}\u001b[0m\r\n`);

    const authTimer = setTimeout(() => {
        if (state === 'awaiting_auth') {
            sendWsError('Handshake timeout');
            ws.close(1008, 'Handshake timeout');
        }
    }, LIMITS.WS_AUTH_TIMEOUT_MS);

    const resetIdleTimer = () => {
        clearTimeout(idleTimer);
        idleTimer = setTimeout(() => {
            safeSend(ws, '\r\nSession closed due to inactivity.\r\n');
            ws.close(1000, 'Idle timeout');
        }, LIMITS.WS_IDLE_TIMEOUT_MS);
    };

    const cleanup = () => {
        if (state === 'closed') return;
        state = 'closed';
        clearTimeout(authTimer);
        clearTimeout(idleTimer);
        if (sshStream) sshStream.end();
        if (sshConn) sshConn.end();
        sshStream = null;
        sshConn = null;
    };

    // 二进制帧 = 控制消息（目前只有 resize）；文本帧 = 握手 JSON（首条）或终端输入（之后）。
    // 键盘输入始终以文本帧发送，因此这样区分不会和任何可能的按键内容冲突。
    ws.on('message', async (message, isBinary) => {
        if (state === 'ready') {
            if (isBinary) {
                try {
                    const frame = ResizeFrameSchema.parse(JSON.parse(message.toString('utf-8')));
                    if (sshStream) sshStream.setWindow(frame.rows, frame.cols, 0, 0);
                } catch {
                    // 畸形的控制帧直接忽略，不应影响正在进行的会话
                }
                return;
            }
            resetIdleTimer();
            if (sshStream && sshStream.writable) sshStream.write(message);
            return;
        }
        // 连接建立期间/已关闭后收到的消息直接丢弃，避免重复发起 SSH 连接
        if (state !== 'awaiting_auth' || isBinary) return;

        state = 'connecting';
        clearTimeout(authTimer);

        try {
            let payload;
            try {
                payload = JSON.parse(message.toString());
            } catch {
                throw new PublicError('Invalid handshake message');
            }
            if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
                throw new PublicError('Invalid handshake message');
            }

            const { token, cols, rows, ...nodeInfo } = payload;
            if (!isValidToken(token)) {
                sendWsError('Unauthorized');
                ws.close(1008, 'Unauthorized');
                return;
            }

            const nodeInput = NodeSchema.parse(nodeInfo);
            // 初始 PTY 尺寸随握手一起发来，省去连接后再补发一次 resize；
            // 缺失或超出范围时退回一个安全的默认值，而不是让整次握手失败。
            const ptySize = PtySizeSchema.safeParse({ cols, rows });
            const initialSize = ptySize.success ? ptySize.data : { cols: 80, rows: 24 };

            safeSend(ws, `\r\nConnecting to ${nodeInput.name} (${nodeInput.host})...\r\n`);
            const conn = await connectSsh(nodeInput);
            if (state === 'closed') { // 连接期间客户端已断开
                conn.end();
                return;
            }
            sshConn = conn;
            conn.on('close', () => {
                if (state !== 'closed') {
                    safeSend(ws, '\r\nSSH connection closed.\r\n');
                    ws.close();
                }
            });
            safeSend(ws, 'SSH connection established. Opening shell...\r\n');

            conn.shell({
                term: 'xterm-256color',
                pty: true,
                cols: initialSize.cols,
                rows: initialSize.rows,
            }, (err, stream) => {
                if (err) {
                    console.error(`[ssh] shell failed: ${err.message}`);
                    sendWsError('Shell creation failed');
                    ws.close();
                    return;
                }
                if (state === 'closed') {
                    stream.end();
                    return;
                }
                sshStream = stream;
                state = 'ready';
                resetIdleTimer();
                safeSend(ws, 'Shell ready.\r\n');

                stream.on('error', (e) => console.error(`[ssh] stream error: ${e.message}`));
                stream.on('data', (data) => {
                    if (ws.readyState !== WebSocket.OPEN) return;
                    ws.send(data.toString('utf-8'));
                    // 背压：客户端消费太慢时暂停读取，避免服务端内存无限增长
                    if (ws.bufferedAmount > LIMITS.WS_MAX_BUFFERED_BYTES) {
                        stream.pause();
                        const poll = setInterval(() => {
                            if (state === 'closed' || ws.bufferedAmount < LIMITS.WS_MAX_BUFFERED_BYTES / 2) {
                                clearInterval(poll);
                                if (state !== 'closed') stream.resume();
                            }
                        }, 100);
                    }
                });
                stream.on('close', () => {
                    safeSend(ws, '\r\nSSH shell session ended.\r\n');
                    ws.close();
                });
            });
        } catch (error) {
            if (error instanceof ZodError) {
                sendWsError(error.issues.map((e) => e.message).join(', '));
            } else if (error instanceof PublicError) {
                sendWsError(error.message);
            } else {
                console.error('[ws] unexpected error:', error);
                sendWsError('Internal server error');
            }
            ws.close();
        }
    });

    ws.on('close', () => {
        console.log(`[ws] client disconnected: ${clientIp}`);
        cleanup();
    });

    ws.on('error', (error) => {
        console.error(`[ws] error: ${error.message}`);
        cleanup();
        ws.terminate();
    });
}

// 每个 IP 的并发连接数
const ipConnections = new Map();

wss.on('connection', (ws, req) => {
    const ip = getClientIp(req);
    ipConnections.set(ip, (ipConnections.get(ip) || 0) + 1);
    ws.once('close', () => {
        const n = (ipConnections.get(ip) || 1) - 1;
        if (n <= 0) ipConnections.delete(ip);
        else ipConnections.set(ip, n);
    });

    // 心跳：清理半开连接
    ws.isAlive = true;
    ws.on('pong', () => { ws.isAlive = true; });

    handleWebSocketConnection(ws, req, ip);
});

const heartbeat = setInterval(() => {
    for (const ws of wss.clients) {
        if (ws.isAlive === false) {
            ws.terminate();
            continue;
        }
        ws.isAlive = false;
        ws.ping();
    }
}, 30_000);
heartbeat.unref();

function rejectUpgrade(socket, status, message) {
    socket.write(`HTTP/1.1 ${status} ${message}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
    socket.destroy();
}

// Manually handle HTTP Upgrade requests for WebSocket path routing
server.on('upgrade', (request, socket, head) => {
    const onSocketError = (err) => console.warn(`[ws] socket error during upgrade: ${err.message}`);
    socket.on('error', onSocketError);

    // 使用固定 base，不信任 Host 头（畸形 Host 会让 new URL 抛异常，进而使进程崩溃）
    let pathname;
    try {
        pathname = new URL(request.url, 'http://localhost').pathname;
    } catch {
        return rejectUpgrade(socket, 400, 'Bad Request');
    }
    if (pathname !== '/ws/ssh') return rejectUpgrade(socket, 404, 'Not Found');

    // CORS 对 WebSocket 不生效，必须手动校验 Origin（防止跨站 WebSocket 劫持）
    const origin = request.headers.origin;
    if (origin && !allowedOrigins.includes(origin)) return rejectUpgrade(socket, 403, 'Forbidden');

    const ip = getClientIp(request);
    if (!wsRateLimit(ip)) return rejectUpgrade(socket, 429, 'Too Many Requests');
    if (wss.clients.size >= LIMITS.WS_MAX_TOTAL || (ipConnections.get(ip) || 0) >= LIMITS.WS_MAX_PER_IP) {
        return rejectUpgrade(socket, 503, 'Service Unavailable');
    }

    wss.handleUpgrade(request, socket, head, (ws) => {
        socket.removeListener('error', onSocketError);
        wss.emit('connection', ws, request);
    });
});

// --- Start Server ---
server.listen(PORT, () => {
    console.log(`Server is running on port: ${PORT}`);
    console.log(`Allowed Origins: ${allowedOrigins.join(', ')}`);
    console.log(`Private targets ${ALLOW_PRIVATE_TARGETS ? 'ALLOWED' : 'blocked'}; proxy hops: ${TRUST_PROXY_HOPS}`);
    if (!IS_PRODUCTION) console.log('NODE_ENV is not "production"');
});
