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
//   API_TOKEN               必填。API / 浏览器 WebSocket 的访问令牌；WebSocket 中只会在 E2E 加密载荷里出现。
//   ALLOWED_ORIGINS         强烈建议设置。逗号分隔的允许来源，例如前端部署在 Vercel 后的域名
//                           （https://your-app.vercel.app）。前后端分离部署后不再有"默认可信来源"，
//                           不设置时仅在非生产环境放行 http://localhost:5173 方便本地调试。
//   TRUST_PROXY_HOPS        可选。前面有几层可信反向代理（Render 的边缘代理等），默认 0
//   ALLOW_PRIVATE_TARGETS   可选。设为 true 才允许连接内网/回环/链路本地地址，默认禁止
//   REQUIRE_HOST_FINGERPRINT可选。设为 true 则强制客户端提供 host_fingerprint。st_fingerprint（防中间人）
const PORT = process.env.PORT || 3000;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

const csv = (value) => (value || '').split(',').map((s) => s.trim()).filter(Boolean);

const API_TOKEN = process.env.API_TOKEN || '';
if (API_TOKEN.length < 16) {
    console.error('FATAL: 必须设置 API_TOKEN 环境变量（至少 16 个字符，例如: openssl rand -hex 32）');
    process.exit(1);
}
const API_TOKEN_HASH = crypto.createHash('sha256').update(API_TOKEN).digest();

// E2E application-layer encryption:
// - Browser receives ONLY the public key.
// - Backend keeps the RSA private key exclusively in E2E_PRIVATE_KEY_PEM.
// - SSH credentials, host data, PTY controls, keyboard input and SSH output
//   are encrypted with an ephemeral AES-256-GCM session key.
const E2E_PRIVATE_KEY_PEM = process.env.E2E_PRIVATE_KEY_PEM || '';
if (!E2E_PRIVATE_KEY_PEM) {
    console.error('FATAL: 必须设置 E2E_PRIVATE_KEY_PEM（RSA 私钥 PEM）。私钥不得放入前端。');
    process.exit(1);
}
let E2E_PUBLIC_KEY_PEM;
try {
    const privateKey = crypto.createPrivateKey(E2E_PRIVATE_KEY_PEM);
    E2E_PUBLIC_KEY_PEM = crypto.createPublicKey(privateKey).export({
        type: 'spki',
        format: 'pem',
    });
} catch (error) {
    console.error('FATAL: E2E_PRIVATE_KEY_PEM 不是有效的 RSA 私钥 PEM:', error.message);
    process.exit(1);
}

const TRUST_PROXY_HOPS = Math.max(0, parseInt(process.env.TRUST_PROXY_HOPS || '0', 10) || 0);
const ALLOW_PRIVATE_TARGETS = process.env.ALLOW_PRIVATE_TARGETS === 'true';
const REQUIRE_HOST_FINGERPRINT = process.env.REQUIRE_HOST_FINGERPRINT === 'true';
const REQUIRE_ACCESS_TOKEN = process.env.REQUIRE_ACCESS_TOKEN !== 'false';

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

const E2E_VERSION = 1;
const E2E_RSA_PADDING = crypto.constants.RSA_PKCS1_OAEP_PADDING;
const E2E_RSA_HASH = 'sha256';
const E2E_IV_BYTES = 12;
const E2E_MAX_PLAINTEXT_BYTES = 24 * 1024;

// base64url is compact and safe inside JSON/WebSocket text frames.
function b64uEncode(buffer) {
    return Buffer.from(buffer).toString('base64url');
}
function b64uDecode(value, label = 'base64url field') {
    if (typeof value !== 'string' || value.length === 0 || value.length > 100_000) {
        throw new PublicError(`Invalid ${label}`);
    }
    try {
        return Buffer.from(value, 'base64url');
    } catch {
        throw new PublicError(`Invalid ${label}`);
    }
}

function rsaUnwrapSessionKey(wrapped) {
    try {
        const key = crypto.privateDecrypt(
            {
                key: E2E_PRIVATE_KEY_PEM,
                padding: E2E_RSA_PADDING,
                oaepHash: E2E_RSA_HASH,
            },
            wrapped,
        );
        if (key.length !== 32) throw new Error('unexpected AES key length');
        return key;
    } catch {
        throw new PublicError('Invalid encrypted handshake');
    }
}

function aesDecrypt(sessionKey, envelope, direction) {
    if (!envelope || envelope.v !== E2E_VERSION || envelope.type !== 'data') {
        throw new PublicError('Invalid encrypted frame');
    }
    if (!Number.isSafeInteger(envelope.seq) || envelope.seq < 0) {
        throw new PublicError('Invalid encrypted frame sequence');
    }

    const iv = b64uDecode(envelope.iv, 'IV');
    const ciphertext = b64uDecode(envelope.data, 'ciphertext');
    if (iv.length !== E2E_IV_BYTES || ciphertext.length < 16 || ciphertext.length > E2E_MAX_PLAINTEXT_BYTES + 16) {
        throw new PublicError('Invalid encrypted frame');
    }

    const aad = Buffer.from(`ssh-gateway:v${E2E_VERSION}:${direction}:${envelope.seq}`, 'utf8');
    try {
        const decipher = crypto.createDecipheriv('aes-256-gcm', sessionKey, iv);
        decipher.setAAD(aad);
        const tag = ciphertext.subarray(ciphertext.length - 16);
        decipher.setAuthTag(tag);
        return Buffer.concat([
            decipher.update(ciphertext.subarray(0, -16)),
            decipher.final(),
        ]);
    } catch {
        throw new PublicError('Encrypted frame authentication failed');
    }
}

function aesEncrypt(sessionKey, seq, plaintext, direction) {
    const input = Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(String(plaintext), 'utf8');
    if (input.length > E2E_MAX_PLAINTEXT_BYTES) throw new PublicError('Encrypted payload too large');
    const iv = crypto.randomBytes(E2E_IV_BYTES);
    const aad = Buffer.from(`ssh-gateway:v${E2E_VERSION}:${direction}:${seq}`, 'utf8');
    const cipher = crypto.createCipheriv('aes-256-gcm', sessionKey, iv);
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(input), cipher.final(), cipher.getAuthTag()]);
    return JSON.stringify({
        v: E2E_VERSION,
        type: 'data',
        seq,
        iv: b64uEncode(iv),
        data: b64uEncode(ciphertext),
    });
}

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
const blockedIpv4Ranges = new net.BlockList();
const blockedIpv6Ranges = new net.BlockList();

[
    ['0.0.0.0', 8],
    ['10.0.0.0', 8],
    ['100.64.0.0', 10],
    ['127.0.0.0', 8],
    ['169.254.0.0', 16],
    ['172.16.0.0', 12],
    ['192.0.0.0', 24],
    ['192.168.0.0', 16],
    ['198.18.0.0', 15],
    ['224.0.0.0', 4],
    ['240.0.0.0', 4],
].forEach(([address, prefix]) => {
    blockedIpv4Ranges.addSubnet(address, prefix, 'ipv4');
});

[
    ['::', 128],
    ['::1', 128],
    ['64:ff9b::', 96],
    ['fc00::', 7],
    ['fe80::', 10],
    ['ff00::', 8],
].forEach(([address, prefix]) => {
    blockedIpv6Ranges.addSubnet(address, prefix, 'ipv6');
});

function isBlockedAddress(address, family) {
    if (Number(family) === 4) {
        return blockedIpv4Ranges.check(address, 'ipv4');
    }

    if (Number(family) === 6) {
        return blockedIpv6Ranges.check(address, 'ipv6');
    }

    return true;
}


async function resolveTarget(host) {
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

    if (!addresses.length) {
        throw new PublicError('Unable to resolve host', 502);
    }

    if (!ALLOW_PRIVATE_TARGETS) {
        for (const { address, family } of addresses) {
            if (isBlockedAddress(address, family)) {
                throw new PublicError('Target address is private or reserved', 403);
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

// --- Public E2E key. This endpoint exposes no secret; only the RSA public key. ---
app.get('/e2e/public-key', apiGuards.origin, apiGuards.noStore, (req, res) => {
    res.type('text/plain').send(E2E_PUBLIC_KEY_PEM);
});

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
// WebSocket SSH Shell — encrypted application protocol
// =====================================================================
function handleWebSocketConnection(ws, req, clientIp) {
    console.log(`[ws] client connected: ${clientIp}`);

    // awaiting_handshake -> connecting -> ready -> closed
    let state = 'awaiting_handshake';
    let sshConn = null;
    let sshStream = null;
    let idleTimer = null;
    let sessionKey = null;
    let nextClientSeq = 0;
    let nextServerSeq = 0;

    const sendEncrypted = (plaintext) => {
        if (!sessionKey || ws.readyState !== WebSocket.OPEN) return;
        const payload = aesEncrypt(sessionKey, nextServerSeq++, plaintext, 's2c');
        ws.send(payload);
    };

    const sendWsError = (message) => {
        if (sessionKey) {
            try { sendEncrypted(`\r\n\u001b[31mError: ${message}\u001b[0m\r\n`); } catch {}
        }
    };

    const authTimer = setTimeout(() => {
        if (state === 'awaiting_handshake') {
            ws.close(1008, 'Handshake timeout');
        }
    }, LIMITS.WS_AUTH_TIMEOUT_MS);

    const resetIdleTimer = () => {
        clearTimeout(idleTimer);
        idleTimer = setTimeout(() => {
            if (sessionKey) {
                try { sendEncrypted('\r\nSession closed due to inactivity.\r\n'); } catch {}
            }
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
        if (sessionKey) sessionKey.fill(0);
        sessionKey = null;
    };

    // Frames can arrive immediately after the encrypted handshake while the SSH
    // connection/shell is still being established. They must not be discarded,
    // otherwise seq=0 can be lost and the next frame (seq=1) looks like a replay.
    const pendingClientFrames = [];
    let pendingClientBytes = 0;
    const MAX_PENDING_CLIENT_FRAMES = 64;
    const MAX_PENDING_CLIENT_BYTES = 256 * 1024;

    const handleClientPlaintext = (plaintext) => {
        resetIdleTimer();

        const text = plaintext.toString('utf8');
        let handledControl = false;
        try {
            const maybeControl = JSON.parse(text);
            if (maybeControl && maybeControl.type === 'resize') {
                const frame = ResizeFrameSchema.parse(maybeControl);
                if (sshStream) {
                    sshStream.setWindow(frame.rows, frame.cols, 0, 0);
                } else {
                    // The handshake already carries the initial PTY size. Queue
                    // later resizes so the latest browser dimensions are applied
                    // once the shell exists.
                    if (pendingClientFrames.length >= MAX_PENDING_CLIENT_FRAMES ||
                        pendingClientBytes + 32 > MAX_PENDING_CLIENT_BYTES) {
                        throw new PublicError('Too many pending terminal frames', 429);
                    }
                    pendingClientFrames.push({ plaintext: null, resize: frame });
                    pendingClientBytes += 32;
                }
                handledControl = true;
            }
        } catch (error) {
            if (error instanceof PublicError) throw error;
            // Not a control frame; treat it as terminal input.
        }

        if (!handledControl && sshStream && sshStream.writable) {
            sshStream.write(plaintext);
            return;
        }

        if (!handledControl && !sshStream) {
            if (pendingClientFrames.length >= MAX_PENDING_CLIENT_FRAMES ||
                pendingClientBytes + plaintext.length > MAX_PENDING_CLIENT_BYTES) {
                throw new PublicError('Too many pending terminal frames', 429);
            }
            pendingClientFrames.push({ plaintext: Buffer.from(plaintext), resize: null });
            pendingClientBytes += plaintext.length;
        }
    };

    const flushPendingClientFrames = () => {
        if (!sshStream || !sshStream.writable) return;
        for (const frame of pendingClientFrames) {
            if (frame.resize) sshStream.setWindow(frame.resize.rows, frame.resize.cols, 0, 0);
            else if (frame.plaintext) sshStream.write(frame.plaintext);
        }
        pendingClientFrames.length = 0;
        pendingClientBytes = 0;
    };

    ws.on('message', async (message, isBinary) => {
        if (state === 'connecting' || state === 'ready') {
            if (isBinary) {
                // Binary frames are no longer accepted. All post-handshake
                // traffic uses authenticated encrypted JSON text frames.
                return;
            }

            try {
                const envelope = JSON.parse(message.toString('utf8'));
                if (envelope.v !== E2E_VERSION || envelope.type !== 'data') return;
                if (envelope.seq !== nextClientSeq) {
                    throw new PublicError('Invalid encrypted frame sequence');
                }

                // Authenticate/decrypt before changing the sequence state.
                const plaintext = aesDecrypt(sessionKey, envelope, 'c2s');
                nextClientSeq += 1;
                handleClientPlaintext(plaintext);
            } catch (error) {
                if (error instanceof PublicError) sendWsError(error.message);
                else console.error('[ws] encrypted frame error:', error);
                ws.close(1008, 'Invalid encrypted frame');
            }
            return;
        }

        // Handshake is the only unencrypted frame, and it contains only:
        // RSA-OAEP wrapped ephemeral AES key + AES-GCM ciphertext.
        // The access token itself is inside that AES-GCM ciphertext.
        if (state !== 'awaiting_handshake' || isBinary) return;

        state = 'connecting';
        clearTimeout(authTimer);

        try {
            if (Buffer.byteLength(message) > LIMITS.WS_MAX_PAYLOAD) {
                throw new PublicError('Handshake too large');
            }

            let envelope;
            try {
                envelope = JSON.parse(message.toString('utf8'));
            } catch {
                throw new PublicError('Invalid encrypted handshake');
            }

            if (!envelope || envelope.v !== E2E_VERSION || envelope.type !== 'handshake') {
                throw new PublicError('Invalid encrypted handshake');
            }

            const wrappedKey = b64uDecode(envelope.key, 'wrapped key');
            const iv = b64uDecode(envelope.iv, 'IV');
            const ciphertext = b64uDecode(envelope.data, 'ciphertext');
            if (iv.length !== E2E_IV_BYTES || wrappedKey.length < 256 || wrappedKey.length > 1024 ||
                ciphertext.length < 16 || ciphertext.length > E2E_MAX_PLAINTEXT_BYTES + 16) {
                throw new PublicError('Invalid encrypted handshake');
            }

            sessionKey = rsaUnwrapSessionKey(wrappedKey);

            // Handshake uses seq=0 and the same authenticated framing primitive.
            const plaintext = (() => {
                const aad = Buffer.from(`ssh-gateway:v${E2E_VERSION}:handshake:0`, 'utf8');
                try {
                    const decipher = crypto.createDecipheriv('aes-256-gcm', sessionKey, iv);
                    decipher.setAAD(aad);
                    const tag = ciphertext.subarray(ciphertext.length - 16);
                    decipher.setAuthTag(tag);
                    return Buffer.concat([
                        decipher.update(ciphertext.subarray(0, -16)),
                        decipher.final(),
                    ]);
                } catch {
                    throw new PublicError('Invalid encrypted handshake');
                }
            })();

            let payload;
            try { payload = JSON.parse(plaintext.toString('utf8')); }
            catch { throw new PublicError('Invalid encrypted handshake'); }

            const { cols, rows, ...nodeInfo } = payload || {};
            const nodeInput = NodeSchema.parse(nodeInfo);
            const ptySize = PtySizeSchema.safeParse({ cols, rows });
            const initialSize = ptySize.success ? ptySize.data : { cols: 80, rows: 24 };

            // From this point onward every server->browser byte is encrypted.
            sendEncrypted(`\r\nConnecting to ${nodeInput.name} (${nodeInput.host})...\r\n`);

            const conn = await connectSsh(nodeInput);
            if (state === 'closed') {
                conn.end();
                return;
            }

            sshConn = conn;
            conn.on('close', () => {
                if (state !== 'closed') {
                    try { sendEncrypted('\r\nSSH connection closed.\r\n'); } catch {}
                    ws.close();
                }
            });

            sendEncrypted('SSH connection established. Opening shell...\r\n');

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
                // Replay authenticated frames that arrived while the SSH shell
                // was being established, preserving their original order.
                try {
                    flushPendingClientFrames();
                } catch (error) {
                    console.error('[ws] pending frame replay failed:', error);
                    sendWsError('Pending terminal frame failed');
                    ws.close(1008, 'Pending terminal frame failed');
                    return;
                }
                resetIdleTimer();
                sendEncrypted('Shell ready.\r\n');

                stream.on('error', (e) => console.error(`[ssh] stream error: ${e.message}`));
                stream.on('data', (data) => {
                    if (ws.readyState !== WebSocket.OPEN || !sessionKey) return;
                    try {
                        // Keep each encrypted WebSocket frame comfortably below
                        // the global ws maxPayload after base64/JSON overhead.
                        for (let offset = 0; offset < data.length; offset += E2E_MAX_PLAINTEXT_BYTES) {
                            const chunk = data.subarray(offset, Math.min(offset + E2E_MAX_PLAINTEXT_BYTES, data.length));
                            ws.send(aesEncrypt(sessionKey, nextServerSeq++, chunk, 's2c'));
                        }
                    } catch (error) {
                        console.error('[ws] output encryption error:', error);
                        ws.close();
                        return;
                    }

                    // Backpressure: pause SSH reads if encrypted WS output queues up.
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
                    try { sendEncrypted('\r\nSSH shell session ended.\r\n'); } catch {}
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
            ws.close(1008, 'Handshake failed');
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
    console.log(`Access token required: ${REQUIRE_ACCESS_TOKEN}`);
    if (!IS_PRODUCTION) console.log('NODE_ENV is not "production"');
});
