/**
 * F.E.A.R. WebSocket-TCP Bridge Server
 *
 * Accepts WebSocket connections from browsers and proxies them
 * to the F.E.A.R. TCP server. Each browser client gets its own
 * TCP connection. The bridge sees only ciphertext.
 *
 * Usage: PORT=3000 node server.js
 *
 * Security configuration (environment):
 *   FEAR_ALLOWED_TARGETS   comma-separated "host:port" the bridge may dial.
 *                          Default: 127.0.0.1:8888
 *   FEAR_ALLOW_ANY_TARGET  set to "1" to disable the allowlist. LOCAL DEV ONLY -
 *                          this re-enables the SSRF / open-proxy behaviour.
 *   FEAR_ALLOWED_ORIGINS   comma-separated browser origins (host[:port]).
 *                          Default: same-origin only.
 */

const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const net = require('net');
const path = require('path');

const app = express();
const server = http.createServer(app);

/* ---------------------------------------------------------------------------
 * Security configuration
 *
 * The bridge used to open a TCP connection to any host:port a browser asked
 * for, which turned a public deployment into an unauthenticated SSRF / open
 * proxy: internal port scanning (distinguishable via `connected` vs `error`),
 * cloud metadata at 169.254.169.254, and attacks sourced from this server's IP.
 * Targets are now strictly allowlisted and upstream errors are not echoed back.
 * ------------------------------------------------------------------------- */

const ALLOWED_TARGETS = new Set(
    (process.env.FEAR_ALLOWED_TARGETS || '127.0.0.1:8888')
        .split(',').map(s => s.trim().toLowerCase()).filter(Boolean)
);
const ALLOW_ANY_TARGET = process.env.FEAR_ALLOW_ANY_TARGET === '1';

const ALLOWED_ORIGINS = (process.env.FEAR_ALLOWED_ORIGINS || '')
    .split(',').map(s => s.trim().toLowerCase()).filter(Boolean);

const MAX_WS_PAYLOAD  = 1 * 1024 * 1024;   /* bytes per browser->bridge message */
const MAX_TCP_BUFFER  = 2 * 1024 * 1024;   /* pending unparsed upstream bytes    */
const MAX_FRAME_CLEN  = 1 * 1024 * 1024;   /* ciphertext length inside one frame */
const MAX_CONN_PER_IP = 16;   /* several users often share one NAT address */
const TCP_CONNECT_MS  = 10000;

/** Live WebSocket connections per client IP, for the per-IP cap. */
const connectionsByIp = new Map();

function targetAllowed(host, port) {
    if (ALLOW_ANY_TARGET) return true;
    return ALLOWED_TARGETS.has(`${String(host).trim().toLowerCase()}:${port}`);
}

/**
 * WebSocket handshakes are not subject to the same-origin policy, so without
 * this check any third-party site could drive the bridge from a visitor's
 * browser. Non-browser clients send no Origin and are allowed through - this
 * complements, and does not replace, the target allowlist above.
 */
function originAllowed(req) {
    const origin = req.headers.origin;
    if (!origin) return true;
    let originHost;
    try {
        originHost = new URL(origin).host.toLowerCase();
    } catch (e) {
        return false;
    }
    if (ALLOWED_ORIGINS.length > 0) return ALLOWED_ORIGINS.includes(originHost);
    return originHost === String(req.headers.host || '').toLowerCase();
}

/* Security headers. All crypto runs in this origin, so without a CSP a single
 * XSS would exfiltrate the identity key and every room key. */
app.use((req, res, next) => {
    res.setHeader('Content-Security-Policy',
        "default-src 'self'; script-src 'self'; style-src 'self'; " +
        "img-src 'self' data:; connect-src 'self'; object-src 'none'; " +
        "base-uri 'none'; frame-ancestors 'none'; form-action 'none'");
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    }
    next();
});

app.use(express.static(path.join(__dirname, 'public')));

const wss = new WebSocketServer({
    server,
    maxPayload: MAX_WS_PAYLOAD,
    verifyClient: (info, cb) => {
        if (!originAllowed(info.req)) {
            console.warn(`[bridge] Rejected WS handshake from origin ${info.req.headers.origin}`);
            return cb(false, 403, 'Forbidden origin');
        }
        cb(true);
    },
});

/**
 * Parse one complete F.E.A.R. frame from a buffer.
 * Returns { frame, consumed } or null if not enough data.
 *
 * Wire format:
 *   [2 roomLen][room][2 nameLen][name][2 nonceLen][nonce][1 type][4 clen][cipher]
 */
function tryParseFrame(buf, offset, length) {
    let pos = offset;
    const end = offset + length;

    // roomLen (2)
    if (pos + 2 > end) return null;
    const roomLen = buf[pos] | (buf[pos + 1] << 8);
    pos += 2;
    if (pos + roomLen > end) return null;
    pos += roomLen;

    // nameLen (2)
    if (pos + 2 > end) return null;
    const nameLen = buf[pos] | (buf[pos + 1] << 8);
    pos += 2;
    if (pos + nameLen > end) return null;
    pos += nameLen;

    // nonceLen (2)
    if (pos + 2 > end) return null;
    const nonceLen = buf[pos] | (buf[pos + 1] << 8);
    pos += 2;
    if (pos + nonceLen > end) return null;
    pos += nonceLen;

    // type (1)
    if (pos + 1 > end) return null;
    pos += 1;

    // clen (4)
    if (pos + 4 > end) return null;
    const clen = buf[pos] | (buf[pos + 1] << 8) | (buf[pos + 2] << 16) | ((buf[pos + 3] << 24) >>> 0);
    pos += 4;

    if (clen > MAX_FRAME_CLEN) return { error: 'frame too large' };
    if (pos + clen > end) return null;
    pos += clen;

    const consumed = pos - offset;
    const frame = Buffer.alloc(consumed);
    buf.copy(frame, 0, offset, pos);
    return { frame, consumed };
}

wss.on('connection', (ws, req) => {
    const clientIP = req.socket.remoteAddress;

    const ipCount = (connectionsByIp.get(clientIP) || 0) + 1;
    if (ipCount > MAX_CONN_PER_IP) {
        console.warn(`[bridge] Connection cap reached for ${clientIP}`);
        ws.close(1013, 'Too many connections');
        return;
    }
    connectionsByIp.set(clientIP, ipCount);

    console.log(`[bridge] WS client connected from ${clientIP} (${ipCount} open)`);

    let tcpSocket = null;
    let tcpBuffer = Buffer.alloc(0);
    let connected = false;

    /* 'error' is normally followed by 'close', so guard against double-release. */
    let ipReleased = false;
    const releaseIp = () => {
        if (ipReleased) return;
        ipReleased = true;
        const n = (connectionsByIp.get(clientIP) || 1) - 1;
        if (n > 0) connectionsByIp.set(clientIP, n);
        else connectionsByIp.delete(clientIP);
    };

    ws.on('message', (data, isBinary) => {
        // First message must be JSON connect command
        if (!connected) {
            try {
                const msg = JSON.parse(data.toString());
                if (msg.type !== 'connect' || !msg.host || !msg.port) {
                    ws.send(JSON.stringify({ type: 'error', message: 'First message must be { type: "connect", host, port }' }));
                    return;
                }

                const host = msg.host;
                const port = parseInt(msg.port, 10);
                if (isNaN(port) || port < 1 || port > 65535) {
                    ws.send(JSON.stringify({ type: 'error', message: 'Invalid port' }));
                    return;
                }

                if (!targetAllowed(host, port)) {
                    console.warn(`[bridge] BLOCKED target ${host}:${port} requested by ${clientIP}`);
                    ws.send(JSON.stringify({ type: 'error', message: 'Target not allowed' }));
                    ws.close();
                    return;
                }

                console.log(`[bridge] Connecting TCP to ${host}:${port} for ${clientIP}`);

                tcpSocket = new net.Socket();
                tcpSocket.setTimeout(TCP_CONNECT_MS);
                tcpSocket.on('timeout', () => {
                    if (!connected) {
                        console.warn(`[bridge] TCP connect timed out for ${clientIP}`);
                        tcpSocket.destroy();
                    }
                });

                tcpSocket.connect(port, host, () => {
                    connected = true;
                    tcpSocket.setTimeout(0);   /* only bound the connect phase */
                    console.log(`[bridge] TCP connected to ${host}:${port}`);
                    ws.send(JSON.stringify({ type: 'connected' }));
                });

                tcpSocket.on('data', (chunk) => {
                    // Buffer TCP data and extract complete frames
                    tcpBuffer = Buffer.concat([tcpBuffer, chunk]);

                    if (tcpBuffer.length > MAX_TCP_BUFFER) {
                        console.error(`[bridge] Upstream buffer limit exceeded for ${clientIP}`);
                        tcpSocket.destroy();
                        if (ws.readyState === 1) ws.close();
                        return;
                    }

                    while (tcpBuffer.length > 0) {
                        const result = tryParseFrame(tcpBuffer, 0, tcpBuffer.length);
                        if (result === null) break; // need more data
                        if (result.error) {
                            console.error(`[bridge] Frame parse error: ${result.error}`);
                            tcpBuffer = Buffer.alloc(0);
                            break;
                        }
                        // Send complete frame to browser as binary
                        if (ws.readyState === 1) {
                            ws.send(result.frame);
                        }
                        tcpBuffer = tcpBuffer.slice(result.consumed);
                    }
                });

                tcpSocket.on('error', (err) => {
                    /* Logged locally only: echoing err.message back to the browser
                     * turned the bridge into a precise open/closed/filtered oracle
                     * for internal hosts. */
                    console.error(`[bridge] TCP error: ${err.message}`);
                    if (ws.readyState === 1) {
                        ws.send(JSON.stringify({ type: 'error', message: 'Upstream connection failed' }));
                    }
                });

                tcpSocket.on('close', () => {
                    console.log(`[bridge] TCP closed for ${clientIP}`);
                    connected = false;
                    if (ws.readyState === 1) {
                        ws.send(JSON.stringify({ type: 'disconnected' }));
                        ws.close();
                    }
                });

            } catch (e) {
                ws.send(JSON.stringify({ type: 'error', message: 'Invalid JSON' }));
            }
            return;
        }

        // Connected: forward binary WS data to TCP
        if (tcpSocket && !tcpSocket.destroyed) {
            const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
            tcpSocket.write(buf);
        }
    });

    ws.on('close', () => {
        console.log(`[bridge] WS closed for ${clientIP}`);
        releaseIp();
        if (tcpSocket && !tcpSocket.destroyed) {
            tcpSocket.destroy();
        }
    });

    ws.on('error', (err) => {
        console.error(`[bridge] WS error: ${err.message}`);
        releaseIp();
        if (tcpSocket && !tcpSocket.destroyed) {
            tcpSocket.destroy();
        }
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
    console.log(`[bridge] F.E.A.R. Web Bridge listening on port ${PORT}`);
    console.log(`[bridge] Open http://localhost:${PORT} in your browser`);
    if (ALLOW_ANY_TARGET) {
        console.warn('[bridge] WARNING: FEAR_ALLOW_ANY_TARGET=1 - target allowlist disabled (SSRF risk).');
    } else {
        console.log(`[bridge] Allowed targets: ${[...ALLOWED_TARGETS].join(', ')}`);
    }
    console.log(`[bridge] Allowed origins: ${ALLOWED_ORIGINS.length ? ALLOWED_ORIGINS.join(', ') : 'same-origin only'}`);
});
