/**
 * F.E.A.R. WebSocket-TCP Bridge Server
 *
 * Accepts WebSocket connections from browsers and proxies them
 * to the F.E.A.R. TCP server. Each browser client gets its own
 * TCP connection. The bridge sees only ciphertext.
 *
 * Usage: PORT=3000 node server.js
 */

const express = require('express');
const http = require('http');
const { WebSocketServer } = require('ws');
const net = require('net');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

app.use(express.static(path.join(__dirname, 'public')));

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

    if (clen > 10 * 1024 * 1024) return { error: 'frame too large' };
    if (pos + clen > end) return null;
    pos += clen;

    const consumed = pos - offset;
    const frame = Buffer.alloc(consumed);
    buf.copy(frame, 0, offset, pos);
    return { frame, consumed };
}

wss.on('connection', (ws, req) => {
    const clientIP = req.socket.remoteAddress;
    console.log(`[bridge] WS client connected from ${clientIP}`);

    let tcpSocket = null;
    let tcpBuffer = Buffer.alloc(0);
    let connected = false;

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

                console.log(`[bridge] Connecting TCP to ${host}:${port} for ${clientIP}`);

                tcpSocket = new net.Socket();
                tcpSocket.connect(port, host, () => {
                    connected = true;
                    console.log(`[bridge] TCP connected to ${host}:${port}`);
                    ws.send(JSON.stringify({ type: 'connected' }));
                });

                tcpSocket.on('data', (chunk) => {
                    // Buffer TCP data and extract complete frames
                    tcpBuffer = Buffer.concat([tcpBuffer, chunk]);

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
                    console.error(`[bridge] TCP error: ${err.message}`);
                    if (ws.readyState === 1) {
                        ws.send(JSON.stringify({ type: 'error', message: `TCP error: ${err.message}` }));
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
        if (tcpSocket && !tcpSocket.destroyed) {
            tcpSocket.destroy();
        }
    });

    ws.on('error', (err) => {
        console.error(`[bridge] WS error: ${err.message}`);
        if (tcpSocket && !tcpSocket.destroyed) {
            tcpSocket.destroy();
        }
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
    console.log(`[bridge] F.E.A.R. Web Bridge listening on port ${PORT}`);
    console.log(`[bridge] Open http://localhost:${PORT} in your browser`);
});
