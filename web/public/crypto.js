/**
 * F.E.A.R. Web Crypto Module
 *
 * AES-256-GCM encryption compatible with F.E.A.R. desktop/Android protocol.
 * Uses libsodium.js (loaded via sodium.js WASM).
 *
 * Protocol constants:
 * - Key: 32 bytes, Nonce: 12 bytes, Tag: 16 bytes
 * - Frame: [2 roomLen][room][2 nameLen][name][2 nonceLen][nonce(12)][1 type][4 clen][cipher]
 * - AD = [2 roomLen][room][2 nameLen][name]
 */

const FearCrypto = (() => {
    'use strict';

    const CRYPTO_KEYBYTES = 32;
    const CRYPTO_NPUBBYTES = 12;
    const CRYPTO_ABYTES = 16;

    // Message types
    const MSG_TYPE_TEXT = 0;
    const MSG_TYPE_FILE_START = 1;
    const MSG_TYPE_FILE_CHUNK = 2;
    const MSG_TYPE_FILE_END = 3;
    const MSG_TYPE_USER_LIST = 4;
    const MSG_TYPE_SIGNED_TEXT = 5;
    const MSG_TYPE_SIGNED_FILE_START = 6;
    const MSG_TYPE_SIGNED_FILE_CHUNK = 7;
    const MSG_TYPE_SIGNED_FILE_END = 8;
    const MSG_TYPE_IDENTITY_ANNOUNCE = 9;
    const MSG_TYPE_KEY_REQUEST = 15;
    const MSG_TYPE_KEY_RESPONSE = 16;
    const MSG_TYPE_MEDIA_RELAY = 17;

    let sodiumReady = false;
    const readyPromise = (async () => {
        let attempts = 0;
        while (typeof sodium === 'undefined' && attempts < 100) {
            await new Promise(r => setTimeout(r, 100));
            attempts++;
        }
        if (typeof sodium === 'undefined') throw new Error('libsodium.js failed to load');
        await sodium.ready;
        if (!sodium.crypto_aead_aes256gcm_is_available || !sodium.crypto_aead_aes256gcm_is_available()) {
            throw new Error('AES-256-GCM not available on this platform. Hardware AES-NI required.');
        }
        sodiumReady = true;
        console.log('[crypto] AES-256-GCM ready');
    })();

    async function ensureReady() {
        if (!sodiumReady) await readyPromise;
    }

    // --- Binary helpers (little-endian) ---

    function writeU16(v) {
        return new Uint8Array([v & 0xFF, (v >> 8) & 0xFF]);
    }

    function readU16(buf, off = 0) {
        return buf[off] | (buf[off + 1] << 8);
    }

    function writeU32(v) {
        return new Uint8Array([v & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF, (v >>> 24) & 0xFF]);
    }

    function readU32(buf, off = 0) {
        return (buf[off] | (buf[off + 1] << 8) | (buf[off + 2] << 16) | (buf[off + 3] << 24)) >>> 0;
    }

    function concat(...bufs) {
        const total = bufs.reduce((s, b) => s + b.length, 0);
        const out = new Uint8Array(total);
        let off = 0;
        for (const b of bufs) { out.set(b, off); off += b.length; }
        return out;
    }

    function strToBytes(s) { return new TextEncoder().encode(s); }
    function bytesToStr(b) { return new TextDecoder().decode(b); }

    // --- Base64url (no padding) ---

    function b64Encode(buf) {
        let bin = '';
        for (let i = 0; i < buf.length; i++) bin += String.fromCharCode(buf[i]);
        return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }

    function b64Decode(str) {
        str = str.replace(/-/g, '+').replace(/_/g, '/');
        while (str.length % 4) str += '=';
        const bin = atob(str);
        const out = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out;
    }

    // --- Service message detection ---

    function isServiceMessage(nonce) {
        for (let i = 0; i < nonce.length; i++) {
            if (nonce[i] !== 0) return false;
        }
        return true;
    }

    // --- Build AD (additional data) ---

    function buildAD(room, name) {
        const rb = strToBytes(room);
        const nb = strToBytes(name);
        return concat(writeU16(rb.length), rb, writeU16(nb.length), nb);
    }

    // --- Frame building ---

    function buildFrame(room, name, nonce, type, payload) {
        const rb = strToBytes(room);
        const nb = strToBytes(name);
        return concat(
            writeU16(rb.length), rb,
            writeU16(nb.length), nb,
            writeU16(nonce.length), nonce,
            new Uint8Array([type]),
            writeU32(payload.length), payload
        );
    }

    async function buildEncryptedFrame(room, name, type, plaintext, key) {
        await ensureReady();
        const nonce = sodium.randombytes_buf(CRYPTO_NPUBBYTES);
        const ad = buildAD(room, name);
        const cipher = sodium.crypto_aead_aes256gcm_encrypt(plaintext, ad, null, nonce, key);
        return buildFrame(room, name, nonce, type, cipher);
    }

    function buildServiceFrame(room, name, type, payload) {
        const zeroNonce = new Uint8Array(CRYPTO_NPUBBYTES);
        return buildFrame(room, name, zeroNonce, type, payload);
    }

    // --- Frame parsing ---

    function parseFrame(data) {
        const buf = data instanceof Uint8Array ? data : new Uint8Array(data);
        let off = 0;

        const roomLen = readU16(buf, off); off += 2;
        const roomBytes = buf.slice(off, off + roomLen); off += roomLen;
        const room = bytesToStr(roomBytes);

        const nameLen = readU16(buf, off); off += 2;
        const nameBytes = buf.slice(off, off + nameLen); off += nameLen;
        const name = bytesToStr(nameBytes);

        const nonceLen = readU16(buf, off); off += 2;
        const nonce = buf.slice(off, off + nonceLen); off += nonceLen;

        const type = buf[off]; off += 1;

        const clen = readU32(buf, off); off += 4;
        const payload = buf.slice(off, off + clen);

        return { room, name, nonce, type, payload, roomBytes, nameBytes };
    }

    async function decryptPayload(payload, nonce, room, name, key) {
        await ensureReady();
        const rb = typeof room === 'string' ? strToBytes(room) : room;
        const nb = typeof name === 'string' ? strToBytes(name) : name;
        const ad = concat(writeU16(rb.length), rb, writeU16(nb.length), nb);
        return sodium.crypto_aead_aes256gcm_decrypt(null, payload, ad, nonce, key);
    }

    // --- User list parsing ---

    function parseUserList(payload) {
        const users = [];
        if (payload.length < 2) return users;
        let off = 0;
        const count = readU16(payload, off); off += 2;
        for (let i = 0; i < count && off + 2 <= payload.length; i++) {
            const ulen = readU16(payload, off); off += 2;
            if (off + ulen > payload.length) break;
            users.push(bytesToStr(payload.slice(off, off + ulen)));
            off += ulen;
        }
        return users;
    }

    // --- Key generation ---

    function generateKey() {
        const key = new Uint8Array(CRYPTO_KEYBYTES);
        crypto.getRandomValues(key);
        return key;
    }

    return {
        ensureReady,
        // Constants
        CRYPTO_KEYBYTES, CRYPTO_NPUBBYTES, CRYPTO_ABYTES,
        MSG_TYPE_TEXT, MSG_TYPE_FILE_START, MSG_TYPE_FILE_CHUNK, MSG_TYPE_FILE_END,
        MSG_TYPE_USER_LIST, MSG_TYPE_SIGNED_TEXT,
        MSG_TYPE_SIGNED_FILE_START, MSG_TYPE_SIGNED_FILE_CHUNK, MSG_TYPE_SIGNED_FILE_END,
        MSG_TYPE_IDENTITY_ANNOUNCE, MSG_TYPE_KEY_REQUEST, MSG_TYPE_KEY_RESPONSE,
        MSG_TYPE_MEDIA_RELAY,
        // Helpers
        writeU16, readU16, writeU32, readU32, concat, strToBytes, bytesToStr,
        b64Encode, b64Decode,
        isServiceMessage, buildAD,
        // Frame ops
        buildFrame, buildEncryptedFrame, buildServiceFrame,
        parseFrame, decryptPayload,
        parseUserList,
        generateKey,
    };
})();
