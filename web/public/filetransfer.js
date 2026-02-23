/**
 * F.E.A.R. Web File Transfer Module
 *
 * CRC32 integrity, chunked send/receive, browser download trigger.
 * Compatible with desktop/Android file transfer protocol.
 */

const FearFileTransfer = (() => {
    'use strict';

    const FILE_CHUNK_SIZE = 8192;

    // --- CRC32 (polynomial 0xEDB88320) ---

    const crcTable = (() => {
        const table = new Uint32Array(256);
        for (let i = 0; i < 256; i++) {
            let c = i;
            for (let j = 0; j < 8; j++) {
                c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
            }
            table[i] = c;
        }
        return table;
    })();

    function crc32(data) {
        let crc = 0xFFFFFFFF;
        for (let i = 0; i < data.length; i++) {
            crc = crcTable[(crc ^ data[i]) & 0xFF] ^ (crc >>> 8);
        }
        return (crc ^ 0xFFFFFFFF) >>> 0;
    }

    // --- Send file ---

    /**
     * Send a file to the room.
     * @param {File} file - Browser File object
     * @param {string} room
     * @param {string} name
     * @param {Uint8Array} key - room encryption key
     * @param {function} wsSend - function(Uint8Array) to send via WS
     * @param {object|null} identity - { pk, sk } or null
     * @param {function} onProgress - function(sent, total)
     */
    async function sendFile(file, room, name, key, wsSend, identity, onProgress) {
        const arrayBuf = await file.arrayBuffer();
        const fileData = new Uint8Array(arrayBuf);
        const totalSize = fileData.length;
        const fileCrc = crc32(fileData);

        // Extract basename
        const basename = file.name.split(/[\\/]/).pop();

        // FILE_START: [2 fn_len][filename][4 size_LE][4 crc_LE]
        const fnBytes = FearCrypto.strToBytes(basename);
        const startPayload = FearCrypto.concat(
            FearCrypto.writeU16(fnBytes.length), fnBytes,
            FearCrypto.writeU32(totalSize),
            FearCrypto.writeU32(fileCrc)
        );

        if (identity) {
            const signed = await FearIdentity.buildSignedPayload(identity.pk, identity.sk, startPayload);
            const frame = await FearCrypto.buildEncryptedFrame(room, name, FearCrypto.MSG_TYPE_SIGNED_FILE_START, signed, key);
            wsSend(frame);
        } else {
            const frame = await FearCrypto.buildEncryptedFrame(room, name, FearCrypto.MSG_TYPE_FILE_START, startPayload, key);
            wsSend(frame);
        }

        // FILE_CHUNKs
        let offset = 0;
        while (offset < totalSize) {
            const chunkSize = Math.min(FILE_CHUNK_SIZE, totalSize - offset);
            const chunkData = fileData.slice(offset, offset + chunkSize);
            const chunkCrc = crc32(chunkData);

            // [4 chunk_crc_LE][chunk_data]
            const chunkPayload = FearCrypto.concat(FearCrypto.writeU32(chunkCrc), chunkData);

            if (identity) {
                const signed = await FearIdentity.buildSignedPayload(identity.pk, identity.sk, chunkPayload);
                const frame = await FearCrypto.buildEncryptedFrame(room, name, FearCrypto.MSG_TYPE_SIGNED_FILE_CHUNK, signed, key);
                wsSend(frame);
            } else {
                const frame = await FearCrypto.buildEncryptedFrame(room, name, FearCrypto.MSG_TYPE_FILE_CHUNK, chunkPayload, key);
                wsSend(frame);
            }

            offset += chunkSize;
            if (onProgress) onProgress(offset, totalSize);

            // Yield to event loop to avoid blocking UI
            if (offset % (FILE_CHUNK_SIZE * 10) === 0) {
                await new Promise(r => setTimeout(r, 0));
            }
        }

        // FILE_END: [4 crc_LE]
        const endPayload = FearCrypto.writeU32(fileCrc);

        if (identity) {
            const signed = await FearIdentity.buildSignedPayload(identity.pk, identity.sk, endPayload);
            const frame = await FearCrypto.buildEncryptedFrame(room, name, FearCrypto.MSG_TYPE_SIGNED_FILE_END, signed, key);
            wsSend(frame);
        } else {
            const frame = await FearCrypto.buildEncryptedFrame(room, name, FearCrypto.MSG_TYPE_FILE_END, endPayload, key);
            wsSend(frame);
        }

        return { filename: basename, size: totalSize, crc: fileCrc };
    }

    // --- FileReceiver class ---

    class FileReceiver {
        constructor() {
            this.reset();
        }

        reset() {
            this.filename = '';
            this.totalSize = 0;
            this.expectedCrc = 0;
            this.chunks = [];
            this.received = 0;
            this.senderName = '';
            this.active = false;
        }

        onFileStart(payload, senderName) {
            this.reset();
            let off = 0;
            const fnLen = FearCrypto.readU16(payload, off); off += 2;
            this.filename = FearCrypto.bytesToStr(payload.slice(off, off + fnLen)); off += fnLen;
            this.totalSize = FearCrypto.readU32(payload, off); off += 4;
            this.expectedCrc = FearCrypto.readU32(payload, off);
            this.senderName = senderName;
            this.active = true;

            // Extract just the basename
            const sep = this.filename.lastIndexOf('/');
            const bsep = this.filename.lastIndexOf('\\');
            const idx = Math.max(sep, bsep);
            if (idx >= 0) this.filename = this.filename.substring(idx + 1);

            return {
                filename: this.filename,
                size: this.totalSize,
                sender: senderName,
            };
        }

        onFileChunk(payload) {
            if (!this.active) return null;
            if (payload.length < 4) return null;

            const chunkCrc = FearCrypto.readU32(payload, 0);
            const chunkData = payload.slice(4);

            // Verify chunk CRC
            if (crc32(chunkData) !== chunkCrc) {
                console.warn('[file] Chunk CRC mismatch');
                return null;
            }

            this.chunks.push(chunkData);
            this.received += chunkData.length;

            return {
                received: this.received,
                total: this.totalSize,
                progress: this.totalSize > 0 ? this.received / this.totalSize : 0,
            };
        }

        onFileEnd(payload) {
            if (!this.active) return null;

            const finalCrc = payload.length >= 4 ? FearCrypto.readU32(payload, 0) : 0;

            // Assemble complete file
            const fileData = FearCrypto.concat(...this.chunks);
            const computedCrc = crc32(fileData);

            const result = {
                filename: this.filename,
                data: fileData,
                size: fileData.length,
                sender: this.senderName,
                crcMatch: computedCrc === this.expectedCrc,
            };

            this.reset();
            return result;
        }
    }

    /**
     * Trigger browser download for received file data.
     */
    function triggerDownload(filename, data) {
        const blob = new Blob([data]);
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.style.display = 'none';
        document.body.appendChild(a);
        a.click();
        setTimeout(() => {
            URL.revokeObjectURL(url);
            a.remove();
        }, 1000);
    }

    function formatSize(bytes) {
        if (bytes >= 1048576) return (bytes / 1048576).toFixed(1) + ' MB';
        if (bytes >= 1024) return (bytes / 1024).toFixed(1) + ' KB';
        return bytes + ' B';
    }

    return {
        FILE_CHUNK_SIZE,
        crc32,
        sendFile,
        FileReceiver,
        triggerDownload,
        formatSize,
    };
})();
