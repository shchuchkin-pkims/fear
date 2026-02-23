/**
 * F.E.A.R. Web Client — Main Application
 *
 * Handles connection, ECDH key exchange, message send/receive,
 * file transfer UI, and identity management.
 */

(async () => {
    'use strict';

    // --- State ---
    let ws = null;
    let roomKey = null;      // Uint8Array(32)
    let roomName = '';
    let userName = '';
    let connectMode = null;  // 'create' | 'join' | 'connect'
    let identity = null;     // { pk, sk } or null
    let fileReceiver = new FearFileTransfer.FileReceiver();

    // ECDH state (create mode)
    let ecdhKeyPair = null;  // { publicKey, privateKey } (X25519)

    // --- DOM refs ---
    const loginScreen = document.getElementById('login-screen');
    const chatScreen = document.getElementById('chat-screen');
    const hostInput = document.getElementById('host-input');
    const portInput = document.getElementById('port-input');
    const roomInput = document.getElementById('room-input');
    const nameInput = document.getElementById('name-input');
    const keyInput = document.getElementById('key-input');
    const keyToggle = document.getElementById('key-toggle');
    const btnCreate = document.getElementById('btn-create');
    const btnJoin = document.getElementById('btn-join');
    const btnConnect = document.getElementById('btn-connect');
    const statusBar = document.getElementById('status-bar');
    const messagesDiv = document.getElementById('messages');
    const messageInput = document.getElementById('message-input');
    const sendBtn = document.getElementById('send-btn');
    const fileBtn = document.getElementById('file-btn');
    const fileInput = document.getElementById('file-input');
    const userListDiv = document.getElementById('user-list');
    const roomLabel = document.getElementById('room-label');
    const disconnectBtn = document.getElementById('disconnect-btn');
    const identityBtn = document.getElementById('identity-btn');
    const identityPanel = document.getElementById('identity-panel');
    const fingerprintDisplay = document.getElementById('fingerprint-display');
    const generateIdBtn = document.getElementById('generate-id-btn');
    const clearIdBtn = document.getElementById('clear-id-btn');
    const userListToggle = document.getElementById('user-list-toggle');
    const sidebar = document.getElementById('sidebar');

    // --- Utility ---

    function setStatus(text, type = 'info') {
        statusBar.textContent = text;
        statusBar.className = 'status-bar status-' + type;
    }

    function timestamp() {
        const d = new Date();
        return d.toLocaleTimeString('en-GB', { hour12: false });
    }

    function scrollToBottom() {
        messagesDiv.scrollTop = messagesDiv.scrollHeight;
    }

    function escapeHtml(s) {
        const div = document.createElement('div');
        div.textContent = s;
        return div.innerHTML;
    }

    function addMessage(html, cls = '') {
        const div = document.createElement('div');
        div.className = 'message ' + cls;
        div.innerHTML = html;
        messagesDiv.appendChild(div);
        scrollToBottom();
    }

    function addSystemMessage(text) {
        addMessage(`<span class="msg-system">[${timestamp()}] ${escapeHtml(text)}</span>`, 'system');
    }

    function addChatMessage(sender, text, badge = '', isSelf = false) {
        const badgeHtml = badge ? `<span class="identity-badge badge-${badge}">[${badge.charAt(0).toUpperCase()}]</span> ` : '';
        const cls = isSelf ? 'msg-self' : 'msg-other';
        addMessage(
            `<span class="msg-time">[${timestamp()}]</span> ${badgeHtml}<span class="msg-sender">${escapeHtml(sender)}:</span> <span class="msg-text">${escapeHtml(text)}</span>`,
            cls
        );
    }

    function addFileMessage(text) {
        addMessage(`<span class="msg-file">[${timestamp()}] ${escapeHtml(text)}</span>`, 'file');
    }

    // --- Show/hide screens ---

    function showChat() {
        loginScreen.style.display = 'none';
        chatScreen.style.display = 'flex';
        roomLabel.textContent = `${roomName}`;
        messageInput.focus();
    }

    function showLogin() {
        chatScreen.style.display = 'none';
        loginScreen.style.display = 'flex';
        messagesDiv.innerHTML = '';
        userListDiv.innerHTML = '';
    }

    // --- Identity ---

    async function loadIdentityState() {
        try {
            await FearIdentity.ensureReady();
            const id = FearIdentity.loadIdentity();
            if (id) {
                identity = id;
                const fp = await FearIdentity.getFingerprint(id.pk);
                fingerprintDisplay.textContent = fp;
                console.log('[identity] Loaded, fingerprint:', fp);
            } else {
                identity = null;
                fingerprintDisplay.textContent = 'No identity';
            }
        } catch (e) {
            console.error('[identity] Load error:', e);
            identity = null;
            fingerprintDisplay.textContent = 'Error';
        }
    }

    generateIdBtn.addEventListener('click', async () => {
        try {
            const id = await FearIdentity.generateIdentity();
            FearIdentity.saveIdentity(id.pk, id.sk);
            identity = id;
            const fp = await FearIdentity.getFingerprint(id.pk);
            fingerprintDisplay.textContent = fp;
            addSystemMessage('Identity generated: ' + fp);

            // If connected, announce identity
            if (ws && roomKey) {
                await sendIdentityAnnounce();
            }
        } catch (e) {
            console.error('[identity] Generate error:', e);
            addSystemMessage('Failed to generate identity: ' + e.message);
        }
    });

    clearIdBtn.addEventListener('click', () => {
        FearIdentity.clearIdentity();
        identity = null;
        fingerprintDisplay.textContent = 'No identity';
        addSystemMessage('Identity cleared');
    });

    identityBtn.addEventListener('click', () => {
        identityPanel.classList.toggle('hidden');
    });

    // --- WebSocket connection ---

    function connectWS(host, port) {
        return new Promise((resolve, reject) => {
            const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
            const wsUrl = `${proto}//${location.host}`;
            ws = new WebSocket(wsUrl);
            ws.binaryType = 'arraybuffer';

            ws.onopen = () => {
                // Send connect command to bridge
                ws.send(JSON.stringify({ type: 'connect', host, port }));
            };

            ws.onmessage = (evt) => {
                if (typeof evt.data === 'string') {
                    const msg = JSON.parse(evt.data);
                    if (msg.type === 'connected') {
                        resolve();
                    } else if (msg.type === 'error') {
                        reject(new Error(msg.message));
                    } else if (msg.type === 'disconnected') {
                        handleDisconnect();
                    }
                    return;
                }
                // Binary frame from TCP server
                handleIncomingFrame(new Uint8Array(evt.data));
            };

            ws.onerror = () => reject(new Error('WebSocket connection failed'));
            ws.onclose = () => {
                if (chatScreen.style.display !== 'none') {
                    handleDisconnect();
                }
            };
        });
    }

    function handleDisconnect() {
        setStatus('Disconnected', 'error');
        addSystemMessage('Disconnected from server');
        ws = null;
        roomKey = null;
        ecdhKeyPair = null;
    }

    function sendBinary(data) {
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(data);
        }
    }

    // --- Register with server (send empty text to create room entry) ---

    async function registerWithServer() {
        const frame = await FearCrypto.buildEncryptedFrame(
            roomName, userName, FearCrypto.MSG_TYPE_TEXT,
            new Uint8Array(0), roomKey
        );
        sendBinary(frame);
    }

    // --- ECDH Key Exchange ---

    async function ecdhCreate() {
        await FearCrypto.ensureReady();
        roomKey = FearCrypto.generateKey();
        ecdhKeyPair = sodium.crypto_box_keypair();

        keyInput.value = FearCrypto.b64Encode(roomKey);
        setStatus('Room created. Waiting for joiners...', 'info');
        addSystemMessage('Room created. Key: ' + FearCrypto.b64Encode(roomKey));
    }

    async function handleKeyRequest(senderName, payload) {
        if (!ecdhKeyPair || !roomKey) return;
        if (payload.length !== 32) return;
        if (senderName === userName) return;

        const joinerPk = payload;

        // Generate ephemeral keypair for this response
        const respKp = sodium.crypto_box_keypair();
        const boxNonce = sodium.randombytes_buf(24);

        // Encrypt room key: crypto_box_easy(roomKey, boxNonce, joinerPk, mySecretKey)
        const boxCipher = sodium.crypto_box_easy(roomKey, boxNonce, joinerPk, respKp.privateKey);

        // Build response: [2 target_len][target_name][32 eph_pk][24 nonce][48 cipher][opt: 32 id_pk + 64 sig]
        const targetBytes = FearCrypto.strToBytes(senderName);
        let responseParts = [
            FearCrypto.writeU16(targetBytes.length), targetBytes,
            respKp.publicKey,
            boxNonce,
            boxCipher,
        ];

        // Sign ephemeral pk with identity if available
        if (identity) {
            const sig = await FearIdentity.signDetached(respKp.publicKey, identity.sk);
            responseParts.push(identity.pk, sig);
        }

        const responsePayload = FearCrypto.concat(...responseParts);
        const frame = FearCrypto.buildServiceFrame(roomName, userName, FearCrypto.MSG_TYPE_KEY_RESPONSE, responsePayload);
        sendBinary(frame);

        addSystemMessage(`Sent room key to "${senderName}"` + (identity ? ' (signed)' : ''));
    }

    async function ecdhJoin() {
        await FearCrypto.ensureReady();
        ecdhKeyPair = sodium.crypto_box_keypair();

        // Send KEY_REQUEST: [32 my_x25519_pk]
        const frame = FearCrypto.buildServiceFrame(roomName, userName, FearCrypto.MSG_TYPE_KEY_REQUEST, ecdhKeyPair.publicKey);
        sendBinary(frame);

        setStatus('Joining... waiting for room key', 'info');
        addSystemMessage('Key exchange request sent. Waiting for response...');

        // Timeout
        return new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
                reject(new Error('Key exchange timeout (30s)'));
            }, 30000);

            window._ecdhResolve = (key) => {
                clearTimeout(timeout);
                resolve(key);
            };
            window._ecdhReject = (err) => {
                clearTimeout(timeout);
                reject(err);
            };
        });
    }

    async function handleKeyResponse(senderName, payload) {
        if (!ecdhKeyPair) return;
        if (senderName === userName) return;

        let off = 0;
        if (payload.length < 2) return;
        const targetLen = FearCrypto.readU16(payload, off); off += 2;
        const targetName = FearCrypto.bytesToStr(payload.slice(off, off + targetLen)); off += targetLen;

        if (targetName !== userName) return; // not for us

        const responderPk = payload.slice(off, off + 32); off += 32;
        const boxNonce = payload.slice(off, off + 24); off += 24;
        const boxCipher = payload.slice(off, off + 48); off += 48;

        // Check for identity signature
        const remaining = payload.length - off;
        let sigVerified = false;
        if (remaining >= 96) { // 32 pk + 64 sig
            const idPk = payload.slice(off, off + 32);
            const sig = payload.slice(off + 32, off + 96);
            sigVerified = await FearIdentity.verifyDetached(responderPk, sig, idPk);
            if (sigVerified) {
                const tofu = FearIdentity.tofuCheck(senderName, idPk);
                const fp = await FearIdentity.getFingerprint(idPk);
                if (tofu === FearIdentity.TOFU_NEW_KEY) {
                    addSystemMessage(`New identity for "${senderName}": ${fp} (TOFU)`);
                } else if (tofu === FearIdentity.TOFU_KEY_CONFLICT) {
                    addSystemMessage(`WARNING: Key CHANGED for "${senderName}"! Fingerprint: ${fp}`);
                } else {
                    addSystemMessage(`Key exchange verified: ${senderName} [${fp}]`);
                }
            } else {
                addSystemMessage(`WARNING: Signature verification FAILED for "${senderName}"`);
            }
        }

        try {
            const decryptedKey = sodium.crypto_box_open_easy(boxCipher, boxNonce, responderPk, ecdhKeyPair.privateKey);
            if (decryptedKey.length === 32) {
                roomKey = new Uint8Array(decryptedKey);
                keyInput.value = FearCrypto.b64Encode(roomKey);
                addSystemMessage(`Room key received from "${senderName}"${sigVerified ? ' (verified)' : ' (unsigned)'}`);

                if (window._ecdhResolve) {
                    window._ecdhResolve(roomKey);
                    window._ecdhResolve = null;
                }
            }
        } catch (e) {
            console.error('[ecdh] Failed to decrypt room key:', e);
            if (window._ecdhReject) {
                window._ecdhReject(new Error('Failed to decrypt room key'));
                window._ecdhReject = null;
            }
        }
    }

    // --- Send identity announce ---

    async function sendIdentityAnnounce() {
        if (!identity || !roomKey) return;
        const payload = await FearIdentity.buildIdentityAnnounce(identity.pk, identity.sk, userName);
        const frame = await FearCrypto.buildEncryptedFrame(roomName, userName, FearCrypto.MSG_TYPE_IDENTITY_ANNOUNCE, payload, roomKey);
        sendBinary(frame);
    }

    // --- Send text message ---

    async function sendTextMessage(text) {
        if (!roomKey || !ws) return;
        const textBytes = FearCrypto.strToBytes(text);
        let frame;

        if (identity) {
            const signed = await FearIdentity.buildSignedPayload(identity.pk, identity.sk, textBytes);
            frame = await FearCrypto.buildEncryptedFrame(roomName, userName, FearCrypto.MSG_TYPE_SIGNED_TEXT, signed, roomKey);
        } else {
            frame = await FearCrypto.buildEncryptedFrame(roomName, userName, FearCrypto.MSG_TYPE_TEXT, textBytes, roomKey);
        }

        sendBinary(frame);

        // Display own message locally
        const badge = identity ? 'T' : '';
        addChatMessage(userName, text, badge, true);
    }

    // --- Handle incoming frames ---

    async function handleIncomingFrame(data) {
        try {
            const { room, name, nonce, type, payload, roomBytes, nameBytes } = FearCrypto.parseFrame(data);

            if (room !== roomName) return;
            if (name === userName) return; // skip own messages

            const isService = FearCrypto.isServiceMessage(nonce);

            if (isService) {
                // Service messages (unencrypted)
                switch (type) {
                    case FearCrypto.MSG_TYPE_USER_LIST:
                        handleUserList(payload);
                        break;
                    case FearCrypto.MSG_TYPE_KEY_REQUEST:
                        if (connectMode === 'create') {
                            await handleKeyRequest(name, payload);
                        }
                        break;
                    case FearCrypto.MSG_TYPE_KEY_RESPONSE:
                        if (connectMode === 'join') {
                            await handleKeyResponse(name, payload);
                        }
                        break;
                }
                return;
            }

            // Encrypted messages — need room key
            if (!roomKey) return;

            let plain;
            try {
                plain = await FearCrypto.decryptPayload(payload, nonce, roomBytes, nameBytes, roomKey);
            } catch (e) {
                // Decryption failure (might be media relay or wrong key)
                return;
            }

            switch (type) {
                case FearCrypto.MSG_TYPE_TEXT:
                    if (plain.length > 0) {
                        addChatMessage(name, FearCrypto.bytesToStr(plain), '', false);
                    }
                    break;

                case FearCrypto.MSG_TYPE_SIGNED_TEXT:
                    await handleSignedText(name, plain);
                    break;

                case FearCrypto.MSG_TYPE_IDENTITY_ANNOUNCE:
                    await handleIdentityAnnounce(name, plain);
                    break;

                case FearCrypto.MSG_TYPE_FILE_START:
                case FearCrypto.MSG_TYPE_FILE_CHUNK:
                case FearCrypto.MSG_TYPE_FILE_END:
                    handleFileMessage(type, plain, name);
                    break;

                case FearCrypto.MSG_TYPE_SIGNED_FILE_START:
                case FearCrypto.MSG_TYPE_SIGNED_FILE_CHUNK:
                case FearCrypto.MSG_TYPE_SIGNED_FILE_END:
                    await handleSignedFileMessage(type, plain, name);
                    break;

                case FearCrypto.MSG_TYPE_MEDIA_RELAY:
                    // Ignore media relay in web client
                    break;
            }
        } catch (e) {
            console.error('[app] Frame handling error:', e);
        }
    }

    // --- Message type handlers ---

    function handleUserList(payload) {
        const users = FearCrypto.parseUserList(payload);
        userListDiv.innerHTML = '';
        for (const u of users) {
            const div = document.createElement('div');
            div.className = 'user-item';
            div.textContent = u;
            if (u === userName) div.classList.add('user-self');
            userListDiv.appendChild(div);
        }
        if (userListToggle) {
            userListToggle.textContent = `Users (${users.length})`;
        }
    }

    async function handleSignedText(senderName, plain) {
        const parsed = FearIdentity.parseSignedPayload(plain);
        if (!parsed) {
            addChatMessage(senderName, FearCrypto.bytesToStr(plain), '!', false);
            return;
        }

        const text = FearCrypto.bytesToStr(parsed.data);
        const sigOk = await FearIdentity.verifyDetached(parsed.data, parsed.signature, parsed.pk);
        let badge = '!';

        if (sigOk) {
            const tofu = FearIdentity.tofuCheck(senderName, parsed.pk);
            if (tofu === FearIdentity.TOFU_KEY_MATCH_VERIFIED) badge = 'V';
            else if (tofu === FearIdentity.TOFU_KEY_CONFLICT) badge = '!';
            else badge = 'T';

            if (tofu === FearIdentity.TOFU_NEW_KEY) {
                const fp = await FearIdentity.getFingerprint(parsed.pk);
                addSystemMessage(`New identity for "${senderName}": ${fp}`);
            } else if (tofu === FearIdentity.TOFU_KEY_CONFLICT) {
                const fp = await FearIdentity.getFingerprint(parsed.pk);
                addSystemMessage(`WARNING: Key CHANGED for "${senderName}"! ${fp}`);
            }
        }

        addChatMessage(senderName, text, badge, false);
    }

    async function handleIdentityAnnounce(senderName, plain) {
        const parsed = FearIdentity.parseIdentityAnnounce(plain);
        if (!parsed) return;

        const nameBytes = FearCrypto.strToBytes(senderName);
        const sigOk = await FearIdentity.verifyDetached(nameBytes, parsed.signature, parsed.pk);

        if (sigOk) {
            const tofu = FearIdentity.tofuCheck(senderName, parsed.pk);
            const fp = await FearIdentity.getFingerprint(parsed.pk);

            if (tofu === FearIdentity.TOFU_NEW_KEY) {
                addSystemMessage(`New identity for "${senderName}": ${fp}`);
            } else if (tofu === FearIdentity.TOFU_KEY_MATCH) {
                addSystemMessage(`"${senderName}" trusted (TOFU): ${fp}`);
            } else if (tofu === FearIdentity.TOFU_KEY_MATCH_VERIFIED) {
                addSystemMessage(`"${senderName}" verified: ${fp}`);
            } else if (tofu === FearIdentity.TOFU_KEY_CONFLICT) {
                addSystemMessage(`WARNING: Key CHANGED for "${senderName}"! ${fp}`);
            }
        }
    }

    function handleFileMessage(type, plain, senderName) {
        const baseType = type; // already unsigned
        if (baseType === FearCrypto.MSG_TYPE_FILE_START) {
            const info = fileReceiver.onFileStart(plain, senderName);
            if (info) {
                addFileMessage(`${info.sender} is sending "${info.filename}" (${FearFileTransfer.formatSize(info.size)})`);
            }
        } else if (baseType === FearCrypto.MSG_TYPE_FILE_CHUNK) {
            const progress = fileReceiver.onFileChunk(plain);
            if (progress) {
                updateFileProgress(progress);
            }
        } else if (baseType === FearCrypto.MSG_TYPE_FILE_END) {
            const result = fileReceiver.onFileEnd(plain);
            if (result) {
                finishFileReceive(result);
            }
        }
    }

    async function handleSignedFileMessage(type, plain, senderName) {
        const parsed = FearIdentity.parseSignedPayload(plain);
        if (!parsed) return;

        const sigOk = await FearIdentity.verifyDetached(parsed.data, parsed.signature, parsed.pk);
        if (sigOk) {
            FearIdentity.tofuCheck(senderName, parsed.pk);
        } else {
            addSystemMessage(`File message signature FAILED from "${senderName}"`);
        }

        // Map to unsigned type
        let unsignedType;
        if (type === FearCrypto.MSG_TYPE_SIGNED_FILE_START) unsignedType = FearCrypto.MSG_TYPE_FILE_START;
        else if (type === FearCrypto.MSG_TYPE_SIGNED_FILE_CHUNK) unsignedType = FearCrypto.MSG_TYPE_FILE_CHUNK;
        else if (type === FearCrypto.MSG_TYPE_SIGNED_FILE_END) unsignedType = FearCrypto.MSG_TYPE_FILE_END;
        else return;

        handleFileMessage(unsignedType, parsed.data, senderName);
    }

    // --- File progress ---

    let fileProgressEl = null;

    function updateFileProgress(progress) {
        if (!fileProgressEl) {
            fileProgressEl = document.createElement('div');
            fileProgressEl.className = 'message file-progress';
            fileProgressEl.innerHTML = '<div class="progress-bar"><div class="progress-fill"></div></div><span class="progress-text"></span>';
            messagesDiv.appendChild(fileProgressEl);
        }
        const pct = Math.round(progress.progress * 100);
        fileProgressEl.querySelector('.progress-fill').style.width = pct + '%';
        fileProgressEl.querySelector('.progress-text').textContent =
            `${FearFileTransfer.formatSize(progress.received)} / ${FearFileTransfer.formatSize(progress.total)} (${pct}%)`;
        scrollToBottom();
    }

    function finishFileReceive(result) {
        if (fileProgressEl) {
            fileProgressEl.remove();
            fileProgressEl = null;
        }

        if (result.crcMatch) {
            addFileMessage(`File received: "${result.filename}" (${FearFileTransfer.formatSize(result.size)}) — CRC OK`);
            // Auto-download
            FearFileTransfer.triggerDownload(result.filename, result.data);
        } else {
            addFileMessage(`File received: "${result.filename}" — CRC MISMATCH (corrupted)`);
        }
    }

    // --- Connection flow ---

    async function doConnect(mode) {
        const host = hostInput.value.trim() || location.hostname;
        const port = portInput.value.trim() || '8888';
        roomName = roomInput.value.trim();
        userName = nameInput.value.trim();
        const keyStr = keyInput.value.trim();

        if (!roomName || !userName) {
            setStatus('Room and name are required', 'error');
            return;
        }

        connectMode = mode;
        setStatus('Connecting...', 'info');
        btnCreate.disabled = btnJoin.disabled = btnConnect.disabled = true;

        try {
            await connectWS(host, port);
            setStatus('TCP connected, setting up...', 'info');

            if (mode === 'create') {
                await ecdhCreate();
                await registerWithServer();
                if (identity) await sendIdentityAnnounce();
                showChat();
                setStatus('Connected — Room created', 'ok');
            } else if (mode === 'join') {
                await registerWithServer();
                try {
                    await ecdhJoin();
                } catch (e) {
                    setStatus('Key exchange failed: ' + e.message, 'error');
                    if (ws) ws.close();
                    btnCreate.disabled = btnJoin.disabled = btnConnect.disabled = false;
                    return;
                }
                if (identity) await sendIdentityAnnounce();
                showChat();
                setStatus('Connected — Joined room', 'ok');
            } else {
                // direct connect with key
                if (!keyStr) {
                    setStatus('Key is required for direct connect', 'error');
                    if (ws) ws.close();
                    btnCreate.disabled = btnJoin.disabled = btnConnect.disabled = false;
                    return;
                }
                roomKey = FearCrypto.b64Decode(keyStr);
                if (roomKey.length !== 32) {
                    setStatus('Invalid key (must be 32 bytes base64url)', 'error');
                    if (ws) ws.close();
                    btnCreate.disabled = btnJoin.disabled = btnConnect.disabled = false;
                    return;
                }
                await registerWithServer();
                if (identity) await sendIdentityAnnounce();
                showChat();
                setStatus('Connected', 'ok');
            }
        } catch (e) {
            setStatus('Connection failed: ' + e.message, 'error');
            btnCreate.disabled = btnJoin.disabled = btnConnect.disabled = false;
        }
    }

    // --- Event listeners ---

    btnCreate.addEventListener('click', () => doConnect('create'));
    btnJoin.addEventListener('click', () => doConnect('join'));
    btnConnect.addEventListener('click', () => doConnect('connect'));

    disconnectBtn.addEventListener('click', () => {
        if (ws) ws.close();
        ws = null;
        roomKey = null;
        ecdhKeyPair = null;
        connectMode = null;
        showLogin();
        setStatus('Disconnected', 'info');
        btnCreate.disabled = btnJoin.disabled = btnConnect.disabled = false;
    });

    keyToggle.addEventListener('click', () => {
        keyInput.type = keyInput.type === 'password' ? 'text' : 'password';
        keyToggle.textContent = keyInput.type === 'password' ? 'Show' : 'Hide';
    });

    // Send message
    async function handleSend() {
        const text = messageInput.value.trim();
        if (!text) return;
        messageInput.value = '';
        await sendTextMessage(text);
    }

    sendBtn.addEventListener('click', handleSend);
    messageInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
            e.preventDefault();
            handleSend();
        }
    });

    // File send
    fileBtn.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', async () => {
        const file = fileInput.files[0];
        if (!file || !roomKey) return;
        fileInput.value = '';

        addFileMessage(`Sending "${file.name}" (${FearFileTransfer.formatSize(file.size)})...`);

        // Show progress
        const progressEl = document.createElement('div');
        progressEl.className = 'message file-progress';
        progressEl.innerHTML = '<div class="progress-bar"><div class="progress-fill"></div></div><span class="progress-text"></span>';
        messagesDiv.appendChild(progressEl);

        try {
            await FearFileTransfer.sendFile(file, roomName, userName, roomKey, sendBinary, identity, (sent, total) => {
                const pct = Math.round(sent / total * 100);
                progressEl.querySelector('.progress-fill').style.width = pct + '%';
                progressEl.querySelector('.progress-text').textContent = `Sending: ${pct}%`;
            });
            progressEl.remove();
            addFileMessage(`File sent: "${file.name}"`);
        } catch (e) {
            progressEl.remove();
            addFileMessage(`File send failed: ${e.message}`);
        }
    });

    // Drag & drop
    const dropZone = document.getElementById('drop-zone');
    chatScreen.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('active');
    });
    chatScreen.addEventListener('dragleave', () => {
        dropZone.classList.remove('active');
    });
    chatScreen.addEventListener('drop', async (e) => {
        e.preventDefault();
        dropZone.classList.remove('active');
        const file = e.dataTransfer.files[0];
        if (!file || !roomKey) return;

        addFileMessage(`Sending "${file.name}" (${FearFileTransfer.formatSize(file.size)})...`);
        try {
            await FearFileTransfer.sendFile(file, roomName, userName, roomKey, sendBinary, identity, null);
            addFileMessage(`File sent: "${file.name}"`);
        } catch (e) {
            addFileMessage(`File send failed: ${e.message}`);
        }
    });

    // User list toggle (mobile)
    if (userListToggle) {
        userListToggle.addEventListener('click', () => {
            sidebar.classList.toggle('open');
        });
    }

    // --- Init ---

    await FearCrypto.ensureReady();
    await loadIdentityState();
    setStatus('Ready', 'info');
})();
