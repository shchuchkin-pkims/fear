/**
 * F.E.A.R. Web Identity Module
 *
 * Ed25519 identity (TOFU model) using libsodium.js.
 * Keys persist in localStorage. Fingerprint = BLAKE2b first 8 bytes.
 */

const FearIdentity = (() => {
    'use strict';

    const PK_BYTES = 32;
    const SK_BYTES = 64;
    const SIG_BYTES = 64;

    const LS_PK_KEY = 'fear_identity_pk';
    const LS_SK_KEY = 'fear_identity_sk';
    const LS_KNOWN_KEYS = 'fear_known_keys';

    // TOFU results
    const TOFU_NEW_KEY = 0;
    const TOFU_KEY_MATCH = 1;
    const TOFU_KEY_MATCH_VERIFIED = 2;
    const TOFU_KEY_CONFLICT = 3;

    async function ensureReady() {
        await FearCrypto.ensureReady();
    }

    // --- Key management ---

    async function generateIdentity() {
        await ensureReady();
        const kp = sodium.crypto_sign_keypair();
        return { pk: kp.publicKey, sk: kp.privateKey };
    }

    function saveIdentity(pk, sk) {
        localStorage.setItem(LS_PK_KEY, FearCrypto.b64Encode(pk));
        localStorage.setItem(LS_SK_KEY, FearCrypto.b64Encode(sk));
    }

    function loadIdentity() {
        const pkB64 = localStorage.getItem(LS_PK_KEY);
        const skB64 = localStorage.getItem(LS_SK_KEY);
        if (!pkB64 || !skB64) return null;
        return {
            pk: FearCrypto.b64Decode(pkB64),
            sk: FearCrypto.b64Decode(skB64),
        };
    }

    function hasIdentity() {
        return localStorage.getItem(LS_PK_KEY) !== null;
    }

    function clearIdentity() {
        localStorage.removeItem(LS_PK_KEY);
        localStorage.removeItem(LS_SK_KEY);
    }

    // --- Fingerprint ---

    async function getFingerprint(pk) {
        await ensureReady();
        const hash = sodium.crypto_generichash(8, pk);
        return Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join(':');
    }

    // --- Sign / Verify ---

    async function signDetached(message, sk) {
        await ensureReady();
        return sodium.crypto_sign_detached(message, sk);
    }

    async function verifyDetached(message, sig, pk) {
        await ensureReady();
        try {
            return sodium.crypto_sign_verify_detached(sig, message, pk);
        } catch {
            return false;
        }
    }

    // --- Identity announce payload: [pk(32)][sig_over_name(64)] ---

    async function buildIdentityAnnounce(pk, sk, name) {
        const nameBytes = FearCrypto.strToBytes(name);
        const sig = await signDetached(nameBytes, sk);
        return FearCrypto.concat(pk, sig);
    }

    function parseIdentityAnnounce(payload) {
        if (payload.length < PK_BYTES + SIG_BYTES) return null;
        return {
            pk: payload.slice(0, PK_BYTES),
            signature: payload.slice(PK_BYTES, PK_BYTES + SIG_BYTES),
        };
    }

    // --- Signed payload: [pk(32)][sig(64)][data] ---

    async function buildSignedPayload(pk, sk, data) {
        const sig = await signDetached(data, sk);
        return FearCrypto.concat(pk, sig, data);
    }

    function parseSignedPayload(payload) {
        if (payload.length < PK_BYTES + SIG_BYTES) return null;
        return {
            pk: payload.slice(0, PK_BYTES),
            signature: payload.slice(PK_BYTES, PK_BYTES + SIG_BYTES),
            data: payload.slice(PK_BYTES + SIG_BYTES),
        };
    }

    // --- Known keys store (TOFU) ---

    function _loadKnownKeys() {
        try {
            const raw = localStorage.getItem(LS_KNOWN_KEYS);
            return raw ? JSON.parse(raw) : {};
        } catch {
            return {};
        }
    }

    function _saveKnownKeys(keys) {
        localStorage.setItem(LS_KNOWN_KEYS, JSON.stringify(keys));
    }

    function tofuCheck(name, pk) {
        const keys = _loadKnownKeys();
        const pkB64 = FearCrypto.b64Encode(pk);
        const entry = keys[name];

        if (!entry) {
            keys[name] = { pk: pkB64, verified: false };
            _saveKnownKeys(keys);
            return TOFU_NEW_KEY;
        }

        if (entry.pk === pkB64) {
            return entry.verified ? TOFU_KEY_MATCH_VERIFIED : TOFU_KEY_MATCH;
        }

        return TOFU_KEY_CONFLICT;
    }

    function markVerified(name) {
        const keys = _loadKnownKeys();
        if (keys[name]) {
            keys[name].verified = true;
            _saveKnownKeys(keys);
            return true;
        }
        return false;
    }

    function removeKey(name) {
        const keys = _loadKnownKeys();
        if (keys[name]) {
            delete keys[name];
            _saveKnownKeys(keys);
            return true;
        }
        return false;
    }

    function listKnownKeys() {
        return _loadKnownKeys();
    }

    function getKnownKey(name) {
        const keys = _loadKnownKeys();
        return keys[name] || null;
    }

    return {
        PK_BYTES, SK_BYTES, SIG_BYTES,
        TOFU_NEW_KEY, TOFU_KEY_MATCH, TOFU_KEY_MATCH_VERIFIED, TOFU_KEY_CONFLICT,
        ensureReady,
        generateIdentity, saveIdentity, loadIdentity, hasIdentity, clearIdentity,
        getFingerprint,
        signDetached, verifyDetached,
        buildIdentityAnnounce, parseIdentityAnnounce,
        buildSignedPayload, parseSignedPayload,
        tofuCheck, markVerified, removeKey, listKnownKeys, getKnownKey,
    };
})();
