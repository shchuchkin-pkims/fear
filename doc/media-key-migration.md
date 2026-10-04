# Media key migration - per-direction keys with a session salt

> Working document for the Phase C media switchover (audit items M3 / M5).
> Produced from a read-only survey of the live media path on both platforms
> (desktop `audio_call` / `video_call`, Android `AudioCallManager` /
> `VideoCallManager`, the shared wire constants and the call entry points),
> then reconciled against the source where the surveys disagreed.
>
> Status: **the 2-party parts of this document are superseded.** The project
> owner confirmed that group audio and video calls are a planned feature, which
> invalidates the caller/callee direction bit and the two-halves salt agreement
> described below. The replacement is at the end of this file, under
> \"Revised design: N-party sender-rooted media keys\"; read that section first
> and treat sections 1.3, 2 and the salt/role parts of 4 and 6 as history kept
> for the reasoning they contain.

I have what I need. Two survey claims were wrong and one major fact was missed; both are resolved below.

---

# Migration spec: live media path → `identity/media_keys.c` (per-direction keys + 16-byte session salt)

**Verified against:** desktop `~/Documents/VS_Code/ClaudeAI/fear-main`, branch `dev` @ `b09f548`; Android `~/Documents/AndroidStudioProjects/FEAR`, branch `dev` @ `dd69a64`. All line references below were re-read over SSH, not taken from the surveys.

## 0. Survey corrections (re-read to resolve, not guessed)

| # | Survey claim | Reality |
|---|---|---|
| C1 | Survey 5: "video stats packets reuse `audio_seq_tx`" | **Wrong.** `video_call.c:878` (fragments) and `video_call.c:910` (stats) both `atomic_fetch_add(&vc->video_seq_tx, 1)`. `audio_seq_tx` is used only at `video_call.c:983`. Survey 2 was right. This matters: stats must stay on the **video** key pair. |
| C2 | Surveys 3 + 4: "Android has no keyed-BLAKE2b helper matching `media_keys.c`; a new lazysodium wrapper must be hand-written and cross-checked against the C vectors" | **Already done.** Commit `dd69a64` ("Port the Phase C key schedule and media keys to Kotlin, with the frozen vectors") added `app/src/main/java/com/fear/crypto/MediaKeys.kt`, `KeySchedule.kt`, `KeyedHash.kt` and `app/src/test/java/com/fear/crypto/MediaKeysTest.kt`. `MediaKeys.info()/derive()/derivePair()` mirror `media_keys.c` byte for byte, behind a `fun interface KeyedHash` seam (`KeyedHash.kt:16-19`) with `SodiumKeyedHash` for production and BouncyCastle Blake2b injected in JVM tests. **The Kotlin half of the primitive is not work to be done.** |
| C3 | Survey 4: "`audio_encrypt_packet`/`audio_decrypt_packet` signatures must gain a per-direction key argument - a shared ABI change across both binaries" | **Wrong.** `audio_crypto.h:32,49` already take `const uint8_t *key`. Callers pass `c->key` / `vc->audio_key`. Switching to `c->key_tx_audio` is a **call-site** change only. No ABI change. Survey 1 was right. |

Two further facts the surveys never state, both load-bearing:

- **These are two independent git repositories.** There is no atomic cross-platform commit. The lockstep point in §7 is a release convention, not a merge.
- **Identity is optional on every path**: `--no-sign` exists on all three `audio_call` subcommands (`audio_call.c:1446, 1570, 1689`) and on `video_call` (`video_call.c:1612`), and `has_identity = 0` at `audio_call.c:1077`. Android has `sendHelloWithoutIdentity()` (`VideoCallManager.kt:793`). **This kills pk-comparison as a universal role source.**

---

## 1. Wire format: HELLO v2

### 1.1 Why a new type byte, not an appended field

Every "append the salt" option was checked against the four live parsers and all of them fail:

- Appending to the desktop **unsigned audio** HELLO (5 → 21 bytes) makes it satisfy `if (len >= HELLO_SIZE_VIDEO)` at `video_call.c:581` and `if (data.size >= 11)` at `VideoCallManager.kt:902`. The receiver then reads `width` from `buf+6`, `height` from `buf+8`, `fps` from `buf[10]` - i.e. it configures its decoder from raw salt bytes. It also kills the `else if (len == 1 + NONCE_PREFIX_LEN)` branch at `audio_call.c:301`.
- Appending **after** the identity blob leaves the salt outside every signature. `audio_call.c:245-247` signs only the 4 prefix bytes; `video_call.c:500-501` signs `[0, HELLO_SIZE_VIDEO + IDENTITY_PK_BYTES)` = `[0,43)`. An unsigned salt is not a DoS-only problem - see §2.3, it is a full nonce-reuse break.
- Inserting **before** the identity blob (the only way to get it signed) shifts pk from 11→27 and sig from 43→59, so old peers verify garbage. Hard break either way.

Since the break is unavoidable, take the version byte with it. **`PKT_TYPE_HELLO2 = 0x7E`.** Verified drop behaviour on all four current implementations, none of which misparse it:

- `audio_call.c:739-768`: not `0x7F`, not `0x04`, falls to `decrypt_opus` → `audio_crypto.c:132` rejects `pkt[0] != PKT_VER_AUDIO` → `continue`.
- `video_call.c:1063-1211`: falls off the end of the if-chain, loop iterates.
- `VideoCallManager.kt:852-864`: `else -> Log.w("Unknown packet type")`.
- `AudioCallManager.kt:1253-1264`: logs unknown version, fails the `== PKT_VER_HELLO` test, fails stats, rejected in `decryptAudioPacket` at `:1454`.

`0x7E` is unused: the type space today is `0x01` audio, `0x02` video frag, `0x04` stats, `0x7F` hello, `0xFE` UDP relay registration.

### 1.2 Layout (one format for audio and video; retires the 5/11/102/107 tier system)

All multi-byte fields **big-endian**, matching every existing field on this wire (`htons` at `video_call.c:490-493`, `htonll_u64` in the nonce and seq).

```
off  size  field
  0    1   0x7E   PKT_TYPE_HELLO2
  1    1   0x02   HELLO2_VERSION
  2    2   uint16 BE  total HELLO length in bytes (30 or 126)
  4    1   flags: 0x01 VIDEO, 0x02 AUDIO, 0x04 IDENTITY
  5    4   nonce prefix, 4 raw random bytes (no endianness)
  9   16   salt half, 16 raw random bytes  <-- new
 25    2   uint16 BE  width   (0 when !VIDEO)
 27    2   uint16 BE  height  (0 when !VIDEO)
 29    1   uint8      fps     (0 when !VIDEO)
        HELLO2_SIZE_BASE   = 30
 30   32   Ed25519 public key      only when flags & IDENTITY
 62   64   Ed25519 sig over [0,62) only when flags & IDENTITY
        HELLO2_SIZE_SIGNED = 126
```

Deliberate choices:

- **Explicit length at off 2.** The single biggest defect in the current wire is that there is no length field and no equality check anywhere, so every parser silently tolerates trailing bytes. New rule: accept **iff** `len == rd_u16(buf+2)` **and** `len == (flags & IDENTITY ? 126 : 30)`. Anything else is dropped **with a log line**. No tolerance, no tiers.
- **Version at off 1**, so the next change negotiates instead of burning another type byte.
- **Video params always present**, zeroed for audio-only. This deletes the length-tier dispatch entirely (dispatch on `flags`), which removes the `video_call.c:581` misparse *and* the pre-existing dead branch at `video_call.c:632-663` (today a 102-byte audio-only signed HELLO from `video_call.c:505-512` lands in the `len >= 11` video branch and its identity is never checked, because `102 < 107`).
- **Everything except the signature is inside the signed range.** Version, length, flags, prefix, salt half, video params, pk: all covered by `identity_sign(pkt, 62, sk, pkt+62)`.
- **Flag numbering adopts `video_types.h:51-57`** (`VIDEO 0x01 / AUDIO 0x02 / IDENTITY 0x04`), matching `Common.kt:59-61`. `audio_call.c:167`'s conflicting `HELLO_FLAG_IDENTITY 0x01` is retired with the v1 HELLO. Bits `0x08..0x80` stay free and reserved-must-be-zero.

### 1.3 Salt agreement, role, and glare - one mechanism

**Both sides always generate.** Each call object produces `local_half[16]` once at startup (`randombytes_buf` / `SecureRandom`, next to the existing nonce-prefix generation at `audio_call.c:1066`, `video_call.c:1671`, `VideoCallManager.kt:142`). Both sides put it in every HELLO. There is no "who generates" and no echo.

**Agreement rule** (pure function of the unordered pair, therefore glare-free by construction):

```
cmp = memcmp(local_half, peer_half, 16)      /* unsigned bytewise */
cmp  < 0  ->  is_caller = 1;  lo = local_half; hi = peer_half
cmp  > 0  ->  is_caller = 0;  lo = peer_half;  hi = local_half
cmp == 0  ->  ABORT the call with an explicit error
session_salt = mk_salt_combine(master, lo, hi)
```

**Glare:** simultaneous generation is the *normal* case, not an exception. Both ends compute identical `lo`/`hi`, therefore identical `session_salt`, and necessarily **opposite** roles. Nothing to resolve.

**`cmp == 0` must abort, not default.** Probability 2^-128 by chance, but it is the exact signature of a reflection attack (an attacker bouncing our own HELLO back at us). A default would hand both sides `is_caller = 1`, which is precisely the catastrophe in §2.3.

**New function** `mk_salt_combine()` - the only addition to the primitive:

```
session_salt[16] = first 16 bytes of
    BLAKE2b(key = master(32), data = "fear.media.salt.v1" || lo(16) || hi(16), out = 16)
```

Rationale for hashing rather than XOR or "smaller half wins": the salt is public, but it must be *unforgeable as a value*. With XOR, an on-path attacker who observed session 1's salt forces session 2 to reuse it by choosing `half = old_salt XOR our_half` - M5 straight back. With "smaller half wins", an all-zero injected half pins the salt forever. Hashing gives preimage resistance, so an attacker can only force a *different* salt, never a *chosen* one. Keying by `master` reuses the **exact same keyed-BLAKE2b seam** already present on both platforms (`crypto_generichash` in C, `KeyedHash.blake2b` in Kotlin) - no new hash mode, no new lazysodium call shape - and as a free bonus makes the salt unpredictable to an off-path observer. The `lo/hi` ordering mirrors the established repo idiom at `IdentityManager.kt:175-187`.

**Idempotence.** HELLOs ping-pong for the entire call (`audio_call.c:741`, `video_call.c:1066-1069`, `VideoCallManager.kt:726-748`). The handler must compare-then-act: if `have_peer_half && memcmp(peer_half, incoming, 16) == 0`, **return immediately** - no re-derivation, no window reset, no state touched.

**Change after keys are live.** Once `keys_ready` is set, a *different* peer half (or prefix) is accepted **only** if the HELLO carries a valid Ed25519 signature from the already-pinned `peer_identity_pk`. In `--no-sign` mode any post-handshake change is logged and ignored. This closes the remote key-reset primitive the surveys correctly flagged (`audio_call.c:273` only parses identity while `peer_verified == 0`, so today anyone can spoof a bare HELLO and reset both replay windows via `audio_call.c:267-270`). Documented cost: **`--no-sign` loses mid-call peer-restart recovery.** That is a real regression from `video_call.c:547-579` and must go in the release notes.

**Session tuple is immutable.** Under v2, `(nonce_prefix, peer_half)` is fixed per session. A prefix-only change with an unchanged half is anomalous (a genuine restart regenerates both) and is ignored. `session_salt` changed is now the single authoritative restart signal - it subsumes the old `prefix_changed` trigger at `audio_call.c:263-270` and `video_call.c:530-543`.

---

## 2. Role assignment

**Decision: derived in-band from the HELLO exchange, by lexicographic comparison of the two salt halves (§1.3). Not from a CLI flag, not from pk, not from the server.**

### 2.1 Why not the CLI flag

`is_caller` reaches `audio_call_start()` correctly for `call` (`audio_call.c:1526`, =1) and `listen` (`:1647`, =0) but **`relay` passes 1 for both peers** (`:1744`). `video_call` has no role concept at all - `start_video_call()` (`:1653`) takes no such parameter and `main()` (`:2004-2050`) never computes one. On Android, `AudioCallManager.kt:608` hardcodes `isInitiator = true` on the relay path and `FearViewModel.kt:975-985` routes every audio call through `startAudioRelay`; `ComposeMainActivity.kt:764-774` sets `EXTRA_IS_RELAY=true` for both peers with no role extra. The Qt GUI cannot supply one either: `Backend` discards `ConnectMode` (`backend.h:43`, `backend.cpp:68-161`), and both call dialogs tick `relayCheck` whenever the backend is connected. Fixing all seven of those sites correctly is a larger and far more fragile change than one `memcmp`.

### 2.2 Why not pk or the server

pk is unavailable under `--no-sign` (§0). The relay server cannot help: `server.c:1136` treats `MSG_TYPE_MEDIA_RELAY` as an opaque payload and **skips the name-uniqueness check for media clients**, so even `--name` is not guaranteed distinct within a room.

### 2.3 What happens if you get this wrong

If both ends compute `is_caller = 1`, `mk_derive_pair` returns **`send == the other side's send`**: both peers encrypt under the identical key, both starting at seq 0, separated only by the 4-byte random prefix. That is not a silent-call bug - it is **strictly worse than today's shared key**, because it reintroduces M3 while removing nothing. This is why `cmp == 0` aborts and why the role must come from a source that is structurally guaranteed to disagree.

### 2.4 Consequences

- `audio_call_start()`'s `is_caller` parameter **stays** and keeps its one existing job (who sends the first HELLO, `audio_call.c:1176`). It no longer feeds key derivation. Do not delete it; do not "fix" `:1744`.
- `video_call` needs **no** new role parameter, no `CallOptions` field, no `main()` change. Surveys 2 and 5 both assumed a signature change here; the wire tiebreak makes it unnecessary.
- **The Qt GUI needs no changes at all**, and neither do `VideoCallActivity`, `ComposeMainActivity`, `FearViewModel` or `FearClient`. No `--role` flag, no `EXTRA_IS_CALLER`, no second stdin line. This is the main payoff of the in-band design.
- `media_keys.h`'s doc comment for `is_caller` ("non-zero for the side that initiated the call") becomes inaccurate - it is now "the side with the lexicographically smaller salt half". Update the comment. **No code change, no vector change.**

---

## 3. Version strategy

**Bump: new HELLO type byte `0x7E` plus an explicit version byte inside it. No negotiation, no fallback.**

**Old and new clients cannot interoperate. Stated plainly: a v2 build and a v1 build will not complete a handshake, and this is intentional.**

Concretely: a v2 peer sends only `0x7E` HELLOs, which a v1 peer drops without ever setting `remote_prefix_ready`, so the v1 peer never starts sending media. In the reverse direction, a v2 peer that receives a `0x7F` HELLO must **detect it explicitly** and fail loudly:

```
[!] Peer is running an incompatible protocol version (pre-Phase-C-3 HELLO).
    Both ends must be updated. Aborting call.
```

This is the entire reason for choosing a new type byte over an appended field. The alternative - a longer `0x7F` HELLO - is accepted by every current parser (`len >= HELLO_SIZE_SIGNED` at `audio_call.c:273` passes for 118 bytes; `data.size >= 11` at `VideoCallManager.kt:902` passes for anything), the salt is silently discarded, the two ends derive different keys, and 100% of media is dropped at the GCM tag check by a bare `continue` (`audio_call.c:767`) with the exception swallowed on Android by design (`Crypto.kt:69-72`, `VideoCallManager.kt:1186-1188`). The user would see a connected call, no audio, no video, and no diagnostic anywhere. A loud abort is strictly better.

**Do not bump `PKT_VER_AUDIO`.** `0x02` is already `PKT_TYPE_VIDEO_FRAG`, so the obvious increment collides. The HELLO gate is sufficient and unambiguous - media never flows without a completed handshake. Leaving the media type bytes alone also means the duplicate definition (`audio_call.c:123` and `audio_crypto.c:21`) does not need touching.

**Delete the dead constants** while in the neighbourhood: `HELLO_MAGIC 0xFEARAUDIO` (`audio_types.h:48`, not a valid C hex literal, would not compile if expanded) and `PROTOCOL_VERSION 1` (`audio_types.h:51`). Both are referenced nowhere.

---

## 4. File-by-file change list

### 4.1 Shared primitive - desktop

**`identity/media_keys.h`** - add `#define MK_SALT_CTX "fear.media.salt.v1"`; declare `int mk_salt_combine(const uint8_t master[MK_KEY_BYTES], const uint8_t half_a[MK_SALT_BYTES], const uint8_t half_b[MK_SALT_BYTES], uint8_t out_salt[MK_SALT_BYTES]);` and `int mk_role_from_halves(const uint8_t local[16], const uint8_t peer[16], int *out_is_caller);` (returns -1 on equal halves). Update the `is_caller` doc comment per §2.4.

**`identity/media_keys.c`** - implement both. `mk_salt_combine` sorts internally with `memcmp` (so it is commutative in its two half arguments), builds `info = MK_SALT_CTX(18) || lo(16) || hi(16)` = 50 bytes, calls `crypto_generichash(out, 16, info, 50, master, 32)`, `sodium_memzero(info)`. **`mk_derive`/`mk_derive_pair` are not modified** - the frozen vectors in `tests/test_media_keys.c:44-63` must continue to pass byte-for-byte.

**New: `identity/media_hello.h` / `media_hello.c`** - the HELLO2 codec, extracted so it is testable. Today `handle_hello` is welded into a 1766-line file behind the whole `AudioCall` struct, which is why no test covers HELLO parsing on either binary. Contents: the layout constants from §1.2; `mh_build(const mh_local_t *in, uint8_t out[126], size_t *out_len)`; `mh_parse(const uint8_t *buf, size_t len, mh_parsed_t *out)` returning a plain struct with a specific error enum for each rejection; `mh_agree(const uint8_t master[32], const uint8_t local_half[16], const uint8_t peer_half[16], uint8_t out_salt[16], int *out_is_caller)`. No sockets, no PortAudio, no SDL - links against libsodium and `identity.c` only. Both binaries call it, which also ends the two-format / two-constant-file drift.

### 4.2 Desktop - `audio_call`

**`audio_call/src/audio_call.c`**

- `:69` - add `#include "media_keys.h"` and `#include "media_hello.h"` (include path already covers `identity/`, `CMakeLists.txt:25`).
- `:122-125` - add `#define PKT_TYPE_HELLO2 0x7E`. Keep `PKT_VER_HELLO 0x7F` solely to detect and reject legacy peers.
- `:167-170` - retire `HELLO_FLAG_IDENTITY 0x01` and `HELLO_SIZE_SIGNED`; both move to `media_hello.h` with the `video_types.h` flag numbering.
- `:188` - replace `uint8_t key[AES_GCM_KEY_LEN]` with `uint8_t master_key[32]; uint8_t key_tx[32]; uint8_t key_rx[32];`.
- `:189-195` - add `uint8_t local_half[MK_SALT_BYTES]; uint8_t peer_half[MK_SALT_BYTES]; uint8_t session_salt[MK_SALT_BYTES]; int have_peer_half; int wire_is_caller; atomic_int keys_ready;` plus a `pthread_mutex_t rekey_lock` (Win32: `CRITICAL_SECTION`) guarding the derive-and-reset critical section.
- `send_hello()` `:237-256` - replace both branches with a single `mh_build()` call. The unsigned branch grows a flags byte and video-params-zeroed region; the signed branch signs `[0,62)` instead of the 4 prefix bytes.
- `handle_hello()` `:257-306` - rewrite over `mh_parse()`. Order: parse → verify signature (if IDENTITY) → idempotence check on `peer_half` → if new, take `rekey_lock`, run `mh_agree()`, `mk_derive_pair(master_key, MK_STREAM_AUDIO, wire_is_caller, session_salt, key_tx, key_rx)`, `memset(&c->rx_audio,0,...)`, `memset(&c->rx_stats,0,...)`, `atomic_store(&c->seq_tx, 0)`, `atomic_store(&c->keys_ready, 1)`, release. Post-`keys_ready` changes require a valid signature from the pinned pk (§1.3).
- `:739-743` (recv dispatch) - dispatch `0x7E` to the new handler; **stop ignoring the return value** (today `handle_hello`'s `-1` at `:258` is discarded and a full 102-byte signed HELLO is still emitted in reply, giving a probe oracle). Only reply on a successful parse. Add a `rbuf[0] == PKT_VER_HELLO` arm that prints the legacy-peer error from §3 once and stops the call.
- `encrypt_opus()` `:528-529` → `c->key_tx`. `decrypt_opus()` `:536-537` → `c->key_rx`; the `remote_prefix_ready` gate at `:535` becomes `atomic_load(&c->keys_ready)`.
- `encrypt_stats()` `:563` → `c->key_tx`; `decrypt_stats()` `:592` → `c->key_rx`; the gate at `:573` → `keys_ready`. **STATS rides the audio directional keys.** Safe because `seq_tx` is shared between audio (`:658`) and stats (`:682`), so the two packet types never collide in nonce space under one key. **Do not add an `MK_STREAM_STATS`** - that would require splitting the counters, which is a larger change with a real nonce-reuse failure mode if done wrong.
- `th_send_func()` `:621-632` - the handshake spin waits on `remote_prefix_ready`; change to `keys_ready` so no frame is ever encrypted with an unset `key_tx`.
- `audio_call_start()` `:1065-1068` - `memcpy(c->master_key, key, 32)`; add `randombytes_buf(c->local_half, MK_SALT_BYTES)`; add `atomic_store(&c->keys_ready, 0)`. `seq_tx` staying at 0 is now safe by construction.
- `:1526 / :1647 / :1744` - **unchanged.** `is_caller` keeps only its `:1176` first-HELLO role.
- `audio_call_stop()` - add `sodium_memzero` for `master_key`, `key_tx`, `key_rx`, `session_salt`, `local_half`. Today `audio_call.c` **never** wipes `c->key` at all (unlike `video_call.c:1447-1449`); fix that here.

**`audio_call/src/audio_crypto.c`, `include/audio_crypto.h`** - doc comments only (`audio_crypto.h:21,44-47`; `audio_crypto.c:5-6,26-29,48-51,102-103`): the "4-byte prefix prevents nonce reuse between parties" wording is now wrong, the per-direction key is what does that. **No signature change** (§0/C3).

**`audio_call/include/audio_types.h`** - delete `HELLO_MAGIC` (`:48`) and `PROTOCOL_VERSION` (`:51`).

**`audio_call/src/audio_hub.c`** - no code change; add a header comment that `hub_forward()` (`:183-208`, up to 32 clients) is N-party and therefore incompatible with 2-party directional keys. See open question O1.

### 4.3 Desktop - `video_call`

**`video_call/src/video_call.c`**

- `:145-147` - replace `audio_key`/`video_key` with `audio_key_tx/audio_key_rx/video_key_tx/video_key_rx`; add the same salt/role/`keys_ready`/`rekey_lock` block as §4.2.
- `derive_subkeys()` `:457-471` - replace both `crypto_kdf_derive_from_key` calls with two `mk_derive_pair()` calls (`MK_STREAM_AUDIO` and `MK_STREAM_VIDEO`). **Rename to `derive_media_keys(vc)` and move the call out of `start_video_call()`** - `:1669` runs before the socket exists and before any HELLO, so no salt can exist there.
- `:1668-1674` - delete the `derive_subkeys()` call at `:1669`; add `randombytes_buf(vc->local_half, MK_SALT_BYTES)` beside the existing prefix generation at `:1671`.
- `send_hello()` `:475-519` - replace all four variants with one `mh_build()` call. **The stack buffer at `:477` is exactly `HELLO_SIZE_VIDEO + IDENTITY_PK_BYTES + IDENTITY_SIG_BYTES` = 107 bytes; it must become `HELLO2_SIZE_SIGNED` = 126, or writing the salt is a 16-byte stack smash on every HELLO** - on a build that per audit M1 has no `-fstack-protector-strong`.
- `handle_hello()` `:521-672` - replace the entire length-tier dispatch (`:522`, `:581`, `:632`, `:664`) with `mh_parse()` + flag dispatch. Same derive-and-reset critical section as §4.2, resetting `rx_video`/`rx_audio`/`rx_stats` and both `audio_seq_tx`/`video_seq_tx`. The existing peer-restart machinery at `:547-579` (frag receiver re-init, VP8 decoder reopen, display clear) hangs off the same condition.
- Key sites: `:678` `encrypt_audio_pkt` → `audio_key_tx`; `:1081` `audio_decrypt_packet` → `audio_key_rx`; `:697` `encrypt_video_frag` → `video_key_tx`; `:721` `decrypt_video_frag` → `video_key_rx`; `:743` `encrypt_stats` → **`video_key_tx`**; `:772` `decrypt_stats` → **`video_key_rx`**. Stats stay on the video pair because `video_seq_tx` feeds both fragments (`:878`) and stats (`:910`) - this is survey correction C1 and getting it backwards is an instant nonce collision.
- `:1072` - `remote_prefix_ready` gate → `keys_ready`. `:820-824` and `:946-956` - both send-thread spins → `keys_ready`.
- `:1447-1449` - extend `sodium_memzero` to the four new keys plus `local_half` and `session_salt`.
- `:1653-1654`, `:2004/:2019/:2033` - **unchanged** (§2.4).

**`video_call/include/video_types.h`** - `:45,48` retire `HELLO_SIZE_AUDIO`/`HELLO_SIZE_VIDEO`; `:51-57` flags move to `media_hello.h` (values preserved); `:74-83` delete `KDF_CONTEXT_AUDIO`/`KDF_CONTEXT_VIDEO`/`KDF_SUBKEY_AUDIO`/`KDF_SUBKEY_VIDEO` - dead once `crypto_kdf` is gone.

### 4.4 Desktop - GUI and console

**`gui/src/audiocallmanager.cpp`, `gui/src/videocallmanager.cpp`, `gui/src/backend.{h,cpp}`, `gui/src/*dialog.cpp`** - **no changes required.** argv builders, the stdin key write and `closeWriteChannel()` all stay as they are. Optional polish: `chatwindow.cpp:302-309` already filters `[create]` lines; add the legacy-peer error string from §3 to whatever surfaces child stderr so the user sees it.

**`client-console/`** - no changes. It neither spawns nor knows about the media binaries; it only produces the room key that becomes `K_call`.

### 4.5 Android

**`app/src/main/java/com/fear/crypto/MediaKeys.kt`** - add `saltCombine(master, halfA, halfB, hash = SodiumKeyedHash): ByteArray` and `roleFromHalves(local, peer): Boolean?` (null on equal), mirroring §4.1 exactly. Keep the `KeyedHash` seam so the JVM tests can inject BouncyCastle.

**New `app/src/main/java/com/fear/crypto/MediaHello.kt`** - Kotlin mirror of `media_hello.c`: same constants, `build()`, `parse()` returning a sealed result, `agree()`. Explicit `ByteOrder.BIG_ENDIAN`.

**New `app/src/main/java/com/fear/crypto/ReplayWindow.kt`** - port of `replay_accept` (`audio_call.c:99-118`): `{ maxSeq: Long, bitmap: Long, started: Boolean }`, 64-entry sliding bitmap, `accept(seq): Boolean`. Android has **zero** replay protection today (verified: no `replay`/`maxSeq`/`bitmap` hits anywhere in `app/src/main/java`). It must land with the salt, not after - the desktop's window-reset condition and Android's absent one would otherwise disagree about when a stream legitimately restarts at seq 0.

**`app/src/main/java/com/fear/VideoCallManager.kt`**

- `:51-52` - four keys instead of two; add `localHalf`, `peerHalf`, `sessionSalt`, `isCallerWire`, `keysReady: AtomicBoolean`, three `ReplayWindow`s.
- `initialize()` `:134-150` - **delete** the `KeyDerivation.deriveAudioKey/deriveVideoKey` calls at `:136-137`; store `masterKey`, generate `localHalf` with `SecureRandom` beside `:142`. Note `Crypto.generateNonce()` returns only 12 bytes (`Crypto.kt:15,18`) and **cannot** supply a 16-byte half - use `SecureRandom` directly.
- `sendHello()` `:750-791` **and** `sendHelloWithoutIdentity()` `:793-805` - collapse both into one `MediaHello.build()` call. The second builder hardcodes `ByteBuffer.allocate(11)` at `:795` and is easy to miss.
- `handleHello()` `:880-933` - rewrite over `MediaHello.parse()`. `:902` `data.size >= 11` and `:913` `sigPrefixOffset = 11` both disappear. The restart detector at `:891` must compare halves, reset `audioSeqTx`/`videoSeqTx` (it does **not** today - only the teardown at `:710-711` does) and re-derive.
- Key sites: `:525` → `audioKeyTx`; `:938` → `audioKeyRx`; `:978` → `videoKeyRx`; `:1045` → `videoKeyRx`; `:498`→`:1132` and `:1089` → `videoKeyTx`.
- `:705-715` teardown - zero the four keys, `localHalf`, `sessionSalt`; clear the replay windows.
- Apply `ReplayWindow.accept()` after each successful decrypt at `:935-973`, `:975-1040`, `:1042-1071`.

**`app/src/main/java/com/fear/AudioCallManager.kt`**

- `:69`, `initialize()` `:108-117` - `roomKey` stops being the AEAD key; becomes `masterKey` plus `audioKeyTx`/`audioKeyRx`; generate `localHalf` beside the prefix at `:110-112`. The re-init guards comparing `roomKey.contentEquals(encryptionKey)` at `:365` and `:578` move to `masterKey`.
- `sendHelloPacket()` `:1582-1588` - `ByteArray(1 + AUDIO_NONCE_PREFIX_LEN)` becomes a `MediaHello.build()` call. Android currently **never** sends a signed audio HELLO; under v2 it should, when an identity is present.
- HELLO parse `:1264-1298` - rewrite over `MediaHello.parse()`. **`:1285-1286` unconditionally overwrites `remoteNoncePrefix` on every HELLO**, with an explicit multi-party comment at `:1273-1275`. Under salt-driven derivation that is a remote key-reset primitive; it must become first-HELLO-or-verified-change only. See open question O1.
- AEAD sites `:1430`, `:1494`, `:1525`, `:1568` → `audioKeyTx`/`audioKeyRx`. Stats share `seqTx` with audio (`:68`, `:1214`, `:1560`), so one key pair covers both, matching the desktop decision.
- Add `ReplayWindow` enforcement in `decryptAudioPacket` `:1452-1503` and `handleStatsPacket` `:1505-1540`.
- `:296`, `:394`, `:608`, `:661` - the four `isInitiator` construction sites keep feeding `:1289` (who answers a HELLO) but **no longer feed key derivation**. `:608`'s hardcoded `true` on the relay path stops being a correctness bug.

**`AudioConstants.kt`, `Common.kt`** - add `PKT_TYPE_HELLO2 = 0x7E`, `HELLO2_VERSION`, `MK_SALT_BYTES = 16` and the HELLO2 size constants. Better: have both files reference `MediaHello`'s constants so the existing drift (these two files already disagree on `AC_OPUS_BITRATE`, 128000 vs 24000, and `AUDIO_MAX_OPUS_BYTES`, 400 vs 1275) cannot spread to the wire format.

**`KeyDerivation.kt`** - becomes dead once `VideoCallManager` stops calling it. Delete in the cleanup step, not before.

**`VideoCallActivity.kt`, `ui/ComposeMainActivity.kt`, `ui/viewmodel/FearViewModel.kt`, `FearClient.kt`** - **no changes** (§2.4).

---

## 5. Build wiring

**Desktop:**

- `audio_call/CMakeLists.txt` - add to `SOURCES` (currently ends at `${CMAKE_SOURCE_DIR}/identity/identity.c`, line 18):
  ```cmake
      ${CMAKE_SOURCE_DIR}/identity/media_keys.c
      ${CMAKE_SOURCE_DIR}/identity/media_hello.c
  ```
  Include dir already present (`:25`), libsodium already linked. `${CMAKE_SOURCE_DIR}` resolves to the repo root because the root adds this via `add_subdirectory` (`CMakeLists.txt:98`).
- `video_call/CMakeLists.txt` - same two lines after `identity/identity.c` (line 25). Include dir already present (`:33`).
- `tests/CMakeLists.txt` - line 40 unchanged; add the new targets from §6.
- `gui/src/CMakeLists.txt` - no change; the GUI does not call `mk_*`.
- **Without this, the first build after the switch fails to link `mk_derive_pair`** - `tests/CMakeLists.txt:40` is currently the only rule in the entire repo that compiles `media_keys.c`.

**Android: no gradle changes are needed.** `app/src/main/java/com/fear/crypto/` is already on the main source set and already compiled. `com.goterl:lazysodium-android:5.1.0@aar` is at `build.gradle.kts:90`; the BouncyCastle test dependency `org.bouncycastle:bcprov-jdk18on:1.78.1` is already at `:132`; and `.github/workflows/android.yml:53` already runs `./gradlew testDebugUnitTest` ahead of `assembleDebug`. New files under `crypto/` and `app/src/test/java/com/fear/crypto/` are picked up automatically. Only `versionCode`/`versionName` (`build.gradle.kts:32-33`) should be bumped, as a breaking release.

---

## 6. Test plan

### 6.1 Pure unit tests, frozen vectors (no processes, no devices)

These fit the existing harness exactly: `tests/test_util.h` `CHECK`/`t_report`, one plain executable per suite via `add_fear_test`, plus the JVM mirror that commit `dd69a64` established.

**`tests/test_media_keys.c`** (extend; the existing vectors at `:44-63` must not move)
- `mk_salt_combine` frozen vectors: `master = 00..1f`, `halfA = 10..1f`, `halfB = f0^i`. Generate the expected value from an **independent** implementation (Python `hashlib.blake2b(key=master, digest_size=16)`), exactly as the existing header comment at `:1-11` describes. Do not generate it from the C code being tested.
- Commutativity: `combine(m, a, b) == combine(m, b, a)`.
- Salt sensitivity: `combine(m, a, b) != combine(m, a, c)`; `combine(m1, a, b) != combine(m2, a, b)`.
- `mk_role_from_halves`: opposite roles for `a<b` and `b<a`; **non-zero return on `a == b`**.
- End-to-end agreement: two synthetic peers with halves A and B independently reach the same `session_salt` and opposite `is_caller`, and `mk_derive_pair` then satisfies `callerSend == calleeRecv` and `calleeSend == callerRecv` for both streams.

**`tests/test_media_hello.c`** (new; `add_fear_test(test_media_hello test_media_hello.c ${IDENTITY_DIR}/media_hello.c ${IDENTITY_DIR}/media_keys.c ${IDENTITY_DIR}/identity.c)`)
- Frozen byte vectors: a fully-specified `mh_local_t` → the exact 30-byte and 126-byte hex strings, field offsets asserted individually (type, version, length, flags, prefix@5, half@9, w@25, h@27, fps@29, pk@30, sig@62).
- Round-trip `build → parse` for all four flag combinations.
- Signature covers `[0,62)`: flip one bit in each of bytes 0..61 in turn and assert `mh_parse` rejects; flip a byte in the signature and assert rejection.
- **Rejection matrix** (this is the part with no coverage today): `len` 0..29; `len` 31..125; `len` 127; length field disagreeing with actual length; `IDENTITY` set at 30 bytes; `IDENTITY` clear at 126 bytes; reserved flag bits set; wrong version byte; wrong type byte.
- Legacy detection: a byte-exact replica of the current 5/11/102/107-byte `0x7F` HELLOs must be classified `MH_ERR_LEGACY_PEER`, not silently dropped.

**`app/src/test/java/com/fear/crypto/`** - `MediaKeysTest` extended with the **same** `mk_salt_combine` vectors, plus new `MediaHelloTest` asserting the **same** frozen HELLO hex strings and the same rejection matrix, and `ReplayWindowTest` mirroring the desktop `replay_accept` semantics (first packet, forward jump ≥64, `diff >= 64` rejection, duplicate-bit rejection). Injecting BouncyCastle here is what makes the vectors mean anything - as the `dd69a64` message puts it, "a framing bug cannot hide behind one library agreeing with itself."

### 6.2 Live loopback (two processes)

Belongs in `tests/` as a shell script alongside `smoke_chat.sh` and `blob_auth.sh`, both of which already drive real binaries under CTest with a `TIMEOUT`.

**`tests/media_loopback.sh`** (`add_test(NAME media_loopback COMMAND bash .../media_loopback.sh $<TARGET_FILE:audio_call>)`, `TIMEOUT 60`)
- Start `audio_call listen <port>` and `audio_call call 127.0.0.1 <port>` on loopback with the same fixed 64-hex key on stdin, `--no-sign` for one run and with generated identities for another.
- Assert both processes print the new "keys ready" line, that the two report **opposite** derived roles, and that each logs a non-zero count of successfully decrypted audio packets. This is the only test that can catch a role inversion, a salt-agreement mismatch, or a replay-window/rekey ordering bug - none of which any pure unit test can reach.
- Negative case, which is the whole point of §3: run a v2 binary against a stub that emits the old 5-byte `0x7F` HELLO and assert the v2 side prints the legacy-peer error and exits non-zero, rather than hanging silently.
- A third case worth automating: start both ends, then inject a spoofed unsigned HELLO with a fresh half from a third socket and assert the call does **not** re-key (the §1.3 hardening).

**Video is not automatable in CI.** `start_video_call()` calls `SDL_Init(SDL_INIT_VIDEO)` at `video_call.c:1659` and returns -1 on failure. Run the video loopback manually with `--no-camera`, or gate it behind a headless-SDL environment variable. Do not pretend it runs in CI.

---

## 7. Implementation sequence

Steps 1-3 change **no wire byte** and can land independently and safely - nothing calls them, exactly the pattern `dd69a64` used for the primitive itself.

1. **Desktop primitive.** `mk_salt_combine` + `mk_role_from_halves` in `media_keys.{h,c}`; extend `tests/test_media_keys.c` with independently-generated vectors. Nothing calls them. *Ships alone. Breaks nothing.*
2. **Android primitive.** `MediaKeys.saltCombine`/`roleFromHalves` + `MediaKeysTest` with the **identical** vectors. *Ships alone. Breaks nothing.* Do this before step 3 so any framing disagreement surfaces at the smallest possible diff.
3. **HELLO2 codec, both platforms.** `identity/media_hello.{h,c}` + `tests/test_media_hello.c` + CMake source entries; `crypto/MediaHello.kt` + `MediaHelloTest`; `crypto/ReplayWindow.kt` + `ReplayWindowTest`. Still unreferenced by any live path. *Ships alone. Breaks nothing.* At the end of this step the CMake wiring from §5 is already in place, so step 4 cannot fail to link.
4. **THE LOCKSTEP LANDING.** Desktop `audio_call.c` + `video_call.c` and Android `AudioCallManager.kt` + `VideoCallManager.kt` all switch to HELLO2 and per-direction keys. This is the breaking change and **the point where the two repos must land together.**
   - Because these are two separate git repositories, "together" is a release convention, not a merge. Concretely: tag `fear` desktop `vX` and `fear-android` `vX` the same day, desktop first (its C vectors are the reference), Android immediately after; state in both release notes that vX does not interoperate with any earlier build, in either direction, on any transport.
   - **What breaks in between:** between the desktop tag and the Android tag, every desktop↔Android call fails at the handshake. With the §3 legacy detection this is a loud, correct error message on both sides rather than a dead call, which is what makes a short window tolerable. Desktop↔desktop and Android↔Android calls keep working within each version. **Do not split step 4 into "audio now, video later"** - `video_call` links `audio_crypto.c` and emits `PKT_TYPE_AUDIO 0x01` packets with the identical header, so `audio_call`↔`video_call` interop is real today and would break.
   - Land all four files as one commit per repo, so a bisect never lands on a half-migrated build.
5. **Optional but recommended, same release: bind the 9-byte header as AAD.** Both AEAD paths pass `NULL, 0` today (`audio_crypto.c:85,151`; `audio_call.c:563,592`; `video_call.c:697,721,743,772`; Android `byteArrayOf()` at `AudioCallManager.kt:1430,1494,1525,1568`). Per-direction keys do **not** close this: in `audio_call`, audio and stats share `c->key_tx` **and** `seq_tx`, so flipping a captured packet's type byte `0x01`↔`0x04` yields a packet that still authenticates under the same key and nonce and is then routed to the wrong parser. `video_call` has the same exposure between fragments and stats under `video_key` / `video_seq_tx`. This is a genuine confusion attack, cheap to close, and the wire is being broken anyway - it will not be free again. It is listed separately because it is the only item that changes `audio_crypto.c` **logic** rather than its comments, and it touches all four Android AEAD sites.
6. **Cleanup.** Delete `KDF_CONTEXT_*`/`KDF_SUBKEY_*` (`video_types.h:74-83`), `KeyDerivation.kt`, `HELLO_MAGIC` and `PROTOCOL_VERSION` (`audio_types.h:48,51`). Update `doc/SECURITY_AUDIT_2026-07.md`: close M3 and M5 (`:137,:139`), correct the stale M6 line (`:140` predates the replay windows, which are implemented), and rewrite `:53`, which currently states `media_keys.c` is an unused primitive. Bump Android `versionCode`/`versionName`.

---

## 8. Open questions - flagged, not invented

**O1. Is group audio still a supported product feature?** This is the one question that could invalidate part of the design, and I cannot answer it from the code. `hub_forward()` (`audio_hub.c:183-208`) rebroadcasts to up to 32 clients; the TCP relay is equally N-party; and `AudioCallManager.kt:1273-1286` carries an explicit comment that accepting a HELLO from any sender is **intentional** for multi-party calls. A caller/callee direction bit is a strictly 2-party abstraction: with three participants the last HELLO wins and every derived rx key is wrong for all but one peer. My recommendation is to declare the salted path 2-party-only, make `hub` mode refuse to start under v2, and delete the multi-party comment - but that removes a feature someone deliberately wrote, so it needs a product decision, not an integrator's guess.

**O2. Can `audio_call` start on a headless CI runner?** The loopback test in §6.2 depends on it. `th_send_func` handles `c->in_stream == NULL` by zeroing the PCM buffer (`audio_call.c:637-640`), which suggests it can, but `Pa_Initialize()` may still fail with no ALSA devices present. **Unverified - I did not run it.** If it fails, the loopback test needs a null-audio backend or a `--no-audio` flag that does not exist today, and that changes the scope of step 3.

**O3. Exact `HELLO2_VERSION` semantics.** I specified `0x02` as a literal with no negotiation rule beyond "reject anything else". Whether a future v3 peer should accept a v2 HELLO and downgrade is a policy question I have deliberately not answered - the field exists so the decision can be made later rather than forced now.

**O4. `MK_SALT_CTX` string value.** I chose `"fear.media.salt.v1"` (18 bytes, no NUL, matching the `sizeof(ctx)-1` convention at `media_keys.c:19-20`) for consistency with `MK_CTX "fear.media.v1"` and `"fear.epoch.v1"`. If the project has a naming convention for domain-separation strings I have not seen, this should be settled **before** step 1, because it is frozen into test vectors on both platforms the moment step 1 lands.

**O5. Behaviour on the `cmp == 0` abort in `--no-sign` mode.** I specified abort. An attacker who can reflect datagrams can therefore force call teardown against unsigned peers. That is a strictly better outcome than nonce reuse, but it is a new denial-of-service surface that did not exist before, and it should be an explicit accepted risk rather than an unnoticed side effect.

---

## Revised design: N-party sender-rooted media keys (`fear.media.v2`)

> Replaces sections 1.3, 2 and the salt/role parts of sections 4 and 6 of this document. Steps 1-3 of section 7 are superseded by section 9 below. Verified against desktop `~/Documents/VS_Code/ClaudeAI/fear-main` branch `dev` and Android `~/Documents/AndroidStudioProjects/FEAR` branch `dev`, re-read over SSH.
>
> **The project owner has confirmed group audio and group video are supported features.** Open question O1 of the previous revision is answered: yes. The direction bit and the two-halves salt fold are therefore dead, and this section replaces them.

### 1. The decision, and why it is this and not the proposals

**Chosen: sender-rooted media keys.** Each participant unilaterally draws a 16-byte `sender_salt`, derives its own send keys from `K_call` plus its own public announcement, and is identified on the wire by a 3-byte `SID` carved out of the existing 8-byte sequence field. No agreement step, no role, no rekey on membership change, zero added bytes per media packet.

The impossibility argument that forces this is short and all three proposals reached it independently: the ciphertext must be decryptable by every participant, so its key can only be a function of `K_call`, sender-specific values, and room-global values. **Receiver-specific key material is structurally impossible with one broadcast ciphertext.** The two-halves fold has exactly two N-party generalisations and both are dead: folding all N halves makes every join and leave a room-wide rekey with transient membership disagreement over lossy UDP (a liveness catastrophe), and folding pairwise makes A emit N-1 ciphertexts per 20 ms frame, which deletes the entire point of `hub_forward()` (`audio_hub.c:183-208`, verified: one `sendto` per client, skip the source, no parsing).

What follows is **not** any of the three proposals as submitted. Nine reviews found seven independent ways to reuse a `(key, nonce)` pair or to silently silence a participant, and every one of them lived in machinery the proposals added around a derivation that was itself sound. The table below is the accounting. Where a judge found a fatal flaw, it is either removed by construction or accepted with a name.

| # | Finding | Disposition here |
|---|---|---|
| Epoch pinned in the KDF vs. the `±1` freshness check makes a room unjoinable after ~2 h, and an epoch change is a KDF-input change with no fresh salt (a reuse path) | **Removed.** No wall clock anywhere in the media path. `ks_epoch_acceptable` is `diff <= 1` (verified, `key_schedule.c:41`), so a frozen epoch and a freshness check cannot both hold in a long call. `epoch` is replaced by a mandatory 16-byte `call_id`, which bounds replay per call instead of per two hours and introduces no clock dependency. Note `ks_epoch_from_unix` has no caller outside `tests/test_key_schedule.c` today, so nothing regresses. |
| Re-derivation is not atomic against the encrypting threads; `video_call` runs `th_vsend` (`video_seq_tx`, fragments at `:878` and stats at `:910`) and `th_asend` (`audio_seq_tx` at `:983`) over one sender identity, so any counter reset can interleave with a key install | **Removed by forbidding mid-call re-derivation entirely.** There is no SID roll (it existed only to serve the epoch check, which is gone), no re-salt on counter exhaustion (which cannot occur, below), and no mid-call `key_version` change. The send context is drawn once before any encrypting thread starts and is never mutated. No lock is required because no mutation exists. |
| `2^32` counter with a mandatory hard stop; the "850 years" figure is wrong by 1000x (`QUALITY_HIGH` is 1500 kbps over `FRAG_MAX_PAYLOAD` 1200, verified `video_types.h:119,155`, so ~156 fragments/s and `2^32` is ~318 days) | **Removed.** The header split is **3-byte SID + 5-byte CTR**, giving `2^40`: 223 years of `QUALITY_HIGH` video, 697 years of 50 pps audio. Exhaustion cannot occur inside a call, so the re-salt recovery path and the reuse route inside it are deleted at zero byte cost. |
| SID grinding against a bounded, recency-ordered trial walk permanently and silently mutes a chosen participant | **Removed.** Buckets are ordered by **install time, oldest first**, never by recency, and at most **two** slots may share a SID. A third install colliding with a live SID is refused and logged. An attacker cannot grind against a victim's SID before the victim draws it, and cannot displace it after. |
| One forged packet at a high counter poisons a victim's replay window permanently (`replay_accept` advances `max_seq` to any successfully-opened seq, `audio_call.c:99-118`) | **Fixed.** `replay_accept` rejects `seq > max_seq + MK_MAX_CTR_JUMP` (16384) and logs an anomaly. This is a change to shipped desktop logic and must land on Android in the same release. |
| A recorded HELLO plus recorded media replays perfectly into a later call, or into a slot that has been evicted, because every key input is public and static | **Fixed for the cross-call case, fixed for the eviction case, one named residual.** `call_id` in the KDF means a recording from call #1 does not decrypt in call #2. A **tombstone** `(salt, high-water CTR, bitmap)` survives slot eviction for the life of the call, so reinstalling a retired salt resumes its window rather than zeroing it. Residual: stale-media injection at a late joiner, section 10. |
| A signed HELLO with no room or call binding is replayable into another room as a TOFU-"VERIFIED" phantom; an unauthenticated HELLO lets an off-path attacker flood the blind hub and lock out joiners | **Fixed.** Every HELLO carries a 16-byte MAC under `K_hello = BLAKE2b(K_call, "fear.media.hello.v2" \|\| call_id)`. Off-path attackers are locked out of the handshake entirely, and a HELLO from any other call fails the MAC. |
| Any room member can derive any other member's send key and forge media attributed to them, so a per-participant "verified" badge over media is false | **Accepted, named, and constrained.** Named consequence: **media is authenticated at room granularity, never at participant granularity, in both signed and unsigned mode.** Product rule in section 7. Upgrade path reserved on the wire (`flags 0x08`, version `0x04`). |
| Key table and decoder pool merged, so a quiet participant is evicted and is inaudible for ten seconds when they speak up | **Fixed.** Two tables. Key slots: 32, matching `MAX_HUB_CLIENTS` (verified `audio_types.h:62`), ~120 B each. Decoder pool: 8 audio / 4 video, LRU on last media. A quiet participant keeps its key slot. |
| The group receive path does not exist: one `OpusDecoder` and one `PcmRing` with no mixer, one `FragReceiver` whose `FragAssembly` is keyed on `frame_id` with no sender field, one `VideoDecoder`, one display surface, one `opusDecoder` on Android | **Accepted as scope, not hidden.** Section 9 costs it separately and stages group audio first. Shipping the crypto alone produces a room where every packet decrypts and nobody is intelligible, which is a worse failure than today's because it looks like it works. |
| `key_version` bound into the KDF while `K_room` rotates on exactly the join/leave events the scheme absorbs | **Kept as a field, constrained by rule.** `key_version` is fixed for the lifetime of a call; a rotation requires a new call with a new `call_id`. A receiver that does not hold the announced generation drops the HELLO with a specific error rather than deriving silently. |
| "All multi-byte integers big-endian, matching every existing field on this wire" is false against `key_schedule.h` | **Corrected explicitly.** The media wire and every v2 KDF input are **big-endian**. `key_schedule.h`'s `[key_version(2)][epoch(4)]` header is **little-endian** (verified `key_schedule.c:44-52`) and is **not reused**; `ks_write_header` / `ks_read_header` are not called from the media path. |

### 2. Derivation

Three keyed-BLAKE2b calls through the `crypto_generichash` / `KeyedHash.blake2b` seam both platforms already have. All multi-byte integers big-endian.

**Inputs held by a participant at call start**

| Value | Width | Source | Lifetime |
|---|---|---|---|
| `K_call` | 32 B | room key, existing stdin / `initialize(roomKey)` path | the call |
| `call_id` | 16 B | signalling, or the initiator, delivered beside `K_call` (section 11, O1). **All-zero is refused.** | the call |
| `key_version` | 2 B | `K_room` generation, `0` when the key came from the CLI | the call, immutable |
| `sender_salt` | 16 B | `randombytes_buf` / `SecureRandom`, drawn once per call object | the call, immutable |
| `idbind` | 32 B | own Ed25519 pk, or 32 x `0x00` when `--no-sign` | the call, immutable |

**1. HELLO authentication key** (computable before any packet is parsed):

```
K_hello (32 B) = BLAKE2b(key = K_call, data = INFO_H, out = 32)

INFO_H = "fear.media.hello.v2"   19 B  ASCII, no NUL
       || call_id                16 B
                                 = 35 B
```

**2. Per-sender, per-stream media key.** This is the whole scheme:

```
K_send(P, stream) (32 B) = BLAKE2b(key = K_call, data = INFO_K, out = 32)

INFO_K = "fear.media.v2"         13 B  ASCII, no NUL
       || stream                  1 B  0 = audio counter domain, 1 = video counter domain
       || key_version             2 B  uint16 BE
       || call_id                16 B
       || sender_salt            16 B  P's own value
       || idbind                 32 B  P's Ed25519 pk, or 32 x 0x00
                                 = 80 B
```

There is no direction byte, no receiver contribution, and no peer input of any kind. The 1-bit direction field is replaced by 128 bits of sender-chosen entropy plus, in signed mode, 256 bits of identity.

**`stream` names a counter domain, not a media type.** That is the exact statement of constraint 3 and it is why there is no `MK_STREAM_STATS`. Verified mapping:

| Binary | Counter | Packet types on it | `stream` |
|---|---|---|---|
| `audio_call` | `c->seq_tx` (`audio_call.c:658`, `:682`) | `0x01` audio, `0x04` stats | 0 |
| `video_call` | `vc->audio_seq_tx` (`video_call.c:983`) | `0x01` audio | 0 |
| `video_call` | `vc->video_seq_tx` (`video_call.c:878`, `:910`) | `0x02` fragment, `0x05` stats | 1 |

Adding a packet type to an existing counter needs nothing. Adding a counter needs a new `stream` id. Both are unit-testable invariants, and the merge direction is as fatal as the split direction: **one key with two independent counters must never be constructed.**

**3. Sender tag (SID), per sender, not per stream**, so one tag identifies a participant across audio, video and stats:

```
SID (3 B) = first 3 bytes of BLAKE2b(key = K_call, data = INFO_S, out = 16)

INFO_S = "fear.media.sid.v2"     17 B
       || call_id                16 B
       || sender_salt            16 B
       || idbind                 32 B
                                 = 81 B
```

Output is 16 and truncated because `crypto_generichash_BYTES_MIN` is 16; you cannot ask libsodium for a 3-byte digest, and BLAKE2b carries the output length in its parameter block, so Kotlin must compute 16 and truncate identically or the vectors diverge.

**4. HELLO MAC:**

```
MAC (16 B) = BLAKE2b(key = K_hello, data = HELLO[0, len-16), out = 16)
```

Compared with `sodium_memcmp` / `MessageDigest.isEqual`, never `memcmp`.

**Why `idbind` is in the KDF.** It costs nothing (the pk is already in the HELLO) and it makes two distinct signed identities structurally unable to share a key regardless of RNG quality, which is the single residual the nonce reviews kept returning to. It does not fork the vector set: there is one derivation function and one vector table with a signed row and an unsigned row. An all-zero pk is not a value `identity_verify` will ever accept, so `idbind` unambiguously encodes both modes without a separate flag.

### 3. Wire format

#### 3.1 Media packet header: 9 bytes before, 9 bytes after, repartitioned

| off | size | field |
|---|---|---|
| 0 | 1 | `type`: `0x01` audio, `0x02` video fragment, `0x04` stats on the audio counter, `0x05` stats on the video counter |
| 1 | 3 | `SID` |
| 4 | 5 | `CTR`, uint40 BE, starts at 0 |
| 9 | .. | AES-256-GCM ciphertext `||` 16-byte tag |

```
nonce (12 B) = SID(3) || 0x00 0x00 0x00 0x00 || CTR(5)
AAD          = header bytes [0,9)
```

**Delta: 0 bytes.** Every buffer in the tree is sized `1 + 8 + payload + 16` (`video_call.c:805`, `audio_call.c` packet buffers, `audio_crypto.c:73-90`), so nothing resizes and the MTU arithmetic, `FRAG_MAX_PAYLOAD 1200` and `AC_MAX_OPUS_BYTES 1275` are untouched.

**`make_nonce()` needs no change.** Verified against `audio_crypto.c:34-43`: passing `prefix = { sid[0], sid[1], sid[2], 0x00 }` and `seq = CTR` with `CTR < 2^40` produces `s0 s1 s2 00 | 00 00 00 c4 c3 c2 c1 c0`, byte-identical to the header-derived nonce above. The prefix argument stops being random and becomes the SID plus one mandatory zero byte; the function body is unchanged and `audio_encrypt_packet` / `audio_decrypt_packet` keep their existing signatures (`audio_crypto.h:32,49` already take `const uint8_t *key` and a 4-byte prefix). Only the header packing and the AAD argument change.

**Splitting stats into `0x04` and `0x05`** costs zero bytes and removes a real cross-binary footgun: today `0x04` means "audio counter" in `audio_call` and "video counter" in `video_call`, so the two binaries would disagree about which key opens a stats packet. Under v2 the type byte alone determines the counter domain and therefore the key.

**AAD is not optional.** Every AEAD site passes `NULL, 0` today (`audio_crypto.c:85,151`; `audio_call.c:560,589`; `video_call.c:694,718,740,769`; `byteArrayOf()` at `AudioCallManager.kt:1430,1494,1525,1568`). Per-sender keys do **not** close this: audio `0x01` and stats `0x04` share one key and one counter, so a captured packet's type byte can be flipped and it still authenticates under the same key and nonce, then reaches the wrong parser. Binding the 9 header bytes also stops a hostile relay rewriting the SID to misfile a packet into another sender's slot.

**Counter guard.** `CTR >= (1ULL << 40)` tears the call down. It is unreachable in practice (223 years at 156 pkt/s) and it is written as an assertion, never as a recovery path, because a recovery path is a re-derivation and re-derivations are forbidden.

#### 3.2 HELLO2: type `0x7E`, version `0x03`

`0x7E` is unused. Verified drop behaviour on all four live parsers: `audio_call.c:739-768` falls through to `audio_crypto.c:132` which rejects on `pkt[0] != PKT_VER_AUDIO`; `video_call.c:1063-1211` falls off the if-chain; `VideoCallManager.kt:852-864` logs an unknown type; `AudioCallManager.kt:1253-1264` rejects at `:1454`.

| off | size | field |
|---|---|---|
| 0 | 1 | `0x7E` `PKT_TYPE_HELLO2` |
| 1 | 1 | `0x03` `HELLO2_VERSION` |
| 2 | 2 | uint16 BE total length: 62 or 158 |
| 4 | 1 | flags: `0x01` VIDEO, `0x02` AUDIO, `0x04` IDENTITY, `0x08` reserved SENDER_KEY_WRAPPED, `0x10..0x80` reserved MBZ |
| 5 | 1 | reserved, MBZ |
| 6 | 2 | uint16 BE `key_version` |
| 8 | 16 | `call_id` |
| 24 | 16 | `sender_salt` |
| 40 | 2 | uint16 BE `width` (0 when `!VIDEO`) |
| 42 | 2 | uint16 BE `height` (0 when `!VIDEO`) |
| 44 | 1 | uint8 `fps` (0 when `!VIDEO`) |
| 45 | 1 | reserved, MBZ |
| 46 | 32 | Ed25519 pk, only when `flags & IDENTITY` |
| 78 | 64 | Ed25519 signature over `[0,78)`, only when `flags & IDENTITY` |
| 46 or 142 | 16 | MAC over `[0, len-16)` |

```
HELLO2_SIZE_BASE   = 62
HELLO2_SIZE_SIGNED = 158
```

**Acceptance rule, no tolerance and no length tiers.** Accept iff `len == rd_u16(buf+2)` **and** `len == (flags & IDENTITY ? 158 : 62)` **and** `buf[1] == 0x03` **and** all reserved bits and bytes are zero **and** `call_id != 0` **and** the MAC verifies under `sodium_memcmp`. Everything else is dropped with a specific log line. The current wire has no length field and no equality check anywhere, which is why every parser silently tolerates trailing bytes; that ends here.

**Order of operations on receipt**, which matters: verify the MAC first (cheap, and it gates everything), then length and flags, then `key_version` availability, then the signature if IDENTITY, then the self-salt check, then install. **Never touch state before the MAC.**

Video parameters are always present and zeroed for audio-only, so dispatch is on `flags`, never on length. That deletes the `video_call.c:581` misparse (where a 21-byte packet would have configured a decoder from raw salt bytes) and the dead branch at `video_call.c:632-663`.

Byte deltas from today's 5 / 11 / 102 / 107 tiers: unsigned audio +57, unsigned video +51, signed audio +56, signed video +51. Steady state in a room of 8 with a 10 s keepalive is 7 x 158 B / 10 s = ~111 B/s at each receiver, against roughly 3 kB/s for one 24 kbps Opus stream. Join burst is one round of N HELLOs, ~1.1 kB at N=8.

**`video_call.c:477`'s `send_hello` stack buffer is exactly `HELLO_SIZE_VIDEO + IDENTITY_PK_BYTES + IDENTITY_SIG_BYTES` = 107 bytes** (verified). It must become 158 or writing the HELLO is a stack smash on every send, on a build that per audit M1 has no `-fstack-protector-strong`.

**Legacy peers.** A received `0x7F` is recognised explicitly and reported **once per source**, then that source is ignored. It must **not** abort the call: that was correct 2-party behaviour and is wrong at N>2, where one stale participant would kill the conference for everyone. Log: `participant is running an incompatible protocol version (pre-v2 HELLO); ignoring`. Old and new builds do not interoperate in either direction on any transport, deliberately, and this belongs in both release notes.

### 4. Sender identification over a blind relay

**Per-packet byte cost: zero.** The SID is carved out of the existing sequence field.

Today the nonce prefix is never on the wire; it is learned from HELLO and cached as a single `remote_nonce_prefix`. That single cached value is exactly what breaks at N>2: `AudioCallManager.kt:1285` unconditionally overwrites it on every HELLO, with a comment at `:1273-1275` saying that is intentional for group calls, which means the last HELLO wins and every other peer's traffic becomes undecryptable. Under v2 the tag is on the wire and the table is per sender.

Receive algorithm, exactly:

```
if (len < 9 + 16) drop
sid = pkt[1..4]; ctr = be40(pkt+4)
bucket = every key slot whose slot.sid == sid, ORDERED BY INSTALL TIME, OLDEST FIRST
if bucket empty:
    rate-limited log "media from unknown SID %06x"
    solicit: send one HELLO, rate-limited to 1/s        /* repairs a lost reply in ~1 RTT */
    drop
for each slot in bucket:                                 /* at most 2 by construction */
    key = key_for_type(slot, pkt[0])                     /* 0x01,0x04 -> stream 0; 0x02,0x05 -> stream 1 */
    nonce = sid || 00 00 00 00 || ctr
    if aead_decrypt(key, nonce, aad = pkt[0..9], ct = pkt+9) == OK:
        if replay_accept(&slot.window[stream], ctr) != 0: drop
        slot.last_media_ms = now; deliver to that sender's decoder; break
```

**We never install a peer slot for our own `sender_salt`**, so our own send key is never in the receive table and reflected media dies at lookup. We do **not** filter on `sid == our own sid`: a peer can legitimately draw our 3-byte tag with probability 2^-24, and a pre-crypto self-SID drop would silently and permanently black-hole it.

**SID collisions are benign and the bucket walk is what makes that true.** Two colliding senders have completely different keys (16-byte salts plus 32-byte `idbind`), so a collision costs one extra failed GCM tag check. Accidental collision probability at 32 participants is `C(32,2)/2^24` = 3.0e-5 per room. Deliberate collision is bounded at install: **at most two slots per SID, first-come wins the ordering, a third is refused and logged.** An attacker cannot grind against a salt that has not been drawn yet, and cannot displace an established slot afterwards. Writing this lookup as an exact-match single-slot lookup, or ordering the bucket by recency, is the single most likely implementation bug in the whole design and both belong in the rejection matrix.

**Why 3 bytes and not 4.** SID width does no security work: collisions are handled by the walk, and grinding is cheap at any width a room member can compute (they hold `K_call`). Width therefore only sets the accidental-collision rate, which is negligible at 3 bytes. The fifth counter byte it buys removes an entire failure class.

**Why derive the SID rather than send `sender_salt[0..2]`.** Keying by `K_call` and `call_id` means the tag is fresh per call and unlinkable across calls to anyone without the room key. That is strictly less linkable than today, where the 4-byte nonce prefix is broadcast in cleartext in the HELLO and is equally stable within a call.

**Rejected: trial decryption with no tag.** Zero bytes but O(N) AES-GCM attempts per packet. At 32 senders of `QUALITY_HIGH` video that is roughly 5000 packets/s x 32 trials on a phone. Rejected on power, and it is precisely the operation AES-GCM's lack of key commitment makes uncomfortable.

**Rejected: a server-attested sender label.** The TCP relay frame does carry a sender name and `server.c` pins it to the connection, but `tcp_relay_recv_media()` discards it (`audio_call.c:460-479`, verified: room and name are read into `skip` and thrown away), the server explicitly skips name-uniqueness for media clients, and the UDP hub carries no name at all. Building on it would make the crypto depend on the relay being honest, which is the opposite of what a zero-knowledge relay is for.

### 5. Join, leave, rejoin

**No participant ever rekeys, re-derives, or resets a counter because of a membership change.** That is the defining property and it is the direct payoff of unilateral salts.

**Join.** The joiner draws its salt, derives `K_send(me, AUDIO)`, `K_send(me, VIDEO)` and its SID, and starts encrypting immediately. It needs no input from anyone, so `th_send_func`'s spin on `remote_prefix_ready` (`audio_call.c:621-632`, `video_call.c:820-824`, `:946-956`) is deleted outright: there is nothing left to wait for. Consequence to state rather than sell as pure simplification: the first ~200 ms of a join is unrecoverable at peers that have not yet installed the joiner.

Cadence: every 250 ms for the first 3 s, then every 10 s as a keepalive. The fast phase ends **on a timer**, not on "heard at least one peer", which is 2-party termination logic that fails at N=8.

An existing participant receiving a HELLO whose MAC verifies and whose `sender_salt` is not already in its table: allocates a key slot, derives that peer's two keys and SID, and replies with **exactly one** HELLO after 0-200 ms of jitter.

**The reply rule is load-bearing and must be written down.** Today `handle_hello` is followed by an unconditional reply (`audio_call.c:741`, `video_call.c:1066-1069`), which behind `hub_forward` at N>=3 is a self-sustaining broadcast storm that does not terminate. The rule is: **reply only to a salt not already in our table**, plus the unconditional keepalive, plus the solicit-on-unknown-SID in section 4 which repairs a lost reply without waiting 10 s. If the key change lands and this does not, group calls melt the hub even though the crypto is correct.

**Leave.** The leaver stops sending. After `MK_SENDER_TIMEOUT_MS` = 30000 with no accepted packet, peers free the decoder, `sodium_memzero` the keys, and **retain a tombstone** `(sender_salt, high-water CTR, window bitmap)` for the remainder of the call. No key change, no counter reset, no interruption to anyone else. A leave is invisible to the crypto.

**Tombstones are what make eviction safe.** Without them, an evicted slot that is reinstalled from a replayed HELLO gets a zeroed replay window and the whole recorded stream is accepted as live. A tombstone is 32 bytes; cap at 64 per call (2 kB), evict oldest, and log when the cap is hit.

**HELLO idempotence.** A HELLO carrying a salt already in the table, or already in the tombstone table, **mutates nothing** and is not replied to. A HELLO never edits an existing slot's key, counter or window. The only permitted transition on an existing slot is **unsigned to signed**: a valid signed HELLO for a salt currently held unsigned upgrades the slot and pins the pk. Never the reverse, which closes the IDENTITY-strip downgrade.

**Rejoin and restart.** A restarted peer returns with a fresh salt, therefore a fresh SID and fresh keys, and its counters legitimately start at 0. To everyone else it is simply a new sender. This deletes the `prefix_changed` machinery at `audio_call.c:263-270` and `video_call.c:530-543` as a special case: "restarted" and "new participant" become one code path, and the "should I reset the replay window" question disappears because the window belongs to a slot that is brand new. With identities present, a HELLO whose pk is already bound to a live slot under a different salt is the authenticated restart signal.

**Table sizing.** Key slots and decode state are **separate pools**, which the proposals conflated:

| Pool | Size | Per entry | Eviction |
|---|---|---|---|
| Key slots | 32 (matches `MAX_HUB_CLIENTS`) | ~120 B: salt, sid, 2 keys, 2 windows, pk, timestamps, RTT state | none while live; a full table **refuses** a new install and surfaces "room is full" |
| Audio decoders | 8 | `OpusDecoder` + `PcmRing` | LRU on last media |
| Video decoders | 4 | `FragReceiver` + `VideoDecoder` + pane | LRU on last media |

A quiet participant keeps its key slot, so it is audible on the first packet after speaking up rather than after the next keepalive. `pcmring_init(&c->out_ring, 128)` is 128 x 960 x 2 = 240 kB, so eight per-sender rings at the current capacity is 1.9 MB before any decoder state; shrink the per-sender ring to ~32 frames in a group build.

**No forward secrecy across a membership change, unchanged from today.** `K_call` is long-lived; a departed member keeps it and can decrypt anything it captured before or after leaving. Sender-rooted keys neither help nor hurt: the property lives in the room key. `key_version` is in the KDF so that when `K_room` does rotate, every media key rolls with it automatically, but **a rotation means a new call with a new `call_id`, never a mid-call rekey.**

**Group-specific bugs that must land in the same release**, all verified, none with a 2-party symptom:

- TOFU is keyed by the literal string `"peer"` (`audio_call.c:277`, `video_call.c:611`, `:648`). With three signed participants the second collides with the first and prints `PEER KEY CHANGED`. Must be keyed by the pk.
- `last_peer_ping_ts` / `peer_ping_recv_time` / `measured_rtt_ms` are single scalars, and the ping/pong echoes whichever peer's stats arrived last to everyone (`video_call.c:905-912`). At N>=3 every displayed RTT is noise, and in `video_call` it feeds `QualityController` and therefore the encoder bitrate for the whole room. Move into the key slot; the quality controller needs a stated group policy.
- `FragAssembly` is keyed on `frame_id` alone, and every sender starts at `frame_id` 0, so `find_or_create_slot` merges fragments from different senders into one assembly. Must be keyed on `(SID, frame_id)`.
- There is no on-demand keyframe path anywhere (`video_codec.c:55` sets `gop_size = fps * 2` and nothing forces an I-frame). A late joiner sees up to 2 s of black per existing sender. Force a keyframe when an unknown salt is installed.
- `hub_prune()` is called only from the `if (n <= 0)` branch of `hub_thread()` on a blocking socket with no `SO_RCVTIMEO` (`audio_hub.c:226-250`), so it never runs while anyone is sending. Under churn the hub's 32 slots fill with dead addresses and `hub_find_or_add` starts returning -1, which is a genuine N-party join failure. `HUB_CLIENT_TIMEOUT_SEC` is also 180 in `audio_hub.c:33` against `HUB_TIMEOUT_SEC` 30 in `audio_types.h:65` and 60 in `audio_call.c:143`.

### 6. Nonce uniqueness

**Claim: no two distinct plaintexts are ever encrypted under the same `(key, nonce)` pair by an honest sender.**

Let `K = BLAKE2b(K_call, "fear.media.v2" || stream || key_version || call_id || sender_salt || idbind)` and `nonce = SID || 0x00000000 || CTR`.

**(a) Exactly one party ever encrypts under a given `K`.** Every participant derives its send keys from its own locally generated `sender_salt`. Receivers derive peers' keys but pass them only to decrypt. This is structural, not conventional: the send path reads only the local send context, and a peer key slot exposes no send-side entry point. A peer slot is never installed for a salt equal to our own.

**(b) Two distinct senders never share `K`.** Sharing `K` requires an 80-byte `INFO_K` collision under BLAKE2b keyed with `K_call`. `INFO_K` contains the full 16-byte salt and the full 32-byte `idbind`. In **signed** mode two distinct identities differ in `idbind`, so a shared key is impossible regardless of RNG quality. In **unsigned** mode it requires a 128-bit salt collision, `C(32,2) x 2^-128` per call. A 3-byte SID collision is not a key collision: the tag is 3 bytes of a 48-byte input span, and the bucket walk handles it.

**(c) Under one key there is exactly one counter, and it is strictly monotone.** Verified: all counters are `atomic_uint_fast64_t` advanced only by `atomic_fetch_add`. `audio_call` audio (`:658`) and stats (`:682`) share `seq_tx` under `K(self, AUDIO)`; `video_call` fragments (`:878`) and stats (`:910`) share `video_seq_tx` under `K(self, VIDEO)`; `video_call` audio (`:983`) uses `audio_seq_tx` under `K(self, AUDIO)`. Two packet types under one key are safe **precisely because** they share one counter. Constraint 3 is preserved and is the reason for the `stream` field rather than an exception to it.

**(d) A counter reaches 0 only inside a send context that has never existed before.** This is the normative rule that the reviews broke every earlier draft on, and it is stated as a requirement on implementers, not as a hope:

> **The send context `(sender_salt, idbind, call_id, key_version, SID, K_send[AUDIO], K_send[VIDEO], counters)` is constructed exactly once, before any encrypting thread is started, and is never mutated for the lifetime of the call object. There is no rekey, no salt roll, no re-derivation, and no counter reset while a call is running. A counter reset is only ever performed as part of constructing a context that has never existed before.**

Because nothing mutates, no lock is needed and no interleaving exists. This is what removes the `video_call` two-thread hazard (`th_vsend` and `th_asend` share one sender identity across two counters, so any non-atomic re-derivation pairs a fresh counter with a stale key), and it is why the epoch, the mandatory SID roll and the counter-exhaustion re-salt were all deleted rather than made safe: each of them was a mid-call mutation.

**(e) No KDF input can change mid-call.** `call_id`, `key_version`, `sender_salt` and `idbind` are all fixed at construction; `stream` is constant per key; there is no wall-clock input. Therefore (d) has nothing to trigger it.

**(f) Cross-stream nonce equality is deliberate and safe.** Audio `CTR = 5` and video `CTR = 5` produce the same nonce under `K_send(P, AUDIO)` and `K_send(P, VIDEO)`, which differ in the `stream` byte of a keyed BLAKE2b input. GCM requires uniqueness of the pair, not of the nonce. An auditor will look at this twice, so it belongs in the header comment.

**(g) Reflection and replay cannot cause reuse.** Both are decrypt events, and decryption consumes no nonce space. Our own media reflected by a hub or NAT finds no slot and dies at lookup. Our own HELLO reflected carries our own salt and is refused. Note what this removes: v1 had to **abort** the call on a reflected HELLO (`mk_role_from_halves` returns -1 on equal halves, `media_keys.c:44`), because either role assignment put both ends on one key at seq 0. That was a real denial-of-service surface against unsigned peers and it is this document's open question O5. With no role to assign, reflection is inert and the abort is deleted.

**(h) No off-path attacker can install a key, reset a counter, or reset a replay window.** Every HELLO is MACed under `K_hello`, which binds `call_id`, so a HELLO from another call fails and a HELLO from this call is byte-identical to one already processed and is therefore a no-op. Today this is a live primitive: `handle_hello` writes `remote_nonce_prefix` and `memset`s both replay windows (`audio_call.c:263-270`) before anything is authenticated, from any datagram source.

**(i) Two processes on one machine sharing a room key.** Independent salts, independent keys, no interaction. Under v1 this was a live hazard: identical deterministic derivation separated only by a 2^-32 prefix draw.

**What is not proven.** Nothing at the protocol level prevents a *sender* from violating (d) or (e) by persisting or restoring a salt. That is an implementation invariant with a blast radius confined to that sender's own two streams, and it is directly testable:

- the salt is drawn only in `audio_call_start` / `start_video_call` / `initialize()` and never written to any file the process creates;
- an all-zero salt, and a salt equal to the previous draw in this process, are refused;
- two consecutive call objects **on a reused manager instance** must yield different salts. This case is not hypothetical on Android: `FearClient.getOrCreateAudioCallManager()` caches one `AudioCallManager` for the process lifetime, `private val seqTx = AtomicLong(0)` at `AudioCallManager.kt:68` is a construction-time field that is never reset, and per-call randomness lives in `initialize()` at `:110-112`. `VideoCallManager` already has the two halves split the other way: the prefix is drawn in `initialize()` at `:142` while both counters are zeroed in teardown at `:709-711`. **Redraw the salt in `initialize()` on both managers**, and the teardown counter reset stays safe because a fresh salt always precedes the next send.

### 7. Unsigned mode (`--no-sign`)

`--no-sign` uses the identical code path with `idbind` = 32 zero bytes. Derivation, nonce construction, tables, tombstones, windows and timers are byte for byte the same. There is no fallback branch and no capability negotiation. This is what finally kills pk-comparison as a role source: there is no role.

**What unsigned mode gains over what ships today and over the v1 plan**, which is not a small list:

- The HELLO MAC locks the hub, the relay server and every off-path attacker out of the handshake. They cannot inject a HELLO, modify one in flight, install a key, claim a SID, or churn the table.
- The remote key-reset primitive closes. `audio_call.c:273` only parses identity while `peer_verified == 0`, so today anyone who can send a datagram can spoof a bare 5-byte HELLO and reset both replay windows.
- Open question O5 is deleted outright, not accepted: there is no equal-halves abort, so a reflected datagram cannot force a teardown.
- The v1 plan's documented regression, "`--no-sign` loses mid-call peer-restart recovery", does not apply. A restart is a new slot, and installing a new slot cannot harm an existing one, so unsigned peers keep restart recovery.

**What unsigned mode does not give you, stated plainly.** You learn that a HELLO came from someone holding `K_call` and `call_id`, not from whom. A malicious room member can announce several salts and appear as several participants, and there is no way to notice that a departed member has returned under a new salt. Both are Sybil-within-the-room, an impersonation and resource problem rather than a confidentiality one, and both were already available to any room member.

**What signed mode adds, and what it deliberately does not.** With `flags & IDENTITY` the HELLO carries the pk at offset 46 and a signature over `[0,78)`, so the version, length, flags, `key_version`, `call_id`, salt and video parameters are all inside the signed range, unlike today where `audio_call.c:245-247` signs only the 4 prefix bytes. On acceptance the salt is pinned to that pk, TOFU runs per sender rather than per call, and `idbind` makes two identities structurally unable to collide. Mixed rooms work because IDENTITY is a per-HELLO flag.

**Blunt statement, and the strongest thing in this section.** The signature authenticates the **announcement**, not the media. Any holder of `K_call` can derive every participant's send key from their public HELLO and encrypt arbitrary audio under any SID, and can deliberately reuse a nonce against a chosen participant. This is inherent to constraint 1 and is not a regression: today's single shared key is weaker in the same way. But it has two mandatory consequences:

1. **The UI must not render a per-participant verified badge next to media.** Verified state belongs to the room roster. A speaker label must be presented as attribution, not authentication. Rendering `[VERIFIED] Alice` over a stream any member can forge is a security claim the wire cannot support.
2. It goes in the release notes as an explicit non-goal, alongside the reserved upgrade path: version `0x04` plus flag `0x08` `SENDER_KEY_WRAPPED` means the HELLO carries per-recipient wrapped sender keys under `identity_pm_room_key` (`identity.c:374`, no media caller today). **The media packet format does not change under that upgrade**, because the packet only ever needed a sender tag and a counter. Where the key came from was never on the wire. That is the reason the tag goes on the wire in this release.

A `--require-identity` switch that drops unsigned HELLOs is worth adding for rooms that care. It is policy, not mechanism.

### 8. The already-shipped artefacts

**Verified disposition basis:** `tests/CMakeLists.txt:40` is the only rule in the entire repository that compiles `identity/media_keys.c`, and a repo-wide grep for `mk_derive`, `mk_derive_pair`, `mk_salt_combine`, `mk_role_from_halves` and `media_keys` returns nothing outside `tests/test_media_keys.c`. On Android, a grep for `MediaKeys.` across `app/src/main/java/` returns nothing. **The v1 primitive shipped as an unreferenced module. No live path and no wire byte has ever depended on it.**

| Artefact | Disposition |
|---|---|
| `mk_derive()` and the `mk_dir_t` enum | **Delete.** v2 does not call it. Keeping it alive with `dir` nailed to `0x00`, purely to preserve vectors, buys a permanent API with a meaningless argument and a retired enum that invites a silent wrong-key mistake forever. The two-stage KDF that would have preserved it was the wrong trade. |
| `mk_derive_pair()` | **Delete.** Meaningless without directions. |
| `mk_salt_combine()` | **Delete.** The 2-party agreement layer has no honest N-party generalisation. |
| `mk_role_from_halves()` | **Delete, and it is the most urgent of the four.** Its equal-halves abort is an active denial-of-service surface against unsigned peers (this document's O5) that has never been exercised because nothing calls it. Deleting it before anything does is the whole point. |
| `MK_CTX "fear.media.v1"`, `MK_SALT_CTX`, `MK_DIR_*` | **Delete.** `MK_KEY_BYTES`, `MK_SALT_BYTES` and `mk_stream_t` survive with the same values. |
| The 5 frozen key vectors, `tests/test_media_keys.c:44-63` | **Delete**, with the functions they pin. |
| The 3 frozen salt vectors, the commutativity assertion and the role assertions in the same file | **Delete.** |
| Kotlin `MediaKeys.kt`: `info()`, `derive()`, `derivePair()`, `saltCombine()`, `roleFromHalves()` | **Delete.** All five mirror functions and their `MediaKeysTest` vectors go with the C. |
| Kotlin `KeyedHash.kt` (`fun interface KeyedHash`, `SodiumKeyedHash`) | **Survives untouched.** This seam is the valuable part of commit `dd69a64`: it is what lets JVM tests inject BouncyCastle so that "a framing bug cannot hide behind one library agreeing with itself". v2 derivations go behind it unchanged. |
| `identity/key_schedule.{h,c}` and `KeySchedule.kt` | **Survive untouched**, and are **not called from the media path.** In particular `ks_write_header` / `ks_read_header` are little-endian and must not be reused; `ks_epoch_from_unix` and `ks_epoch_acceptable` are not used at all, because v2 has no wall-clock input. |
| `KeyDerivation.kt`, `KDF_CONTEXT_*`, `KDF_SUBKEY_*`, `derive_subkeys()` | **Delete** at the switchover. `derive_subkeys` is replaced by a local-only derivation that can stay where it is at `video_call.c:1669`, because the send key needs no peer input. |
| `HELLO_SIZE_AUDIO`, `HELLO_SIZE_VIDEO`, `HELLO_SIZE_SIGNED`, `HELLO_FLAG_IDENTITY 0x01` in `audio_call.c:167`, `HELLO_MAGIC`, `PROTOCOL_VERSION` | **Delete.** Flag numbering adopts `video_types.h:51-57` (VIDEO `0x01`, AUDIO `0x02`, IDENTITY `0x04`), matching `Common.kt:59-61`. |

**Deleting committed code is the right call here and it should be done in the cleanup commit of this release, not deferred.** These functions are the 2-party agreement layer of a design the owner has just invalidated. Leaving them in the tree behind an `@deprecated` note for "one release later" means the next person to need a media key finds two primitives, one of which is a trap that tears down unsigned calls on a reflected datagram. The frozen vectors are protecting a test file, not a wire format, and they will pass forever while pinning behaviour nothing executes.

**What replaces them.** New v2 vectors for `mk_derive_sender`, `mk_sender_id` and `mk_hello_key`, generated independently in Python `hashlib.blake2b` and never from the C under test, with one signed row (`idbind` = a fixed pk) and one unsigned row (`idbind` = 32 zeros); byte-exact 62-byte and 158-byte HELLO hex with per-offset assertions; and the same vectors mirrored in Kotlin through the surviving `KeyedHash` seam.

### 9. Implementation sequence

| # | Step | Wire bytes changed | Repos |
|---|---|---|---|
| 1 | **Desktop primitive.** `identity/media_keys.{h,c}`: add `MK_CTX_V2`, `MK_SID_CTX`, `MK_HELLO_CTX`, `MK_SID_BYTES 3`, `MK_CALLID_BYTES 16`; add `mk_derive_sender()`, `mk_sender_id()` (compute 16, truncate to 3), `mk_hello_key()`. Extend `tests/test_media_keys.c` with independently generated v2 vectors. ~90 lines. | **none** | desktop |
| 2 | **Android primitive.** `MediaKeys.kt`: `deriveSender`, `senderId`, `helloKey` behind the existing `KeyedHash` seam; the identical vectors in `MediaKeysTest`. Do this before step 3 so any framing disagreement surfaces at the smallest possible diff. | **none** | android |
| 3 | **Codec and tables, both platforms.** New `identity/media_hello.{h,c}` (~280 lines: the 62/158 codec, `mh_build`, `mh_parse` with one error enum value per rejection, `MH_ERR_LEGACY_PEER` for a byte-exact `0x7F`, `mh_mac`, `mh_verify_mac`; links against libsodium and `identity.c` only, no sockets, no PortAudio, no SDL). New `identity/media_senders.{h,c}` (~280 lines: slot table, install-time-ordered bucket lookup, two-per-SID cap, tombstones, admission and refusal, per-sender replay windows with the bounded forward jump). Kotlin mirrors `MediaHello.kt`, `SenderTable.kt`, `ReplayWindow.kt` with explicit `ByteOrder.BIG_ENDIAN`. Add all three C files to `audio_call/CMakeLists.txt` and `video_call/CMakeLists.txt` **now**, so step 5 cannot fail to link. New `tests/test_media_hello.c` and `tests/test_media_senders.c` plus their JVM mirrors. | **none** | both |
| 4 | **`call_id` plumbing.** Deliver `call_id` alongside `K_call` on every path: GUI argv/stdin, console invite, Android `initialize()`. Media binaries refuse to start on a missing or all-zero `call_id`. This is the one prerequisite that is neither crypto nor media, and it must be finished before step 5 (see O1). | none yet | both, plus GUI and console |
| 5 | **THE BREAKING LOCKSTEP LANDING.** `audio_call.c`, `video_call.c`, `AudioCallManager.kt`, `VideoCallManager.kt` all switch to HELLO2, per-sender keys, the 3+5 header, AAD, the sender table and the reply rule, in one commit per repo. Includes the `video_call.c:477` buffer growth to 158, `sodium_memzero` on teardown in `audio_call` (which never wipes `c->key` today), TOFU keyed by pk, per-slot RTT state, `FragAssembly` keyed on `(SID, frame_id)`, and the `0x7F` per-source legacy report. | **all of them** | both, same-day tags |
| 6 | **Group media path.** Per-sender `OpusDecoder` plus an N-to-1 saturating mixer; per-sender `FragReceiver` and `VideoDecoder`; keyframe on new sender; display policy. Separately costed, see below. | none | both |
| 7 | **Cleanup.** Delete `mk_derive`, `mk_derive_pair`, `mk_salt_combine`, `mk_role_from_halves`, `MK_DIR_*`, their vectors and their Kotlin mirrors; `KeyDerivation.kt`; `KDF_*`; `HELLO_MAGIC`; `PROTOCOL_VERSION`. Close M3 and M5 in `doc/SECURITY_AUDIT_2026-07.md` and rewrite the line that calls `media_keys.c` an unused primitive. Bump `versionCode` / `versionName`. | none | both |

Steps 1-4 change no wire byte and land independently. **Step 5 is the breaking landing.** These are two independent git repositories, so "together" is a same-day release convention, not a merge: tag desktop first because its C vectors are the reference, Android immediately after, and state in both release notes that the release does not interoperate with any earlier build in either direction on any transport. Between the two tags every desktop-Android call fails loudly at the handshake rather than presenting as a connected call with no media, which is what makes a short window tolerable. Do not split step 5 into audio-then-video.

**Tests.** `tests/media_loopback.sh` **does not exist** (verified: `tests/` contains `blob_auth.sh`, `smoke_chat.sh` and six `test_*.c`). It is a new file, not an extension, and it is the only test in the plan that can catch what this work exists to fix, so it must be budgeted. It needs a **three-process hub run** asserting that each of three participants decrypts the other two, plus a forced-SID-collision case, a tombstone case (evict a slot, replay its HELLO and media, assert rejection), and a legacy `0x7F` case. `audio_call` also needs a null-audio mode for CI: `th_send_func` handles `c->in_stream == NULL` by zeroing the PCM buffer, but `Pa_Initialize()` may still fail with no ALSA devices, and no such flag exists today (O7).

**Honest scoping.** The key scheme is the small half: roughly a week per platform for steps 1-5. Step 6 is one to two weeks per platform and is where group calls live or die. **Shipping steps 1-5 without step 6 produces a room where every packet decrypts correctly and nobody can understand anybody**, which is a worse failure than today's because it looks like it works, and the three-process loopback would pass. If group calling must be staged, stage it as **group audio first**: one mixer, N Opus decoders, no display work, and leave group video behind the same wire format, which already supports it.

### 10. Accepted residual risks

Each of these is a decision, not an oversight, and each has a name so it can go in the release notes.

1. **Insider forgery and deliberate nonce reuse.** Any holder of `K_call` can derive every participant's send key and forge or nonce-reuse against them. Inherent to constraint 1, not a regression, closed only by sender-key wrapping (reserved on the wire). Product consequence: no per-participant verified badge over media.
2. **Stale-media injection at a late joiner.** Within one call, an on-path attacker can replay a participant's earlier HELLO and media to someone who joins later and therefore has no tombstone. The live stream's higher counters then advance the window and the replay dies, so the effect is a burst of stale audio at join, not a takeover. Closed by per-sender attestation, deferred.
3. **No forward secrecy across a leave.** A departed member keeps `K_call`. The fix is `K_room` rotation and a new call, which `key_version` in the KDF makes automatic when it happens.
4. **Salt duplication by one sender inside one `call_id`** (stubbed RNG, seeded container PRNG, VM or filesystem snapshot restored twice). Signed mode is immune between distinct identities. Unsigned mode is not. Blast radius is confined to that sender's own two streams: keystream XOR plus GHASH subkey recovery and therefore forgery under that key, meaning impersonation of one participant, not compromise of the room. A persisted boot counter is deliberately **not** added: it introduces writable state the media path does not have, does nothing against snapshot restore, and a rolled-back file reintroduces the problem it was meant to solve.
5. **Cross-binary stats.** `audio_call` puts stats on `0x04` (audio counter) and `video_call` on `0x05` (video counter), so the two binaries still cannot read each other's stats and each shows RTT 0. This is not a regression: `audio_call` encrypts with the raw stdin key (`audio_call.c:1065`) while `video_call` derives subkeys via `crypto_kdf_derive_from_key` (`:457-471`), so **the two binaries do not interoperate at all today**, contrary to section 7 of the previous revision. Under v2 audio starts interoperating for the first time, which will make the remaining stats gap newly visible.
6. **A room member can occupy key slots.** A member holds `K_call` and can therefore MAC unlimited HELLOs with fresh salts. Bounded by the 32-slot table with refusal rather than eviction, plus a per-room new-install rate limit of 5/s. A member could already degrade a call by flooding media; this is not a new boundary, but it is new code that must be bounded.

### 11. Open questions for the project owner

These are product or ownership decisions. Everything in sections 1 through 10 is decided.

**O1. Which layer owns `call_id`, and can it be delivered before step 5?** This is the blocking one. `call_id` is what closes cross-call replay by a non-member, and it is mandatory (all-zero is refused). It must reach `audio_call`, `video_call`, `AudioCallManager` and `VideoCallManager` on every path: local UDP, UDP hub, TCP relay, GUI-spawned, Android. The cheapest option is a second stdin line beside the 64-hex key on desktop and a second parameter to `initialize()` on Android, with the initiator generating it. If signalling should own it instead, that decision changes step 4 and must be made before step 1 freezes the context strings.

**O2. Group video in this release, or group audio first?** Recommendation is audio first behind the same wire format. This is a schedule decision, not a design one.

**O3. Maximum participants as a product number.** The transport advertises 32; a phone will not run 32 Opus decoders and 32 VP8 decoders. The design proposes 32 key slots with 8 audio and 4 video decoders. Confirm or set different numbers.

**O4. Does `key_version` stay?** Nothing in the tree produces a nonzero one (`key_schedule` has no non-test caller), so it will be `0` in every packet on day one. It is 2 bytes in the HELLO and it is the hook `K_room` rotation hangs on. Keeping it means putting it in now rather than breaking the wire a second time; dropping it means one fewer field with undefined semantics. Recommendation: keep.

**O5. Should `--require-identity` exist?** A per-room policy switch that drops unsigned HELLOs. Mechanism does not need it; some rooms might.

**O6. Speaker attribution in the UI.** Given section 7, what does the participant list show for an unsigned sender, and how is a signed sender's label styled so it does not read as authentication of the audio? Recommendation for unsigned is a stable meaningless label such as `speaker a3f1c2` from the SID.

**O7. Can `audio_call` run headless in CI, and may it gain a `--no-audio` flag?** The three-process loopback test depends on it. Unverified: `Pa_Initialize()` may fail with no ALSA devices. If it cannot, step 3's test scope grows.

**O8. Domain separation strings.** `"fear.media.v2"`, `"fear.media.sid.v2"`, `"fear.media.hello.v2"` follow the existing `"fear.media.v1"` / `"fear.epoch.v1"` convention. They freeze into vectors on both platforms the moment step 1 lands, so settle them before step 1.

**O9. Is hub hardening in this release?** `hub_forward` needs no crypto change, which is the payoff of the whole design, but `hub_find_or_add` admits any UDP source with no key check and `hub_prune` is unreachable during an active call. Neither is caused by this work, both are exposed by promoting the hub from "2-party only" to a supported group transport, and both are a real N-party join failure under churn.

---

## Owner decisions (31 July 2026)

The open questions of the revised section are answered as follows.

**O1 - who owns `call_id`: the initiator, delivered beside `K_call`.** The
side that starts the call draws 16 random bytes and passes them to the media
binaries the same way the key already travels: a second stdin line on desktop
and a second parameter to `initialize()` on Android. No signalling layer is
introduced for this. `mk_*` refuse an all-zero `call_id`, so a path that
forgets to plumb it fails loudly at the first derivation instead of quietly
dropping the cross-call replay barrier.

**O2 - group audio first, group video after**, behind the same wire format.
The format already carries what video needs, so this is purely a scheduling
split: one mixer and N Opus decoders first, no display work.

**O3 - 32 key slots reserved, decoder count set by what the hardware
manages.** The table is sized for 32 participants because the transport
already advertises that many and a table resize is a wire-visible change.
The number of simultaneous decoders is a runtime limit, not a protocol
constant: start with what a phone sustains and raise it once measured.

Everything else in the revised section stands as written.

---

## Step 5 checklist (the one indivisible landing)

Everything below already exists and is tested; step 5 is only the
switchover. Nothing in this list changes a byte until all of it is done,
which is why it cannot be split across commits.

**Ready to call, currently unused:**

| Module | What it gives step 5 |
|---|---|
| `identity/media_keys.c` | `mk_derive_sender`, `mk_sender_id`, `mk_hello_key`, `mk_call_id_parse` |
| `identity/media_hello.c` | `mh_build` / `mh_parse`, legacy-peer detection |
| `identity/media_senders.c` | slot table, replay windows, tombstones, SID lookup |
| `identity/media_packet.c` | `mp_encrypt` / `mp_peek` / `mp_decrypt`, `[type][SID][counter]` + AAD |
| `identity/call_invite.c` | invite payload; `call_id` already reaches both ends |
| Kotlin mirrors | `MediaKeys`, `MediaHello`, `SenderTable`, `CallInvite` |

All five C files are already in the `audio_call` and `video_call` source
lists, so the switchover cannot fail to link.

**Desktop, `audio_call/src/audio_call.c`:**

- [ ] struct: drop `key`, `local_nonce_prefix`, `remote_nonce_prefix`,
      `remote_prefix_ready`, `rx_audio`, `rx_stats`; add `master_key`,
      `own_salt`, `own_sid`, `key_tx`, `ms_table_t senders`, `keys_ready`
- [ ] `--call-id` becomes mandatory; refuse to start without it
- [ ] `send_hello` / `handle_hello` rewritten over `mh_build` / `mh_parse`
- [ ] `encrypt_opus` / `decrypt_opus` / `encrypt_stats` / `decrypt_stats`
      over `mp_encrypt` / `mp_decrypt`; stats ride the audio key, because
      they share the audio counter
- [ ] receive path: `mp_peek` for the SID, `ms_find_by_sid` for candidate
      keys, `ms_accept_seq` after a successful decrypt
- [ ] delete the send-thread spin on `remote_prefix_ready`: a sender needs
      no peer input to start
- [ ] `sodium_memzero` on teardown - this file never wipes its key today

**Desktop, `video_call/src/video_call.c`:** the same, plus

- [ ] `derive_subkeys` replaced by per-sender derivation; the call at
      `start_video_call` moves after the HELLO
- [ ] the `send_hello` stack buffer grows to `MH_SIZE_SIGNED`; at 107
      bytes today, writing a HELLO2 into it is a stack smash
- [ ] stats ride the **video** key, because they share the video counter

**Android:** `AudioCallManager.kt` and `VideoCallManager.kt`, same shape.
Note `initialize()` needs the `call_id` parameter, and the HELLO parse in
`AudioCallManager` currently overwrites the remote prefix on every HELLO -
under the new scheme that would be a remote key-reset primitive.

**Tests that must exist before this is called done:**

- [ ] `tests/media_loopback.sh`: three processes over the hub, each
      decrypting the other two. This is the only test that can catch a
      role inversion or a salt-agreement mismatch, and no unit test can
      reach it.
- [ ] a forced SID-collision case, a tombstone case, and a legacy-peer
      case in that same script

**Release:** tag desktop and Android the same day, desktop first because
its vectors are the reference, and say plainly in both release notes that
the version does not interoperate with any earlier build in either
direction. Between the two tags every cross-platform call fails at the
handshake - loudly, thanks to the legacy-peer detection, which is what
makes a short window tolerable.
