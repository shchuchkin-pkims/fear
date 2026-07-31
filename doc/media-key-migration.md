# Media key migration - per-direction keys with a session salt

> Working document for the Phase C media switchover (audit items M3 / M5).
> Produced from a read-only survey of the live media path on both platforms
> (desktop `audio_call` / `video_call`, Android `AudioCallManager` /
> `VideoCallManager`, the shared wire constants and the call entry points),
> then reconciled against the source where the surveys disagreed.
>
> Status: steps 1-3 change no wire byte and can land independently. Step 4 is
> the breaking change and needs desktop and Android to ship together. Section
> 8 lists open questions that are **product decisions, not implementation
> details** - O1 (is group audio still supported?) can invalidate part of the
> design and must be answered before step 4.

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