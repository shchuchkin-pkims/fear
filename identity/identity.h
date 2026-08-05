/**
 * @file identity.h
 * @brief Ed25519 digital identity for F.E.A.R. messenger
 *
 * Provides optional sender authentication via Ed25519 signatures.
 * Uses SSH-like TOFU (Trust On First Use) model:
 * - Users generate a persistent Ed25519 keypair stored locally
 * - Public keys are exchanged in-band (inside encrypted messages/HELLO)
 * - First-seen keys are trusted and stored in known_keys database
 * - Key changes trigger warnings (possible impersonation)
 *
 * All crypto via libsodium. Pure C11, no platform-specific dependencies
 * beyond POSIX/Win32 filesystem calls. Android NDK compatible.
 */

#ifndef FEAR_IDENTITY_H
#define FEAR_IDENTITY_H

#include <stdint.h>
#include <stddef.h>
#include <sodium.h>

/* Ed25519 constants (from libsodium) */
#define IDENTITY_PK_BYTES  crypto_sign_PUBLICKEYBYTES   /* 32 */
#define IDENTITY_SK_BYTES  crypto_sign_SECRETKEYBYTES   /* 64 */
#define IDENTITY_SIG_BYTES crypto_sign_BYTES            /* 64 */

/* Fingerprint: 8 bytes displayed as xx:xx:xx:xx:xx:xx:xx:xx + null */
#define IDENTITY_FINGERPRINT_LEN 24

/* TOFU check results */
typedef enum {
    TOFU_NEW_KEY           = 0,  /* First time seeing this name; key stored and trusted */
    TOFU_KEY_MATCH         = 1,  /* Name known, key matches, NOT manually verified */
    TOFU_KEY_MATCH_VERIFIED = 2, /* Name known, key matches, manually verified */
    TOFU_KEY_CONFLICT      = 3   /* Name known, public key DOES NOT match (warning!) */
} tofu_result_t;

/**
 * Generate a new Ed25519 keypair and write to file.
 * Creates parent directory (~/.fear/) if needed.
 * File format: two lines, "PK:<base64url>" and "SK:<base64url>".
 * File permissions set to 0600 on POSIX.
 *
 * @param path  Output file path (e.g. ~/.fear/identity)
 * @return 0 on success, -1 on error
 */
int identity_generate(const char *path);

/**
 * Load Ed25519 keypair from file.
 *
 * @param path  Identity file path
 * @param pk    Output: 32-byte public key
 * @param sk    Output: 64-byte secret key
 * @return 0 on success, -1 if file missing/corrupt
 */
int identity_load(const char *path, uint8_t *pk, uint8_t *sk);

/**
 * Load only the public key from identity file (first line).
 *
 * @param path  Identity file path
 * @param pk    Output: 32-byte public key
 * @return 0 on success, -1 if file missing/corrupt
 */
int identity_load_pk(const char *path, uint8_t *pk);

/**
 * Create a detached Ed25519 signature.
 *
 * @param msg      Message to sign
 * @param msg_len  Message length
 * @param sk       64-byte secret key
 * @param sig_out  Output: 64-byte signature
 * @return 0 on success
 */
int identity_sign(const uint8_t *msg, size_t msg_len,
                  const uint8_t sk[IDENTITY_SK_BYTES],
                  uint8_t sig_out[IDENTITY_SIG_BYTES]);

/**
 * Verify a detached Ed25519 signature.
 *
 * @param msg      Message that was signed
 * @param msg_len  Message length
 * @param sig      64-byte signature
 * @param pk       32-byte public key
 * @return 0 if valid, -1 if invalid
 */
int identity_verify(const uint8_t *msg, size_t msg_len,
                    const uint8_t sig[IDENTITY_SIG_BYTES],
                    const uint8_t pk[IDENTITY_PK_BYTES]);

/**
 * TOFU (Trust On First Use) check against known-keys database.
 *
 * Database format: one line per entry, "<name>\t<base64url(pk)>\n".
 * On TOFU_NEW_KEY, the entry is appended to the database file.
 *
 * @param db_path  Path to known_keys file (e.g. ~/.fear/known_keys)
 * @param name     Peer display name
 * @param pk       32-byte Ed25519 public key of peer
 * @return TOFU_NEW_KEY, TOFU_KEY_MATCH, or TOFU_KEY_CONFLICT
 */
tofu_result_t identity_tofu_check(const char *db_path,
                                  const char *name,
                                  const uint8_t pk[IDENTITY_PK_BYTES]);

/**
 * Get default identity file path.
 * POSIX: ~/.fear/identity
 * Windows: %APPDATA%\fear\identity
 *
 * @param buf      Output buffer
 * @param bufsize  Buffer size
 * @return 0 on success, -1 on error
 */
int identity_default_path(char *buf, size_t bufsize);

/**
 * Get default known-keys database path.
 * POSIX: ~/.fear/known_keys
 * Windows: %APPDATA%\fear\known_keys
 *
 * @param buf      Output buffer
 * @param bufsize  Buffer size
 * @return 0 on success, -1 on error
 */
int identity_default_known_keys_path(char *buf, size_t bufsize);

/**
 * Compute human-readable fingerprint of a public key.
 * Format: "ab:cd:ef:01:23:45:67:89" (first 8 bytes of BLAKE2b hash).
 *
 * @param pk   32-byte public key
 * @param out  Output buffer (at least IDENTITY_FINGERPRINT_LEN bytes)
 * @return Pointer to out
 */
char *identity_pk_fingerprint(const uint8_t pk[IDENTITY_PK_BYTES],
                              char out[IDENTITY_FINGERPRINT_LEN]);

/* "pm:" + 22-char base64url(16-byte blake2b) + null = 26 bytes */
#define IDENTITY_PM_ROOM_ID_LEN 32

/* Сохраняем старое имя как алиас, чтобы существующий код собирался во время
 * переименования. Удалим алиас в Phase C. */
#define IDENTITY_DM_ROOM_ID_LEN IDENTITY_PM_ROOM_ID_LEN

/** Длина комнаты на проводе: "r:" + 22 знака base64url + NUL. */
#define IDENTITY_WIRE_ROOM_LEN 26

/**
 * Имя комнаты, каким его видит ретранслятор.
 *
 * На проводе едет не «general», а хеш от него: оператору незачем читать в
 * своём журнале, кто в какой комнате сидит, а маршрутизировать по метке он
 * может ровно так же. Заодно исчезает приставка «pm:», по которой личные
 * комнаты отличались от общих с одного взгляда.
 *
 * Честно о пределе: хеш без секрета, и «general» подбирается по словарю.
 * Это защита от чтения журнала и от случайного взгляда, а не от оператора,
 * который целенаправленно ищет. Скрыть название полностью мешает вход по
 * имени: входящий ещё не знает ключа комнаты, а значит и вывести метку под
 * ним не может.
 */
int identity_wire_room(const char *room_name, char out[IDENTITY_WIRE_ROOM_LEN]);

/**
 * Идентификатор личной комнаты - устаревший вывод, только для переноса.
 *
 * Считается из двух открытых ключей и без секрета, а значит его может
 * посчитать кто угодно, кому эти ключи известны. Ретранслятор знает
 * открытые ключи всех, кто занял имя, поэтому мог перебрать пары и
 * подписать каждую личную комнату именами обоих собеседников. Новый вывод -
 * identity_pm_room_id_v2 - закрывает это; здесь остаётся только чтобы найти
 * старую переписку и перенести её.
 */
int identity_pm_room_id_v1(const uint8_t my_pk[IDENTITY_PK_BYTES],
                           const uint8_t other_pk[IDENTITY_PK_BYTES],
                           char out[IDENTITY_PM_ROOM_ID_LEN]);

/**
 * Идентификатор личной комнаты из ключа пары.
 *
 * BLAKE2b под ключом K_pm - секретом, который выводят только двое. Для
 * ретранслятора это непрозрачная метка: перебрать пары открытых ключей и
 * узнать, кто с кем переписывается, больше нельзя.
 *
 * Ключ, а не открытые ключи, на входе намеренно: тогда видно, что для
 * вычисления нужен секрет, и ни один вызывающий не сможет случайно
 * посчитать его из общедоступного.
 */
int identity_pm_room_id_v2(const uint8_t k_pm[32],
                           char out[IDENTITY_PM_ROOM_ID_LEN]);


/* Совместимость со старым именем. Ведёт в устаревший вывод: новый требует
 * ключ пары, которого у вызывающего этой обёртки нет. */
static inline int identity_dm_room_id(const uint8_t my_pk[IDENTITY_PK_BYTES],
                                      const uint8_t other_pk[IDENTITY_PK_BYTES],
                                      char out[IDENTITY_DM_ROOM_ID_LEN]) {
    return identity_pm_room_id_v1(my_pk, other_pk, out);
}

/**
 * Деёрминированный 32-байтовый ключ AES-256-GCM для ЛС-комнаты с peer-ом.
 *
 * Вычисляется как HKDF-подобная свёртка X25519-shared-secret:
 *   x_my_sk = ed25519_sk_to_curve25519(my_sk)
 *   x_other_pk = ed25519_pk_to_curve25519(other_pk)
 *   shared = X25519(x_my_sk, x_other_pk)
 *   K_pm   = BLAKE2b(key=shared, data="fear.pm.v1.key" || lo_pk || hi_pk, 32)
 *
 * Свойства:
 *   - оба собеседника получают один и тот же K_pm без обмена сообщениями;
 *   - никто, кроме обоих обладателей secret-key, не может его вычислить;
 *   - вход домен-разделён константой "fear.pm.v1.key", а заодно фиксирует
 *     порядок pk через lo/hi (на случай повторного использования shared
 *     для других целей в будущем).
 *
 * @param my_sk     64-байтовый ed25519 secret key (полный, как в файле)
 * @param other_pk  32-байтовый ed25519 public key собеседника
 * @param out_key   Буфер ровно 32 байта — заполнится K_pm
 * @return 0 при успехе, -1 при ошибке
 */
int identity_pm_room_key(const uint8_t my_sk[IDENTITY_SK_BYTES],
                         const uint8_t other_pk[IDENTITY_PK_BYTES],
                         uint8_t out_key[32]);

/** Длина слепого адреса ящика. */
#define IDENTITY_INBOX_ADDR_BYTES 32

/**
 * Слепой адрес офлайн-ящика пары.
 *
 * Письмо тому, кого нет в комнате, адресуется не открытым ключом, а этим
 * адресом: BLAKE2b под ключом K_pm. Вычислить его может лишь тот, у кого
 * этот секрет есть, то есть двое собеседников; для ретранслятора это
 * непрозрачная метка, по которой не видно ни кому письмо, ни от кого.
 *
 * Знание адреса и есть право забрать почту. Подписи здесь не помогут:
 * K_pm у сервера нет и быть не должно, а значит проверить MAC под ним он
 * не может. Зато и множество «кто знает адрес» совпадает с множеством
 * «кому оно адресовано».
 *
 * Адрес постоянен, а не меняется по времени. Меняющийся заставил бы
 * получателя спрашивать по адресу за каждый прошедший час хранения -
 * сотни запросов на контакт. Плата за постоянство: оператор видит, что
 * две неизвестные ему стороны переписываются, но не кто они.
 */
int identity_inbox_addr(const uint8_t k_pm[32],
                        uint8_t out[IDENTITY_INBOX_ADDR_BYTES]);

/**
 * Mark a known key as manually verified.
 *
 * @param db_path  Path to known_keys file
 * @param name     Peer display name
 * @return 0 on success, -1 if name not found or error
 */
int identity_mark_verified(const char *db_path, const char *name);

/**
 * Remove a key entry from the known-keys database.
 *
 * @param db_path  Path to known_keys file
 * @param name     Peer display name to remove
 * @return 0 on success, -1 if name not found or error
 */
int identity_remove_key(const char *db_path, const char *name);

/**
 * Import a public key into the known-keys database.
 * If name already exists, replaces the key (resets verified to 0).
 *
 * @param db_path  Path to known_keys file
 * @param name     Peer display name
 * @param pk       32-byte Ed25519 public key
 * @param verified 1 to mark as verified, 0 for TOFU-trusted
 * @return 0 on success, -1 on error
 */
int identity_import_key(const char *db_path, const char *name,
                        const uint8_t pk[IDENTITY_PK_BYTES], int verified);

/**
 * Callback type for identity_list_keys.
 * @param name       Peer display name
 * @param pk_b64     Base64url-encoded public key
 * @param verified   1 if manually verified, 0 otherwise
 * @param ctx        User context pointer
 */
typedef void (*identity_key_callback_t)(const char *name, const char *pk_b64,
                                        int verified, void *ctx);

/**
 * List all entries in the known-keys database.
 *
 * @param db_path   Path to known_keys file
 * @param callback  Called for each entry
 * @param ctx       User context passed to callback
 * @return Number of entries, or -1 on error
 */
int identity_list_keys(const char *db_path, identity_key_callback_t callback,
                       void *ctx);

#endif /* FEAR_IDENTITY_H */
