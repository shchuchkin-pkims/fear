/**
 * @file tls.c
 * @brief Реализация внешнего слоя TLS
 */

#include "tls.h"

#include <stdio.h>
#include <string.h>

static char g_err[256] = "";

/* Настройки исходящих соединений. Общие для обеих сборок - и с OpenSSL, и
 * без него: спрашивают о них одинаково, а отказывает уже сам wrap. */
static int  g_want = 0;
static char g_want_pin[TLS_FINGERPRINT_LEN] = "";

void tls_want(int want, const char *pin_hex) {
    g_want = want ? 1 : 0;
    if (pin_hex && pin_hex[0]) snprintf(g_want_pin, sizeof g_want_pin, "%s", pin_hex);
    else g_want_pin[0] = '\0';
}

int tls_wanted(void) { return g_want; }
const char *tls_wanted_pin(void) { return g_want_pin[0] ? g_want_pin : NULL; }

static void set_err(const char *s) {
    snprintf(g_err, sizeof g_err, "%s", s ? s : "");
}

const char *tls_last_error(void) {
    return g_err[0] ? g_err : "no error";
}

#ifndef FEAR_HAVE_TLS

/*
 * Сборка без OpenSSL.
 *
 * Функции есть, но отказывают. Это намеренно: молча соединиться открытым
 * текстом там, где человек попросил TLS, - худшее из возможного. Он
 * решил бы, что защищён, и вёл бы себя соответственно.
 */

int tls_available(void) { return 0; }
int tls_enabled(void) { return 0; }

int tls_client_wrap(int fd, const char *sni, const char *pin_hex) {
    (void)fd; (void)sni; (void)pin_hex;
    set_err("this build has no TLS support (built without OpenSSL)");
    return -1;
}

int tls_server_wrap(int fd) {
    (void)fd;
    set_err("this build has no TLS support (built without OpenSSL)");
    return -1;
}

int tls_server_init(const char *cert_file, const char *key_file) {
    (void)cert_file; (void)key_file;
    set_err("this build has no TLS support (built without OpenSSL)");
    return -1;
}

int tls_peer_fingerprint(int fd, char out[TLS_FINGERPRINT_LEN]) {
    (void)fd; (void)out;
    return -1;
}

int tls_is_wrapped(int fd) { (void)fd; return 0; }
int tls_send(int fd, const void *buf, size_t len) { (void)fd; (void)buf; (void)len; return -1; }
int tls_recv(int fd, void *buf, size_t len) { (void)fd; (void)buf; (void)len; return -1; }
void tls_close(int fd) { (void)fd; }

#else /* FEAR_HAVE_TLS */

#ifndef _WIN32
#  include <signal.h>
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#ifdef _WIN32
#  include <windows.h>
   static CRITICAL_SECTION g_lock;
   static int g_lock_ready = 0;
#  define LOCK_INIT()   do { if (!g_lock_ready) { InitializeCriticalSection(&g_lock); g_lock_ready = 1; } } while (0)
#  define LOCK()        EnterCriticalSection(&g_lock)
#  define UNLOCK()      LeaveCriticalSection(&g_lock)
#else
#  include <pthread.h>
   static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
#  define LOCK_INIT()   ((void)0)
#  define LOCK()        pthread_mutex_lock(&g_lock)
#  define UNLOCK()      pthread_mutex_unlock(&g_lock)
#endif

/*
 * Соответствие «сокет - сеанс TLS».
 *
 * Отдельной таблицей, а не полем в структуре соединения, ради одного:
 * send_all и recv_all принимают голый дескриптор и вызываются из сотни
 * мест. Протащить туда новый тип значило бы переписать всё это, а тут
 * достаточно спросить таблицу.
 *
 * Размер с запасом: у клиента соединение одно, у сервера - сколько он
 * держит клиентов.
 */
#define TLS_MAX_CONN 512

typedef struct {
    int   fd;      /**< -1 - свободно */
    SSL  *ssl;
} tls_slot_t;

static tls_slot_t g_slots[TLS_MAX_CONN];
static int  g_slots_ready = 0;
static SSL_CTX *g_server_ctx = NULL;

static void slots_init_locked(void) {
    if (g_slots_ready) return;
#ifndef _WIN32
    /*
     * SIGPIPE - в игнор, иначе первый же ушедший собеседник убивает процесс.
     *
     * Обычный send в этом коде возвращает ошибку и живёт дальше, а OpenSSL
     * пишет в сокет сам и о MSG_NOSIGNAL не знает. Закрытие сеанса шлёт
     * close_notify - и если собеседник уже отключился, запись в закрытый
     * сокет поднимает SIGPIPE, а его действие по умолчанию - завершить
     * процесс. Для сервера это значит: один ушедший клиент роняет всех
     * остальных.
     *
     * Ставится здесь, потому что это первое, что делает любой путь через
     * этот модуль, и ставится один раз.
     */
    signal(SIGPIPE, SIG_IGN);
#endif
    for (int i = 0; i < TLS_MAX_CONN; i++) { g_slots[i].fd = -1; g_slots[i].ssl = NULL; }
    g_slots_ready = 1;
}

static SSL *slot_find(int fd) {
    SSL *s = NULL;
    LOCK_INIT();
    LOCK();
    slots_init_locked();
    for (int i = 0; i < TLS_MAX_CONN; i++) {
        if (g_slots[i].fd == fd) { s = g_slots[i].ssl; break; }
    }
    UNLOCK();
    return s;
}

static int slot_add(int fd, SSL *ssl) {
    int ok = -1;
    LOCK_INIT();
    LOCK();
    slots_init_locked();
    for (int i = 0; i < TLS_MAX_CONN; i++) {
        if (g_slots[i].fd == -1) {
            g_slots[i].fd = fd;
            g_slots[i].ssl = ssl;
            ok = 0;
            break;
        }
    }
    UNLOCK();
    return ok;
}

static SSL *slot_take(int fd) {
    SSL *s = NULL;
    LOCK_INIT();
    LOCK();
    slots_init_locked();
    for (int i = 0; i < TLS_MAX_CONN; i++) {
        if (g_slots[i].fd == fd) {
            s = g_slots[i].ssl;
            g_slots[i].fd = -1;
            g_slots[i].ssl = NULL;
            break;
        }
    }
    UNLOCK();
    return s;
}

static void set_ssl_err(const char *what) {
    unsigned long e = ERR_get_error();
    char buf[160];
    if (e) {
        ERR_error_string_n(e, buf, sizeof buf);
        snprintf(g_err, sizeof g_err, "%s: %s", what, buf);
    } else {
        snprintf(g_err, sizeof g_err, "%s", what);
    }
}

int tls_available(void) { return 1; }
int tls_enabled(void) { return g_server_ctx != NULL; }

/** Отпечаток сертификата: SHA-256 в hex, тот же, что показывает openssl. */
static int cert_fingerprint(X509 *cert, char out[TLS_FINGERPRINT_LEN]) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int n = 0;
    if (!X509_digest(cert, EVP_sha256(), md, &n) || n == 0) return -1;
    for (unsigned int i = 0; i < n && (2 * i + 2) < TLS_FINGERPRINT_LEN; i++) {
        snprintf(out + 2 * i, 3, "%02x", md[i]);
    }
    out[2 * n] = '\0';
    return 0;
}

int tls_client_wrap(int fd, const char *sni, const char *pin_hex) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) { set_ssl_err("SSL_CTX_new"); return -1; }

    /* Ниже 1.2 не опускаемся: всё, что раньше, давно сломано, а
     * договориться о нём означало бы позволить понижение. */
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    const int pinned = (pin_hex && pin_hex[0]);
    if (!pinned) {
        /* Обычная проверка по системному хранилищу. */
        if (!SSL_CTX_set_default_verify_paths(ctx)) {
            set_ssl_err("cannot load system trust store");
            SSL_CTX_free(ctx);
            return -1;
        }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    } else {
        /*
         * Отпечаток вместо удостоверяющего центра.
         *
         * Для своего ретранслятора это не послабление, а более уместная
         * проверка: доверие здесь и так строится на сверке отпечатков
         * голосом, а не на списке чужих центров. Сверяем сами, после
         * рукопожатия, - см. ниже.
         */
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }

    SSL *ssl = SSL_new(ctx);
    if (!ssl) { set_ssl_err("SSL_new"); SSL_CTX_free(ctx); return -1; }

    if (sni && sni[0]) {
        SSL_set_tlsext_host_name(ssl, sni);
        if (!pinned) {
            /* Без этого проверка сертификата не сверяет имя, и годился бы
             * любой действительный сертификат на любое имя. */
            X509_VERIFY_PARAM *param = SSL_get0_param(ssl);
            X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
            if (!X509_VERIFY_PARAM_set1_host(param, sni, 0)) {
                set_ssl_err("cannot pin hostname");
                SSL_free(ssl); SSL_CTX_free(ctx);
                return -1;
            }
        }
    }

    SSL_set_fd(ssl, fd);
    if (SSL_connect(ssl) != 1) {
        set_ssl_err("TLS handshake failed");
        SSL_free(ssl); SSL_CTX_free(ctx);
        return -1;
    }

    if (pinned) {
        X509 *cert = SSL_get1_peer_certificate(ssl);
        if (!cert) {
            set_err("server sent no certificate");
            SSL_free(ssl); SSL_CTX_free(ctx);
            return -1;
        }
        char fp[TLS_FINGERPRINT_LEN];
        int ok = (cert_fingerprint(cert, fp) == 0);
        X509_free(cert);
        if (!ok) {
            set_err("cannot compute certificate fingerprint");
            SSL_free(ssl); SSL_CTX_free(ctx);
            return -1;
        }
        /* Сравнение без учёта регистра: отпечаток человек переписывает
         * руками, и держать его в одном регистре - лишнее требование. */
        int match = 1;
        for (int i = 0; i < TLS_FINGERPRINT_LEN - 1; i++) {
            char a = fp[i];
            char b = pin_hex[i];
            if (b >= 'A' && b <= 'F') b = (char)(b - 'A' + 'a');
            if (a != b) { match = 0; break; }
            if (a == '\0') break;
        }
        if (!match) {
            snprintf(g_err, sizeof g_err,
                     "certificate fingerprint does not match the pin (got %s)", fp);
            SSL_free(ssl); SSL_CTX_free(ctx);
            return -1;
        }
    }

    if (slot_add(fd, ssl) != 0) {
        set_err("too many TLS connections");
        SSL_free(ssl); SSL_CTX_free(ctx);
        return -1;
    }
    /* Контекст держится сеансом; освободится вместе с ним в tls_close. */
    SSL_CTX_free(ctx);
    return 0;
}

int tls_server_init(const char *cert_file, const char *key_file) {
    if (!cert_file || !key_file) { set_err("certificate and key are both required"); return -1; }

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) { set_ssl_err("SSL_CTX_new"); return -1; }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    if (SSL_CTX_use_certificate_chain_file(ctx, cert_file) != 1) {
        set_ssl_err("cannot read the certificate");
        SSL_CTX_free(ctx);
        return -1;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) != 1) {
        set_ssl_err("cannot read the private key");
        SSL_CTX_free(ctx);
        return -1;
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
        set_ssl_err("the key does not match the certificate");
        SSL_CTX_free(ctx);
        return -1;
    }

    if (g_server_ctx) SSL_CTX_free(g_server_ctx);
    g_server_ctx = ctx;
    return 0;
}

int tls_server_wrap(int fd) {
    if (!g_server_ctx) { set_err("TLS not configured on this server"); return -1; }

    SSL *ssl = SSL_new(g_server_ctx);
    if (!ssl) { set_ssl_err("SSL_new"); return -1; }
    SSL_set_fd(ssl, fd);
    if (SSL_accept(ssl) != 1) {
        set_ssl_err("TLS handshake failed");
        SSL_free(ssl);
        return -1;
    }
    if (slot_add(fd, ssl) != 0) {
        set_err("too many TLS connections");
        SSL_free(ssl);
        return -1;
    }
    return 0;
}

int tls_peer_fingerprint(int fd, char out[TLS_FINGERPRINT_LEN]) {
    SSL *ssl = slot_find(fd);
    if (!ssl || !out) return -1;
    X509 *cert = SSL_get1_peer_certificate(ssl);
    if (!cert) return -1;
    int rc = cert_fingerprint(cert, out);
    X509_free(cert);
    return rc;
}

int tls_is_wrapped(int fd) { return slot_find(fd) != NULL; }

int tls_send(int fd, const void *buf, size_t len) {
    SSL *ssl = slot_find(fd);
    if (!ssl) return -1;
    const int n = SSL_write(ssl, buf, (int)len);
    if (n <= 0) { set_ssl_err("SSL_write"); return -1; }
    return n;
}

int tls_recv(int fd, void *buf, size_t len) {
    SSL *ssl = slot_find(fd);
    if (!ssl) return -1;
    const int n = SSL_read(ssl, buf, (int)len);
    if (n > 0) return n;
    const int err = SSL_get_error(ssl, n);
    if (err == SSL_ERROR_ZERO_RETURN) return 0;   /* собеседник закрыл честно */
    set_ssl_err("SSL_read");
    return -1;
}

void tls_close(int fd) {
    SSL *ssl = slot_take(fd);
    if (!ssl) return;
    /* Один заход: ответа на close_notify можем и не дождаться, а висеть
     * здесь при разрыве связи незачем - сокет всё равно закроют. */
    SSL_shutdown(ssl);
    SSL_free(ssl);
}

#endif /* FEAR_HAVE_TLS */
