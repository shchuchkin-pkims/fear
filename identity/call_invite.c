/**
 * @file call_invite.c
 * @brief Call invitation payload (see call_invite.h).
 */
#include "call_invite.h"

#include <sodium.h>
#include <string.h>

#define OFF_VERSION   0
#define OFF_FLAGS     1
#define OFF_CALLID    2
#define OFF_PORT     18
#define OFF_HOSTLEN  20
#define OFF_HOST     21

const char *ci_strerror(ci_status_t st) {
    switch (st) {
        case CI_OK:            return "ok";
        case CI_ERR_ARGS:      return "bad arguments";
        case CI_ERR_TOO_SHORT: return "invite too short";
        case CI_ERR_VERSION:   return "unsupported invite version";
        case CI_ERR_RESERVED:  return "reserved flag bits set";
        case CI_ERR_CALLID:    return "call_id is all zero";
        case CI_ERR_LENGTH:    return "host length disagrees with the payload";
        case CI_ERR_HOST:      return "host contains illegal characters";
    }
    return "unknown";
}

/**
 * A hostname, an IPv4 literal or a bracketless IPv6 literal, and nothing
 * else. This value came from another party and goes on to a connect call
 * and into log lines, so the check belongs here rather than at each use.
 */
static int host_char_ok(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '.' || c == '-' || c == ':';
}

ci_status_t ci_build(const ci_invite_t *in,
                     uint8_t *out, size_t out_cap, size_t *out_len) {
    if (!in || !out || !out_len) return CI_ERR_ARGS;
    if (in->flags & CI_FLAG_RESERVED) return CI_ERR_RESERVED;
    if (sodium_is_zero(in->call_id, MK_CALLID_BYTES)) return CI_ERR_CALLID;

    const size_t host_len = strnlen(in->host, CI_MAX_HOST + 1);
    if (host_len > CI_MAX_HOST) return CI_ERR_LENGTH;
    for (size_t i = 0; i < host_len; i++) {
        if (!host_char_ok(in->host[i])) return CI_ERR_HOST;
    }

    const size_t total = CI_HEADER_BYTES + host_len;
    if (out_cap < total) return CI_ERR_ARGS;

    memset(out, 0, total);
    out[OFF_VERSION] = CI_VERSION;
    out[OFF_FLAGS]   = in->flags;
    memcpy(out + OFF_CALLID, in->call_id, MK_CALLID_BYTES);
    out[OFF_PORT]     = (uint8_t)((in->port >> 8) & 0xFF);
    out[OFF_PORT + 1] = (uint8_t)(in->port & 0xFF);
    out[OFF_HOSTLEN]  = (uint8_t)host_len;
    if (host_len) memcpy(out + OFF_HOST, in->host, host_len);

    *out_len = total;
    return CI_OK;
}

ci_status_t ci_parse(const uint8_t *buf, size_t len, ci_invite_t *out) {
    if (!buf || !out) return CI_ERR_ARGS;
    if (len < CI_HEADER_BYTES) return CI_ERR_TOO_SHORT;
    if (len > CI_MAX_BYTES) return CI_ERR_LENGTH;

    if (buf[OFF_VERSION] != CI_VERSION) return CI_ERR_VERSION;

    const uint8_t flags = buf[OFF_FLAGS];
    if (flags & CI_FLAG_RESERVED) return CI_ERR_RESERVED;

    if (sodium_is_zero(buf + OFF_CALLID, MK_CALLID_BYTES)) return CI_ERR_CALLID;

    const size_t host_len = buf[OFF_HOSTLEN];
    /* No tolerance for trailing bytes: an invite is a fixed shape, and
     * accepting extra data is how parsers drift apart across platforms. */
    if (len != CI_HEADER_BYTES + host_len) return CI_ERR_LENGTH;

    for (size_t i = 0; i < host_len; i++) {
        if (!host_char_ok((char)buf[OFF_HOST + i])) return CI_ERR_HOST;
    }

    memset(out, 0, sizeof *out);
    out->flags = flags;
    memcpy(out->call_id, buf + OFF_CALLID, MK_CALLID_BYTES);
    out->port = (uint16_t)(((uint16_t)buf[OFF_PORT] << 8) | (uint16_t)buf[OFF_PORT + 1]);
    if (host_len) memcpy(out->host, buf + OFF_HOST, host_len);
    out->host[host_len] = '\0';
    return CI_OK;
}
