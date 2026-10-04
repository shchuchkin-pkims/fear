/**
 * Call invitation payload: frozen bytes and the rejection matrix.
 *
 * The invite is what lets two peers agree on a call_id at all, so its
 * layout has to be identical on desktop, in the GUI and on Android. The
 * expected bytes below are pinned here and mirrored in the Kotlin test.
 */
#include "call_invite.h"
#include "test_util.h"

#include <sodium.h>
#include <string.h>

static void bin2hex(const uint8_t *bin, size_t len, char *out) {
    static const char *d = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i]     = d[bin[i] >> 4];
        out[2 * i + 1] = d[bin[i] & 0x0F];
    }
    out[2 * len] = '\0';
}

int main(void) {
    CHECK(sodium_init() >= 0);

    uint8_t call_id[MK_CALLID_BYTES];
    for (size_t i = 0; i < sizeof call_id; i++) call_id[i] = (uint8_t)(0x10 + i);

    uint8_t buf[CI_MAX_BYTES];
    size_t len = 0;
    char hex[2 * CI_MAX_BYTES + 1];

    /* --- with a direct hint ---------------------------------------------- */
    ci_invite_t in;
    memset(&in, 0, sizeof in);
    in.flags = CI_FLAG_AUDIO;
    memcpy(in.call_id, call_id, sizeof call_id);
    in.port = 45000;
    strcpy(in.host, "192.168.0.108");

    CHECK(ci_build(&in, buf, sizeof buf, &len) == CI_OK);
    CHECK(len == CI_HEADER_BYTES + 13);
    bin2hex(buf, len, hex);
    CHECK(strcmp(hex,
        "0101"                              /* version, flags */
        "101112131415161718191a1b1c1d1e1f"  /* call_id */
        "afc8"                              /* port 45000, big endian */
        "0d"                                /* host length */
        "3139322e3136382e302e313038") == 0);  /* "192.168.0.108" */

    ci_invite_t got;
    CHECK(ci_parse(buf, len, &got) == CI_OK);
    CHECK(got.flags == CI_FLAG_AUDIO);
    CHECK(memcmp(got.call_id, call_id, sizeof call_id) == 0);
    CHECK(got.port == 45000);
    CHECK(strcmp(got.host, "192.168.0.108") == 0);

    /* --- relayed call: no hint at all ------------------------------------- */
    memset(&in, 0, sizeof in);
    in.flags = CI_FLAG_AUDIO | CI_FLAG_VIDEO;
    memcpy(in.call_id, call_id, sizeof call_id);

    CHECK(ci_build(&in, buf, sizeof buf, &len) == CI_OK);
    CHECK(len == CI_HEADER_BYTES);
    bin2hex(buf, len, hex);
    CHECK(strcmp(hex,
        "0103"
        "101112131415161718191a1b1c1d1e1f"
        "0000"
        "00") == 0);

    CHECK(ci_parse(buf, len, &got) == CI_OK);
    CHECK(got.flags == (CI_FLAG_AUDIO | CI_FLAG_VIDEO));
    CHECK(got.port == 0);
    CHECK(got.host[0] == '\0');

    /* An IPv6 literal survives the character check. */
    memset(&in, 0, sizeof in);
    in.flags = CI_FLAG_AUDIO;
    memcpy(in.call_id, call_id, sizeof call_id);
    strcpy(in.host, "2001:db8::1");
    CHECK(ci_build(&in, buf, sizeof buf, &len) == CI_OK);
    CHECK(ci_parse(buf, len, &got) == CI_OK);
    CHECK(strcmp(got.host, "2001:db8::1") == 0);

    /* --- rejection matrix -------------------------------------------------- */
    /* Rebuild a good invite to mutate. */
    memset(&in, 0, sizeof in);
    in.flags = CI_FLAG_AUDIO;
    memcpy(in.call_id, call_id, sizeof call_id);
    in.port = 45000;
    strcpy(in.host, "host.example");
    CHECK(ci_build(&in, buf, sizeof buf, &len) == CI_OK);

    uint8_t evil[CI_MAX_BYTES];

    memcpy(evil, buf, len); evil[0] = 0x02;
    CHECK(ci_parse(evil, len, &got) == CI_ERR_VERSION);

    memcpy(evil, buf, len); evil[1] |= 0x80;
    CHECK(ci_parse(evil, len, &got) == CI_ERR_RESERVED);

    memcpy(evil, buf, len); memset(evil + 2, 0, MK_CALLID_BYTES);
    CHECK(ci_parse(evil, len, &got) == CI_ERR_CALLID);

    /* Declared host length must match the payload exactly: no trailing bytes. */
    memcpy(evil, buf, len); evil[20] = (uint8_t)(evil[20] + 1);
    CHECK(ci_parse(evil, len, &got) == CI_ERR_LENGTH);
    CHECK(ci_parse(buf, len - 1, &got) == CI_ERR_LENGTH);
    CHECK(ci_parse(buf, CI_HEADER_BYTES - 1, &got) == CI_ERR_TOO_SHORT);
    CHECK(ci_parse(buf, 0, &got) == CI_ERR_TOO_SHORT);

    /* A host from another party reaches a connect call and a log line, so
     * anything that is not hostname material is refused here. */
    memcpy(evil, buf, len); evil[21] = ' ';
    CHECK(ci_parse(evil, len, &got) == CI_ERR_HOST);
    memcpy(evil, buf, len); evil[21] = '\n';
    CHECK(ci_parse(evil, len, &got) == CI_ERR_HOST);
    memcpy(evil, buf, len); evil[21] = ';';
    CHECK(ci_parse(evil, len, &got) == CI_ERR_HOST);

    /* --- build-side checks --------------------------------------------------- */
    memset(&in, 0, sizeof in);
    in.flags = CI_FLAG_AUDIO;
    CHECK(ci_build(&in, buf, sizeof buf, &len) == CI_ERR_CALLID);

    memcpy(in.call_id, call_id, sizeof call_id);
    in.flags = CI_FLAG_AUDIO | 0x40;
    CHECK(ci_build(&in, buf, sizeof buf, &len) == CI_ERR_RESERVED);

    in.flags = CI_FLAG_AUDIO;
    strcpy(in.host, "bad host");
    CHECK(ci_build(&in, buf, sizeof buf, &len) == CI_ERR_HOST);

    in.host[0] = '\0';
    CHECK(ci_build(&in, buf, CI_HEADER_BYTES - 1, &len) == CI_ERR_ARGS);
    CHECK(ci_strerror(CI_ERR_HOST) != NULL);

    return t_report("test_call_invite");
}
