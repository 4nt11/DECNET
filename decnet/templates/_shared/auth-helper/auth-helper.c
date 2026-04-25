/*
 * auth-helper — RFC 5424 cred-capture helper invoked via pam_exec.so.
 *
 * Wired into /etc/pam.d/sshd as:
 *   auth optional pam_exec.so expose_authtok stdout /usr/sbin/auth-helper
 *
 * Behaviour:
 *   - Reads $PAM_USER and $PAM_RHOST from environ (set by pam_exec).
 *   - Reads PAM_AUTHTOK from stdin (NUL-terminated, written by pam_exec
 *     when invoked with `expose_authtok`).
 *   - Emits a single RFC 5424 line on /proc/1/fd/1 in the same shape as
 *     templates/syslog_bridge.py:syslog_line() — facility local0, PEN
 *     55555, MSGID `auth_attempt` (matches FTP's existing event type so
 *     the parser + dashboard pick it up with zero changes).
 *
 * Two password fields ride in the SD-block:
 *   password      RFC 5424-escaped ASCII-printable, '?' for non-printables.
 *                 FTP-compatible; consumed by existing dashboard rendering.
 *   password_b64  base64 of the exact PAM_AUTHTOK bytes. Lossless.
 *                 Preserves NUL/0xff/control bytes that the plain field
 *                 would silently drop — useful fingerprinting signal.
 *
 * Fail-open: every error path silently exits 0. The PAM line is `optional`
 * so a malfunctioning helper must never break sshd auth.
 *
 * PII discipline: the password value is attacker-supplied bytes. Decky
 * services are not for admin SSH; throwaway creds (root:admin) are the
 * convention. Limitations tracked in development/DEBT.md (DEBT-038).
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define MAX_USER  256
#define MAX_HOST  256
#define MAX_PW    1024
#define LINE_BUF  8192

static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Standard base64 with '=' padding. NUL-terminates *out*. Returns bytes
 * written (excluding the NUL). On overflow returns 0 and NUL-terminates. */
static size_t b64_encode(const unsigned char *in, size_t inlen,
                         char *out, size_t outcap) {
    size_t i = 0, o = 0;
    while (i + 3 <= inlen) {
        if (o + 4 >= outcap) { out[0] = '\0'; return 0; }
        unsigned x = ((unsigned)in[i] << 16) |
                     ((unsigned)in[i+1] << 8) |
                      (unsigned)in[i+2];
        out[o++] = B64[(x >> 18) & 0x3f];
        out[o++] = B64[(x >> 12) & 0x3f];
        out[o++] = B64[(x >>  6) & 0x3f];
        out[o++] = B64[ x        & 0x3f];
        i += 3;
    }
    if (i < inlen) {
        if (o + 4 >= outcap) { out[0] = '\0'; return 0; }
        unsigned x = (unsigned)in[i] << 16;
        if (i + 1 < inlen) x |= (unsigned)in[i+1] << 8;
        out[o++] = B64[(x >> 18) & 0x3f];
        out[o++] = B64[(x >> 12) & 0x3f];
        out[o++] = (i + 1 < inlen) ? B64[(x >> 6) & 0x3f] : '=';
        out[o++] = '=';
    }
    out[o] = '\0';
    return o;
}

/* RFC 5424 §6.3.3: in SD-PARAM-VALUE, escape \\ → \\\\, " → \", ] → \].
 * Non-printables become '?' so the line stays parser-safe. */
static size_t sd_escape(const unsigned char *in, size_t inlen,
                        char *out, size_t outcap) {
    size_t o = 0;
    for (size_t i = 0; i < inlen; i++) {
        unsigned char c = in[i];
        if (c == '\\' || c == '"' || c == ']') {
            if (o + 3 >= outcap) break;
            out[o++] = '\\';
            out[o++] = c;
        } else if (c >= 0x20 && c < 0x7f) {
            if (o + 2 >= outcap) break;
            out[o++] = c;
        } else {
            if (o + 2 >= outcap) break;
            out[o++] = '?';
        }
    }
    out[o] = '\0';
    return o;
}

int main(void) {
    const char *user  = getenv("PAM_USER");
    const char *rhost = getenv("PAM_RHOST");
    if (!user)  user  = "";
    if (!rhost) rhost = "";

    /* Read password until NUL (pam_exec's expose_authtok contract) or EOF. */
    unsigned char pw_raw[MAX_PW];
    size_t pw_len = 0;
    while (pw_len < sizeof(pw_raw)) {
        ssize_t n = read(0, pw_raw + pw_len, sizeof(pw_raw) - pw_len);
        if (n <= 0) break;
        for (ssize_t i = 0; i < n; i++) {
            if (pw_raw[pw_len + i] == 0) {
                pw_len += (size_t)i;
                goto pw_done;
            }
        }
        pw_len += (size_t)n;
    }
pw_done:;

    /* Timestamp: YYYY-MM-DDThh:mm:ss.uuuuuu+00:00 — matches the shape
     * datetime.now(timezone.utc).isoformat() emits in syslog_bridge.py. */
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) return 0;
    struct tm tm;
    if (gmtime_r(&ts.tv_sec, &tm) == NULL) return 0;
    char tsbuf[40];
    snprintf(tsbuf, sizeof(tsbuf),
        "%04d-%02d-%02dT%02d:%02d:%02d.%06ld+00:00",
        tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
        tm.tm_hour, tm.tm_min, tm.tm_sec,
        (long)(ts.tv_nsec / 1000));

    char host[MAX_HOST];
    if (gethostname(host, sizeof(host) - 1) != 0) {
        host[0] = '-'; host[1] = '\0';
    } else {
        host[sizeof(host) - 1] = '\0';
    }

    /* Escape / encode the dynamic fields. Buffers sized 2x source to
     * survive worst-case escape expansion. */
    char user_esc [MAX_USER * 2];
    char rhost_esc[MAX_HOST * 2];
    char pw_esc   [MAX_PW   * 2];
    char pw_b64   [MAX_PW   * 2];

    sd_escape((const unsigned char *)user,  strlen(user),  user_esc,  sizeof(user_esc));
    sd_escape((const unsigned char *)rhost, strlen(rhost), rhost_esc, sizeof(rhost_esc));
    sd_escape(pw_raw, pw_len, pw_esc, sizeof(pw_esc));
    b64_encode(pw_raw, pw_len, pw_b64, sizeof(pw_b64));

    /* Priority: facility=local0(16), severity=INFO(6) → <16*8+6> = <134>.
     * Matches the syslog_bridge.py default exactly. */
    char line[LINE_BUF];
    int n = snprintf(line, sizeof(line),
        "<134>1 %s %s auth-helper - auth_attempt "
        "[relay@55555 username=\"%s\" password=\"%s\" "
        "password_b64=\"%s\" src_ip=\"%s\"]\n",
        tsbuf, host, user_esc, pw_esc, pw_b64, rhost_esc);
    if (n <= 0 || (size_t)n >= sizeof(line)) return 0;

    /* /proc/1/fd/1 is the entrypoint's stdout — the fd Docker captures
     * for `docker logs`. Same channel rsyslog forwards auth.* into via
     * the existing template; we bypass rsyslog entirely so behaviour is
     * deterministic across rsyslog config drift. */
    int fd = open("/proc/1/fd/1", O_WRONLY | O_APPEND);
    if (fd < 0) return 0;
    ssize_t w = write(fd, line, (size_t)n);
    (void)w;
    close(fd);

    return 0;
}
