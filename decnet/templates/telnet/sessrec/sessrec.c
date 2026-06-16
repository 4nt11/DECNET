/*
 * sessrec — interactive session recorder for SSH / Telnet deckies.
 *
 * Invoked as the login shell (via /etc/passwd shell swap). On interactive tty
 * sessions it:
 *   1. forkpty()'s /bin/bash -l and relays stdin/stdout/SIGWINCH bidirectionally;
 *   2. records each chunk as an asciinema v2 event in a *shared* JSONL day-shard
 *      (/var/lib/systemd/coredump/transcripts/sessions-YYYY-MM-DD.jsonl) with
 *      the session's UUID as a sid tag on every line;
 *   3. on exit emits one RFC 5424 syslog line (event_type=session_recorded)
 *      direct to PID 1's stdout — bypasses rsyslog the same way syslog_bridge.py
 *      does in the Python service templates.
 *
 * Storage shape is one JSONL shard per (decky, UTC day). Concurrent sessions
 * append the shard lock-free: each write() is < PIPE_BUF (4096) and O_APPEND
 * guarantees atomic interleave on Linux regular files. Events larger than one
 * atomic write are chunked. Per-session cap: 10 MB; overflow writes one sentinel
 * line and stops emitting (session itself continues). Disk-free precheck on the
 * shard mount; below 200 MB free we emit session_skipped and exec bash directly.
 *
 * Non-tty invocation (e.g. `ssh host cmd`) short-circuits to execvp(bash) so
 * non-interactive command execution still surfaces via the existing
 * PROMPT_COMMAND logger hook rather than this path.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <pty.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <utmp.h>
#include <poll.h>

#define TRANSCRIPTS_DIR   "/var/lib/systemd/coredump/transcripts"
#define PID1_STDOUT       "/proc/1/fd/1"
#define MIN_FREE_BYTES    ((uint64_t)200 * 1024 * 1024)    /* 200 MB disk precheck */
#define SESSION_CAP_BYTES ((uint64_t) 10 * 1024 * 1024)    /* 10 MB per-session cap */
#define ATOMIC_CHUNK      3900                              /* < PIPE_BUF (4096) */
#define BUF_SIZE          4096
#define LINE_SCRATCH      (ATOMIC_CHUNK * 2 + 512)
#define DEFAULT_SHELL     "/bin/bash"
#define COMM_DISGUISE     "kworker/u8:2-ev"                 /* fits 15-char comm cap */

/* ─── tiny utilities ──────────────────────────────────────────────────────── */

static volatile sig_atomic_t sigwinch_pending = 0;

static void sigwinch_handler(int sig) { (void)sig; sigwinch_pending = 1; }

static double monotonic_since(const struct timespec *t0) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    double dt = (double)(now.tv_sec  - t0->tv_sec)
              + (double)(now.tv_nsec - t0->tv_nsec) / 1e9;
    return dt < 0.0 ? 0.0 : dt;
}

/* Write all bytes, retrying on EINTR. Returns 0 on success. */
static int write_all(int fd, const void *buf, size_t n) {
    const uint8_t *p = buf;
    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += w; n -= (size_t)w;
    }
    return 0;
}

/* Pick 16 bytes of entropy, format as UUIDv4 (8-4-4-4-12 hex, 36 chars + NUL). */
static int mint_uuid(char out[37]) {
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    uint8_t b[16];
    ssize_t n = read(fd, b, sizeof b);
    close(fd);
    if (n != (ssize_t)sizeof b) return -1;
    b[6] = (b[6] & 0x0f) | 0x40; /* v4 */
    b[8] = (b[8] & 0x3f) | 0x80; /* variant */
    snprintf(out, 37,
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        b[0],b[1],b[2],b[3], b[4],b[5], b[6],b[7], b[8],b[9],
        b[10],b[11],b[12],b[13],b[14],b[15]);
    return 0;
}

/* JSON-escape raw bytes into dst. Returns written length (excluding NUL),
 * or -1 on overflow. Handles control chars, quote, backslash, and non-UTF8
 * bytes (emitted as \u00XX so the output stays valid JSON regardless of
 * terminal payload encoding). */
static ssize_t json_escape(char *dst, size_t cap, const uint8_t *src, size_t n) {
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t c = src[i];
        const char *esc = NULL;
        char buf[8];
        size_t add;
        switch (c) {
            case '"':  esc = "\\\""; add = 2; break;
            case '\\': esc = "\\\\"; add = 2; break;
            case '\b': esc = "\\b";  add = 2; break;
            case '\f': esc = "\\f";  add = 2; break;
            case '\n': esc = "\\n";  add = 2; break;
            case '\r': esc = "\\r";  add = 2; break;
            case '\t': esc = "\\t";  add = 2; break;
            default:
                if (c < 0x20 || c == 0x7f) {
                    snprintf(buf, sizeof buf, "\\u%04x", c);
                    esc = buf; add = 6;
                } else {
                    esc = NULL; add = 1;
                }
        }
        if (o + add + 1 >= cap) return -1;
        if (esc) { memcpy(dst + o, esc, add); o += add; }
        else     { dst[o++] = (char)c; }
    }
    dst[o] = '\0';
    return (ssize_t)o;
}

/* ─── disk precheck + shard resolution ────────────────────────────────────── */

static uint64_t free_bytes(const char *path) {
    struct statvfs s;
    if (statvfs(path, &s) != 0) return 0;
    return (uint64_t)s.f_bavail * (uint64_t)s.f_frsize;
}

static void today_utc(char out[11]) {
    time_t t = time(NULL);
    struct tm tm;
    gmtime_r(&t, &tm);
    strftime(out, 11, "%Y-%m-%d", &tm);
}

/* Build /var/lib/systemd/coredump/transcripts/sessions-YYYY-MM-DD.jsonl */
static void shard_path(char out[512]) {
    char day[11];
    today_utc(day);
    snprintf(out, 512, "%s/sessions-%s.jsonl", TRANSCRIPTS_DIR, day);
}

/* ─── src_ip resolution ───────────────────────────────────────────────────── */

static void resolve_src_ip(char out[NI_MAXHOST]) {
    out[0] = '\0';

    /* SSH: $SSH_CONNECTION = "<client_ip> <client_port> <server_ip> <server_port>" */
    const char *sc = getenv("SSH_CONNECTION");
    if (sc && *sc) {
        size_t i = 0;
        while (sc[i] && sc[i] != ' ' && i < NI_MAXHOST - 1) {
            out[i] = sc[i]; i++;
        }
        out[i] = '\0';
        if (out[0]) return;
    }

    /* Telnet: busybox telnetd -l /bin/login leaves the client socket as fd 0. */
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;
    if (getpeername(STDIN_FILENO, (struct sockaddr *)&ss, &sl) == 0) {
        if (getnameinfo((struct sockaddr *)&ss, sl, out, NI_MAXHOST,
                        NULL, 0, NI_NUMERICHOST) == 0 && out[0]) {
            return;
        }
    }

    /* Last-resort: utmp host field for the current tty. */
    char ttybuf[64];
    if (ttyname_r(STDIN_FILENO, ttybuf, sizeof ttybuf) == 0) {
        const char *short_tty = ttybuf;
        if (strncmp(short_tty, "/dev/", 5) == 0) short_tty += 5;
        setutent();
        struct utmp *u;
        while ((u = getutent()) != NULL) {
            if (u->ut_type == USER_PROCESS &&
                strncmp(u->ut_line, short_tty, sizeof u->ut_line) == 0) {
                size_t cap = sizeof u->ut_host;
                if (cap > NI_MAXHOST - 1) cap = NI_MAXHOST - 1;
                memcpy(out, u->ut_host, cap);
                out[cap] = '\0';
                break;
            }
        }
        endutent();
    }
}

/* ─── shard emitters ──────────────────────────────────────────────────────── */

/* Emit a single line via O_APPEND on the shard. Line must include trailing \n
 * and be < ATOMIC_CHUNK for atomic-append guarantees. */
static int shard_emit(int fd, const char *line, size_t n) {
    if (n == 0) return 0;
    /* Single write() < PIPE_BUF is atomic under O_APPEND (POSIX.1-2017 §7.1.1,
     * Linux write(2) NOTES). Don't loop — partial writes don't happen for
     * regular files under this size and a retry would break atomicity. */
    ssize_t w = write(fd, line, n);
    return (w == (ssize_t)n) ? 0 : -1;
}

static void emit_header(int fd, const char *sid, unsigned short cols,
                        unsigned short rows, time_t unix_ts) {
    /* Sanitize $TERM — attacker-controlled via the ssh client. */
    const char *raw_term = getenv("TERM");
    if (!raw_term || !*raw_term) raw_term = "xterm-256color";
    char term[64];
    if (json_escape(term, sizeof term,
                    (const uint8_t *)raw_term, strnlen(raw_term, 63)) < 0) {
        term[0] = '-'; term[1] = '\0';
    }

    char line[LINE_SCRATCH];
    int n = snprintf(line, sizeof line,
        "{\"sid\":\"%s\",\"hdr\":{\"version\":2,\"width\":%u,\"height\":%u,"
        "\"timestamp\":%lld,\"env\":{\"SHELL\":\"/bin/bash\",\"TERM\":\"%s\"}}}\n",
        sid, (unsigned)cols, (unsigned)rows, (long long)unix_ts, term);
    if (n > 0 && n < (int)sizeof line) shard_emit(fd, line, (size_t)n);
}

/* Emit a single ≤ATOMIC_CHUNK event line. Caller is responsible for chunking. */
static int emit_event_chunk(int fd, const char *sid, double t,
                            char ch, const uint8_t *data, size_t n) {
    static char scratch[LINE_SCRATCH];
    char escaped[LINE_SCRATCH];
    if (json_escape(escaped, sizeof escaped, data, n) < 0) return -1;
    int w = snprintf(scratch, sizeof scratch,
        "{\"sid\":\"%s\",\"t\":%.6f,\"ch\":\"%c\",\"d\":\"%s\"}\n",
        sid, t, ch, escaped);
    if (w <= 0 || w >= (int)sizeof scratch) return -1;
    return shard_emit(fd, scratch, (size_t)w);
}

static void emit_resize(int fd, const char *sid, double t,
                        unsigned short cols, unsigned short rows) {
    char line[256];
    int n = snprintf(line, sizeof line,
        "{\"sid\":\"%s\",\"t\":%.6f,\"ch\":\"r\",\"d\":\"%ux%u\"}\n",
        sid, t, (unsigned)cols, (unsigned)rows);
    if (n > 0 && n < (int)sizeof line) shard_emit(fd, line, (size_t)n);
}

static void emit_trunc_sentinel(int fd, const char *sid) {
    char line[128];
    int n = snprintf(line, sizeof line, "{\"sid\":\"%s\",\"trunc\":true}\n", sid);
    if (n > 0) shard_emit(fd, line, (size_t)n);
}

/* Escape an SD-PARAM-VALUE per RFC 5424 §6.3.3 — backslash, double-quote, and
 * right bracket must be backslash-escaped; everything else is passed through.
 * Also drops control chars (< 0x20) and 0x7F since they wreck the collector's
 * line-oriented parser. */
static void sd_escape(char *dst, size_t cap, const char *src) {
    size_t o = 0;
    if (cap == 0) return;
    for (size_t i = 0; src[i] && o + 2 < cap; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c < 0x20 || c == 0x7f) continue;
        if (c == '\\' || c == '"' || c == ']') {
            if (o + 3 >= cap) break;
            dst[o++] = '\\';
        }
        dst[o++] = (char)c;
    }
    dst[o] = '\0';
}

/* ─── syslog emitters (direct to PID 1 stdout) ────────────────────────────── */

/* Format & write an RFC 5424 line with a [relay@55555 ...] SD block matching
 * what decnet/templates/syslog_bridge.py emits. Routes the line to PID 1's
 * stdout fd so the container's Docker log stream picks it up — same channel
 * the other service templates use. */
static void syslog_emit(const char *event_type, const char *sd_params,
                        const char *msg) {
    int fd = open(PID1_STDOUT, O_WRONLY | O_APPEND | O_CLOEXEC);
    if (fd < 0) return;

    const char *node = getenv("NODE_NAME");
    if (!node || !*node) node = "-";

    char ts[64];
    struct timespec tsp;
    clock_gettime(CLOCK_REALTIME, &tsp);
    struct tm tm;
    gmtime_r(&tsp.tv_sec, &tm);
    int n = (int)strftime(ts, sizeof ts, "%Y-%m-%dT%H:%M:%S", &tm);
    snprintf(ts + n, sizeof ts - n, ".%06ld+00:00", tsp.tv_nsec / 1000);

    char line[LINE_SCRATCH];
    int w = snprintf(line, sizeof line,
        "<134>1 %s %s sessrec - %s [relay@55555 %s]%s%s\n",
        ts, node, event_type, sd_params ? sd_params : "",
        msg && *msg ? " " : "", msg ? msg : "");
    if (w > 0 && w < (int)sizeof line) write_all(fd, line, (size_t)w);
    close(fd);
}

/* ─── main relay ─────────────────────────────────────────────────────────── */

static int open_shard(void) {
    if (mkdir(TRANSCRIPTS_DIR, 0700) != 0 && errno != EEXIST) return -1;
    char path[512];
    shard_path(path);
    return open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0640);
}

/* Emit an "o" or "i" event, chunking to ATOMIC_CHUNK and tracking bytes_used
 * against SESSION_CAP_BYTES. On cap crossing, emits the sentinel once and
 * returns non-zero so the caller stops emitting for this sid. */
static int emit_chunked(int fd, const char *sid, double t, char ch,
                        const uint8_t *data, size_t n,
                        uint64_t *bytes_used, int *truncated) {
    if (*truncated) return 0;
    size_t off = 0;
    while (off < n) {
        size_t take = n - off;
        if (take > ATOMIC_CHUNK / 4) take = ATOMIC_CHUNK / 4;
        /* /4 because each raw byte can expand up to 6x under JSON \u00XX
         * escaping. Keeps the final line < ATOMIC_CHUNK. */
        if (emit_event_chunk(fd, sid, t, ch, data + off, take) != 0) {
            /* Shard write failed — treat as truncation to avoid infinite retry
             * loop and to keep the pty relay going. */
            *truncated = 1;
            emit_trunc_sentinel(fd, sid);
            return 1;
        }
        *bytes_used += take;
        off += take;
        if (*bytes_used >= SESSION_CAP_BYTES) {
            *truncated = 1;
            emit_trunc_sentinel(fd, sid);
            return 1;
        }
    }
    return 0;
}

static void run_relay(int shard_fd, const char *sid, const char *src_ip,
                      const char *service) {
    /* Capture parent tty state so we can restore + copy winsize to the pty. */
    struct termios orig_t, raw_t;
    int have_orig = (tcgetattr(STDIN_FILENO, &orig_t) == 0);
    struct winsize ws = {24, 80, 0, 0};
    ioctl(STDIN_FILENO, TIOCGWINSZ, &ws);

    emit_header(shard_fd, sid, ws.ws_col, ws.ws_row, time(NULL));

    int master_fd = -1;
    pid_t child = forkpty(&master_fd, NULL, have_orig ? &orig_t : NULL, &ws);
    if (child < 0) {
        /* Give up recording; fall through to plain shell. */
        execlp(DEFAULT_SHELL, DEFAULT_SHELL, "-l", (char *)NULL);
        _exit(127);
    }
    if (child == 0) {
        /* Child: the login shell. exec into bash, leaving the pty as its ctty. */
        execlp(DEFAULT_SHELL, DEFAULT_SHELL, "-l", (char *)NULL);
        _exit(127);
    }

    /* Parent: raw mode on the local tty so keystrokes pass through unmolested. */
    if (have_orig) {
        raw_t = orig_t;
        cfmakeraw(&raw_t);
        tcsetattr(STDIN_FILENO, TCSANOW, &raw_t);
    }

    struct sigaction sa = {0};
    sa.sa_handler = sigwinch_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGWINCH, &sa, NULL);

    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    uint64_t bytes_used = 0;
    int truncated = 0;

    uint8_t buf[BUF_SIZE];
    struct pollfd pfds[2] = {
        { .fd = STDIN_FILENO, .events = POLLIN },
        { .fd = master_fd,    .events = POLLIN },
    };

    int child_alive = 1;
    while (child_alive) {
        if (sigwinch_pending) {
            sigwinch_pending = 0;
            struct winsize nw;
            if (ioctl(STDIN_FILENO, TIOCGWINSZ, &nw) == 0) {
                ioctl(master_fd, TIOCSWINSZ, &nw);
                if (!truncated) emit_resize(shard_fd, sid,
                                             monotonic_since(&t0),
                                             nw.ws_col, nw.ws_row);
            }
        }

        int r = poll(pfds, 2, 1000);
        if (r < 0) {
            if (errno == EINTR) continue;
            break;
        }

        if (pfds[0].revents & POLLIN) {
            ssize_t n = read(STDIN_FILENO, buf, sizeof buf);
            if (n > 0) {
                write_all(master_fd, buf, (size_t)n);
                emit_chunked(shard_fd, sid, monotonic_since(&t0), 'i',
                             buf, (size_t)n, &bytes_used, &truncated);
            } else if (n == 0) {
                /* stdin EOF — close master so the shell sees EOF too. */
                close(master_fd);
                master_fd = -1;
                pfds[1].fd = -1;
            }
        }

        if (master_fd >= 0 && (pfds[1].revents & POLLIN)) {
            ssize_t n = read(master_fd, buf, sizeof buf);
            if (n > 0) {
                write_all(STDOUT_FILENO, buf, (size_t)n);
                emit_chunked(shard_fd, sid, monotonic_since(&t0), 'o',
                             buf, (size_t)n, &bytes_used, &truncated);
            } else {
                /* pty master EOF = shell exited. */
                break;
            }
        }

        if ((pfds[0].revents | pfds[1].revents) & (POLLHUP | POLLERR | POLLNVAL)) {
            if (pfds[1].revents & (POLLHUP | POLLERR | POLLNVAL)) break;
        }

        /* Reap without blocking; tolerate children that exit slightly before
         * we see the master EOF. */
        int status;
        pid_t r2 = waitpid(child, &status, WNOHANG);
        if (r2 == child) {
            child_alive = 0;
            /* Let pty flush remaining output on the next poll cycle. */
            break;
        }
    }

    /* Final reap. */
    int status = 0;
    if (child_alive) waitpid(child, &status, 0);
    if (master_fd >= 0) close(master_fd);

    if (have_orig) tcsetattr(STDIN_FILENO, TCSANOW, &orig_t);

    double duration = monotonic_since(&t0);

    /* src_ip is always an IP literal (getnameinfo NI_NUMERICHOST or an IPv4/6
     * token from $SSH_CONNECTION / utmp). 128 B is enough for IPv6 + zone id
     * + escaping headroom, and keeps the syslog line bounded. */
    char ip_esc[128];
    sd_escape(ip_esc, sizeof ip_esc, src_ip[0] ? src_ip : "-");

    char sd[1024];
    snprintf(sd, sizeof sd,
        "sid=\"%s\" service=\"%s\" src_ip=\"%s\" duration_s=\"%.3f\" "
        "bytes=\"%llu\" truncated=\"%s\"",
        sid, service, ip_esc, duration,
        (unsigned long long)bytes_used, truncated ? "true" : "false");
    syslog_emit("session_recorded", sd, NULL);
}

/* ─── main ────────────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    (void)argc; (void)argv;
    prctl(PR_SET_NAME, (unsigned long)COMM_DISGUISE, 0, 0, 0);

    /* Non-interactive (`ssh host cmd`) — bypass recording entirely. The
     * existing PROMPT_COMMAND syslog hook still logs the single command. */
    if (!isatty(STDIN_FILENO)) {
        execlp(DEFAULT_SHELL, DEFAULT_SHELL, "-l", (char *)NULL);
        _exit(127);
    }

    /* Disk pressure: skip recording, fall through to plain shell. */
    if (free_bytes(TRANSCRIPTS_DIR) < MIN_FREE_BYTES &&
        free_bytes("/var/lib/systemd/coredump") < MIN_FREE_BYTES) {
        /* statvfs on the transcripts dir may fail if not yet created; check
         * the parent mount as a fallback before deciding. */
        syslog_emit("session_skipped", "reason=\"disk_pressure\"", NULL);
        execlp(DEFAULT_SHELL, DEFAULT_SHELL, "-l", (char *)NULL);
        _exit(127);
    }

    int shard_fd = open_shard();
    if (shard_fd < 0) {
        syslog_emit("session_skipped", "reason=\"shard_open_failed\"", NULL);
        execlp(DEFAULT_SHELL, DEFAULT_SHELL, "-l", (char *)NULL);
        _exit(127);
    }

    char sid[37];
    if (mint_uuid(sid) != 0) {
        close(shard_fd);
        execlp(DEFAULT_SHELL, DEFAULT_SHELL, "-l", (char *)NULL);
        _exit(127);
    }

    /* Service discriminant: env var SESSREC_SERVICE set by the template
     * entrypoint (ssh vs telnet). SSH forwards env via PAM; busybox /bin/login
     * strips env, so as a fallback we read /etc/sessrec.service, a one-line
     * file the template entrypoint writes at boot. */
    const char *service = getenv("SESSREC_SERVICE");
    static char svc_buf[16];
    if (!service || !*service) {
        FILE *sf = fopen("/etc/sessrec.service", "r");
        if (sf) {
            if (fgets(svc_buf, sizeof svc_buf, sf)) {
                size_t n = strlen(svc_buf);
                while (n > 0 && (svc_buf[n - 1] == '\n' || svc_buf[n - 1] == ' ')) {
                    svc_buf[--n] = '\0';
                }
                if (svc_buf[0]) service = svc_buf;
            }
            fclose(sf);
        }
    }
    if (!service || !*service) service = "ssh";

    char src_ip[NI_MAXHOST];
    resolve_src_ip(src_ip);

    /* Hostname banner — /bin/login emits "Last login: …" before exec'ing the
     * shell; we want our header anchored before the shell starts writing, so
     * emit_header() has already run inside run_relay(). */

    run_relay(shard_fd, sid, src_ip, service);
    close(shard_fd);

    /* Exit code mirrors the shell's — a bash logout shouldn't surface here
     * as an error to the parent (sshd / login). */
    return 0;
}
