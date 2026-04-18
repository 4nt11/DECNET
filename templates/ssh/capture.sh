#!/bin/bash
# DECNET SSH honeypot file-catcher.
#
# Watches attacker-writable paths with inotifywait. On close_write/moved_to,
# copies the file to the host-mounted quarantine dir, writes a .meta.json
# with attacker attribution, and emits an RFC 5424 syslog line.
#
# Attribution chain (strongest → weakest):
#   pid-chain : fuser/lsof finds writer PID → walk PPid to sshd session
#               → cross-ref with `ss` to get src_ip/src_port
#   utmp-only : writer PID gone (scp exited); fall back to `who --ips`
#   unknown   : no live session at all (unlikely under real attack)

set -u

CAPTURE_DIR="${CAPTURE_DIR:-/var/decnet/captured}"
CAPTURE_MAX_BYTES="${CAPTURE_MAX_BYTES:-52428800}"  # 50 MiB
CAPTURE_WATCH_PATHS="${CAPTURE_WATCH_PATHS:-/root /tmp /var/tmp /home /var/www /opt /dev/shm}"

mkdir -p "$CAPTURE_DIR"
chmod 700 "$CAPTURE_DIR"

# Filenames we never capture (noise from container boot / attacker-irrelevant).
_is_ignored_path() {
    local p="$1"
    case "$p" in
        "$CAPTURE_DIR"/*) return 0 ;;
        /var/decnet/*)    return 0 ;;
        */.bash_history)  return 0 ;;
        */.viminfo)       return 0 ;;
        */ssh_host_*_key*) return 0 ;;
    esac
    return 1
}

# Resolve the writer PID best-effort. Prints the PID or nothing.
_writer_pid() {
    local path="$1"
    local pid
    pid="$(fuser "$path" 2>/dev/null | tr -d ' \t\n')"
    if [ -n "$pid" ]; then
        printf '%s' "${pid%% *}"
        return
    fi
    # Fallback: scan /proc/*/fd for an open handle on the path.
    for fd_link in /proc/[0-9]*/fd/*; do
        [ -L "$fd_link" ] || continue
        if [ "$(readlink -f "$fd_link" 2>/dev/null)" = "$path" ]; then
            printf '%s' "$(echo "$fd_link" | awk -F/ '{print $3}')"
            return
        fi
    done
}

# Walk PPid chain from $1 until we hit an sshd session leader.
# Prints: <sshd_pid> <user>   (empty on no match).
_walk_to_sshd() {
    local pid="$1"
    local depth=0
    while [ -n "$pid" ] && [ "$pid" != "0" ] && [ "$pid" != "1" ] && [ $depth -lt 20 ]; do
        local cmd
        cmd="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)"
        # sshd session leaders look like: "sshd: root@pts/0" or "sshd: root@notty"
        if echo "$cmd" | grep -qE '^sshd: [^ ]+@'; then
            local user
            user="$(echo "$cmd" | sed -E 's/^sshd: ([^@]+)@.*/\1/')"
            printf '%s %s' "$pid" "$user"
            return
        fi
        pid="$(awk '/^PPid:/ {print $2}' "/proc/$pid/status" 2>/dev/null)"
        depth=$((depth + 1))
    done
}

# Emit a JSON array of currently-established SSH peers.
# Each item: {pid, src_ip, src_port}.
_ss_sessions_json() {
    ss -Htnp state established sport = :22 2>/dev/null \
        | awk '
            {
                peer=$4; local_=$3;
                # peer looks like 198.51.100.7:55342  (may be IPv6 [::1]:x)
                n=split(peer, a, ":");
                port=a[n];
                ip=peer; sub(":" port "$", "", ip);
                gsub(/[\[\]]/, "", ip);
                # extract pid from users:(("sshd",pid=1234,fd=5))
                pid="";
                if (match($0, /pid=[0-9]+/)) {
                    pid=substr($0, RSTART+4, RLENGTH-4);
                }
                printf "{\"pid\":%s,\"src_ip\":\"%s\",\"src_port\":%s}\n",
                       (pid==""?"null":pid), ip, (port+0);
            }' \
        | jq -s '.'
}

# Emit a JSON array of logged-in users from utmp.
# Each item: {user, src_ip, login_at}.
_who_sessions_json() {
    who --ips 2>/dev/null \
        | awk '{ printf "{\"user\":\"%s\",\"tty\":\"%s\",\"login_at\":\"%s %s\",\"src_ip\":\"%s\"}\n", $1, $2, $3, $4, $NF }' \
        | jq -s '.'
}

_capture_one() {
    local src="$1"
    [ -f "$src" ] || return 0
    _is_ignored_path "$src" && return 0

    local size
    size="$(stat -c '%s' "$src" 2>/dev/null)"
    [ -z "$size" ] && return 0
    if [ "$size" -gt "$CAPTURE_MAX_BYTES" ]; then
        logger -p user.info -t decnet-capture "file_skipped size=$size path=$src reason=oversize"
        return 0
    fi

    # Attribution first — PID may disappear after the copy races.
    local writer_pid writer_comm writer_cmdline writer_uid writer_loginuid
    writer_pid="$(_writer_pid "$src")"
    if [ -n "$writer_pid" ] && [ -d "/proc/$writer_pid" ]; then
        writer_comm="$(cat "/proc/$writer_pid/comm" 2>/dev/null)"
        writer_cmdline="$(tr '\0' ' ' < "/proc/$writer_pid/cmdline" 2>/dev/null)"
        writer_uid="$(awk '/^Uid:/ {print $2}' "/proc/$writer_pid/status" 2>/dev/null)"
        writer_loginuid="$(cat "/proc/$writer_pid/loginuid" 2>/dev/null)"
    fi

    local ssh_pid ssh_user
    if [ -n "$writer_pid" ]; then
        read -r ssh_pid ssh_user < <(_walk_to_sshd "$writer_pid" || true)
    fi

    local ss_json who_json
    ss_json="$(_ss_sessions_json 2>/dev/null || echo '[]')"
    who_json="$(_who_sessions_json 2>/dev/null || echo '[]')"

    # Resolve src_ip via ss by matching ssh_pid.
    local src_ip="" src_port="null" attribution="unknown"
    if [ -n "${ssh_pid:-}" ]; then
        local matched
        matched="$(echo "$ss_json" | jq -c --argjson p "$ssh_pid" '.[] | select(.pid==$p)')"
        if [ -n "$matched" ]; then
            src_ip="$(echo "$matched" | jq -r '.src_ip')"
            src_port="$(echo "$matched" | jq -r '.src_port')"
            attribution="pid-chain"
        fi
    fi
    if [ "$attribution" = "unknown" ] && [ "$(echo "$who_json" | jq 'length')" -gt 0 ]; then
        src_ip="$(echo "$who_json" | jq -r '.[0].src_ip')"
        attribution="utmp-only"
    fi

    local sha
    sha="$(sha256sum "$src" 2>/dev/null | awk '{print $1}')"
    [ -z "$sha" ] && return 0

    local ts base stored_as
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    base="$(basename "$src")"
    stored_as="${ts}_${sha:0:12}_${base}"

    cp --preserve=timestamps,ownership "$src" "$CAPTURE_DIR/$stored_as" 2>/dev/null || return 0

    local mtime
    mtime="$(stat -c '%y' "$src" 2>/dev/null)"

    local decky="${HOSTNAME:-unknown}"

    jq -n \
        --arg captured_at "$ts" \
        --arg orig_path "$src" \
        --arg stored_as "$stored_as" \
        --arg sha "$sha" \
        --argjson size "$size" \
        --arg mtime "$mtime" \
        --arg decky "$decky" \
        --arg attribution "$attribution" \
        --arg writer_pid "${writer_pid:-}" \
        --arg writer_comm "${writer_comm:-}" \
        --arg writer_cmdline "${writer_cmdline:-}" \
        --arg writer_uid "${writer_uid:-}" \
        --arg writer_loginuid "${writer_loginuid:-}" \
        --arg ssh_pid "${ssh_pid:-}" \
        --arg ssh_user "${ssh_user:-}" \
        --arg src_ip "$src_ip" \
        --arg src_port "$src_port" \
        --argjson concurrent "$who_json" \
        --argjson ss_snapshot "$ss_json" \
        '{
            captured_at: $captured_at,
            orig_path: $orig_path,
            stored_as: $stored_as,
            sha256: $sha,
            size: $size,
            mtime: $mtime,
            decky: $decky,
            attribution: $attribution,
            writer: {
                pid: ($writer_pid | if . == "" then null else tonumber? end),
                comm: $writer_comm,
                cmdline: $writer_cmdline,
                uid: ($writer_uid | if . == "" then null else tonumber? end),
                loginuid: ($writer_loginuid | if . == "" then null else tonumber? end)
            },
            ssh_session: {
                pid: ($ssh_pid | if . == "" then null else tonumber? end),
                user: (if $ssh_user == "" then null else $ssh_user end),
                src_ip: (if $src_ip == "" then null else $src_ip end),
                src_port: ($src_port | if . == "null" or . == "" then null else tonumber? end)
            },
            concurrent_sessions: $concurrent,
            ss_snapshot: $ss_snapshot
        }' > "$CAPTURE_DIR/$stored_as.meta.json"

    logger -p user.info -t decnet-capture \
        "file_captured orig_path=$src sha256=$sha size=$size stored_as=$stored_as src_ip=${src_ip:-unknown} ssh_user=${ssh_user:-unknown} attribution=$attribution"
}

# Main loop.
# shellcheck disable=SC2086
inotifywait -m -r -q \
    --event close_write --event moved_to \
    --format '%w%f' \
    $CAPTURE_WATCH_PATHS 2>/dev/null \
| while IFS= read -r path; do
    _capture_one "$path" &
done
