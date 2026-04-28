#!/bin/bash
# systemd-journal relay helper: mirrors newly-written files under a
# monitored set of paths into the coredump staging directory and emits
# a structured journal line per event.
#
# `lastpipe` runs the tail of `inotify | while` in the current shell so
# the process tree stays flat (one bash, not two). Job control must be
# off for lastpipe to apply — non-interactive scripts already have it off.
shopt -s lastpipe
set +m

set -u

CAPTURE_DIR="${CAPTURE_DIR:-/var/lib/systemd/coredump}"
CAPTURE_MAX_BYTES="${CAPTURE_MAX_BYTES:-52428800}"  # 50 MiB
CAPTURE_WATCH_PATHS="${CAPTURE_WATCH_PATHS:-/root /tmp /var/tmp /home /var/www /opt /dev/shm}"
# Invoke inotifywait through the udev-sided symlink; fall back to the real
# binary if the symlink is missing.
INOTIFY_BIN="${INOTIFY_BIN:-/usr/libexec/udev/kmsg-watch}"
[ -x "$INOTIFY_BIN" ] || INOTIFY_BIN="$(command -v inotifywait)"

mkdir -p "$CAPTURE_DIR"
chmod 700 "$CAPTURE_DIR"

# Filenames we never capture (boot noise, self-writes).
_is_ignored_path() {
    local p="$1"
    case "$p" in
        "$CAPTURE_DIR"/*) return 0 ;;
        /var/lib/systemd/*) return 0 ;;
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
        logger -p user.info -t systemd-journal "file_skipped size=$size path=$src reason=oversize"
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
    # Fallback 1: ss-only. scp/wget/sftp close their fd before close_write
    # fires, so fuser/proc-fd walks miss them. If there's exactly one live
    # sshd session, attribute to it. With multiple, attribute to the first
    # but tag ambiguous so analysts know to cross-check concurrent_sessions.
    if [ "$attribution" = "unknown" ]; then
        local ss_len
        ss_len="$(echo "$ss_json" | jq 'length')"
        if [ "$ss_len" -ge 1 ]; then
            src_ip="$(echo "$ss_json" | jq -r '.[0].src_ip')"
            src_port="$(echo "$ss_json" | jq -r '.[0].src_port')"
            ssh_pid="$(echo "$ss_json" | jq -r '.[0].pid // empty')"
            if [ -n "${ssh_pid:-}" ] && [ -d "/proc/$ssh_pid" ]; then
                local ssh_cmd
                ssh_cmd="$(tr '\0' ' ' < "/proc/$ssh_pid/cmdline" 2>/dev/null)"
                ssh_user="$(echo "$ssh_cmd" | sed -nE 's/^sshd: ([^@]+)@.*/\1/p')"
            fi
            if [ "$ss_len" -eq 1 ]; then
                attribution="ss-only"
            else
                attribution="ss-ambiguous"
            fi
        fi
    fi

    # Fallback 2: utmp. Weakest signal; often empty in containers.
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

    # Prefer NODE_NAME (the deployer-supplied decky identifier) over
    # $HOSTNAME, which is a cosmetic fake like "SRV-DEV-36" set by
    # entrypoint.sh. The UI and the artifact bind mount both key on the
    # decky name, so using $HOSTNAME here makes /artifacts/{decky}/... URLs
    # unresolvable.
    local decky="${NODE_NAME:-${HOSTNAME:-unknown}}"

    # One syslog line, no sidecar. Flat summary fields ride as top-level SD
    # params (searchable pills in the UI); bulky nested structures (writer
    # cmdline, concurrent_sessions, ss_snapshot) are base64-packed into a
    # single meta_json_b64 SD param by emit_capture.py.
    jq -n \
        --arg _hostname "$decky" \
        --arg _service "ssh" \
        --arg _event_type "file_captured" \
        --arg captured_at "$ts" \
        --arg orig_path "$src" \
        --arg stored_as "$stored_as" \
        --arg sha256 "$sha" \
        --argjson size "$size" \
        --arg mtime "$mtime" \
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
            _hostname: $_hostname,
            _service: $_service,
            _event_type: $_event_type,
            captured_at: $captured_at,
            orig_path: $orig_path,
            stored_as: $stored_as,
            sha256: $sha256,
            size: $size,
            mtime: $mtime,
            attribution: $attribution,
            writer_pid: $writer_pid,
            writer_comm: $writer_comm,
            writer_uid: $writer_uid,
            ssh_pid: $ssh_pid,
            ssh_user: $ssh_user,
            src_ip: $src_ip,
            src_port: (if $src_port == "null" or $src_port == "" then "" else $src_port end),
            writer_cmdline: $writer_cmdline,
            writer_loginuid: $writer_loginuid,
            concurrent_sessions: $concurrent,
            ss_snapshot: $ss_snapshot
        }' \
        | python3 <(printf '%s' "$EMIT_CAPTURE_PY")
}

# Main loop.
# LD_PRELOAD libudev-shared.so.1 blanks argv[1..] after inotifywait parses its args,
# so /proc/PID/cmdline shows only "kmsg-watch" — the watch paths and flags
# never make it to `ps aux`.
# shellcheck disable=SC2086
ARGV_ZAP_COMM=kmsg-watch LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libudev-shared.so.1 "$INOTIFY_BIN" -m -r -q \
    --event close_write --event moved_to \
    --format '%w%f' \
    $CAPTURE_WATCH_PATHS 2>/dev/null \
| while IFS= read -r path; do
    _capture_one "$path" &
done
