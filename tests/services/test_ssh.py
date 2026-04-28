"""
Tests for the SSHService plugin (real OpenSSH, Cowrie removed).
"""

from decnet.services.registry import all_services, get_service
from decnet.archetypes import get_archetype


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fragment(service_cfg: dict | None = None, log_target: str | None = None) -> dict:
    return get_service("ssh").compose_fragment(
        "test-decky", log_target=log_target, service_cfg=service_cfg
    )


def _dockerfile_text() -> str:
    return (get_service("ssh").dockerfile_context() / "Dockerfile").read_text()


def _entrypoint_text() -> str:
    return (get_service("ssh").dockerfile_context() / "entrypoint.sh").read_text()


def _capture_script_path():
    return get_service("ssh").dockerfile_context() / "capture.sh"


def _capture_text() -> str:
    return _capture_script_path().read_text()


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def test_ssh_registered():
    assert "ssh" in all_services()


def test_real_ssh_not_registered():
    assert "real_ssh" not in all_services()


def test_ssh_ports():
    assert get_service("ssh").ports == [22]


def test_ssh_is_build_service():
    assert get_service("ssh").default_image == "build"


def test_ssh_dockerfile_context_exists():
    svc = get_service("ssh")
    ctx = svc.dockerfile_context()
    assert ctx.is_dir(), f"Dockerfile context missing: {ctx}"
    assert (ctx / "Dockerfile").exists()
    assert (ctx / "entrypoint.sh").exists()


# ---------------------------------------------------------------------------
# No Cowrie env vars
# ---------------------------------------------------------------------------

def test_no_cowrie_vars():
    """The old Cowrie emulation is gone — no COWRIE_* env should leak in.

    NODE_NAME is intentionally present: it pins the decky identifier used
    by rsyslog (HOSTNAME field) and capture.sh (_hostname for file_captured
    events), so the /artifacts/{decky}/... URL lines up with the bind mount.
    """
    env = _fragment()["environment"]
    cowrie_keys = [k for k in env if k.startswith("COWRIE_")]
    assert cowrie_keys == [], f"Unexpected Cowrie vars: {cowrie_keys}"


def test_node_name_matches_decky():
    """SSH must propagate decky_name via NODE_NAME so logs/artifacts key on it."""
    frag = _fragment()
    assert frag["environment"]["NODE_NAME"] == "test-decky"


# ---------------------------------------------------------------------------
# compose_fragment structure
# ---------------------------------------------------------------------------

def test_fragment_has_build():
    frag = _fragment()
    assert "build" in frag and "context" in frag["build"]


def test_fragment_container_name():
    assert _fragment()["container_name"] == "test-decky-ssh"


def test_fragment_restart_policy():
    assert _fragment()["restart"] == "unless-stopped"


def test_fragment_cap_add():
    assert "NET_BIND_SERVICE" in _fragment().get("cap_add", [])


def test_default_password():
    assert _fragment()["environment"]["SSH_ROOT_PASSWORD"] == "admin"


def test_custom_password():
    assert _fragment(service_cfg={"password": "h4x!"})["environment"]["SSH_ROOT_PASSWORD"] == "h4x!"


def test_custom_hostname():
    assert _fragment(service_cfg={"hostname": "prod-db-01"})["environment"]["SSH_HOSTNAME"] == "prod-db-01"


def test_no_hostname_by_default():
    assert "SSH_HOSTNAME" not in _fragment()["environment"]


def test_no_log_target_in_env():
    assert "LOG_TARGET" not in _fragment(log_target="10.0.0.1:5140").get("environment", {})


# ---------------------------------------------------------------------------
# Logging pipeline wiring (Dockerfile + entrypoint)
# ---------------------------------------------------------------------------

def test_dockerfile_has_rsyslog():
    assert "rsyslog" in _dockerfile_text()


def test_dockerfile_runs_as_root():
    lines = [line.strip() for line in _dockerfile_text().splitlines()]
    user_lines = [line for line in lines if line.startswith("USER ")]
    assert user_lines == [], f"Unexpected USER directive(s): {user_lines}"


def test_dockerfile_rsyslog_conf_created():
    df = _dockerfile_text()
    assert "50-journal-forward.conf" in df
    assert "RFC5424fmt" in df


def test_dockerfile_drops_sshd_native_chatter():
    """sshd's native syslog (`Failed password`, `Connection from`, …) and
    the pam_unix lines emitted from sshd's PAM stack add no signal — the
    auth-helper writes structured login_attempt events out-of-band. The
    rsyslog config must drop them via a `:programname, isequal, "sshd" stop`
    rule that comes BEFORE the forwarding actions. sudo / login pam_unix
    lines must still flow (different programname)."""
    df = _dockerfile_text()
    stop_rule = ':programname, isequal, "sshd" stop'
    assert stop_rule in df, "sshd drop rule missing from rsyslog config"
    # Order matters: stop must precede the forwarding actions inside the
    # same printf block, otherwise rsyslog forwards before evaluating it.
    stop_idx = df.index(stop_rule)
    fwd_idx = df.index("auth,authpriv.*  /proc/1/fd/1;RFC5424fmt")
    assert stop_idx < fwd_idx, "stop rule must come before forwarding action"


def test_dockerfile_sudoers_syslog():
    df = _dockerfile_text()
    assert "syslog=auth" in df
    assert "log_input" in df
    assert "log_output" in df


def test_dockerfile_prompt_command_logger():
    df = _dockerfile_text()
    assert "PROMPT_COMMAND" in df
    assert "logger" in df


def test_entrypoint_has_no_named_pipe():
    # Named pipes in the container are a liability — readable and writable
    # by any root process. The log bridge must not rely on one.
    ep = _entrypoint_text()
    assert "mkfifo" not in ep
    assert "syslog-relay" not in ep


def test_entrypoint_has_no_relay_cat():
    # No intermediate cat relay either (removed together with the pipe).
    ep = _entrypoint_text()
    assert "systemd-journal-fwd" not in ep


def test_dockerfile_rsyslog_targets_pid1_stdout():
    df = _dockerfile_text()
    # rsyslog writes straight to /proc/1/fd/1 — no pipe file on disk.
    assert "/proc/1/fd/1" in df
    assert "syslog-relay" not in df
    assert "decnet-logs" not in df


def test_dockerfile_disables_rsyslog_privdrop():
    # rsyslogd must stay root so it can write to PID 1's stdout fd.
    # Dropping to the syslog user makes every auth/user line silently fail.
    df = _dockerfile_text()
    assert "#$PrivDropToUser" in df
    assert "#$PrivDropToGroup" in df


def test_entrypoint_starts_rsyslogd():
    assert "rsyslogd" in _entrypoint_text()


def test_entrypoint_sshd_no_dash_e():
    ep = _entrypoint_text()
    assert "sshd -D" in ep
    assert "sshd -D -e" not in ep


# ---------------------------------------------------------------------------
# Deaddeck archetype
# ---------------------------------------------------------------------------

def test_deaddeck_uses_ssh():
    arch = get_archetype("deaddeck")
    assert "ssh" in arch.services
    assert "real_ssh" not in arch.services


def test_deaddeck_nmap_os():
    assert get_archetype("deaddeck").nmap_os == "linux"


def test_deaddeck_preferred_distros_not_empty():
    assert len(get_archetype("deaddeck").preferred_distros) >= 1


# ---------------------------------------------------------------------------
# File-catcher: Dockerfile wiring
# ---------------------------------------------------------------------------

def test_dockerfile_installs_inotify_tools():
    assert "inotify-tools" in _dockerfile_text()


def test_dockerfile_installs_attribution_tools():
    df = _dockerfile_text()
    for pkg in ("psmisc", "iproute2", "jq"):
        assert pkg in df, f"missing {pkg} in Dockerfile"


def test_dockerfile_installs_default_recon_tools():
    df = _dockerfile_text()
    # Attacker-facing baseline: a lived-in box has these.
    for pkg in ("iputils-ping", "ca-certificates", "nmap"):
        assert pkg in df, f"missing {pkg} in Dockerfile"


def test_dockerfile_stages_capture_script_for_inlining():
    df = _dockerfile_text()
    # capture.sh is no longer COPY'd to a runtime path; it's staged under
    # /tmp/build and folded into /entrypoint.sh as an XOR+gzip+base64 blob
    # by _build_stealth.py, then the staging dir is wiped in the same layer.
    assert "capture.sh" in df
    assert "/tmp/build/" in df
    assert "_build_stealth.py" in df
    assert "rm -rf /tmp/build" in df
    # The old visible install path must be gone.
    assert "/usr/libexec/udev/journal-relay" not in df


def test_dockerfile_masks_inotifywait_as_kmsg_watch():
    df = _dockerfile_text()
    # Symlink so inotifywait invocations show as the plausible binary name.
    assert "kmsg-watch" in df
    assert "inotifywait" in df


def test_dockerfile_does_not_ship_decnet_capture_name():
    # The old obvious name must be gone.
    assert "decnet-capture" not in _dockerfile_text()


def test_dockerfile_creates_quarantine_dir():
    df = _dockerfile_text()
    # In-container path masquerades as the real systemd-coredump dir.
    assert "/var/lib/systemd/coredump" in df
    assert "chmod 700" in df


def test_dockerfile_ssh_loglevel_verbose():
    assert "LogLevel VERBOSE" in _dockerfile_text()


def test_dockerfile_prompt_command_logs_ssh_client():
    df = _dockerfile_text()
    assert "PROMPT_COMMAND" in df
    assert "SSH_CLIENT" in df


# ---------------------------------------------------------------------------
# File-catcher: capture.sh semantics
# ---------------------------------------------------------------------------

def test_capture_script_exists_and_executable():
    import os
    p = _capture_script_path()
    assert p.exists(), f"capture.sh missing: {p}"
    assert os.access(p, os.X_OK), "capture.sh must be executable"


def test_capture_script_uses_close_write_and_moved_to():
    body = _capture_text()
    assert "close_write" in body
    assert "moved_to" in body
    assert "inotifywait" in body


def test_capture_script_skips_quarantine_path():
    body = _capture_text()
    # Must not loop on its own writes — quarantine lives under /var/lib/systemd.
    assert "/var/lib/systemd/" in body


def test_capture_script_resolves_writer_pid():
    body = _capture_text()
    assert "fuser" in body
    # walks PPid to find sshd session leader
    assert "PPid" in body
    assert "/proc/" in body


def test_capture_script_snapshots_ss_and_utmp():
    body = _capture_text()
    assert "ss " in body or "ss -" in body
    assert "who " in body or "who --" in body


def test_capture_script_no_longer_writes_sidecar():
    body = _capture_text()
    # The old .meta.json sidecar was replaced by a single syslog event that
    # carries the same metadata — see emit_capture.py.
    assert ".meta.json" not in body


def test_capture_script_pipes_to_emit_capture():
    body = _capture_text()
    # capture.sh builds the event JSON with jq and pipes to python3 reading
    # from an fd that carries the in-memory emit_capture source; no on-disk
    # emit_capture.py exists in the running container anymore.
    assert "EMIT_CAPTURE_PY" in body
    assert "python3" in body
    assert "/opt/emit_capture.py" not in body
    assert "file_captured" in body
    for key in ("attribution", "sha256", "src_ip", "ssh_user", "writer_cmdline"):
        assert key in body, f"capture field {key} missing from capture.sh"


def test_ssh_dockerfile_ships_capture_emitter():
    df = _dockerfile_text()
    # Python sources are staged for the build-time inlining step, not COPY'd
    # to /opt (which would leave them world-readable for any attacker shell).
    assert "syslog_bridge.py" in df
    assert "emit_capture.py" in df
    assert "/opt/emit_capture.py" not in df
    assert "/opt/syslog_bridge.py" not in df
    # python3 is needed to run the emitter; python3-minimal keeps the image small.
    assert "python3" in df


def test_capture_script_enforces_size_cap():
    body = _capture_text()
    assert "CAPTURE_MAX_BYTES" in body


# ---------------------------------------------------------------------------
# File-catcher: entrypoint wiring
# ---------------------------------------------------------------------------

def test_entrypoint_starts_capture_watcher():
    ep = _entrypoint_text()
    # Invokes the udev-disguised path, not the old obvious name.
    assert "journal-relay" in ep
    assert "decnet-capture" not in ep
    # Started before sshd so drops during first login are caught.
    assert ep.index("journal-relay") < ep.index("exec /usr/sbin/sshd")


def test_capture_script_uses_masked_inotify_bin():
    body = _capture_text()
    assert "INOTIFY_BIN" in body
    assert "kmsg-watch" in body


# ---------------------------------------------------------------------------
# argv_zap LD_PRELOAD shim (hides inotifywait args from ps)
# ---------------------------------------------------------------------------

def test_argv_zap_source_shipped():
    ctx = get_service("ssh").dockerfile_context()
    src = ctx / "argv_zap.c"
    assert src.exists(), "argv_zap.c missing from SSH template context"
    body = src.read_text()
    assert "__libc_start_main" in body
    assert "PR_SET_NAME" in body


def test_dockerfile_compiles_argv_zap():
    df = _dockerfile_text()
    assert "argv_zap.c" in df
    # The installed .so is disguised as a multiarch udev-companion library
    # (sits next to real libudev.so.1). The old argv_zap.so name was a tell.
    assert "/usr/lib/x86_64-linux-gnu/libudev-shared.so.1" in df
    assert "argv_zap.so" not in df
    # gcc must be installed AND purged in the same layer (image-size hygiene).
    assert "gcc" in df
    assert "apt-get purge" in df


def test_capture_script_preloads_argv_zap():
    body = _capture_text()
    assert "LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libudev-shared.so.1" in body
    assert "argv_zap.so" not in body


def test_capture_script_sets_argv_zap_comm():
    body = _capture_text()
    # Comm must mirror argv[0] for the inotify invocation.
    assert "ARGV_ZAP_COMM=kmsg-watch" in body


def test_argv_zap_reads_comm_from_env():
    ctx = get_service("ssh").dockerfile_context()
    src = (ctx / "argv_zap.c").read_text()
    assert "ARGV_ZAP_COMM" in src
    assert "getenv" in src


def test_entrypoint_watcher_bash_uses_argv_zap():
    ep = _entrypoint_text()
    # The bash that runs the capture loop must be LD_PRELOADed so the
    # (large) bash -c argument doesn't leak via /proc/PID/cmdline.
    assert "LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libudev-shared.so.1" in ep
    assert "ARGV_ZAP_COMM=journal-relay" in ep
    assert "argv_zap.so" not in ep


def test_capture_script_header_is_sanitized():
    body = _capture_text()
    # Header should not betray the honeypot if an attacker `cat`s the file.
    first_lines = "\n".join(body.splitlines()[:20])
    assert "honeypot" not in first_lines.lower()
    assert "attacker" not in first_lines.lower()


# ---------------------------------------------------------------------------
# File-catcher: compose_fragment volume
# ---------------------------------------------------------------------------

def test_fragment_mounts_quarantine_volume():
    frag = _fragment()
    vols = frag.get("volumes", [])
    assert any(
        v.endswith(":/var/lib/systemd/coredump:rw") for v in vols
    ), f"quarantine volume missing: {vols}"


def test_fragment_quarantine_host_path_layout():
    vols = _fragment()["volumes"]
    host = vols[0].split(":", 1)[0]
    assert host == "/var/lib/decnet/artifacts/test-decky/ssh"


def test_fragment_quarantine_path_per_decky():
    frag_a = get_service("ssh").compose_fragment("decky-01")
    frag_b = get_service("ssh").compose_fragment("decky-02")
    assert frag_a["volumes"] != frag_b["volumes"]
    assert "decky-01" in frag_a["volumes"][0]
    assert "decky-02" in frag_b["volumes"][0]
