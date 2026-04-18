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
    env = _fragment()["environment"]
    cowrie_keys = [k for k in env if k.startswith("COWRIE_") or k == "NODE_NAME"]
    assert cowrie_keys == [], f"Unexpected Cowrie vars: {cowrie_keys}"


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


def test_dockerfile_sudoers_syslog():
    df = _dockerfile_text()
    assert "syslog=auth" in df
    assert "log_input" in df
    assert "log_output" in df


def test_dockerfile_prompt_command_logger():
    df = _dockerfile_text()
    assert "PROMPT_COMMAND" in df
    assert "logger" in df


def test_entrypoint_creates_named_pipe():
    assert "mkfifo" in _entrypoint_text()


def test_entrypoint_relay_pipe_path_is_disguised():
    ep = _entrypoint_text()
    # Pipe lives under /run/systemd/journal/, not the obvious /var/run/decnet-logs.
    assert "/run/systemd/journal/syslog-relay" in ep
    assert "decnet-logs" not in ep


def test_entrypoint_cat_relay_is_cloaked():
    ep = _entrypoint_text()
    # `cat` is invoked via exec -a so ps shows systemd-journal-fwd.
    assert "systemd-journal-fwd" in ep
    assert "exec -a" in ep


def test_dockerfile_rsyslog_uses_disguised_pipe():
    df = _dockerfile_text()
    assert "/run/systemd/journal/syslog-relay" in df
    assert "decnet-logs" not in df


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


def test_dockerfile_copies_capture_script():
    df = _dockerfile_text()
    # Installed under plausible udev path to hide from casual `ps` inspection.
    assert "COPY capture.sh /usr/libexec/udev/journal-relay" in df
    assert "chmod +x" in df and "journal-relay" in df


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


def test_capture_script_writes_meta_json():
    body = _capture_text()
    assert ".meta.json" in body
    for key in ("attribution", "ssh_session", "writer", "sha256"):
        assert key in body, f"meta key {key} missing from capture.sh"


def test_capture_script_emits_syslog_with_attribution():
    body = _capture_text()
    assert "logger" in body
    assert "file_captured" in body
    assert "src_ip" in body


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
    assert "argv_zap.so" in df
    # gcc must be installed AND purged in the same layer (image-size hygiene).
    assert "gcc" in df
    assert "apt-get purge" in df


def test_capture_script_preloads_argv_zap():
    body = _capture_text()
    assert "LD_PRELOAD=/usr/lib/argv_zap.so" in body


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
    # The bash that runs journal-relay must be LD_PRELOADed so its
    # argv[1] (the script path) doesn't leak via /proc/PID/cmdline.
    assert "LD_PRELOAD=/usr/lib/argv_zap.so" in ep
    assert "ARGV_ZAP_COMM=journal-relay" in ep


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
