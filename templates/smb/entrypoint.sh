#!/bin/bash
set -e
mkdir -p /tmp/smb_share
exec python3 /opt/smb_honeypot.py
