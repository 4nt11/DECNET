#!/bin/bash
set -e
mkdir -p /tmp/smb_share
exec python3 /opt/server.py
