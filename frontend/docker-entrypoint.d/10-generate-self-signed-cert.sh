#!/bin/sh
# Generate a self-signed TLS certificate at container start if one isn't present.
# Runs before nginx starts (nginx image executes /docker-entrypoint.d/*.sh in order).
# The key is created inside the container only and is NEVER committed to the repo.
set -e

CERT_DIR=/etc/nginx/certs
CRT="$CERT_DIR/server.crt"
KEY="$CERT_DIR/server.key"

mkdir -p "$CERT_DIR"

if [ -s "$CRT" ] && [ -s "$KEY" ]; then
    echo "[entrypoint] TLS certificate already present — reusing $CRT"
    exit 0
fi

echo "[entrypoint] generating self-signed TLS certificate (valid 825 days)…"
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$KEY" -out "$CRT" -days 825 \
    -subj "/O=ThreatProbe Scanner/CN=threatprobe.local" \
    -addext "subjectAltName=DNS:localhost,DNS:threatprobe.local,IP:127.0.0.1"
chmod 600 "$KEY"
echo "[entrypoint] self-signed certificate written to $CRT"
