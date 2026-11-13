#!/usr/bin/env bash
set -euo pipefail

# Optional Nginx TLS Reverse Proxy terminating TLS on TCP `PROXY_LISTEN_PORT` and
# forwarding HTTP/1.1 + WebSocket Upgrade to `mesh-server` (US-046, US-051, US-057 AC1).
# Generates a dedicated Lab Root CA (`ca.crt`) + leaf certificate for `PROXY_PUBLIC_HOST`
# (`vpn.mesh.internal`) so `meshd` nodes can verify the proxy via `TlsAuthMode::SystemCa`
# without `NetmapSnapshot.pin_set` causing `PinMismatch`.

UPSTREAM_HOST="${PROXY_UPSTREAM_HOST:-172.28.0.10}"
UPSTREAM_PORT="${PROXY_UPSTREAM_PORT:-443}"
PROXY_LISTEN_PORT="${PROXY_LISTEN_PORT:-443}"
PROXY_PUBLIC_HOST="${PROXY_PUBLIC_HOST:-vpn.mesh.internal}"
PROXY_PUBLIC_IP="${PROXY_PUBLIC_IP:-172.28.0.12}"

CERT_DIR="/etc/nginx/mesh-certs"
mkdir -p "${CERT_DIR}"
chmod 0755 "${CERT_DIR}"

if [ ! -f "${CERT_DIR}/ca.crt" ] || [ ! -f "${CERT_DIR}/ca.key" ]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -nodes -days 90 \
    -keyout "${CERT_DIR}/ca.key" \
    -out "${CERT_DIR}/ca.crt" \
    -subj "/CN=Mesh-Lab-Root-CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" >/dev/null 2>&1
  chmod 0600 "${CERT_DIR}/ca.key"
  chmod 0644 "${CERT_DIR}/ca.crt"
fi

if [ ! -f "${CERT_DIR}/proxy.crt" ] || [ ! -f "${CERT_DIR}/proxy.key" ]; then
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -nodes \
    -keyout "${CERT_DIR}/proxy.key" \
    -out "${CERT_DIR}/leaf.csr" \
    -subj "/CN=${PROXY_PUBLIC_HOST}" >/dev/null 2>&1

  cat > "${CERT_DIR}/leaf-ext.cnf" <<EOF
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:${PROXY_PUBLIC_HOST},IP:${PROXY_PUBLIC_IP},IP:127.0.0.1
EOF

  openssl x509 -req -in "${CERT_DIR}/leaf.csr" \
    -CA "${CERT_DIR}/ca.crt" -CAkey "${CERT_DIR}/ca.key" -CAcreateserial \
    -out "${CERT_DIR}/leaf.crt" -days 30 \
    -extfile "${CERT_DIR}/leaf-ext.cnf" >/dev/null 2>&1

  cat "${CERT_DIR}/leaf.crt" "${CERT_DIR}/ca.crt" > "${CERT_DIR}/proxy.crt"
  chmod 0600 "${CERT_DIR}/proxy.key"
  chmod 0644 "${CERT_DIR}/leaf.crt" "${CERT_DIR}/proxy.crt"
  rm -f "${CERT_DIR}/leaf.csr" "${CERT_DIR}/leaf-ext.cnf"
fi

SPKI_PIN="$(openssl x509 -in "${CERT_DIR}/leaf.crt" -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | sha256sum | awk '{print "sha256:" $1}')"
printf '%s\n' "${SPKI_PIN}" > "${CERT_DIR}/proxy.pin"
chmod 0644 "${CERT_DIR}/proxy.pin"

cat > /etc/nginx/conf.d/default.conf <<EOF
map \$http_upgrade \$connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen ${PROXY_LISTEN_PORT} ssl;
    server_name ${PROXY_PUBLIC_HOST} _;

    ssl_certificate     ${CERT_DIR}/proxy.crt;
    ssl_certificate_key ${CERT_DIR}/proxy.key;
    ssl_protocols       TLSv1.2 TLSv1.3;

    location / {
        proxy_pass http://${UPSTREAM_HOST}:${UPSTREAM_PORT};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
EOF

exec nginx -g 'daemon off;'