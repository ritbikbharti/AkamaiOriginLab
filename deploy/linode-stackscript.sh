#!/bin/bash
# <UDF name="cert_cn" Label="Domain or IP for the self-signed cert (CN / SAN)" default="" example="lab.example.com - leave blank to auto-detect the Linode's public IP" />
#
# Linode StackScript: boots a fresh Ubuntu Linode running AkamaiOriginLab
# behind nginx with a self-signed TLS cert. Deploy and browse to
# https://<linode-ip>/  (browser will warn about the self-signed cert - accept
# to proceed). HTTP on port 80 redirects to HTTPS.
#
# Tested on Ubuntu 22.04 LTS and 24.04 LTS.

set -euxo pipefail
exec > >(tee /var/log/stackscript.log) 2>&1

REPO_URL="https://github.com/ritbikbharti/AkamaiOriginLab.git"
BRANCH="main"

export DEBIAN_FRONTEND=noninteractive

apt-get update -y
apt-get upgrade -y
apt-get install -y curl git ufw ca-certificates nginx openssl

# Node.js 20 LTS via NodeSource
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -y nodejs

# Service user with no shell
id akamai >/dev/null 2>&1 || useradd --system --home /opt/AkamaiOriginLab --shell /usr/sbin/nologin akamai

# Clone (or refresh) the repo. The repo dir is owned by `akamai` after the
# first successful run, so root running git inside it would otherwise trip
# git's CVE-2022-24765 dubious-ownership protection. Mark it explicitly safe
# (idempotent - git deduplicates entries).
mkdir -p /opt
git config --global --add safe.directory /opt/AkamaiOriginLab
if [ -d /opt/AkamaiOriginLab/.git ]; then
  git -C /opt/AkamaiOriginLab fetch --all
  git -C /opt/AkamaiOriginLab checkout "$BRANCH"
  git -C /opt/AkamaiOriginLab pull --ff-only
else
  git clone --branch "$BRANCH" "$REPO_URL" /opt/AkamaiOriginLab
fi
chown -R akamai:akamai /opt/AkamaiOriginLab

# Determine cert subject: explicit UDF, else auto-detect public IP
PUBLIC_IP="$(curl -fsSL --max-time 5 https://api.ipify.org || hostname -I | awk '{print $1}')"
CERT_CN_VALUE="${CERT_CN:-$PUBLIC_IP}"

# Build SAN list - always include the public IP and localhost; if the user
# gave a hostname, add it as DNS, otherwise treat it as an IP.
SAN_LINE="IP:${PUBLIC_IP},DNS:localhost"
if [ -n "${CERT_CN:-}" ]; then
  if [[ "$CERT_CN" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    SAN_LINE="${SAN_LINE},IP:${CERT_CN}"
  else
    SAN_LINE="${SAN_LINE},DNS:${CERT_CN}"
  fi
fi

# Generate self-signed cert (825 days, the macOS/iOS max)
mkdir -p /etc/ssl/akamaioriginlab
openssl req -x509 -nodes -days 825 -newkey rsa:2048 \
  -keyout /etc/ssl/akamaioriginlab/privkey.pem \
  -out    /etc/ssl/akamaioriginlab/fullchain.pem \
  -subj "/CN=${CERT_CN_VALUE}" \
  -addext "subjectAltName=${SAN_LINE}"
chmod 600 /etc/ssl/akamaioriginlab/privkey.pem

# nginx reverse proxy: 80 -> 443 redirect, 443 -> node on 127.0.0.1:3000
rm -f /etc/nginx/sites-enabled/default
cat >/etc/nginx/sites-available/akamai-origin-lab <<'EOF'
server {
  listen 80 default_server;
  listen [::]:80 default_server;
  return 301 https://$host$request_uri;
}

server {
  # Use the old-style "ssl http2" listen syntax for compatibility with the
  # nginx version shipped on Ubuntu 22.04 (1.18) and 24.04 (1.24). The newer
  # standalone "http2 on;" directive only works on nginx >= 1.25.1.
  listen 443 ssl http2 default_server;
  listen [::]:443 ssl http2 default_server;

  ssl_certificate     /etc/ssl/akamaioriginlab/fullchain.pem;
  ssl_certificate_key /etc/ssl/akamaioriginlab/privkey.pem;
  ssl_protocols       TLSv1.2 TLSv1.3;

  client_max_body_size 10m;

  location / {
    proxy_pass         http://127.0.0.1:3000;
    proxy_http_version 1.1;
    proxy_set_header   Host              $host;
    proxy_set_header   X-Real-IP         $remote_addr;
    proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header   X-Forwarded-Proto $scheme;
    proxy_set_header   Connection        "";
  }
}
EOF
ln -sf /etc/nginx/sites-available/akamai-origin-lab /etc/nginx/sites-enabled/akamai-origin-lab
nginx -t

# Firewall: SSH + 80 + 443; node port 3000 stays internal
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

# systemd unit for the Node app (loopback only)
NODE_BIN="$(readlink -f "$(command -v node)")"
cat >/etc/systemd/system/akamai-origin-lab.service <<EOF
[Unit]
Description=AkamaiOriginLab origin server
After=network.target

[Service]
Type=simple
User=akamai
WorkingDirectory=/opt/AkamaiOriginLab
Environment=PORT=3000
ExecStart=${NODE_BIN} server.js
Restart=on-failure
RestartSec=2
# Make sure systemctl restart actually frees port 3000 before relaunching:
# send SIGTERM to the main process, SIGKILL the rest of the cgroup after 5s.
# Without this, restarts can race and hit EADDRINUSE.
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now akamai-origin-lab.service
systemctl restart nginx

echo "AkamaiOriginLab is live: https://${CERT_CN_VALUE}/  (self-signed cert - accept the browser warning)"
