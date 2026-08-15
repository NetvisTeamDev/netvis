#!/usr/bin/env bash
#
# Run ONCE on a fresh Ubuntu/Debian VPS:
#
#   scp deploy/setup-server.sh ubuntu@YOUR.IP:/tmp/
#   ssh ubuntu@YOUR.IP "bash /tmp/setup-server.sh netvis.cc"
#
# Installs Caddy, creates the service user, writes the config and the
# systemd unit, and closes the firewall. It does NOT install the licensing
# binary - deploy.ps1 does that, and can be re-run for every update.
set -euo pipefail

# OVH's Ubuntu/Debian images log you in as a normal user, not root, so
# re-run under sudo rather than failing halfway through with a pile of
# permission errors.
if [ "$(id -u)" -ne 0 ]; then
  exec sudo -E bash "$0" "$@"
fi

DOMAIN="${1:-netvis.cc}"
echo "==> setting up for $DOMAIN"

apt-get update
apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl ufw

# Caddy is not in Debian/Ubuntu's own repositories - it ships from its
# maintainers' Cloudsmith repo, which has to be added first.
if ! command -v caddy >/dev/null; then
  echo "==> installing caddy"
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
    | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
    > /etc/apt/sources.list.d/caddy-stable.list
  chmod o+r /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  chmod o+r /etc/apt/sources.list.d/caddy-stable.list
  apt-get update
  apt-get install -y caddy
fi

# Unprivileged service account. It owns /opt/netvis and nothing else.
id -u netvis >/dev/null 2>&1 || adduser --system --group --home /opt/netvis netvis
mkdir -p /opt/netvis/downloads

# Written only if absent, so re-running this never clobbers a config you've
# since edited.
if [ ! -f /opt/netvis/config.json ]; then
  cat > /opt/netvis/config.json <<'EOF'
{
  "listen": "127.0.0.1:8443",
  "db": "/opt/netvis/licenses.db",
  "tls": false,
  "rate_limit_per_minute": 30,
  "trust_proxy": true
}
EOF
fi
chown -R netvis:netvis /opt/netvis

echo "==> caddy config"
cat > /etc/caddy/Caddyfile <<EOF
# Caddy terminates HTTPS and proxies to the licensing server, which listens
# on localhost only. Certificates are fetched from Let's Encrypt on first
# start and renewed automatically.
$DOMAIN, www.$DOMAIN {
	encode gzip
	reverse_proxy 127.0.0.1:8443
}
EOF

echo "==> systemd unit"
cat > /etc/systemd/system/netvis-licensing.service <<'EOF'
[Unit]
Description=netvis licensing server
After=network.target

[Service]
Type=simple
User=netvis
WorkingDirectory=/opt/netvis
ExecStart=/opt/netvis/licensing serve
Restart=always
RestartSec=3

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/netvis

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable netvis-licensing >/dev/null

echo "==> firewall"
ufw allow OpenSSH >/dev/null
ufw allow 80,443/tcp >/dev/null
ufw --force enable >/dev/null

systemctl restart caddy

echo
echo "Server is ready. Note 8443 is deliberately NOT open - the licensing"
echo "server is reachable only through Caddy."
echo "Now run deploy.ps1 from your PC to upload the binary."
