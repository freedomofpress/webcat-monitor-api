#!/bin/sh
# Fresh Debian 13 box -> installed, configured, services enabled. Idempotent; run as root from a checkout.
# Expects two volumes mounted: /srv/index (NVMe) and /srv/archive (HDD); see README for the fstab lines.
#   setup.sh                      install and configure, empty index (then bootstrap.sh, or snapshot.sh restore)
#   setup.sh --gcp-key FILE       also activate the Google service account used for Rekor v1 (BigQuery)
set -eu
SRC=$(cd "$(dirname "$0")" && pwd)
KEY=""; [ "${1:-}" = "--gcp-key" ] && KEY=$2

apt-get -qq update; apt-get -qq install -y python3 python3-cryptography python3-zstandard zstd sqlite3 curl ca-certificates gnupg rsync >/dev/null
if ! command -v clickhouse >/dev/null; then
  cd /tmp && curl -fsSL https://clickhouse.com/ | sh >/dev/null 2>&1 && install -m 755 clickhouse /usr/local/bin/clickhouse && rm -f clickhouse
  /usr/local/bin/clickhouse install --noninteractive >/dev/null
fi
if ! command -v gcloud >/dev/null; then
  curl -fsS https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg
  echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" > /etc/apt/sources.list.d/google-cloud-sdk.list
  apt-get -qq update; apt-get -qq install -y google-cloud-cli >/dev/null
fi

# one unprivileged user owns both volumes and runs everything: ClickHouse writes archive files itself (file())
id clickhouse >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin clickhouse
mkdir -p /srv/index/clickhouse /srv/archive/clickhouse /opt/webcat-monitor /run/lock
chown -R clickhouse:clickhouse /srv/index /srv/archive

rsync -a --delete --exclude .git --exclude __pycache__ "$SRC/" /opt/webcat-monitor/
chown -R clickhouse:clickhouse /opt/webcat-monitor
install -m 644 "$SRC/clickhouse.xml" /etc/clickhouse-server/config.d/webcat.xml
install -m 644 "$SRC/clickhouse-users.xml" /etc/clickhouse-server/users.d/webcat.xml
install -m 644 "$SRC/clickhouse-server.service" "$SRC/webcat-api.service" "$SRC/webcat-monitor.service" "$SRC/webcat-monitor.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now clickhouse-server >/dev/null 2>&1
for i in $(seq 1 30); do clickhouse-client -q "SELECT 1" >/dev/null 2>&1 && break; sleep 2; done
clickhouse-client --multiquery < /opt/webcat-monitor/schema.sql
systemctl enable --now webcat-api webcat-monitor.timer >/dev/null 2>&1

HOST=$(sed -n 's/^hostname = "\([^"]*\)".*/\1/p' "$SRC/sources.toml")
if [ -n "$HOST" ]; then  # nginx in front of the API, certificate from Let's Encrypt
  apt-get -qq install -y nginx certbot python3-certbot-nginx >/dev/null
  sed "s/HOSTNAME/$HOST/" "$SRC/nginx.conf" > /etc/nginx/sites-available/webcat-monitor
  ln -sf /etc/nginx/sites-available/webcat-monitor /etc/nginx/sites-enabled/webcat-monitor; rm -f /etc/nginx/sites-enabled/default
  nginx -t -q && systemctl reload nginx
  [ -e "/etc/letsencrypt/live/$HOST" ] || certbot --nginx -n --agree-tos --register-unsafely-without-email --redirect -d "$HOST"
fi

if [ -n "$KEY" ]; then
  mkdir -p /srv/index/gcloud; chmod 700 /srv/index/gcloud
  sudo -u clickhouse env CLOUDSDK_CONFIG=/srv/index/gcloud HOME=/srv/index gcloud auth activate-service-account --key-file="$KEY" >/dev/null
  chown -R clickhouse:clickhouse /srv/index/gcloud
fi
echo "setup done: $(clickhouse-client -q 'SELECT version()'), api $(systemctl is-active webcat-api), timer $(systemctl is-active webcat-monitor.timer)"
echo "next: bootstrap.sh (history from the endpoints) or snapshot.sh restore <source>"
