#!/usr/bin/env bash
# Сервер состояния «Всем миром» (этап Э1) на knigaistorii.ru.
# Запуск от root:  bash api-install.sh
# Скрипт идемпотентен: можно запускать повторно, в том числе после прерванной установки.
set -euo pipefail

DOMAIN="knigaistorii.ru"
REPO="dburlaku/vsemmirom"
BRANCH="main"
APP="/opt/vm-api"
ENVF="/etc/vm-api.env"
say(){ printf "\n\033[1m== %s\033[0m\n" "$*"; }

say "0/7 Если прошлая установка обрывалась — доводим её до конца"
dpkg --configure -a >/dev/null 2>&1 || true
apt-get -f install -y -qq >/dev/null 2>&1 || true

say "1/7 Пакеты"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq postgresql nodejs npm curl
NODE_MAJOR=$(node -p "process.versions.node.split('.')[0]")
if [ "$NODE_MAJOR" -lt 18 ]; then
  echo "  Node $NODE_MAJOR устарел, ставлю 22 из NodeSource"
  curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
  apt-get install -y -qq nodejs
fi
echo "  node $(node -v), $(psql --version)"
systemctl enable --now postgresql >/dev/null 2>&1 || true

say "2/7 База данных"
if ! su postgres -c "psql -tAc \"select 1 from pg_roles where rolname='vm'\"" | grep -q 1; then
  PGPASS=$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)
  su postgres -c "psql -q -c \"create role vm login password '$PGPASS'\""
  su postgres -c "createdb -O vm vm"
  umask 077
  printf 'DATABASE_URL=postgres://vm:%s@127.0.0.1:5432/vm\nPORT=8081\n' "$PGPASS" > "$ENVF"
  chmod 600 "$ENVF"
  echo "  база vm создана, доступ записан в $ENVF"
else
  echo "  роль vm уже есть, $ENVF не трогаю"
fi

say "3/7 Код сервиса"
mkdir -p "$APP"
tmp=$(mktemp -d)
curl -fsSL "https://codeload.github.com/$REPO/tar.gz/refs/heads/$BRANCH" | tar xz -C "$tmp" --strip-components=1
# файлы сервиса лежат либо в api/, либо в корне репозитория
SRC=""
for d in "$tmp/api" "$tmp"; do [ -f "$d/server.js" ] && SRC="$d" && break; done
if [ -z "$SRC" ]; then echo "  ОШИБКА: в репозитории нет server.js"; rm -rf "$tmp"; exit 1; fi
cp -f "$SRC/server.js" "$SRC/schema.sql" "$SRC/package.json" "$APP/"
rm -rf "$tmp"
cd "$APP" && npm install --omit=dev --no-audit --no-fund --silent
id -u vmapi >/dev/null 2>&1 || useradd --system --home "$APP" --shell /usr/sbin/nologin vmapi
chown -R vmapi:vmapi "$APP"

say "4/7 Сервис"
cat > /etc/systemd/system/vm-api.service <<EOF
[Unit]
Description=Всем миром — сервер состояния заказа
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=vmapi
WorkingDirectory=$APP
EnvironmentFile=$ENVF
ExecStart=/usr/bin/node $APP/server.js
Restart=always
RestartSec=3
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$APP

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable vm-api >/dev/null
systemctl restart vm-api
sleep 3
systemctl is-active vm-api || { journalctl -u vm-api -n 30 --no-pager; exit 1; }

say "5/7 nginx"
mkdir -p /etc/nginx/snippets
cat > /etc/nginx/snippets/vm-api.conf <<'NG'
location /api/ {
    proxy_pass http://127.0.0.1:8081;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_read_timeout 60s;
    client_max_body_size 16m;
}
NG
SITE=/etc/nginx/sites-available/$DOMAIN
if ! grep -q "snippets/vm-api.conf" "$SITE"; then
  cp "$SITE" "$SITE.bak.$(date +%s)"
  sed -i "0,/root \/var\/www\/$DOMAIN;/s//root \/var\/www\/$DOMAIN;\n    include snippets\/vm-api.conf;/" "$SITE"
fi
nginx -t && systemctl reload nginx

say "6/7 Свежие страницы сайта"
bash /root/update.sh || true
# серверный код не должен раздаваться по HTTP, если случайно попал в веб-корень
rm -f /var/www/$DOMAIN/server.js /var/www/$DOMAIN/schema.sql /var/www/$DOMAIN/package.json

say "7/7 Проверка"
printf '  %-26s %s\n' 'сервис'     "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8081/api/health)"
R="--resolve $DOMAIN:443:127.0.0.1"
printf '  %-26s %s\n' 'через nginx' "$(curl -sk $R -o /dev/null -w '%{http_code}' https://$DOMAIN/api/health)"
printf '  %-26s %s\n' 'серверный код скрыт' "$(curl -sk $R -o /dev/null -w '%{http_code}' https://$DOMAIN/server.js)"
for p in / /quiz.html /app.html; do
  printf '  %-26s %s\n' "$p" "$(curl -sk $R -o /dev/null -w '%{http_code}' https://$DOMAIN$p)"
done
echo
echo "Ожидается: сервис 200, nginx 200, серверный код 404, страницы 200."
echo "Журнал сервиса: journalctl -u vm-api -n 50 --no-pager"
