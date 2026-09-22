#!/bin/bash
# =============================================================================
#  Протокол: Hysteria2 (QUIC/UDP) — обход DPI в РФ
#  Обфускация: Salamander (трафик выглядит как случайный UDP)
#  Сертификат: самоподписанный, отпечаток закреплён в ссылке (pinSHA256)
#
#  Зачем: UDP лучше держит пинг в играх, голос и видео. Работает там,
#  где UDP не режут (обычно дома); на мобильных сетях его часто режут.
#
#  Запуск:
#    bash install_hysteria2.sh
# =============================================================================

set -eu

# ── Цвета ─────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'
YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

ok()   { echo -e "${GREEN}[✓]${NC} $1"; }
info() { echo -e "${YELLOW}[→]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }
hdr()  {
  echo -e "\n${BLUE}════════════════════════════════════════${NC}"
  echo -e "${BLUE}  $1${NC}"
  echo -e "${BLUE}════════════════════════════════════════${NC}"
}

# ── Пути ──────────────────────────────────────────────────────────────────────
HYS_DIR="/etc/hysteria"
HYS_CFG="$HYS_DIR/config.yaml"
PARAMS="$HYS_DIR/.params"
USERS="$HYS_DIR/users.json"
CERT="$HYS_DIR/server.crt"
KEY="$HYS_DIR/server.key"
LINK_LIB="/usr/local/lib/hysteria_link.sh"
BACKUP_DIR="$HYS_DIR/backups"
# SNI и цель masquerade. С Salamander SNI в трафике не виден, а masquerade
# отвечает только тем, кто знает пароль обфускации, — выбор домена здесь
# некритичен (баг REALITY с сертификатом microsoft к Hysteria не относится)
MASQ_DOMAIN="www.microsoft.com"
MASQ_URL="https://www.microsoft.com/"

# ── 1. Предстартовые проверки ─────────────────────────────────────────────────
hdr "ПРЕДСТАРТОВЫЕ ПРОВЕРКИ"

[ "$EUID" -ne 0 ] && err "Запустите от root: sudo bash $0"
ok "Root-права подтверждены"

ARCH=$(uname -m)
[[ "$ARCH" != "x86_64" && "$ARCH" != "aarch64" ]] && \
  err "Неподдерживаемая архитектура: $ARCH (нужна x86_64 или aarch64)"
ok "Архитектура: $ARCH"

info "Определяем IP сервера..."
SERVER_IP=$(curl -4 -s --max-time 10 https://ifconfig.me 2>/dev/null || \
            curl -4 -s --max-time 10 https://icanhazip.com 2>/dev/null || true)
if [ -z "$SERVER_IP" ]; then
  SERVER_IP=$(hostname -I | awk '{print $1}')
  [ -z "$SERVER_IP" ] && err "Не удалось определить IP сервера"
  info "Внешний IP не определён, используется локальный: $SERVER_IP"
  info "Ссылки будут работать только внутри локальной сети"
else
  ok "IP сервера: $SERVER_IP"
fi

# ── 2. Выбор порта ────────────────────────────────────────────────────────────
hdr "ВЫБОР ПОРТА (UDP)"

echo ""
echo -e "  ${CYAN}443${NC}  — стандартный HTTPS/QUIC (лучшая маскировка)"
echo -e "  ${CYAN}8443${NC} — альтернативный"
echo -e "  ${CYAN}2053${NC} — Cloudflare-стиль"
echo ""
echo -e "  ${YELLOW}Важно:${NC} Hysteria2 работает по UDP (QUIC), а не TCP."
echo ""
read -p "Введите порт (Enter = 443): " HYS_PORT < /dev/tty
HYS_PORT=${HYS_PORT:-443}

if ! [[ "$HYS_PORT" =~ ^[0-9]+$ ]] || (( HYS_PORT < 1 || HYS_PORT > 65535 )); then
  HYS_PORT=443
fi
ok "Порт: $HYS_PORT/udp"

# ── 3. Установка зависимостей ─────────────────────────────────────────────────
hdr "УСТАНОВКА ЗАВИСИМОСТЕЙ"

apt-get update -qq
apt-get install -y -qq curl openssl jq qrencode nginx ufw fail2ban
ok "Зависимости установлены"

# ── 4. UFW ────────────────────────────────────────────────────────────────────
hdr "НАСТРОЙКА FIREWALL (UFW)"

ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp    comment "SSH"
ufw allow 80/tcp    comment "HTTP"
ufw allow "$HYS_PORT/udp" comment "Hysteria2"
ufw --force enable

ok "UFW настроен (открыты: 22/tcp, 80/tcp, $HYS_PORT/udp)"

# ── 5. Fail2Ban ───────────────────────────────────────────────────────────────
hdr "НАСТРОЙКА FAIL2BAN"

# На Debian 12 без rsyslog файла auth.log нет — тогда читаем журнал systemd
if [ -f /var/log/auth.log ]; then
  F2B_SOURCE="logpath  = /var/log/auth.log"
else
  F2B_SOURCE="backend  = systemd"
fi

cat > /etc/fail2ban/jail.d/hysteria.conf << EOF
[sshd]
enabled  = true
port     = 22
filter   = sshd
$F2B_SOURCE
maxretry = 3
bantime  = 3600
EOF

systemctl enable fail2ban --quiet || true
if systemctl restart fail2ban; then
  ok "Fail2Ban запущен (SSH: макс 3 попытки, бан 1 час)"
else
  warn "Fail2Ban не запустился — на работу VPN это не влияет"
fi

# ── 6. BBR + UDP-буферы ───────────────────────────────────────────────────────
hdr "СЕТЕВОЙ ТЮНИНГ (BBR + UDP)"

# BBR (полезен для nginx и общего TCP)
grep -q 'tcp_congestion_control=bbr' /etc/sysctl.conf || {
  echo "net.core.default_qdisc=fq"           >> /etc/sysctl.conf
  echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
}

# Увеличенные UDP-буферы — без них Hysteria2 ругается и режет скорость QUIC
grep -q 'net.core.rmem_max=16777216' /etc/sysctl.conf || {
  echo "net.core.rmem_max=16777216" >> /etc/sysctl.conf
  echo "net.core.wmem_max=16777216" >> /etc/sysctl.conf
}

if sysctl -p -q >/dev/null 2>&1; then
  ok "BBR включён, UDP-буферы увеличены (16 МБ)"
else
  warn "Часть сетевых настроек не применилась (ограничение хостинга) — не критично"
fi

# ── 7. Nginx (порт 80 — легенда прикрытия и проверка доступности) ─────────────
hdr "NGINX (легенда прикрытия)"

if ss -tlnp | grep ':80 ' | grep -qv nginx; then
  info "Порт 80 занят другим процессом. Nginx может не запуститься."
  read -p "Перезаписать конфиг nginx и перезапустить? (y/n, Enter = y): " NGINX_CONFIRM < /dev/tty
  NGINX_CONFIRM=${NGINX_CONFIRM:-y}
  [[ "$NGINX_CONFIRM" != "y" && "$NGINX_CONFIRM" != "Y" ]] && {
    info "Пропускаем настройку Nginx"
    SKIP_NGINX=1
  }
fi

if [[ "${SKIP_NGINX:-0}" != "1" ]]; then
  mkdir -p /var/www/html

  cat > /var/www/html/index.html << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Welcome</title>
  <style>
    body { font-family: -apple-system, sans-serif; max-width: 600px;
           margin: 120px auto; text-align: center; color: #333; }
    h1   { color: #0078d4; font-weight: 300; }
    p    { color: #666; }
  </style>
</head>
<body>
  <h1>Welcome</h1>
  <p>The server is up and running.</p>
</body>
</html>
EOF

  cat > /etc/nginx/sites-available/default << 'NGINXCFG'
server {
    listen 80 default_server;
    server_name _;
    root /var/www/html;
    index index.html;

    location / {
        try_files $uri $uri/ =404;
    }
}
NGINXCFG

  nginx -t -q
  systemctl enable nginx --quiet
  systemctl restart nginx
  ok "Nginx запущен на порту 80"
fi

# ── 8. Установка Hysteria2 ────────────────────────────────────────────────────
hdr "УСТАНОВКА HYSTERIA2"

# Официальный установщик ставит бинарник + systemd-сервис hysteria-server.
# || true — сервис стартует с дефолтным конфигом и может упасть, свой конфиг
# мы кладём ниже (та же логика, что в xray-скрипте с install-release.sh).
bash <(curl -fsSL https://get.hy2.sh/) || true

command -v hysteria &>/dev/null || err "Hysteria2 не установился, проверьте подключение к интернету"
HYS_VER=$(hysteria version 2>&1 | awk '/^Version:/ {print $2}' | head -1 || true)
ok "Hysteria2 установлен ${HYS_VER:+($HYS_VER)}"

# ── 9. Бэкап старой конфигурации ──────────────────────────────────────────────
# До генерации сертификата и паролей — иначе в бэкап попадут уже новые
hdr "БЭКАП"

mkdir -p "$BACKUP_DIR"

if [ -f "$HYS_CFG" ]; then
  TS=$(date +%Y%m%d_%H%M%S)
  cp "$HYS_CFG" "$BACKUP_DIR/config.yaml.$TS"
  [ -f "$USERS" ] && cp "$USERS" "$BACKUP_DIR/users.json.$TS"
  ok "Бэкап сохранён: $BACKUP_DIR/config.yaml.$TS"
else
  ok "Новая установка, бэкап не требуется"
fi

# ── 10. Самоподписанный сертификат ────────────────────────────────────────────
hdr "ГЕНЕРАЦИЯ СЕРТИФИКАТА"

mkdir -p "$HYS_DIR"

# ECDSA prime256v1 — быстрый и лёгкий, CN = маскировочный домен.
# Сертификат самоподписан, поэтому в ссылку кладём его отпечаток (pinSHA256):
# клиенты на ядре Xray (v2rayN, v2rayNG) проверяют именно его — allowInsecure
# в Xray с 26.2.6 удалён. Клиенты на sing-box (NekoBox) идут по insecure=1.
# SAN не добавляем: иначе включится sniGuard и начнёт рвать клиентов с другим
# SNI. Xray при совпадении отпечатка имя в сертификате не проверяет.
openssl ecparam -genkey -name prime256v1 -out "$KEY" 2>/dev/null
openssl req -new -x509 -days 3650 -key "$KEY" -out "$CERT" \
  -subj "/CN=$MASQ_DOMAIN" 2>/dev/null

chmod 644 "$CERT"
chmod 600 "$KEY"
# Сервис hysteria-server работает под пользователем hysteria — даём ему доступ
if id hysteria &>/dev/null; then
  chown hysteria:hysteria "$CERT" "$KEY"
fi
ok "Сертификат создан (CN=$MASQ_DOMAIN, 10 лет)"

# ── 11. Генерация паролей и пользователя ─────────────────────────────────────
hdr "ГЕНЕРАЦИЯ КЛЮЧЕЙ"

# Пароль обфускации — общий для всего сервера (пресекретный ключ Salamander)
OBFS_PASSWORD=$(openssl rand -hex 16)
# Пароль основного пользователя
MAIN_PASSWORD=$(openssl rand -hex 16)

# Источник правды по пользователям — JSON (управляется через jq, как в xray)
echo "{\"main\":\"$MAIN_PASSWORD\"}" | jq . > "$USERS"
chmod 600 "$USERS"

# Параметры сервера (подключаются в утилитах через source)
cat > "$PARAMS" << EOF
HYS_PORT=$HYS_PORT
SNI=$MASQ_DOMAIN
OBFS_PASSWORD=$OBFS_PASSWORD
MASQ_URL=$MASQ_URL
EOF
chmod 600 "$PARAMS"

ok "Ключи сгенерированы (обфускация + пользователь main)"

# ── 12. Библиотека генерации ссылок и конфига ─────────────────────────────────
hdr "БИБЛИОТЕКА ССЫЛОК"

mkdir -p /usr/local/lib

cat > "$LINK_LIB" << 'LINKLIB'
#!/bin/bash
# =============================================================================
#  Общая библиотека для утилит Hysteria2
#  Использование: source /usr/local/lib/hysteria_link.sh
# =============================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'
YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
export RED GREEN YELLOW CYAN NC

HYS_DIR="/etc/hysteria"
HYS_CFG="$HYS_DIR/config.yaml"
PARAMS="$HYS_DIR/.params"
USERS="$HYS_DIR/users.json"

# Пересобрать config.yaml из .params + users.json и перезапустить сервис
rebuild_config() {
  # shellcheck disable=SC1090
  source "$PARAMS"
  {
    echo "listen: :$HYS_PORT"
    echo ""
    echo "tls:"
    echo "  cert: $HYS_DIR/server.crt"
    echo "  key: $HYS_DIR/server.key"
    echo ""
    echo "obfs:"
    echo "  type: salamander"
    echo "  salamander:"
    echo "    password: $OBFS_PASSWORD"
    echo ""
    echo "auth:"
    echo "  type: userpass"
    echo "  userpass:"
    jq -r 'to_entries[] | "    \(.key): \(.value)"' "$USERS"
    echo ""
    echo "masquerade:"
    echo "  type: proxy"
    echo "  proxy:"
    echo "    url: $MASQ_URL"
    echo "    rewriteHost: true"
  } > "$HYS_CFG"
  chmod 600 "$HYS_CFG"
  if id hysteria &>/dev/null; then
    chown hysteria:hysteria "$HYS_CFG" 2>/dev/null || true
  fi
}
export -f rebuild_config

# Генерация Hysteria2-ссылки по имени пользователя
gen_link() {
  local user="$1"
  # shellcheck disable=SC1090
  source "$PARAMS"

  local pass
  pass=$(jq -r --arg u "$user" '.[$u] // empty' "$USERS")
  if [ -z "$pass" ]; then
    echo -e "${RED}Пользователь '$user' не найден${NC}" >&2
    return 1
  fi

  local ip
  ip=$(timeout 5 curl -4 -s https://ifconfig.me 2>/dev/null || \
       timeout 5 curl -4 -s https://icanhazip.com 2>/dev/null || true)
  if [ -z "$ip" ]; then
    ip=$(hostname -I | awk '{print $1}')
    [ -z "$ip" ] && { echo -e "${RED}Не удалось определить IP сервера${NC}" >&2; return 1; }
  fi

  # Отпечаток сертификата: SHA-256 от DER, hex без двоеточий
  local pin
  pin=$(openssl x509 -in "$HYS_DIR/server.crt" -noout -fingerprint -sha256 2>/dev/null |         cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f')
  if [ ${#pin} -ne 64 ]; then
    echo -e "${RED}Не удалось прочитать отпечаток сертификата${NC}" >&2
    return 1
  fi

  echo "hysteria2://${user}:${pass}@${ip}:${HYS_PORT}/?insecure=1&pinSHA256=${pin}&obfs=salamander&obfs-password=${OBFS_PASSWORD}&sni=${SNI}#${user}"
}
export -f gen_link
LINKLIB

chmod +x "$LINK_LIB"
ok "Библиотека: $LINK_LIB"

# ── 13. Первичная сборка конфига ──────────────────────────────────────────────
hdr "СОЗДАНИЕ КОНФИГУРАЦИИ HYSTERIA2"

# shellcheck disable=SC1090
source "$LINK_LIB"
rebuild_config
ok "Конфигурация создана: $HYS_CFG"

# ── 14. Утилиты управления ────────────────────────────────────────────────────
hdr "СОЗДАНИЕ УТИЛИТ"

# ── hymain ──────────────────────────────────────────────────────────────────
cat > /usr/local/bin/hymain << 'SCRIPT'
#!/bin/bash
source /usr/local/lib/hysteria_link.sh
link=$(gen_link "main") || exit 1
echo ""
echo -e "${CYAN}════════════════════════════════════════${NC}"
echo -e "${CYAN}  Основной пользователь (main)${NC}"
echo -e "${CYAN}════════════════════════════════════════${NC}"
echo ""
echo -e "${GREEN}Ссылка:${NC}"
echo "$link"
echo ""
echo -e "${GREEN}QR-код:${NC}"
echo "$link" | qrencode -t ansiutf8
echo ""
SCRIPT
chmod +x /usr/local/bin/hymain

# ── hynewuser ────────────────────────────────────────────────────────────────
cat > /usr/local/bin/hynewuser << 'SCRIPT'
#!/bin/bash
source /usr/local/lib/hysteria_link.sh

echo ""
read -p "Введите имя пользователя: " user

if [[ ! "$user" =~ ^[a-zA-Z0-9_-]+$ ]]; then
  echo -e "${RED}Ошибка: допустимы только буквы, цифры, _ и -${NC}"
  exit 1
fi

if jq -e --arg u "$user" 'has($u)' "$USERS" | grep -q true; then
  echo -e "${RED}Пользователь '$user' уже существует${NC}"
  exit 1
fi

pass=$(openssl rand -hex 16)
tmpfile=$(mktemp)
jq --arg u "$user" --arg p "$pass" '. + {($u): $p}' "$USERS" > "$tmpfile" \
  && mv "$tmpfile" "$USERS" && chmod 600 "$USERS"

rebuild_config
systemctl restart hysteria-server

link=$(gen_link "$user") || exit 1
echo ""
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo -e "${GREEN}  Пользователь '$user' создан!${NC}"
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo ""
echo -e "${GREEN}Ссылка:${NC}"
echo "$link"
echo ""
echo -e "${GREEN}QR-код:${NC}"
echo "$link" | qrencode -t ansiutf8
echo ""
SCRIPT
chmod +x /usr/local/bin/hynewuser

# ── hyrmuser ─────────────────────────────────────────────────────────────────
cat > /usr/local/bin/hyrmuser << 'SCRIPT'
#!/bin/bash
source /usr/local/lib/hysteria_link.sh

mapfile -t users < <(jq -r 'keys[]' "$USERS" 2>/dev/null)

if [[ ${#users[@]} -eq 0 ]]; then
  echo -e "${RED}Нет клиентов для удаления${NC}"; exit 1
fi

echo ""
echo -e "${CYAN}Список клиентов:${NC}"
for i in "${!users[@]}"; do
  marker=""
  [[ "${users[$i]}" == "main" ]] && marker=" ${YELLOW}(основной)${NC}"
  echo -e "  $((i+1)). ${users[$i]}$marker"
done
echo ""

read -p "Номер для удаления: " choice

if ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#users[@]} )); then
  echo -e "${RED}Неверный номер${NC}"; exit 1
fi

selected="${users[$((choice - 1))]}"

if [[ "$selected" == "main" ]]; then
  echo -e "${RED}Нельзя удалить основного пользователя${NC}"; exit 1
fi

read -p "Удалить '$selected'? (y/n): " confirm
[[ "$confirm" != "y" && "$confirm" != "Y" ]] && { echo "Отменено"; exit 0; }

tmpfile=$(mktemp)
jq --arg u "$selected" 'del(.[$u])' "$USERS" > "$tmpfile" \
  && mv "$tmpfile" "$USERS" && chmod 600 "$USERS"

rebuild_config
systemctl restart hysteria-server
echo -e "${GREEN}Клиент '$selected' удалён${NC}"
SCRIPT
chmod +x /usr/local/bin/hyrmuser

# ── hysharelink ──────────────────────────────────────────────────────────────
cat > /usr/local/bin/hysharelink << 'SCRIPT'
#!/bin/bash
source /usr/local/lib/hysteria_link.sh

mapfile -t users < <(jq -r 'keys[]' "$USERS" 2>/dev/null)

if [[ ${#users[@]} -eq 0 ]]; then
  echo -e "${RED}Нет клиентов${NC}"; exit 1
fi

echo ""
echo -e "${CYAN}Список клиентов:${NC}"
for i in "${!users[@]}"; do
  marker=""
  [[ "${users[$i]}" == "main" ]] && marker=" ${YELLOW}(основной)${NC}"
  echo -e "  $((i+1)). ${users[$i]}$marker"
done
echo ""

read -p "Выберите номер: " choice

if ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#users[@]} )); then
  echo -e "${RED}Неверный номер${NC}"; exit 1
fi

selected="${users[$((choice - 1))]}"
link=$(gen_link "$selected") || exit 1

echo ""
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo -e "${GREEN}  Ссылка для: $selected${NC}"
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo ""
echo "$link"
echo ""
echo -e "${CYAN}QR-код:${NC}"
echo "$link" | qrencode -t ansiutf8
echo ""
SCRIPT
chmod +x /usr/local/bin/hysharelink

# ── hyuserlist ───────────────────────────────────────────────────────────────
cat > /usr/local/bin/hyuserlist << 'SCRIPT'
#!/bin/bash
source /usr/local/lib/hysteria_link.sh

mapfile -t users < <(jq -r 'keys[]' "$USERS" 2>/dev/null)

if [[ ${#users[@]} -eq 0 ]]; then
  echo -e "${RED}Список пуст${NC}"; exit 1
fi

echo ""
echo -e "${CYAN}════════════════════════════════════════${NC}"
echo -e "${CYAN}  Клиенты (всего: ${#users[@]})${NC}"
echo -e "${CYAN}════════════════════════════════════════${NC}"
for i in "${!users[@]}"; do
  marker=""
  [[ "${users[$i]}" == "main" ]] && marker=" ${YELLOW}(основной)${NC}"
  echo -e "  $((i+1)). ${users[$i]}$marker"
done
echo ""
SCRIPT
chmod +x /usr/local/bin/hyuserlist

# ── hybackup ─────────────────────────────────────────────────────────────────
cat > /usr/local/bin/hybackup << 'SCRIPT'
#!/bin/bash
source /usr/local/lib/hysteria_link.sh
BACKUP_DIR="/etc/hysteria/backups"
mkdir -p "$BACKUP_DIR"
TS=$(date +%Y%m%d_%H%M%S)
cp /etc/hysteria/config.yaml "$BACKUP_DIR/config.yaml.$TS"
cp /etc/hysteria/users.json  "$BACKUP_DIR/users.json.$TS"
echo ""
echo -e "${GREEN}Бэкап создан:${NC}"
echo "  $BACKUP_DIR/config.yaml.$TS"
echo ""
SCRIPT
chmod +x /usr/local/bin/hybackup

# ── hystatus ─────────────────────────────────────────────────────────────────
cat > /usr/local/bin/hystatus << 'SCRIPT'
#!/bin/bash
source /usr/local/lib/hysteria_link.sh
source "$PARAMS"
echo ""
echo -e "${CYAN}════ Статус Hysteria2 ════${NC}"
systemctl status hysteria-server --no-pager -l
echo ""
echo -e "${CYAN}Версия:${NC} $(hysteria version 2>&1 | awk '/^Version:/ {print $2}' | head -1)"
echo -e "${CYAN}Порт:${NC} $HYS_PORT/udp"
echo -e "${CYAN}Обфускация:${NC} salamander"
echo -e "${CYAN}Отпечаток сертификата (pinSHA256):${NC}"
openssl x509 -in "$HYS_DIR/server.crt" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f'
echo ""
SCRIPT
chmod +x /usr/local/bin/hystatus

# ── h (главное меню) ─────────────────────────────────────────────────────────
cat > /usr/local/bin/h << 'SCRIPT'
#!/bin/bash
source /usr/local/lib/hysteria_link.sh

show_menu() {
  echo ""
  echo -e "${CYAN}╔════════════════════════════════════════╗${NC}"
  echo -e "${CYAN}║        Hysteria2 — Меню                ║${NC}"
  echo -e "${CYAN}╠════════════════════════════════════════╣${NC}"
  echo -e "${CYAN}║${NC}  1. Ссылка основного пользователя      ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}  2. Создать пользователя               ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}  3. Удалить пользователя               ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}  4. Ссылка для пользователя            ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}  5. Список пользователей               ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}  6. Статус Hysteria2                   ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}  7. Перезапустить Hysteria2            ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}  8. Создать бэкап                      ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}  9. Помощь                             ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}  0. Выход                              ${CYAN}║${NC}"
  echo -e "${CYAN}╚════════════════════════════════════════╝${NC}"
  echo ""
}

show_help() {
  echo ""
  echo -e "${CYAN}╔════════════════════════════════════════════════════════╗${NC}"
  echo -e "${CYAN}║              Hysteria2 — Справка                     ║${NC}"
  echo -e "${CYAN}╠════════════════════════════════════════════════════════╣${NC}"
  echo -e "${CYAN}║${NC}                                                        ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}  ${GREEN}КОМАНДЫ (можно вызывать напрямую):${NC}                    ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}    h           — это меню                               ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}    hymain      — ссылка и QR основного пользователя     ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}    hynewuser   — создать нового пользователя            ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}    hyrmuser    — удалить пользователя                   ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}    hysharelink — ссылка для выбранного пользователя     ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}    hyuserlist  — список всех пользователей              ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}    hybackup    — создать бэкап конфигурации             ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}    hystatus    — статус и версия Hysteria2              ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}                                                        ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}  ${GREEN}ФАЙЛЫ:${NC}                                                ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}    /etc/hysteria/config.yaml  — конфиг Hysteria2        ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}    /etc/hysteria/users.json   — пользователи            ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}    /etc/hysteria/.params      — параметры сервера       ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}    /etc/hysteria/backups/     — бэкапы                  ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}                                                        ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}  ${GREEN}СЕРВИС:${NC}                                               ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}    systemctl restart hysteria-server  — перезапуск      ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}    systemctl stop hysteria-server     — остановить      ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}    journalctl -u hysteria-server -f   — логи            ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}                                                        ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}  ${GREEN}КЛИЕНТЫ (поддержка Hysteria2):${NC}                        ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}    Android:  v2rayNG, NekoBox, Hiddify                  ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}    iOS:      Streisand, Shadowrocket                    ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}    Windows:  v2rayN (ядро Xray или sing-box), Hiddify   ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}    macOS:    Hiddify, V2Box                             ${CYAN}║${NC}"
  echo -e "${CYAN}║${NC}                                                        ${CYAN}║${NC}"
  echo -e "${CYAN}╚════════════════════════════════════════════════════════╝${NC}"
  echo ""
}

while true; do
  show_menu
  read -p "Выберите действие: " action
  case "$action" in
    1) hymain ;;
    2) hynewuser ;;
    3) hyrmuser ;;
    4) hysharelink ;;
    5) hyuserlist ;;
    6) hystatus ;;
    7) systemctl restart hysteria-server && echo -e "${GREEN}Hysteria2 перезапущен${NC}" ;;
    8) hybackup ;;
    9) show_help ;;
    0) echo ""; exit 0 ;;
    *) echo -e "${RED}Неверный выбор${NC}" ;;
  esac
done
SCRIPT
chmod +x /usr/local/bin/h

ok "Все утилиты созданы (главное меню: h)"

# ── 15. Запуск Hysteria2 ──────────────────────────────────────────────────────
hdr "ЗАПУСК HYSTERIA2"

systemctl enable hysteria-server --quiet
systemctl restart hysteria-server
sleep 2

if systemctl is-active --quiet hysteria-server; then
  ok "Hysteria2 работает"
else
  err "Hysteria2 не запустился!\nЛоги: journalctl -u hysteria-server -n 50\nКонфиг: cat $HYS_CFG"
fi

# ── 16. Итог ──────────────────────────────────────────────────────────────────
hdr "УСТАНОВКА ЗАВЕРШЕНА"

echo ""
echo -e "  ${GREEN}IP сервера:${NC}   $SERVER_IP"
echo -e "  ${GREEN}Порт:${NC}         $HYS_PORT/udp"
echo -e "  ${GREEN}Протокол:${NC}     Hysteria2 (QUIC)"
echo -e "  ${GREEN}Обфускация:${NC}   Salamander"
echo -e "  ${GREEN}Маскировка:${NC}   $MASQ_DOMAIN"
echo ""

hymain

echo -e "${YELLOW}Следующие шаги:${NC}"
echo "  1. Скопируйте ссылку в v2rayN / v2rayNG / NekoBox / Hiddify"
echo "  2. Меню управления:      h"
echo "  3. Создать пользователя: hynewuser"
echo "  4. Список пользователей: hyuserlist"
echo ""
echo -e "  ${YELLOW}Проверка доступности:${NC} откройте http://$SERVER_IP (должно быть 'Welcome')"
echo -e "  ${YELLOW}Если UDP на вашей сети режется${NC} — попробуйте порт 443 или смените сеть."
echo ""
echo -e "${GREEN}✓ Готово!${NC}"
echo ""
