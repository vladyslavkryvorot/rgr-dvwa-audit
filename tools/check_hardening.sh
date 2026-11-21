#!/usr/bin/env bash
# Перевірка шарів глибокого захисту стенда «після» незалежно від коду застосунку.
# Імітує обхід SafeUpload/SafePath: файли кладуться в uploads напряму (docker exec від www-data).
set -uo pipefail
URL="${DVWA_URL:-http://127.0.0.1:8080}"
C=rgr-dvwa
check() { # опис, очікування, фактичне
  local verdict="FAIL"; [[ "$3" == $2 ]] && verdict="OK"
  printf '%-4s %-72s очікується: %-14s фактично: %s\n' "$verdict" "$1" "$2" "$3"
}
echo "# Шари глибокого захисту ($(date -u +%FT%TZ)), стенд $URL"
docker exec -u www-data $C sh -c 'printf "<?php echo 7*191;" > /var/www/html/hackable/uploads/layer.php'
check "Apache: .php у uploads не віддається і не виконується (V1/V2)" "403" \
  "$(curl -s -o /dev/null -w '%{http_code}' "$URL/hackable/uploads/layer.php")"
docker exec -u www-data $C sh -c 'printf "<FilesMatch \"\\\\.lay\$\">\nSetHandler application/x-httpd-php\n</FilesMatch>\n" > /var/www/html/hackable/uploads/.htaccess; printf "<?php echo 7*191;" > /var/www/html/hackable/uploads/layer.lay'
BODY="$(curl -s "$URL/hackable/uploads/layer.lay")"
check "Apache: .htaccess у uploads ігнорується, код не виконується (V7)" "*7\*191*" "$BODY"
check "Apache: сам .htaccess не віддається" "403" \
  "$(curl -s -o /dev/null -w '%{http_code}' "$URL/hackable/uploads/.htaccess")"
check "Apache: nosniff для uploads" "*nosniff*" \
  "$(curl -sI "$URL/hackable/uploads/layer.lay" | tr -d '\r' | grep -i x-content-type-options)"
docker exec $C sh -c 'rm -f /var/www/html/hackable/uploads/layer.php /var/www/html/hackable/uploads/layer.lay /var/www/html/hackable/uploads/.htaccess'
check "PHP: open_basedir блокує /etc/passwd (V4–V6)" "*open_basedir*" \
  "$(docker exec -u www-data $C php -d display_errors=stderr -r 'readfile("/etc/passwd");' 2>&1 | head -1)"
check "PHP: allow_url_include вимкнено (T6)" "" "$(docker exec $C php -r 'echo ini_get("allow_url_include");')"
check "PHP: display_errors вимкнено (T9)" "" "$(docker exec $C php -r 'echo ini_get("display_errors");')"
check "PHP: заголовок X-Powered-By відсутній" "" \
  "$(curl -sI "$URL/login.php" | tr -d '\r' | grep -i x-powered-by)"
check "ФС: www-data не може змінити код застосунку (T16)" "*Permission denied*" \
  "$(docker exec -u www-data $C sh -c 'echo x >> /var/www/html/index.php' 2>&1)"
check "ФС: www-data не може змінити config.inc.php" "*Permission denied*" \
  "$(docker exec -u www-data $C sh -c 'echo x >> /var/www/html/config/config.inc.php' 2>&1)"
check "Мережа: контейнер dvwa без маршруту назовні" "*unreachable*" \
  "$(docker exec $C ping -c1 -W2 1.1.1.1 2>&1 | tail -1)"
