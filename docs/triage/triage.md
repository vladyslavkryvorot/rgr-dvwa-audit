# Тріаж знахідок автоматизованого аналізу (стан «до», `scans/before/`)

Інструменти та версії: Semgrep 1.140.0 (`p/php`, `p/owasp-top-ten` + 7 власних правил `tools/semgrep-rules/rgr-variant8.yml`),
Trivy 0.67.2 (fs + образ, SBOM CycloneDX 1.6), gitleaks 8.28.0 (історія git і робоче дерево).
Сирий перелік знахідок Semgrep: [`semgrep_before_raw.csv`](semgrep_before_raw.csv). Зведення: `scans/before/summary.json`.

Позначення: **TP** — істинна знахідка (true positive); **FP** — хибнопозитивна (false positive);
**TP-н** — істинна в коді, але недосяжна в конфігурації стенда. Колонка «V» посилається на вразливість, підтверджену вручну на етапі 3.

## 1. SAST (Semgrep) — знахідки в межах профілю

| # | Правило | Файл:рядок | Вердикт | Обґрунтування | V |
|---|---|---|---|---|---|
| S1 | rgr-v8-upload-client-filename | upload/source/low.php:9 | **TP** | Ім'я та розширення файлу задає клієнт, перевірок немає, тож `.php` зберігається у web root | V1 |
| S2 | rgr-v8-upload-trusts-client-mime | upload/source/medium.php:10 | **TP** | Єдина перевірка спирається на `Content-Type` від клієнта | V2 |
| S3 | rgr-v8-upload-client-filename | upload/source/medium.php:18 | **TP** | Після підробки типу зберігається ім'я клієнта (`x.php`) | V2 |
| S4 | rgr-v8-upload-client-filename | upload/source/high.php:20 | **TP** | Розширення перевіряється, але ім'я задає клієнт: можливий перезапис (T7), а збережений поліглот далі включається через LFI | V3 |
| S5 | rgr-v8-upload-trusts-client-mime | upload/source/impossible.php:11 | **FP** | Клієнтський тип лише доповнює перевірку: файл перекодовується через GD і зберігається під ім'ям `md5(uniqid())`, тож підробка нічого не дає | — |
| S6–S8 | rgr-v8-response-discloses-path | upload/source/{low,medium,high}.php | **TP** | У відповідь потрапляє `../../hackable/uploads/<ім'я>`: порушник дізнається розташування й точне ім'я для подальшого виклику (низька критичність, T9) | V7 |
| S9 | rgr-v8-response-discloses-path | upload/source/impossible.php:45 | **FP** | Посилання на публічний URL файлу з випадковим ім'ям, внутрішніх шляхів ФС немає | — |
| S10 | rgr-v8-include-request-param | fi/source/low.php:4 | **TP** | `$file = $_GET['page']` без будь-якої перевірки, далі `include($file)` | V4 |
| S11 | rgr-v8-include-request-param | fi/source/medium.php:4 | **TP** | Те саме, перевірка неповна (див. S12) | V5 |
| S12 | rgr-v8-path-filter-str-replace | fi/source/medium.php:8 | **TP** | Після заміни `....//` перетворюється на `../`; абсолютний шлях `/etc/passwd` не фільтрується | V5 |
| S13 | rgr-v8-include-request-param | fi/source/high.php:4 | **TP** | Значення лише порівнюється з шаблоном (S14) | V6 |
| S14 | rgr-v8-fnmatch-path-allowlist | fi/source/high.php:7 | **TP** | `fnmatch("file*")` пропускає `file:///etc/passwd` | V6 |
| S15 | rgr-v8-include-dynamic-path | fi/index.php:36 | **TP** | Спільний приймач (sink) `include($file)` для S10–S14 | V4–V6 |
| S16 | tainted-filename (реєстр) | fi/source/high.php:7 | **TP** (неточно) | Вразливість реальна, але правило вказує на `fnmatch()` як на файлову операцію й позначає її CWE-918 (SSRF). Правильна класифікація — CWE-22/98, приймач — S15 | V6 |

## 2. SAST (Semgrep) — знахідки реєстру, що стосуються шляхів (поза навчальними модулями)

| # | Правило | Файл:рядок | Вердикт | Обґрунтування | V |
|---|---|---|---|---|---|
| S17–S19 | tainted-filename | view_source.php:63, 67, 68 | **TP** | `file_get_contents("../vulnerabilities/{$id}/source/{$security}.php")`: `security=../../../config/config.inc` показує вихідний код конфігурації з паролем БД, **навіть на рівні impossible**. CWE-22 (реєстр позначає CWE-918, що неточно: префікс `../` унеможливлює обгортки, тож SSRF немає) | **V8** |
| S20 | tainted-filename | view_help.php:20 | **FP** | Шлях закінчується на `/help/help.php`, тому досяжні лише наявні файли довідки модулів, які й так публічні | — |
| S21 | tainted-filename | view_help.php:22 | **TP** | `eval('?>' . file_get_contents(".../help/help.{$locale}.php"))`: `locale=x/../../../../phpinfo` **виконує** довільний `.php` на диску (CWE-98/CWE-95) | **V9** |
| S22–S25 | tainted-filename | view_source_all.php:14–26 | **FP** | Суфікс `/source/{low,…}.php` фіксований: досяжні лише файли з такими іменами, тобто публічний код модулів | — |
| S26 | tainted-filename | instructions.php:26 | **FP** | Ключ `doc` перевіряється через `array_key_exists($selectedDocId, $docs)`, а шлях береться з allowlist | — |

## 3. SAST (Semgrep) — знахідки поза профілем (тріаж групами)

| Група | К-сть | Вердикт | Обґрунтування |
|---|---|---|---|
| tainted-exec у exec/source/{low,medium,high}.php | 12 | TP | Навмисні вразливості модуля Command Injection (CWE-78) |
| tainted-exec у exec/source/impossible.php | 4 | **FP** | Кожен октет IP перевіряється `is_numeric()`, кількість октетів дорівнює 4 |
| tainted-exec у api/src/HealthController.php:88 | 1 | TP | `exec("ping -c 4 " . $target)` з JSON-тіла запиту (CWE-78) |
| tainted-sql-string у гілці `MYSQL`: brute/low:12, sqli/low:10, sqli_blind/{low,high}:11 | 4 | TP | Навмисні SQL-ін'єкції (CWE-89) |
| tainted-sql-string у гілці `SQLITE`: sqli/low:31, sqli_blind/low:32, high:33, medium:34 | 4 | TP-н | Код уразливий, але гілка недосяжна: на стенді `SQLI_DB=mysql` |
| tainted-sql-string у bac/{low,medium}.php — запити з `$id` | 4 | **FP** | `user_id` перевіряється `preg_match('/^\d+$/')` (і `intval()` на low) |
| tainted-sql-string у bac/{low,medium}.php — журнал `bac_log` | 2 | TP | Заголовок `X-Forwarded-For` вставляється в `INSERT` без екранування (CWE-89) |
| echoed-request у csp/source/jsonp.php | 1 | TP | Довільний `callback` у JSONP — навмисний обхід CSP; класичного XSS немає (`Content-Type: application/json`) |
| phpinfo-use у phpinfo.php | 1 | TP | Розкриття конфігурації (CWE-200) |
| **Разом поза профілем** | **33** | 21 TP / 4 TP-н / 8 FP | Помилки розбору (2: Dockerfile і pdf.html) — це не PHP-файли, вони на результат не впливають |

Разом Semgrep — 59 знахідок: у профілі та на шляхах 26 (18 TP, 8 FP), поза профілем 33.
Частка FP: власні правила — 2/15 = **13 %**; реєстр у частині шляхів — 6/11 = **55 %**; реєстр загалом — 14/44 = **32 %**.
**Висновок щодо інструмента.** Реєстр `p/php` не знайшов жодної вразливості завантаження (S1–S4): там немає правил на `move_uploaded_file`, а включення в DVWA міжфайлове (`$file` задається в `source/*.php`, а включається в `index.php`). Зате реєстр знайшов V8 і V9 поза навчальними модулями. Тому власні правила й реєстр доповнюють одне одного.

## 4. SCA (Trivy) і SBOM

| Ціль | Знахідок | Вердикт | Обґрунтування |
|---|---|---|---|
| Composer-залежності `vulnerabilities/api` (вихідний код і `vendor/` в образі) | 0 | — | `composer.lock` оновлюється Dependabot в upstream; вразливих версій немає |
| ОС-пакети образу (Debian 13.7, база `php:8.4-apache`) | 1753 (1 CRITICAL, 164 HIGH, 649 MEDIUM, 917 LOW, 22 UNKNOWN) | TP за версією / переважно неексплуатовані | 1684 мають статус `affected` без виправлення в Debian, 58 мають виправлення (`fixed`: 54 MEDIUM, 4 LOW) |
| CVE-2026-6653 (libxml2, CRITICAL) | 1 | **FP за досяжністю** | Опис стосується пакета mingw-libxml2 (Windows), а DoS настає лише при розборі XML, тоді як застосунок XML від користувача не розбирає. Виправлення в Debian немає |

Рішення: для 58 пакетів із виправленнями оновити ОС-пакети під час збирання образу (`apt-get upgrade`); решту прийняти й відстежувати (розділ 5 звіту).
SBOM: CycloneDX 1.6, 205 компонентів (`scans/before/sbom.cdx.json`).

## 5. Сканування секретів (gitleaks)

| # | Правило | Файл:рядок | Вердикт | Обґрунтування |
|---|---|---|---|---|
| G1 | generic-api-key | vulnerabilities/csrf/help/help.php:54 | **FP** | `user-token: 026d…` — приклад CSRF-токена в навчальній довідці, а не ключ доступу |
| — | (пропуск) | config/config.inc.php.dist:20 | **FN** | Дефолтний пароль БД `p@ssw0rd` не виявлено, бо пароль короткий і низькоентропійний. Значення синтетичне й задокументоване в upstream; у РГР його винесено в змінні середовища `.env` |

Рішення: G1 внести до allowlist `.gitleaks.toml` з обґрунтуванням. FN показує обмеження сигнатурного підходу: короткі паролі в конфігураціях треба перевіряти вручну.

## 6. Підсумок тріажу

| Інструмент | Усього | TP | FP | Частка FP |
|---|---|---|---|---|
| Semgrep (власні правила) | 15 | 13 | 2 | 13 % |
| Semgrep (реєстр) | 44 | 30 (з них 4 TP-н) | 14 | 32 % |
| Trivy (ОС-пакети) | 1753 | 58 з виправленням (до оновлення) | 1 CRITICAL за досяжністю | — |
| gitleaks | 1 | 0 | 1 | 100 % (+1 FN) |

## 7. Тріаж залишкових знахідок після виправлень (`scans/after/`)

| Знахідка | К-сть | Вердикт | Обґрунтування |
|---|---|---|---|
| rgr-v8-upload-trusts-client-mime, upload/source/impossible.php:11 | 1 | FP (прийнято в базову лінію) | Без змін відносно S5. Еталонний рівень DVWA перекодовує файл, тож клієнтський тип лише доповнює перевірку |
| rgr-v8-response-discloses-path, upload/source/impossible.php:45 | 1 | FP (прийнято в базову лінію) | Без змін відносно S9. Виводиться лише публічний URL |
| tainted-filename, view_source.php:63–68 | 3 | FP після виправлення | Правило реєстру не розпізнає `SafePath::isModuleId()` / `isSecurityLevel()` як санітизацію. Те, що V8 більше не відтворюється, доведено регресійним тестом `V8` |
| tainted-filename, view_help.php:31 | 1 | FP після виправлення | Шлях `$helpFile` повертає `SafePath::within()` після allowlist. Доведено тестом `V9` |
| tainted-filename, view_source_all.php, instructions.php | 5 | FP | Без змін відносно S22–S26 |
| Решта знахідок реєстру поза профілем | 33 | без змін | Поза обсягом РГР; рекомендації — розділ 5 звіту |
| Trivy: 1695 CVE ОС-пакетів без виправлення в Debian | 1695 | прийнято, з моніторингом | Виправлень у дистрибутиві немає (`affected`/`will_not_fix`); `apt-get upgrade` закрив усі 58 CVE з виправленнями |
| gitleaks: 1894 `sourcegraph-access-token` у `scans/before/trivy-image.json` | 0 після allowlist | FP | Шістнадцяткові ідентифікатори у JSON-звіті Trivy. Каталог звітів `scans/` винесено в allowlist `.gitleaks.toml` |
