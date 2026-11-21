# Порівняння результатів інструментів «до» та «після» виправлень

### SAST — Semgrep, власні правила варіанта 8

| Показник | До | Після | Зміна |
|---|---|---|---|
| `rgr-v8-fnmatch-path-allowlist` | 1 | 0 | -1 |
| `rgr-v8-include-dynamic-path` | 1 | 0 | -1 |
| `rgr-v8-include-request-param` | 3 | 0 | -3 |
| `rgr-v8-path-filter-str-replace` | 1 | 0 | -1 |
| `rgr-v8-response-discloses-path` | 4 | 1 | -3 |
| `rgr-v8-upload-client-filename` | 3 | 0 | -3 |
| `rgr-v8-upload-trusts-client-mime` | 2 | 1 | -1 |
| **Разом (власні правила)** | 15 | 2 | -13 |

### SAST — Semgrep, правила реєстру

| Показник | До | Після | Зміна |
|---|---|---|---|
| `echoed-request` | 1 | 1 | +0 |
| `phpinfo-use` | 1 | 1 | +0 |
| `tainted-exec` | 17 | 17 | +0 |
| `tainted-filename` | 11 | 9 | -2 |
| `tainted-sql-string` | 14 | 14 | +0 |
| **Разом (реєстр p/php, p/owasp-top-ten)** | 44 | 42 | -2 |

### SCA — Trivy, образ стенда

| Показник | До | Після | Зміна |
|---|---|---|---|
| ОС образу | debian 13.7 | debian 13.8 |  |
| CRITICAL | 1 | 1 | +0 |
| HIGH | 164 | 164 | +0 |
| MEDIUM | 649 | 595 | -54 |
| LOW | 917 | 913 | -4 |
| UNKNOWN | 22 | 22 | +0 |
| з виправленням (FixedVersion) | 58 | 0 | -58 |
| усього | 1753 | 1695 | -58 |

### Секрети — gitleaks

| Показник | До | Після | Зміна |
|---|---|---|---|
| історія git | 1 | 0 | -1 |
| робоче дерево dvwa/ | 1 | 0 | -1 |
