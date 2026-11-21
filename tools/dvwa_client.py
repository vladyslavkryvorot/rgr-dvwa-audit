"""Мінімальний клієнт до ЛОКАЛЬНОГО стенда DVWA (лише 127.0.0.1).

Використовується PoC-скриптами (exploits/) і регресійними тестами (tests/regression/).
Адресу задає змінна DVWA_URL (типово http://127.0.0.1:8080).
"""
from __future__ import annotations

import os
import re
from urllib.parse import urlparse

import requests

DEFAULT_URL = "http://127.0.0.1:8080"
# Синтетичні облікові дані DVWA за замовчуванням (лише для стенда).
DEFAULT_USER = "admin"
DEFAULT_PASSWORD = "password"
_TOKEN_RE = re.compile(r"name=['\"]user_token['\"] value=['\"]([0-9a-f]+)['\"]")


def _assert_local(url: str) -> None:
    """Захисний запобіжник: клієнт відмовляється працювати з нелокальними цілями."""
    host = urlparse(url).hostname
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise RuntimeError(f"Ціль {host!r} не є локальним стендом — заборонено (розділ 1.2 практикуму)")


class DVWA:
    def __init__(self, base_url: str | None = None) -> None:
        self.base = (base_url or os.environ.get("DVWA_URL", DEFAULT_URL)).rstrip("/")
        _assert_local(self.base)
        self.s = requests.Session()

    def url(self, path: str) -> str:
        return f"{self.base}/{path.lstrip('/')}"

    def _token(self, path: str) -> str:
        r = self.s.get(self.url(path), timeout=10)
        m = _TOKEN_RE.search(r.text)
        if not m:
            raise RuntimeError(f"user_token не знайдено на {path}")
        return m.group(1)

    def setup_db(self) -> None:
        tok = self._token("setup.php")
        r = self.s.post(self.url("setup.php"),
                        data={"create_db": "Create / Reset Database", "user_token": tok}, timeout=30)
        r.raise_for_status()

    def login(self, user: str = DEFAULT_USER, password: str = DEFAULT_PASSWORD) -> None:
        tok = self._token("login.php")
        r = self.s.post(self.url("login.php"),
                        data={"username": user, "password": password, "Login": "Login", "user_token": tok},
                        timeout=10, allow_redirects=True)
        if "index.php" not in r.url and "Logout" not in r.text:
            raise RuntimeError("Не вдалося увійти до DVWA (чи виконано setup_db?)")

    def set_security(self, level: str) -> None:
        tok = self._token("security.php")
        self.s.post(self.url("security.php"),
                    data={"security": level, "seclev_submit": "Submit", "user_token": tok}, timeout=10)
        self.s.cookies.set("security", level, domain=urlparse(self.base).hostname)

    # ── Операції модулів профілю варіанта ──────────────────────────────────
    def upload(self, filename: str, content: bytes, content_type: str) -> requests.Response:
        files = {"uploaded": (filename, content, content_type)}
        data = {"Upload": "Upload", "MAX_FILE_SIZE": "100000"}
        page = self.s.get(self.url("vulnerabilities/upload/"), timeout=10).text
        m = _TOKEN_RE.search(page)
        if m:
            data["user_token"] = m.group(1)
        return self.s.post(self.url("vulnerabilities/upload/"), files=files, data=data, timeout=10)

    def include(self, page: str) -> requests.Response:
        return self.s.get(self.url("vulnerabilities/fi/"), params={"page": page}, timeout=10)


def session(level: str = "low", base_url: str | None = None, setup: bool = False) -> DVWA:
    d = DVWA(base_url)
    if setup:
        d.setup_db()
    d.login()
    d.set_security(level)
    return d


if __name__ == "__main__":
    c = session(setup=True)
    print("DVWA готовий:", c.base)
