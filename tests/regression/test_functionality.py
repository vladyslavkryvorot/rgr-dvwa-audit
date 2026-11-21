"""Функціональні тести: виправлення не повинні ламати легітимну роботу модулів.

Без них «зелені» тести test_vulns_fixed.py могли б означати, що модуль просто перестав працювати.
"""
import base64
import re

import pytest

import dvwa_client

# Коректне PNG-зображення 1x1 (синтетичне).
PNG_1X1 = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")
LEVELS = ["low", "medium", "high"]


@pytest.mark.parametrize("level", LEVELS)
def test_valid_png_upload_is_accepted_and_served(level):
    c = dvwa_client.session(level)
    r = c.upload("holiday photo.png", PNG_1X1, "image/png")
    m = re.search(r"([0-9a-f]{32}\.png)", r.text)
    assert m, f"легітимне PNG не прийнято на рівні {level}"
    img = c.s.get(c.url(f"hackable/uploads/{m.group(1)}"), timeout=10)
    assert img.status_code == 200
    assert img.headers["Content-Type"].startswith("image/png")
    assert img.content.startswith(b"\x89PNG")
    assert "hackable/uploads" not in r.text, "відповідь не має розкривати внутрішній шлях (T9)"


@pytest.mark.parametrize("level", LEVELS)
@pytest.mark.parametrize("page,marker", [("file1.php", "File 1"), ("file2.php", "File 2"),
                                         ("file3.php", "File 3"), ("include.php", "file1.php")])
def test_allowed_include_pages_still_work(level, page, marker):
    c = dvwa_client.session(level)
    r = c.include(page)
    assert r.status_code == 200 and marker in r.text and "ERROR: File not found" not in r.text


def test_view_source_and_help_still_work():
    c = dvwa_client.session("low")
    src = c.s.get(c.url("vulnerabilities/view_source.php"), params={"id": "upload", "security": "low"}, timeout=10)
    assert "File Upload Source" in src.text and "SafeUpload" in src.text
    hlp = c.s.get(c.url("vulnerabilities/view_help.php"),
                  params={"id": "fi", "security": "low", "locale": "en"}, timeout=10)
    assert "Not Found" not in hlp.text and len(hlp.text) > 1000
