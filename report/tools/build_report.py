"""Збірка звіту РГР: report.md → HTML (ДСТУ 3008:2015) → PDF через headless Chrome.

    python report/tools/build_report.py
Продукує report/build/report.html і report/report.pdf.
"""
from __future__ import annotations

import html as html_mod
import re
import sys
from pathlib import Path

import markdown

ROOT = Path(__file__).resolve().parents[2]
REPORT = ROOT / "report"
BUILD = REPORT / "build"
sys.path.insert(0, str(Path(__file__).parent))


# ── Витяг тіла з включених Markdown-документів (без титулів-дублів) ──────────

def section_body(path: Path, drop_heading: bool = True) -> str:
    text = path.read_text(encoding="utf-8")
    if drop_heading:
        lines = text.splitlines()
        # прибрати перший заголовок H1 документа, щоб не дублювати заголовок додатка
        for i, ln in enumerate(lines):
            if ln.startswith("# "):
                lines = lines[i + 1:]
                break
        text = "\n".join(lines)
    # знизити рівень заголовків на один (## → ###), щоб вписати в структуру додатка
    text = re.sub(r"^(#{1,5}) ", lambda m: "#" * min(len(m.group(1)) + 1, 6) + " ", text, flags=re.M)
    return text


def listings() -> str:
    files = [
        ("dvwa/dvwa/includes/SafeUpload.php", "SafeUpload::store() і перевірка вмісту"),
        ("dvwa/dvwa/includes/SafePath.php", "SafePath::resolveInclude() і канонізація"),
        ("tools/semgrep-rules/rgr-variant8.yml", "Приклад власного правила Semgrep"),
    ]
    out = []
    for rel, title in files:
        code = (ROOT / rel).read_text(encoding="utf-8")
        out.append(f"### {rel}\n\n*{title}.*\n\n```\n{code.strip()}\n```\n")
    return "\n".join(out)


INCLUDES = {
    "::: include-threat-model :::": lambda: section_body(ROOT / "docs/threat-model/threat_model.md"),
    "::: include-triage :::": lambda: section_body(ROOT / "docs/triage/triage.md"),
    "::: include-listings :::": lambda: listings(),
}


def expand_includes(text: str) -> str:
    for marker, fn in INCLUDES.items():
        text = text.replace(marker, fn())
    return text


# ── Блоки titlepage / toc ───────────────────────────────────────────────────

def extract_fenced(text: str, name: str) -> tuple[str, str]:
    """Витягти ::: name ... ::: → (внутрішній markdown, решта тексту із плейсхолдером)."""
    m = re.search(rf"^::: {name}\n(.*?)^:::$", text, flags=re.S | re.M)
    if not m:
        return "", text
    return m.group(1), text[:m.start()] + f"@@{name}@@" + text[m.end():]


# ── Нумерація рисунків і таблиць у межах розділу ────────────────────────────

def number_captions(soup_html: str) -> str:
    chapter = [0]
    fig = [0]
    tbl = [0]

    def repl_h1(m):
        chapter[0] += 1
        fig[0] = 0
        tbl[0] = 0
        return m.group(0)

    # нумерацію виконуємо на рівні markdown-рядків підписів до перетворення в HTML
    return soup_html


def build_html(md_text: str) -> str:
    titlepage_md, md_text = extract_fenced(md_text, "titlepage")
    _, md_text = extract_fenced(md_text, "toc")

    md = markdown.Markdown(extensions=["tables", "fenced_code", "attr_list", "toc", "sane_lists"],
                           extension_configs={"toc": {"toc_depth": "1-2", "permalink": False}})
    body_html = md.convert(md_text)
    titlepage_html = markdown.markdown(titlepage_md, extensions=["attr_list"])

    # розставити клас chapter першому H1 кожного розділу (розрив сторінки)
    body_html = re.sub(r"<h1([^>]*)>", r'<h1 class="chapter"\1>', body_html)

    # побудувати зміст із H1/H2
    toc_items = re.findall(r'<h([12])[^>]*id="([^"]+)"[^>]*>(.*?)</h\1>', body_html)
    toc_html = ['<nav class="toc"><h1 class="chapter">Зміст</h1><ol>']
    for level, hid, title in toc_items:
        cls = "toc-sub" if level == "2" else "toc-main"
        clean = re.sub("<.*?>", "", title)
        toc_html.append(f'<li class="{cls}"><a href="#{hid}">{clean}</a></li>')
    toc_html.append("</ol></nav>")

    # загортання таблиць і рисунків у figure з підписами «Таблиця N.M» / «Рисунок N.M»
    body_html = wrap_tables_and_figures(body_html)

    body_html = body_html.replace("@@titlepage@@", f'<section class="titlepage">{titlepage_html}</section>')
    body_html = body_html.replace("@@toc@@", "\n".join(toc_html))

    css = (REPORT / "tools" / "style.css").read_text(encoding="utf-8")
    return (f"<!doctype html><html lang='uk'><head><meta charset='utf-8'>"
            f"<title>РГР — Аудит захищеності DVWA (варіант 8)</title>"
            f"<style>{css}</style></head><body>{body_html}</body></html>")


def wrap_tables_and_figures(html: str) -> str:
    """Підписи «Таблиця N.M — …» зверху таблиці, «Рисунок N.M — …» знизу рисунка.
    Текст підпису вже є в markdown як абзац перед таблицею або alt зображення."""
    # Таблиці: абзац, що починається з «Таблиця …», стає caption наступної таблиці
    html = re.sub(r"<p>(Таблиця[^<]*)</p>\s*<table>",
                  lambda m: f'<figure class="table"><div class="caption">{m.group(1)}</div><table>', html)
    html = html.replace("</table>", "</table></figure>")
    # підчистити зайві обгортки, якщо таблиця була без підпису
    html = re.sub(r'<figure class="table"><div class="caption">(?![^<]*Таблиця)', "<figure class=\"table\">", html)

    # Рисунки: <img alt="Рисунок N.M — підпис"> → figure з figcaption
    def fig(m):
        alt = html_mod.unescape(m.group("alt"))
        return (f'<figure class="figure"><img src="{m.group("src")}" alt="{m.group("alt")}">'
                f'<figcaption>{alt}</figcaption></figure>')

    html = re.sub(r'<img alt="(?P<alt>[^"]*)" src="(?P<src>[^"]*)"\s*/?>', fig, html)
    html = re.sub(r"<p>(<figure class=\"figure\">.*?</figure>)</p>", r"\1", html, flags=re.S)
    return html


def main() -> int:
    BUILD.mkdir(parents=True, exist_ok=True)
    md_text = (REPORT / "report.md").read_text(encoding="utf-8")
    md_text = expand_includes(md_text)
    html = build_html(md_text)
    # абсолютні шляхи до рисунків для Chrome
    html = html.replace('src="figures/', f'src="{(REPORT / "figures").as_uri()}/')
    out_html = BUILD / "report.html"
    out_html.write_text(html, encoding="utf-8")

    from cdp import Chrome
    chrome = Chrome()
    try:
        chrome.goto(out_html.as_uri(), settle=1.2)
        chrome.pdf(REPORT / "report.pdf")
    finally:
        chrome.close()
    pages = len((REPORT / "report.pdf").read_bytes().split(b"/Type /Page")) - 1
    print(f"HTML: {out_html}")
    print(f"PDF:  {REPORT / 'report.pdf'} (~{pages} об'єктів сторінок)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
