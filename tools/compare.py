"""Порівняння «до/після» за звітами scans/before і scans/after → scans/comparison.md."""
from __future__ import annotations

import collections
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(stage: str, name: str):
    try:
        return json.loads((ROOT / "scans" / stage / name).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def semgrep_by_rule(stage: str, name: str) -> collections.Counter:
    rep = load(stage, name) or {"results": []}
    return collections.Counter(r["check_id"].split(".")[-1] for r in rep["results"])


def trivy(stage: str) -> dict:
    rep = load(stage, "trivy-image.json") or {"Results": []}
    vs = [v for r in rep["Results"] for v in (r.get("Vulnerabilities") or [])]
    c = collections.Counter(v["Severity"] for v in vs)
    c["з виправленням (FixedVersion)"] = sum(1 for v in vs if v.get("FixedVersion"))
    c["усього"] = len(vs)
    os_name = next((r["Target"].split("(")[-1].rstrip(")") for r in rep["Results"] if r.get("Class") == "os-pkgs"), "?")
    c["_os"] = os_name
    return c


def table(title: str, rows: list[tuple[str, object, object]]) -> list[str]:
    out = [f"### {title}", "", "| Показник | До | Після | Зміна |", "|---|---|---|---|"]
    for name, b, a in rows:
        delta = f"{a - b:+d}" if isinstance(a, int) and isinstance(b, int) else ""
        out.append(f"| {name} | {b} | {a} | {delta} |")
    return out + [""]


def main() -> int:
    lines = ["# Порівняння результатів інструментів «до» та «після» виправлень", ""]
    cb, ca = semgrep_by_rule("before", "semgrep-custom.json"), semgrep_by_rule("after", "semgrep-custom.json")
    rows = [(f"`{r}`", cb[r], ca[r]) for r in sorted(set(cb) | set(ca))]
    rows.append(("**Разом (власні правила)**", sum(cb.values()), sum(ca.values())))
    lines += table("SAST — Semgrep, власні правила варіанта 8", rows)

    rb, ra = semgrep_by_rule("before", "semgrep.json"), semgrep_by_rule("after", "semgrep.json")
    for r in cb | ca:
        rb.pop(r, None); ra.pop(r, None)
    rows = [(f"`{r}`", rb[r], ra[r]) for r in sorted(set(rb) | set(ra))]
    rows.append(("**Разом (реєстр p/php, p/owasp-top-ten)**", sum(rb.values()), sum(ra.values())))
    lines += table("SAST — Semgrep, правила реєстру", rows)

    tb, ta = trivy("before"), trivy("after")
    rows = [(k, tb[k], ta[k]) for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "з виправленням (FixedVersion)", "усього")]
    rows.insert(0, ("ОС образу", tb["_os"], ta["_os"]))
    lines += table("SCA — Trivy, образ стенда", rows)

    gb = (load("before", "gitleaks-git.json") or [], load("before", "gitleaks-dir.json") or [])
    ga = (load("after", "gitleaks-git.json") or [], load("after", "gitleaks-dir.json") or [])
    lines += table("Секрети — gitleaks", [("історія git", len(gb[0]), len(ga[0])),
                                         ("робоче дерево dvwa/", len(gb[1]), len(ga[1]))])
    (ROOT / "scans" / "comparison.md").write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
