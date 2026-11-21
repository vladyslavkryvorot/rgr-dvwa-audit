"""Калькулятор базової оцінки CVSS v3.1 (за специфікацією FIRST, розд. 7).

Реалізовано самостійно за https://www.first.org/cvss/v3.1/specification-document;
для звірки можна використати калькулятор курсу labs/code/lab01_threat_model/cvss.py
(https://github.com/sokolusha/software-security-course) та офіційний калькулятор FIRST.

    python tools/cvss31.py "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
"""
from __future__ import annotations

import sys

AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
AC = {"L": 0.77, "H": 0.44}
UI = {"N": 0.85, "R": 0.62}
PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
REQUIRED = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def roundup(value: float) -> float:
    """Roundup з додатка A специфікації 3.1 (стійкий до похибок плаваючої коми)."""
    as_int = round(value * 100000)
    if as_int % 10000 == 0:
        return as_int / 100000.0
    return (as_int // 10000 + 1) / 10.0


def parse(vector: str) -> dict[str, str]:
    body = vector.removeprefix("CVSS:3.1/")
    metrics = dict(part.split(":", 1) for part in body.split("/"))
    missing = [m for m in REQUIRED if m not in metrics]
    if missing:
        raise ValueError(f"У векторі бракує метрик: {', '.join(missing)}")
    return metrics


def base_score(vector: str) -> float:
    m = parse(vector)
    changed = m["S"] == "C"
    iss = 1 - (1 - CIA[m["C"]]) * (1 - CIA[m["I"]]) * (1 - CIA[m["A"]])
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    pr = (PR_CHANGED if changed else PR_UNCHANGED)[m["PR"]]
    exploitability = 8.22 * AV[m["AV"]] * AC[m["AC"]] * pr * UI[m["UI"]]
    if impact <= 0:
        return 0.0
    if changed:
        return roundup(min(1.08 * (impact + exploitability), 10))
    return roundup(min(impact + exploitability, 10))


def severity(score: float) -> str:
    if score == 0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


if __name__ == "__main__":
    for vec in sys.argv[1:] or ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"]:
        s = base_score(vec)
        print(f"{vec}\t{s}\t{severity(s)}")
