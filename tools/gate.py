"""Критерій проходження (quality gate) — варіант 8 ЛР6: «блокувати за появи нових знахідок
відносно базової лінії». Основа — каркас lab06_cicd/gate.py репозиторію курсу (fail closed).

    python tools/gate.py scans/after/semgrep-custom.json            # перевірка
    python tools/gate.py scans/after/semgrep-custom.json --update   # записати базову лінію

Базова лінія (tools/baseline.json) містить лише знахідки, що за тріажем є хибнопозитивними
й прийнятими з обґрунтуванням. Відбиток знахідки не залежить від номера рядка:
правило + файл + нормалізований текст рядка коду, тож зсув коду не створює «нових» знахідок.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / "tools" / "baseline.json"


def load(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def fingerprint(result: dict) -> str:
    rule = result["check_id"].split(".")[-1]
    path = result["path"]
    try:
        line = (ROOT / path).read_text(encoding="utf-8", errors="replace").splitlines()[result["start"]["line"] - 1]
    except (OSError, IndexError):
        line = ""
    norm = " ".join(line.split())
    return hashlib.sha256(f"{rule}|{path}|{norm}".encode()).hexdigest()[:16]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("report", type=Path)
    ap.add_argument("--update", action="store_true", help="записати поточні знахідки як базову лінію")
    args = ap.parse_args(argv)

    report = load(args.report)
    if report is None or "results" not in report:
        print(f"::error::Quality gate: звіт {args.report} відсутній або пошкоджений — складання заблоковано")
        return 1
    if report.get("errors"):
        print(f"::error::Quality gate: Semgrep повідомив про {len(report['errors'])} помилок — fail closed")
        return 1
    current = {fingerprint(r): r for r in report["results"]}

    if args.update:
        BASELINE.write_text(json.dumps(
            {fp: f"{r['check_id'].split('.')[-1]} {r['path']}:{r['start']['line']}" for fp, r in sorted(current.items())},
            ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"Базову лінію оновлено: {len(current)} знахідок → {BASELINE.relative_to(ROOT)}")
        return 0

    baseline = load(BASELINE)
    if baseline is None:
        print("::error::Quality gate: базова лінія tools/baseline.json відсутня — fail closed")
        return 1
    new = {fp: r for fp, r in current.items() if fp not in baseline}
    print(f"Знахідок усього: {len(current)}, у базовій лінії: {len(current) - len(new)}, нових: {len(new)}")
    for r in new.values():
        print(f"::error file={r['path']},line={r['start']['line']}::{r['check_id'].split('.')[-1]}: "
              f"{' '.join(r['extra']['message'].split())[:160]}")
    if new:
        print(f"::error::Quality gate: {len(new)} нових знахідок відносно базової лінії — складання заблоковано")
        return 1
    print("Quality gate: пройдено")
    return 0


if __name__ == "__main__":
    sys.exit(main())
