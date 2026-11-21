"""Зведення звітів сканерів одного етапу (scans/<stage>/) у summary.json і таблицю в консолі."""
from __future__ import annotations

import collections
import json
import sys
from pathlib import Path

PROFILE_PATHS = ("dvwa/vulnerabilities/upload/", "dvwa/vulnerabilities/fi/", "dvwa/dvwa/includes/Safe")


def load(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def semgrep_summary(rep: dict | None) -> dict:
    if rep is None:
        return {"error": "звіт відсутній"}
    res = rep.get("results", [])
    by_sev = collections.Counter(r["extra"]["severity"] for r in res)
    profile = [r for r in res if r["path"].startswith(PROFILE_PATHS)]
    return {
        "total": len(res),
        "by_severity": dict(by_sev),
        "profile_total": len(profile),
        "by_rule_profile": dict(collections.Counter(r["check_id"].split(".")[-1] for r in profile)),
        "errors": len(rep.get("errors", [])),
    }


def trivy_summary(rep: dict | None) -> dict:
    if rep is None:
        return {"error": "звіт відсутній"}
    vulns = [v for r in rep.get("Results", []) for v in (r.get("Vulnerabilities") or [])]
    by_sev = collections.Counter(v.get("Severity", "UNKNOWN") for v in vulns)
    by_target = collections.Counter(r.get("Target") for r in rep.get("Results", []) for _ in (r.get("Vulnerabilities") or []))
    def cvss3(v):
        scores = [s.get("V3Score", 0) for s in (v.get("CVSS") or {}).values()]
        return max(scores or [0])
    return {
        "total": len(vulns),
        "by_severity": dict(by_sev),
        "by_target": dict(by_target),
        "max_cvss3": max((cvss3(v) for v in vulns), default=0),
    }


def gitleaks_summary(rep) -> dict:
    if rep is None:
        return {"error": "звіт відсутній"}
    return {"total": len(rep), "by_rule": dict(collections.Counter(f.get("RuleID") for f in rep)),
            "files": sorted({f.get("File") for f in rep})}


def main(out: str) -> int:
    d = Path(out)
    sbom = load(d / "sbom.cdx.json") or {}
    summary = {
        "semgrep_all": semgrep_summary(load(d / "semgrep.json")),
        "semgrep_custom": semgrep_summary(load(d / "semgrep-custom.json")),
        "trivy_fs": trivy_summary(load(d / "trivy-fs.json")),
        "trivy_image": trivy_summary(load(d / "trivy-image.json")),
        "sbom": {"format": sbom.get("bomFormat"), "spec": sbom.get("specVersion"),
                 "components": len(sbom.get("components", []))},
        "gitleaks_git": gitleaks_summary(load(d / "gitleaks-git.json")),
        "gitleaks_dir": gitleaks_summary(load(d / "gitleaks-dir.json")),
    }
    (d / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
