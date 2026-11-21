#!/usr/bin/env bash
# Прогін інструментів аналізу захищеності: SAST, SCA + SBOM, секрети.
#   tools/run_scans.sh before   # стан до виправлень
#   tools/run_scans.sh after    # стан після виправлень
# Результати записуються до scans/<stage>/. Сканери працюють з офіційних Docker-образів
# з фіксованими версіями й не звертаються до стенда (статичний аналіз коду й образу).
set -euo pipefail

STAGE="${1:?Вкажіть етап: before | after}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/scans/$STAGE"
mkdir -p "$OUT"

SEMGREP_IMG="semgrep/semgrep:1.140.0"
TRIVY_IMG="aquasec/trivy:0.67.2"
GITLEAKS_IMG="zricethezav/gitleaks:v8.28.0"
DVWA_IMG="rgr-dvwa/dvwa:local"

echo "== [sast] Semgrep: реєстр (p/php, p/owasp-top-ten) + власні правила варіанта 8"
docker run --rm -v "$ROOT:/src" -w /src "$SEMGREP_IMG" semgrep scan --metrics=off --quiet \
  --config p/php --config p/owasp-top-ten --config tools/semgrep-rules/ \
  --exclude 'vendor' --json --output "scans/$STAGE/semgrep.json" dvwa || true

echo "== [sast] Semgrep: лише власні правила (база для quality gate)"
docker run --rm -v "$ROOT:/src" -w /src "$SEMGREP_IMG" semgrep scan --metrics=off --quiet \
  --config tools/semgrep-rules/ --exclude 'vendor' \
  --json --output "scans/$STAGE/semgrep-custom.json" dvwa || true

echo "== [sca] Trivy: залежності Composer у вихідному коді"
docker run --rm -v "$ROOT:/src:ro" -v rgr-trivy-cache:/root/.cache "$TRIVY_IMG" fs --quiet \
  --scanners vuln --format json --output /dev/stdout /src/dvwa > "$OUT/trivy-fs.json" || true

echo "== [sca] Trivy: образ стенда $DVWA_IMG (ОС-пакети + vendor/ API)"
TAR="$(mktemp -t dvwa-image).tar"
docker save "$DVWA_IMG" -o "$TAR"
docker run --rm -v "$TAR:/image.tar:ro" -v rgr-trivy-cache:/root/.cache "$TRIVY_IMG" image --quiet \
  --scanners vuln --input /image.tar --format json --output /dev/stdout > "$OUT/trivy-image.json" || true

echo "== [sca] SBOM CycloneDX образу"
docker run --rm -v "$TAR:/image.tar:ro" -v rgr-trivy-cache:/root/.cache "$TRIVY_IMG" image --quiet \
  --input /image.tar --format cyclonedx --output /dev/stdout > "$OUT/sbom.cdx.json" || true
rm -f "$TAR"

echo "== [secrets] gitleaks: історія git і робоче дерево"
docker run --rm -v "$ROOT:/repo" -w /repo "$GITLEAKS_IMG" git /repo --redact --no-banner \
  --report-format json --report-path "scans/$STAGE/gitleaks-git.json" --exit-code 0 || true
docker run --rm -v "$ROOT:/repo" -w /repo "$GITLEAKS_IMG" dir /repo/dvwa --redact --no-banner \
  --report-format json --report-path "scans/$STAGE/gitleaks-dir.json" --exit-code 0 || true

echo "== Підсумок"
python3 "$ROOT/tools/summarize_scans.py" "$OUT"
