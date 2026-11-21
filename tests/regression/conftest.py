import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))


@pytest.fixture(scope="session", autouse=True)
def dvwa_ready():
    """Переконатися, що стенд піднято й БД ініціалізовано (setup.php), інакше — skip з поясненням."""
    import requests
    import dvwa_client
    base = os.environ.get("DVWA_URL", dvwa_client.DEFAULT_URL)
    try:
        requests.get(f"{base}/login.php", timeout=5)
    except requests.RequestException:
        pytest.skip(f"Стенд DVWA недоступний за {base} — виконайте docker compose up -d")
    try:
        dvwa_client.DVWA(base).login()
    except RuntimeError:
        dvwa_client.DVWA(base).setup_db()
