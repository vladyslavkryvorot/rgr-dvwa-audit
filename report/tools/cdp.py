"""Мінімальний клієнт Chrome DevTools Protocol для знімків екрана й друку в PDF (інструменти звіту)."""
from __future__ import annotations

import base64
import json
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

import websocket

CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"


class Chrome:
    def __init__(self, port: int = 9333, width: int = 1200, height: int = 800) -> None:
        self.profile = tempfile.mkdtemp(prefix="rgr-chrome-")
        self.proc = subprocess.Popen(
            [CHROME, "--headless=new", f"--remote-debugging-port={port}", f"--user-data-dir={self.profile}",
             "--no-first-run", "--disable-gpu", "--hide-scrollbars", f"--window-size={width},{height}",
             "--remote-allow-origins=*", "about:blank"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(50):
            try:
                tabs = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/json"))
                ws_url = next(t["webSocketDebuggerUrl"] for t in tabs if t["type"] == "page")
                break
            except Exception:  # noqa: BLE001 — Chrome ще стартує
                time.sleep(0.2)
        else:
            raise RuntimeError("Chrome DevTools не відповідає")
        self.ws = websocket.create_connection(ws_url, timeout=60)
        self._id = 0
        self.send("Page.enable")
        self.send("Network.enable")
        self.viewport(width, height)

    def send(self, method: str, **params):
        self._id += 1
        self.ws.send(json.dumps({"id": self._id, "method": method, "params": params}))
        while True:
            msg = json.loads(self.ws.recv())
            if msg.get("id") == self._id:
                if "error" in msg:
                    raise RuntimeError(f"{method}: {msg['error']}")
                return msg.get("result", {})

    def viewport(self, width: int, height: int, scale: float = 1.0) -> None:
        self.send("Emulation.setDeviceMetricsOverride", width=width, height=height, deviceScaleFactor=scale, mobile=False)

    def set_cookies(self, url: str, cookies: dict[str, str]) -> None:
        for name, value in cookies.items():
            self.send("Network.setCookie", name=name, value=value, url=url)

    def goto(self, url: str, settle: float = 0.6) -> None:
        self.send("Page.navigate", url=url)
        self.wait_load()
        time.sleep(settle)

    def wait_load(self, timeout: float = 30) -> None:
        end = time.time() + timeout
        while time.time() < end:
            state = self.eval("document.readyState")
            if state == "complete":
                return
            time.sleep(0.1)

    def eval(self, js: str, await_promise: bool = False):
        r = self.send("Runtime.evaluate", expression=js, awaitPromise=await_promise, returnByValue=True)
        if "exceptionDetails" in r:
            raise RuntimeError(r["exceptionDetails"].get("exception", {}).get("description", r["exceptionDetails"]))
        return r.get("result", {}).get("value")

    def screenshot(self, path: Path, selector: str | None = None, full: bool = False, pad: int = 8) -> None:
        params: dict = {"format": "png", "captureBeyondViewport": True}
        if selector:
            box = self.eval(f"(() => {{ const r = document.querySelector({json.dumps(selector)}).getBoundingClientRect();"
                            f" return [r.x + scrollX, r.y + scrollY, r.width, r.height]; }})()")
            x, y, w, h = box
            params["clip"] = {"x": max(0, x - pad), "y": max(0, y - pad), "width": w + 2 * pad, "height": h + 2 * pad, "scale": 2}
        elif full:
            w, h = self.eval("[document.documentElement.scrollWidth, document.documentElement.scrollHeight]")
            params["clip"] = {"x": 0, "y": 0, "width": w, "height": h, "scale": 2}
        data = self.send("Page.captureScreenshot", **params)["data"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(base64.b64decode(data))

    def pdf(self, path: Path) -> None:
        data = self.send("Page.printToPDF", preferCSSPageSize=True, printBackground=True,
                         displayHeaderFooter=False, generateDocumentOutline=True, generateTaggedPDF=True)["data"]
        path.write_bytes(base64.b64decode(data))

    def close(self) -> None:
        try:
            self.send("Browser.close")
        except Exception:  # noqa: BLE001
            pass
        self.proc.wait(timeout=10)
