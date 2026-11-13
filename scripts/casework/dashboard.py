from pathlib import Path

ASSETS = Path(__file__).resolve().parents[1] / "assets"
STYLE = (ASSETS / "investigations.css").read_text(encoding="utf-8")
VIEW = (ASSETS / "investigations.html").read_text(encoding="utf-8")
SCRIPT = (ASSETS / "investigations.js").read_text(encoding="utf-8")
