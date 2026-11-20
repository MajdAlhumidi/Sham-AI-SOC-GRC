from pathlib import Path

ASSETS = Path(__file__).resolve().parents[1] / "assets"
STYLE = (ASSETS / "investigations.css").read_text(encoding="utf-8")
STYLE += (ASSETS / "case-tools.css").read_text(encoding="utf-8")
VIEW = (ASSETS / "investigations.html").read_text(encoding="utf-8")
VIEW = VIEW.replace('  </div>\n  <dialog', (ASSETS / "comparison.html").read_text(encoding="utf-8") + '\n  </div>\n  <dialog', 1)
SCRIPT = (ASSETS / "investigations.js").read_text(encoding="utf-8")
SCRIPT += (ASSETS / "case-tools.js").read_text(encoding="utf-8")
SCRIPT += (ASSETS / "comparison.js").read_text(encoding="utf-8")
