"""Static GRC workspace assets; protected data is requested after unlocking."""
from pathlib import Path

_assets = Path(__file__).resolve().parent / 'assets'
GRC_STYLE = (_assets / 'grc.css').read_text(encoding='utf-8')
GRC_VIEW = (_assets / 'grc.html').read_text(encoding='utf-8')
GRC_SCRIPT = (_assets / 'grc.js').read_text(encoding='utf-8')
