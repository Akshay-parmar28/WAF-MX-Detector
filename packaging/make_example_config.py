"""Regenerate config.example.json from the code defaults (placeholders only)."""
import json
import pathlib
import sys

root = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / "src"))
from wafmx.config import Settings  # noqa: E402

s = Settings(allowed_domains=["example.com", "*.example.net"])
(root / "config.example.json").write_text(json.dumps(s.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
print("wrote config.example.json")
