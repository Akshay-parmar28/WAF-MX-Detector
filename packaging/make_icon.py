"""Write packaging/app.ico (generated, not committed)."""
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))
from wafmx.ui.icon import save_ico  # noqa: E402

save_ico(str(pathlib.Path(__file__).with_name("app.ico")))
print("wrote app.ico")
