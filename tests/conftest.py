import pathlib
import sys

# Umožní import balíčku collector i bez editable instalace.
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "collector"))
