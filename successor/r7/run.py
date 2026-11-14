"""Source-checkout bootstrap; installed users can use python -m zti_r7."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
from zti_r7.cli import main

raise SystemExit(main())
