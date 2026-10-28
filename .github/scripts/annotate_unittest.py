"""
Turns the failures in a unittest output file into GitHub Actions error annotations.

Job logs need a signed-in user even on public repositories; annotations do not, so failures can
be read from the run page or the API by anyone.
Usage:  python annotate_unittest.py OUTPUT_FILE EXIT_CODE
"""

import re
import sys
from pathlib import Path

SEPARATOR = "=" * 70
DIVIDER = "-" * 70


def escape(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "").replace("\n", "%0A")


def main() -> int:
    text = Path(sys.argv[1]).read_text(encoding="utf-8", errors="replace")
    code = int(sys.argv[2])
    if code == 0:
        return 0
    blocks = text.split("\n" + SEPARATOR + "\n")[1:]
    for block in blocks:
        title, _, body = block.partition("\n" + DIVIDER + "\n")
        body = body.split("\n" + DIVIDER + "\n")[0]
        print(f"::error title={escape(title.strip()[:200])}::{escape(body.strip()[-4000:])}")
    if not blocks:  # crash or error outside a test (import error, segfault...)
        tail = "\n".join(text.splitlines()[-60:])
        print(f"::error title=Tests exited with code {code}::{escape(tail)}")
    summary = re.findall(r"^(Ran \d+ tests.*|FAILED.*|OK.*)$", text, re.MULTILINE)
    if summary:
        print(f"::notice title=Test summary::{escape(' / '.join(summary))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
