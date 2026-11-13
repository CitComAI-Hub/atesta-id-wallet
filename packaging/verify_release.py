"""Checks the signature of a release's SHA256SUMS, as the installed applications do (updates.py).

    python packaging/verify_release.py release/SHA256SUMS

Reads SHA256SUMS.sig next to it and fails unless it is a valid Ed25519 signature by
updates.UPDATE_PUBLIC_KEY. The APT repository (.github/workflows/apt.yml) only publishes a .deb
listed in a signed SHA256SUMS: a file uploaded to the release by hand is refused, as it is by the
automatic updates. Needs only 'cryptography'. See docs/RELEASING.md.
"""

import base64
import re
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    sums = Path(sys.argv[1])
    signature = sums.with_name(sums.name + ".sig")
    trusted = re.search(r'UPDATE_PUBLIC_KEY = "([^"]+)"',
                        (ROOT / "atesta_id_wallet" / "updates.py").read_text(encoding="utf-8")).group(1)
    try:
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(trusted, validate=True))
        key.verify(base64.b64decode(signature.read_bytes().strip(), validate=True), sums.read_bytes())
    except (OSError, ValueError, InvalidSignature) as exc:
        print(f"{sums} is not signed with UPDATE_PUBLIC_KEY ({type(exc).__name__}: {exc})", file=sys.stderr)
        return 1
    print(f"✔ {sums}: valid signature")
    return 0


if __name__ == "__main__":
    sys.exit(main())
