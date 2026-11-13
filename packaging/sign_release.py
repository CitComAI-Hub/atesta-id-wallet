"""Signs SHA256SUMS for the automatic updates (atesta_id_wallet/updates.py).

    UPDATE_SIGNING_KEY=<base64 Ed25519 seed> python packaging/sign_release.py release/SHA256SUMS

Writes SHA256SUMS.sig (base64 signature) next to it, and fails if the key does not match
updates.UPDATE_PUBLIC_KEY (the one the released applications trust). See docs/RELEASING.md.
"""

import base64
import os
import re
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    sums = Path(sys.argv[1])
    seed = base64.b64decode(os.environ["UPDATE_SIGNING_KEY"].strip(), validate=True)
    key = Ed25519PrivateKey.from_private_bytes(seed)
    trusted = re.search(r'UPDATE_PUBLIC_KEY = "([^"]+)"',
                        (ROOT / "atesta_id_wallet" / "updates.py").read_text(encoding="utf-8")).group(1)
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if base64.b64encode(public).decode() != trusted:
        print("UPDATE_SIGNING_KEY does not match UPDATE_PUBLIC_KEY in atesta_id_wallet/updates.py", file=sys.stderr)
        return 1
    signature = key.sign(sums.read_bytes())
    Ed25519PublicKey.from_public_bytes(base64.b64decode(trusted)).verify(signature, sums.read_bytes())
    sums.with_name(sums.name + ".sig").write_text(base64.b64encode(signature).decode() + "\n", encoding="ascii")
    print(f"✔ {sums}.sig")
    return 0


if __name__ == "__main__":
    sys.exit(main())
