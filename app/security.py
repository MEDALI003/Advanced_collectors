from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any


def canonical_json(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_hmac(secret: str, data: Any) -> str:
    return hmac.new(secret.encode("utf-8"), canonical_json(data), hashlib.sha256).hexdigest()


def verify_hmac(secret: str, data: Any, signature: str) -> bool:
    expected = compute_hmac(secret, data)
    return hmac.compare_digest(expected, signature)
