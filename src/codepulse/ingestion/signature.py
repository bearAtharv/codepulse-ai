"""GitHub webhook HMAC-SHA256 signature verification (Section 3.1.1)."""

import hashlib
import hmac


def verify_webhook_signature(
    payload_body: bytes,
    signature_header: str,
    secret: str,
) -> bool:
    """Verify the ``X-Hub-Signature-256`` header against the raw request body.

    Uses constant-time comparison (``hmac.compare_digest``) to prevent
    timing attacks.

    Returns ``False`` on missing, malformed, or mismatched signatures.
    """
    if not signature_header or not signature_header.startswith("sha256="):
        return False

    expected = "sha256=" + hmac.new(
        secret.encode("utf-8"), payload_body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature_header)
