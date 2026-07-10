import json
import hashlib
import os
import re
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization


class PromptSanitizer:
    """
    Prototype: redacts common PII patterns from LLM prompts, then produces a
    hash-chained, signed log of what was sent.

    This is NOT a certified compliance tool and does not, on its own, satisfy
    any regulatory framework. See README for exactly what it does and doesn't prove.
    """

    def __init__(self, log_path="audit_trail.jsonl", key_path="signing_key.raw"):
        self.log_path = log_path
        self.key_path = key_path
        self.private_key = self._load_or_create_key()
        self.public_key = self.private_key.public_key()

        # Regex-based PII patterns: deliberately simple and explainable.
        # NOT a replacement for an NLP-based detector (e.g. Microsoft Presidio),
        # which also catches names, addresses, and other context-dependent PII
        # that regex fundamentally cannot.
        self.pii_patterns = {
            "SSN_US": r"\b\d{3}-\d{2}-\d{4}\b",
            "EMAIL": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "PHONE_INTL": r"\+\d{1,3}[\s.-]?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{2,4}",
            "IBAN": r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b",
            "CREDIT_CARD": r"\b(?:\d[ -]?){13,16}\b",
        }

    def _load_or_create_key(self):
        """Loads a persistent Ed25519 key if present, otherwise creates one.

        WARNING: this writes a raw private key to disk for local-prototype
        convenience only. Never commit signing_key.raw to version control,
        and never do this in anything resembling production — use a proper
        KMS/secrets manager there instead.
        """
        if os.path.exists(self.key_path):
            with open(self.key_path, "rb") as f:
                return ed25519.Ed25519PrivateKey.from_private_bytes(f.read())
        key = ed25519.Ed25519PrivateKey.generate()
        with open(self.key_path, "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        return key

    def _sanitize(self, text: str) -> str:
        sanitized = text
        for pii_type, pattern in self.pii_patterns.items():
            sanitized = re.sub(pattern, f"[REDACTED_{pii_type}]", sanitized)
        return sanitized

    def _last_entry_hash(self) -> str:
        if not os.path.exists(self.log_path):
            return "0" * 64
        with open(self.log_path, "r", encoding="utf-8") as f:
            lines = [l for l in f if l.strip()]
        if not lines:
            return "0" * 64
        return json.loads(lines[-1])["entry_hash"]

    def process_prompt(self, user_id: str, raw_prompt: str) -> str:
        sanitized = self._sanitize(raw_prompt)
        prev_hash = self._last_entry_hash()

        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user_id": hashlib.sha256(user_id.encode("utf-8")).hexdigest(),
            "sanitized_payload": sanitized,
            "payload_hash": hashlib.sha256(sanitized.encode("utf-8")).hexdigest(),
            "previous_entry_hash": prev_hash,
        }
        # Chaining: this entry's hash depends on the previous entry's hash,
        # so editing or deleting an earlier line breaks every hash after it —
        # that's what makes tampering detectable, not just "signed".
        entry_hash = hashlib.sha256(
            (prev_hash + json.dumps(record, sort_keys=True)).encode("utf-8")
        ).hexdigest()
        record["entry_hash"] = entry_hash
        record["signature_ed25519"] = self.private_key.sign(entry_hash.encode("utf-8")).hex()

        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

        return sanitized

    def verify_log(self) -> bool:
        """Re-walks the whole log, recomputing every hash and checking every
        signature. Returns True only if nothing has been altered, reordered,
        or removed since it was written."""
        if not os.path.exists(self.log_path):
            return True
        prev_hash = "0" * 64
        with open(self.log_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                if not line.strip():
                    continue
                entry = json.loads(line)
                core = {k: v for k, v in entry.items()
                        if k not in ("entry_hash", "signature_ed25519")}
                expected_hash = hashlib.sha256(
                    (prev_hash + json.dumps(core, sort_keys=True)).encode("utf-8")
                ).hexdigest()
                if expected_hash != entry["entry_hash"]:
                    print(f"Chain broken at line {line_num}")
                    return False
                try:
                    self.public_key.verify(
                        bytes.fromhex(entry["signature_ed25519"]),
                        entry["entry_hash"].encode("utf-8"),
                    )
                except Exception:
                    print(f"Bad signature at line {line_num}")
                    return False
                prev_hash = entry["entry_hash"]
        return True


if __name__ == "__main__":
    tool = PromptSanitizer()

    prompts = [
        "Summarize the medical history for John Doe, contact j.doe@acmehealth.org. SSN 123-45-6789.",
        "Draft a reply to +49 151 2345678 regarding invoice DE89370400440532013000.",
    ]

    print("--- Sanitizing prompts ---")
    for i, p in enumerate(prompts, 1):
        print(f"[{i}] {tool.process_prompt(user_id=f'usr_{i}', raw_prompt=p)}")

    print("\n--- Verifying full log ---")
    print("VALID — chain and signatures intact" if tool.verify_log() else "TAMPERED OR CORRUPT")
