import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

GENESIS_HASH = "0" * 64

FIELDS = (
    "timestamp",
    "user_id",
    "sanitized_payload",
    "payload_hash",
    "previous_entry_hash",
    "entry_hash",
    "signature_ed25519",
)
HASH_FIELDS = ("user_id", "payload_hash", "previous_entry_hash", "entry_hash")

_HASH_RE = re.compile(r"[0-9a-f]{64}")
_SIGNATURE_RE = re.compile(r"[0-9a-f]{128}")


def compute_entry_hash(previous_hash: str, core: dict) -> str:
    """Hash of the running previous hash plus every field except the entry
    hash and the signature."""
    return hashlib.sha256((previous_hash + json.dumps(core, sort_keys=True)).encode("utf-8")).hexdigest()


def _diagnostic(message: str) -> None:
    # Diagnostics name a line and a reason only. Entry contents never appear.
    print(message, file=sys.stderr)


def _is_hash(value) -> bool:
    return isinstance(value, str) and _HASH_RE.fullmatch(value) is not None


def _schema_error(entry):
    """Returns a short reason if `entry` is not a well-formed log record."""
    if not isinstance(entry, dict):
        return "entry is not a JSON object"
    if set(entry) != set(FIELDS):
        return "fields are missing or unexpected"
    if not isinstance(entry["sanitized_payload"], str):
        return "sanitized_payload is not a string"
    if not isinstance(entry["timestamp"], str):
        return "timestamp is not a string"
    try:
        datetime.fromisoformat(entry["timestamp"])
    except ValueError:
        return "timestamp is not an ISO 8601 time"
    for name in HASH_FIELDS:
        if not _is_hash(entry[name]):
            return f"{name} is not a 64 character lowercase hex string"
    signature = entry["signature_ed25519"]
    if not (isinstance(signature, str) and _SIGNATURE_RE.fullmatch(signature)):
        return "signature_ed25519 is not a 128 character lowercase hex string"
    return None


def _load_public_key(public_key_bytes) -> ed25519.Ed25519PublicKey:
    if not isinstance(public_key_bytes, (bytes, bytearray)) or len(public_key_bytes) != 32:
        raise ValueError("public key must be 32 raw Ed25519 public key bytes")
    try:
        return ed25519.Ed25519PublicKey.from_public_bytes(bytes(public_key_bytes))
    except ValueError:
        raise ValueError("public key bytes are not a valid Ed25519 public key") from None


def _walk_log(log_path: str, public_key: ed25519.Ed25519PublicKey):
    """Checks every entry and returns the hash of the last one, or None after
    printing a line-numbered reason when any check fails. A missing or empty
    log is a valid empty history and its head is the genesis hash."""
    previous_hash = GENESIS_HASH
    if not os.path.exists(log_path):
        return previous_hash
    try:
        with open(log_path, "r", encoding="utf-8") as f:
            for line_num, line in enumerate(f, 1):
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                except (ValueError, RecursionError):
                    _diagnostic(f"Line {line_num}: not valid JSON")
                    return None
                problem = _schema_error(entry)
                if problem:
                    _diagnostic(f"Line {line_num}: {problem}")
                    return None
                if entry["previous_entry_hash"] != previous_hash:
                    _diagnostic(f"Line {line_num}: previous_entry_hash does not match the preceding entry")
                    return None
                try:
                    payload_hash = hashlib.sha256(entry["sanitized_payload"].encode("utf-8")).hexdigest()
                except UnicodeEncodeError:
                    # JSON permits lone surrogates, which have no UTF-8 encoding.
                    _diagnostic(f"Line {line_num}: sanitized_payload cannot be encoded as UTF-8")
                    return None
                if entry["payload_hash"] != payload_hash:
                    _diagnostic(f"Line {line_num}: payload_hash does not match sanitized_payload")
                    return None
                core = {k: v for k, v in entry.items() if k not in ("entry_hash", "signature_ed25519")}
                if compute_entry_hash(previous_hash, core) != entry["entry_hash"]:
                    _diagnostic(f"Line {line_num}: entry hash does not match the entry")
                    return None
                try:
                    public_key.verify(
                        bytes.fromhex(entry["signature_ed25519"]),
                        entry["entry_hash"].encode("utf-8"),
                    )
                except InvalidSignature:
                    _diagnostic(f"Line {line_num}: signature is not valid for this public key")
                    return None
                previous_hash = entry["entry_hash"]
    except UnicodeDecodeError:
        _diagnostic("Log is not valid UTF-8")
        return None
    return previous_hash


def verify_log_file(log_path: str, public_key_bytes: bytes, expected_head_hash=None) -> bool:
    """Verifies a log with only a public key. No private key is read or created.

    Every nonblank line must be a record with exactly the expected fields, each
    link must name the real preceding hash (the first must name the genesis
    hash), payload_hash must match the payload, and every signature must be
    valid under `public_key_bytes`. Malformed logs return False.

    A valid signature under a key shows only that the holder of that key signed
    the entry. It identifies the original signer only if the caller obtained
    the public key from a source it trusts independently of the log.

    Without `expected_head_hash`, a valid prefix of a longer log verifies,
    because a hash chain cannot show that later entries ever existed. With it,
    the last verified entry hash must equal the value the caller retained
    separately from the log. The genesis hash stands for an empty history.

    Raises ValueError for a malformed public key or checkpoint, since those are
    caller errors and not properties of the log.
    """
    public_key = _load_public_key(public_key_bytes)
    if expected_head_hash is not None and not _is_hash(expected_head_hash):
        raise ValueError("expected_head_hash must be a 64 character lowercase hex string")
    head = _walk_log(log_path, public_key)
    if head is None:
        return False
    if expected_head_hash is not None and head != expected_head_hash:
        _diagnostic("Log head does not match the expected head hash")
        return False
    return True


def _log_has_entries(log_path: str) -> bool:
    if not os.path.exists(log_path):
        return False
    with open(log_path, "rb") as f:
        return any(line.strip() for line in f)


class PromptSanitizer:
    """
    Prototype, used in-process. It is not a network proxy and sends nothing.

    `process_prompt` redacts a few regex-defined PII shapes from one string,
    appends a signed, hash-chained record of the sanitized payload it produced,
    and returns that payload. The log is a record of what this function
    produced. It does not show what a caller then did with the returned value:
    the caller can discard it, send something else, or send nothing.

    This is NOT a certified compliance tool and does not, on its own, satisfy
    any regulatory framework. See README for what verification does and does
    not establish.
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
        """Loads a persistent raw Ed25519 private key, or creates one for a new history.

        The key file is 32 unencrypted bytes. This is for a local prototype
        only. Real systems keep signing keys in a KMS, HSM or secrets manager.

        A new key is never created while the log already has entries, because
        a replacement key would silently start a different signing identity.
        """
        if os.path.exists(self.key_path):
            with open(self.key_path, "rb") as f:
                raw = f.read()
            if len(raw) != 32:
                raise ValueError("signing key file must contain exactly 32 raw bytes")
            return ed25519.Ed25519PrivateKey.from_private_bytes(raw)
        if _log_has_entries(self.log_path):
            raise FileNotFoundError(
                "signing key file is missing but the log already has entries; "
                "refusing to create a new signing key"
            )
        key = ed25519.Ed25519PrivateKey.generate()
        raw = key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        # Exclusive creation with owner-only permissions where the platform honours them.
        fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
        return key

    def public_key_bytes(self) -> bytes:
        """Raw 32 byte Ed25519 public key. Keep a copy somewhere trusted
        separately from the log if you want signatures tied to this signer."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def _sanitize(self, text: str) -> str:
        sanitized = text
        for pii_type, pattern in self.pii_patterns.items():
            sanitized = re.sub(pattern, f"[REDACTED_{pii_type}]", sanitized)
        return sanitized

    def current_head_hash(self) -> str:
        """Hash of the last entry, after verifying the log under this instance's
        key. The genesis hash means an empty history. Retain the returned value
        outside the log to detect later truncation with `verify_log`."""
        head = _walk_log(self.log_path, self.public_key)
        if head is None:
            raise ValueError("log failed verification, so no head hash is returned")
        return head

    def process_prompt(self, user_id: str, raw_prompt: str) -> str:
        """Sanitizes `raw_prompt`, logs the sanitized payload, and returns it.

        The stored `user_id` is an unsalted SHA-256. It is deterministic and
        linkable across entries, and guessable when identifiers come from a
        small or predictable space. It is pseudonymous, not anonymous.

        Refuses to append to a log that fails verification under this key.
        Verification cannot reveal entries that were removed from the end of a
        log. There is no file locking, so concurrent writers can corrupt the chain.
        """
        sanitized = self._sanitize(raw_prompt)
        previous_hash = self.current_head_hash() if _log_has_entries(self.log_path) else GENESIS_HASH

        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user_id": hashlib.sha256(user_id.encode("utf-8")).hexdigest(),
            "sanitized_payload": sanitized,
            "payload_hash": hashlib.sha256(sanitized.encode("utf-8")).hexdigest(),
            "previous_entry_hash": previous_hash,
        }
        entry_hash = compute_entry_hash(previous_hash, record)
        record["entry_hash"] = entry_hash
        record["signature_ed25519"] = self.private_key.sign(entry_hash.encode("utf-8")).hex()

        # A final line without a newline would otherwise be joined to the new record.
        prefix = ""
        if os.path.exists(self.log_path) and os.path.getsize(self.log_path) > 0:
            with open(self.log_path, "rb") as f:
                f.seek(-1, os.SEEK_END)
                if f.read(1) != b"\n":
                    prefix = "\n"
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(prefix + json.dumps(record) + "\n")

        return sanitized

    def verify_log(self, expected_head_hash=None) -> bool:
        """Verifies the log under this instance's public key. See `verify_log_file`."""
        return verify_log_file(self.log_path, self.public_key_bytes(), expected_head_hash)


if __name__ == "__main__":
    prompts = [
        "Summarize the medical history for John Doe, contact j.doe@acmehealth.org. SSN 123-45-6789.",
        "Draft a reply to +49 151 2345678 regarding invoice DE89370400440532013000.",
    ]
    with tempfile.TemporaryDirectory() as workdir:
        log_path = os.path.join(workdir, "audit_trail.jsonl")
        tool = PromptSanitizer(log_path=log_path, key_path=os.path.join(workdir, "signing_key.raw"))

        print("--- Sanitizing prompts ---")
        for i, p in enumerate(prompts, 1):
            print(f"[{i}] {tool.process_prompt(user_id=f'usr_{i}', raw_prompt=p)}")

        public_key = tool.public_key_bytes()
        head = tool.current_head_hash()
        print("\n--- Verifying with the public key only ---")
        ok = verify_log_file(log_path, public_key)
        print("Structure, chain and signatures valid" if ok else "TAMPERED OR CORRUPT")

        print("\n--- Dropping the last entry ---")
        with open(log_path, encoding="utf-8") as f:
            first_line = f.readline()
        with open(log_path, "w", encoding="utf-8") as f:
            f.write(first_line)
        print("Without a retained head hash:", "valid" if verify_log_file(log_path, public_key) else "invalid")
        print("With the retained head hash: ", "valid" if verify_log_file(log_path, public_key, head) else "invalid")
