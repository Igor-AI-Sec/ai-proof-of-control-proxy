import json
import hashlib
import re
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

class AIPrivacyFirewall:
    """
    Zero-Trust Middleware for LLM PII Sanitization.
    Implements Cryptographic Proof-of-Control for EU AI Act Article 12 Compliance.
    Maps to CSA AICM v1.0.3 Domain: Data Security & Privacy (DSP).
    """

    def __init__(self, log_path: str = "audit_trail.jsonl"):
        self.log_path = log_path
        # In a production environment, keys are fetched from a secure KMS.
        # Generating ephemeral keys here for zero-friction demonstration.
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        
        # Simulated Regex-based PII detection (Drop-in replacement for Microsoft Presidio)
        self.pii_patterns = {
            "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
            "EMAIL": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        }

    def _sanitize_payload(self, text: str) -> str:
        """Redacts sensitive information based on defined patterns."""
        sanitized_text = text
        for pii_type, pattern in self.pii_patterns.items():
            sanitized_text = re.sub(pattern, f"[REDACTED_{pii_type}]", sanitized_text)
        return sanitized_text

    def _sign_payload(self, payload: str) -> str:
        """Generates an Ed25519 cryptographic signature for the sanitized payload."""
        signature = self.private_key.sign(payload.encode('utf-8'))
        return signature.hex()

    def process_prompt(self, user_id: str, raw_prompt: str) -> str:
        """
        Intercepts the prompt, sanitizes it, and generates an immutable audit log.
        """
        # 1. Sanitize
        sanitized_prompt = self._sanitize_payload(raw_prompt)
        
        # 2. Cryptographic Hashing & Signing (Proof-of-Control)
        payload_hash = hashlib.sha256(sanitized_prompt.encode('utf-8')).hexdigest()
        signature = self._sign_payload(payload_hash)
        
        # 3. CSA AICM Mapped Audit Log Generation
        audit_event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "PII_SANITIZATION",
            "framework_mapping": {
                "regulation": "EU_AI_ACT_ART_12",
                "csa_aicm_v1.0.3": "DSP-01" 
            },
            "user_id": hashlib.sha256(user_id.encode('utf-8')).hexdigest(), # Pseudonymized
            "original_length": len(raw_prompt),
            "sanitized_payload": sanitized_prompt,
            "payload_hash": payload_hash,
            "signature_ed25519": signature,
            "public_key": self.public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ).hex()
        }

        # 4. Append to immutable flat file (.jsonl)
        with open(self.log_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(audit_event) + "\n")

        return sanitized_prompt

# ==========================================
# Demonstration (Clean Room Simulation)
# ==========================================
if __name__ == "__main__":
    firewall = AIPrivacyFirewall()
    
    # Synthetic, fictitious prompt data
    synthetic_prompt = "Please summarize the medical history for John Doe, contact him at j.doe@acmehealth.org. His SSN is 123-45-6789."
    
    print("--- Intercepting Raw LLM Prompt ---")
    safe_prompt = firewall.process_prompt(user_id="usr_9982", raw_prompt=synthetic_prompt)
    
    print(f"Sanitized Prompt sent to LLM:\n> {safe_prompt}\n")
    print("Audit log successfully appended to 'audit_trail.jsonl'.")
