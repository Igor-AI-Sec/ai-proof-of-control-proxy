# Deterministic AI Privacy Firewall & Proof-of-Control

A Zero-Trust Middleware for LLM PII Sanitization. 
This script intercepts prompts, redacts sensitive data, and implements Cryptographic Proof-of-Control (via Ed25519) to generate immutable audit logs.

## Regulatory & Compliance Mapping
* **EU AI Act:** Article 12 (Record-keeping automation)
* **CSA AICM v1.0.3:** Domain DSP-01 (Data Security & Privacy)

## How to test locally (Clean Room Simulation)
1. Install dependencies:
   `pip install -r requirements.txt`
2. Run the proxy script:
   `python sanitizer_proxy.py`
