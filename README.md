# LLM Prompt Sanitizer with Hash-Chained, Signed Logging (Prototype)

A small Python prototype exploring one idea: before a user prompt reaches an LLM, strip out common PII, then produce a tamper-evident, signed log of what was sent — one you can independently re-verify later.

## What it actually does

1. **Redacts PII via regex**: US-format SSNs, email addresses, international phone numbers, IBANs, and credit-card-shaped digit sequences. This is deterministic pattern matching, not NLP — it will miss names, physical addresses, and anything that doesn't match these shapes, and it will occasionally flag things that aren't PII.
2. **Hashes and chains** each log entry: every entry's hash includes the previous entry's hash, so editing, deleting, or reordering any past entry breaks the chain from that point forward.
3. **Signs** each entry with a persistent Ed25519 keypair (generated once, then loaded from disk on subsequent runs).
4. **Verifies**: `verify_log()` walks the whole file, recomputes every hash, and checks every signature. Tested by deliberately corrupting a log entry — the tool correctly reports the break and the exact line.

## What this proves, and what it doesn't

- **Proves**: if `verify_log()` passes, no entry in the log has been added, removed, reordered, or edited since it was written — that's a real, tested guarantee, not just an aspiration.
- **Does not prove**: that "no sensitive data reached the model." Redaction only catches the patterns listed above; anything outside that shape passes through untouched. Broader coverage would need an NLP-based detector (e.g. Presidio) — this doesn't replace one.
- **Is not** a network middleware or proxy — it's a Python class called in-process. There's no traffic interception here (yet).

## What this is not

This is a prototype exploring one small, real piece of a bigger problem (PII in LLM prompts + tamper-evident logging), not a compliance product. It does not implement, satisfy, or certify compliance with the EU AI Act, the CSA AI Controls Matrix, or any other regulatory framework — no single script can, and claiming otherwise would be dishonest. If you're working toward actual compliance, "redact → hash-chain → sign → verify" is one honest building block among many you'd need, not a solution.

## Security note

`signing_key.raw` is generated locally and **must never be committed to version control** — anyone holding it could forge validly-signed entries. Add it to `.gitignore` before pushing. In anything beyond a local prototype, keys belong in a proper KMS/secrets manager, not a flat file.

## Ideas for extending this
- Swap the regex layer for a real NLP-based PII detector
- Move key storage to a KMS
- Add a small CLI wrapper instead of calling the class directly

## How to run
```
pip install -r requirements.txt
python sanitizer_proxy.py
```

## License
MIT
