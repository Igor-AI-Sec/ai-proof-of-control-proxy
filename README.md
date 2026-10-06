# Prompt sanitizer with a signed hash-chain log

An in-process Python prototype, not a network proxy. It does not intercept traffic, call an LLM, or send anything anywhere. One class redacts a few regex-defined PII shapes from a string and appends a signed, hash-chained record of the sanitized result to a local file. A verifier can check that file later using only a public key.

The repository name is historical. There is no proxy here.

## What it does

1. **Redacts** five PII shapes with regular expressions (see the limits below).
2. **Logs** one JSON line per call to `process_prompt()`, holding the sanitized payload, its SHA-256, a hash of the user id, the previous entry hash, an entry hash and an Ed25519 signature over the entry hash.
3. **Verifies** the file with `verify_log_file(log_path, public_key_bytes, expected_head_hash=None)`. It needs no private key and creates no files.

## What `process_prompt()` does and does not show

It sanitizes one string, logs the sanitized payload it produced, and returns that payload. The log is a record of what this function produced.

It does not show what a caller did next. A caller can discard the returned value, send something else, or send nothing, and the log still verifies. Nothing here proves what reached an LLM.

## What verification checks

For every nonblank line, the verifier requires a JSON object with exactly the expected fields and types. It then checks that:

- `previous_entry_hash` equals the hash of the preceding entry, and the first entry uses the genesis value (64 zeros)
- `payload_hash` equals the SHA-256 of `sanitized_payload`
- the entry hash matches a recomputation over the entry and the running previous hash
- the Ed25519 signature is valid under the public key you supplied

Malformed or corrupt log content returns `False` with a line-numbered reason on stderr. The reason never includes entry contents. A malformed public key or a malformed `expected_head_hash` argument raises `ValueError` instead, because that is a caller error and not a property of the log. Blank lines are ignored.

Timestamps are checked for valid ISO 8601 syntax only. They are self-asserted record data. The verifier does not establish trusted time, ordering by wall-clock time, or where a timestamp came from. A missing or empty log is a valid empty history, and the verifier treats the genesis hash as its head.

## What it can and cannot detect

| Change to the log | Without a retained head hash | With a retained head hash |
|---|---|---|
| Edited content, timestamp, user id or hash fields | detected | detected |
| Edited or invalid signature | detected | detected |
| Reordered or duplicated entries | detected | detected |
| Inserted entry without the signing key | detected | detected |
| Deleted first or middle entry | detected | detected |
| Removed last entry, or any valid suffix | **not detectable** | detected |
| Truncation to an older valid prefix | **not detectable** | detected |
| Emptied or deleted log | **not detectable** (an empty history is valid) | detected |

A hash chain only ties each entry to the ones before it. It cannot show that later entries ever existed. A valid empty or shortened log does not prove that a longer history did not exist.

To detect truncation, keep the head hash somewhere separate from the log and trusted on its own, such as another system or a signed external record. `PromptSanitizer.current_head_hash()` returns the value to keep, and `verify_log_file(..., expected_head_hash=...)` checks it. A checkpoint stored in the same file as the log protects nothing, because whoever can truncate the log can also change it.

How a checkpoint behaves:

- `expected_head_hash` is compared for exact equality with the final verified entry hash. A checkpoint is one specific known head.
- If valid entries are appended after the checkpoint was retained, the old checkpoint no longer matches the grown log. To keep a current completeness check, retain the new head after each trusted append.
- A checkpoint shows completeness only relative to the point in history when it was retained. It says nothing about entries added and then removed after that point.
- Capture `current_head_hash()` while the trusted history is intact. Called after an undetected suffix truncation, it returns the head of the truncated prefix and cannot reveal the missing suffix.
- `process_prompt()` does not take a checkpoint. A valid prefix can therefore be extended into a new, internally valid branch, and only the previously retained head checkpoint rejects that rewritten branch.

## Trust in the signing key

A valid signature shows that the holder of some key signed the entry. It shows that the original signer wrote it only if you obtained the public key from a source you trust separately from the log.

If you supply the public key you retained earlier, a log rewritten with a different key fails. If you take the public key from the same place as the log, or generate one at verification time, a rewritten log can verify. Whoever holds the private key can also create new valid history, including entries that replace older ones if no head hash was retained.

`PromptSanitizer.public_key_bytes()` returns the raw 32-byte public key to keep.

## Private key storage

`signing_key.raw` is the raw 32-byte Ed25519 private key in an unencrypted file, created with owner-only permissions where the platform honours them. This is for a local prototype. A real system keeps signing keys in a KMS, HSM or secrets manager. The file is listed in `.gitignore` and should never be committed.

A new key is created only for a new, empty history. If the log already has entries and the key file is missing, the constructor raises an error instead of starting a different signing identity.

## Appending

`process_prompt()` verifies the existing log under the current key before appending and refuses if it fails. That stops a known-corrupt history from being extended. It cannot reveal entries removed from the end of the log. There is no file locking, so concurrent writers can produce a log that fails verification, and a crash during a write can leave a partial final line that blocks further appends until it is repaired.

## Redaction limits

The patterns are deliberately simple regular expressions:

- hyphenated US SSNs such as `123-45-6789`
- ASCII-style email addresses
- phone numbers that start with `+`
- compact uppercase IBANs
- 13 to 16 digit sequences, with optional spaces or hyphens, as credit-card shapes

It does not detect names or street addresses. It does not reliably handle lowercase or spaced IBANs, phone numbers without a leading `+`, SSNs without hyphens, or unusual and Unicode email forms (a Unicode local part can be partly left behind). The card pattern has no Luhn check, so unrelated 13 to 16 digit numbers such as order ids or timestamps are replaced, and sequences of 12 or 17 or more digits are not. Some inputs get a misleading label, for example a spaced IBAN can be partly replaced as a card number, and a phone number written with a `00` prefix instead of `+` can match the card pattern and be labelled as a card. This is not general PII detection. Use an NLP-based detector such as Presidio for that.

## User id hashing

The stored `user_id` is an unsalted SHA-256 of the identifier you pass in. It is deterministic, so the same user is linkable across entries, and identifiers from a small or predictable space can be guessed by hashing candidates. It is pseudonymous, not anonymous.

## Scope

This does not implement, satisfy or certify compliance with the EU AI Act, the CSA AI Controls Matrix or any other framework. It is one small building block: redact, hash-chain, sign and verify a local file.

## How to run

```
pip install -r requirements.txt
python sanitizer_proxy.py
python -m unittest discover -s tests -v
```

The demo works in a temporary directory and leaves no log or key behind. The tests use temporary directories and throwaway keys only.
