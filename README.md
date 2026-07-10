Title: I built a tool to prove my AI redaction logs weren't tampered with. It doesn't prove the redaction worked.

Subtitle: A hash-chained signature system, broken on purpose to see if it would notice — and the harder problem hiding underneath.

---

Anyone who has put real users in front of an LLM has had this thought at 2am: someone is going to paste a customer's SSN, or their own, straight into a prompt. You can tell people not to. They will anyway.

So I built something small: a script that sits between a prompt and the model, strips out anything that looks like an SSN, email, phone number, IBAN, or card number, and — this is the part I actually cared about — signs and logs what it did, in a way you could later prove wasn't quietly edited afterward.

I built it. It works. Then I tried to break it on purpose, and that's where it got interesting.

## What it actually does

Nothing exotic. Five regex patterns catch the obvious shapes of PII and replace them with `[REDACTED_X]`. Each redacted prompt gets hashed, and each hash gets folded into the previous one — a chain, the same basic idea a git history or a ledger uses. The chain is signed with an Ed25519 key, loaded from disk so it persists across runs instead of resetting every time. A separate function walks the whole log afterward and tells you if anything broke.

## The test: I tried to lie to my own log

The obvious question for anything claiming "tamper-evident" is whether it actually notices tampering, or just says it does.

So I ran the script twice — two separate runs, loading the same key from disk both times, the way it would work in real use — producing four log entries. Then I opened the log file directly and edited one line in the middle: appended a few words to an already-logged prompt, the kind of quiet edit someone might make if they realized afterward they'd logged something they shouldn't have.

Ran the verifier. `Chain broken at line 2.` Caught immediately, and it named the exact line.

That's a lower bar than it sounds like, and I want to be honest about why it's not nothing either. A single signature on a single entry only ever proves that one entry wasn't changed after signing — it says nothing if someone deletes an entire earlier entry and leaves the rest alone. Chaining is the part that closes that gap: touch anything, and every entry downstream stops verifying. That's the actual claim now, tested instead of asserted.

## What this doesn't prove — and this is the part that matters more

Here's the twist I didn't expect going in.

A clean pass from the verifier tells you the log wasn't touched after it was written. It tells you *nothing* about whether the redaction step upstream caught everything it should have.

My five patterns catch a US Social Security Number, an email, a phone number, an IBAN, a card-shaped run of digits. They do not catch a name. They do not catch "the guy who lives on Rosenstraße." They do not catch anything shaped slightly differently than I guessed. Regex matches shape, not meaning — that's the entire limitation of the approach, and no amount of hashing or signing touches it.

So you can have a perfectly verified, perfectly tamper-evident log of a prompt that still contains someone's home address, sitting right there in plain text, cryptographically signed and provably untouched since the moment it was written. The signature proves the wrong thing looks fine. It was never built to check the right thing.

It's the same shape of problem as checking whether a link is alive versus whether the page behind it says what was claimed. Verifying *that something happened as recorded* is a much easier problem than verifying *that the right thing happened in the first place*. I built the easy half first, because it's the half you can actually test by trying to break it. The hard half needs a real PII detector — the kind of NLP-based tool (Presidio and similar) that understands context, not just shape — and that's a different, much bigger project than a weekend script.

## What I'm not claiming

No regulatory framework gets satisfied by a personal script, and I'm not going to pretend otherwise here. This doesn't make anything "EU AI Act compliant" or map cleanly onto any control framework — compliance is an organizational and legal outcome, not a side effect of importing a crypto library. What it is: a small, honestly-scoped demonstration that hash-chained signing is a real, checkable way to make a log tamper-evident, and a reminder to myself that tamper-evidence and correctness are two completely different guarantees that are easy to blur together in a README.

## In the end

I set out to build a small proof that a log wasn't touched after the fact. I got that, and I tested it hard enough to actually believe it. What I didn't get — and didn't set out to get, which is exactly the problem — is any proof that the thing being logged was safe in the first place. Tamper-evidence and correctness sound like they pull in the same direction. They don't. One's a lock on the door; the other is knowing what's in the room. I only built the lock.

Code's on [GitHub](https://github.com/Igor-AI-Sec/ai-proof-of-control-proxy), including the exact steps to reproduce the tampering test above. Fork it, break it worse than I did, tell me what I missed.
