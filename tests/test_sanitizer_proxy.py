import contextlib
import copy
import hashlib
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

# The module under test sits in the repository root, which is not on the path
# when discovery starts in tests/.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from sanitizer_proxy import GENESIS_HASH, PromptSanitizer, compute_entry_hash, verify_log_file


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def raw_public_key(private_key):
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )


class TempDirCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="sanitizer_test_")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

    def path(self, name):
        return os.path.join(self.dir, name)

    def make_log(self, count=4, tag="log"):
        log, key = self.path(tag + ".jsonl"), self.path(tag + ".key")
        tool = PromptSanitizer(log_path=log, key_path=key)
        for i in range(1, count + 1):
            tool.process_prompt(f"usr_{i}", f"prompt {i} for a{i}@example.org")
        return tool

    @staticmethod
    def read_entries(log):
        with open(log, encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    @staticmethod
    def write_entries(log, entries):
        with open(log, "w", encoding="utf-8") as f:
            for entry in entries:
                f.write(json.dumps(entry) + "\n")

    def verify(self, tool, expected_head_hash=None):
        """Returns (result, stderr text) and fails the test if verification raises."""
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            result = tool.verify_log(expected_head_hash)
        return result, err.getvalue()

    def forge(self, private_key, builders, tag="forged"):
        """Writes correctly signed records built by `builders`, each called with
        the running previous hash. The records can be internally inconsistent."""
        log = self.path(tag + ".jsonl")
        previous, entries = GENESIS_HASH, []
        for build in builders:
            record = build(previous)
            entry_hash = compute_entry_hash(previous, record)
            record["entry_hash"] = entry_hash
            record["signature_ed25519"] = private_key.sign(entry_hash.encode("utf-8")).hex()
            entries.append(record)
            previous = entry_hash
        self.write_entries(log, entries)
        return log


def good_record(payload, previous):
    return {
        "timestamp": "2026-01-01T00:00:00+00:00",
        "user_id": sha("u"),
        "sanitized_payload": payload,
        "payload_hash": sha(payload),
        "previous_entry_hash": previous,
    }


class TestRedaction(TempDirCase):
    def setUp(self):
        super().setUp()
        self.tool = PromptSanitizer(self.path("r.jsonl"), self.path("r.key"))

    def check(self, text, expected):
        self.assertEqual(self.tool._sanitize(text), expected)

    def test_hyphenated_us_ssn(self):
        self.check("SSN 123-45-6789 end", "SSN [REDACTED_SSN_US] end")

    def test_ascii_email(self):
        self.check("mail j.doe+tag@sub.example.co.uk now", "mail [REDACTED_EMAIL] now")

    def test_plus_prefixed_international_phone(self):
        self.check("call +49 151 2345678 today", "call [REDACTED_PHONE_INTL] today")
        self.check("+1-415-555-0132", "[REDACTED_PHONE_INTL]")

    def test_compact_uppercase_iban(self):
        self.check("invoice DE89370400440532013000", "invoice [REDACTED_IBAN]")

    def test_credit_card_shaped_sequences(self):
        for text in ("4111111111111111", "4111-1111-1111-1111", "4111 1111 1111 1111", "378282246310005"):
            with self.subTest(text=text):
                self.check(text, "[REDACTED_CREDIT_CARD]")

    def test_prompt_with_several_shapes(self):
        out = self.tool._sanitize("a@b.org 123-45-6789 +49 151 2345678")
        self.assertEqual(out, "[REDACTED_EMAIL] [REDACTED_SSN_US] [REDACTED_PHONE_INTL]")

    def test_limit_names_and_addresses_are_not_detected(self):
        text = "John Doe lives at 12 Rosenstrasse"
        self.check(text, text)

    def test_limit_lowercase_iban_is_not_detected(self):
        self.check("de89370400440532013000", "de89370400440532013000")

    def test_limit_spaced_iban_is_not_reliably_handled(self):
        self.assertNotEqual(self.tool._sanitize("DE89 3704 0044 0532 0130 00"), "[REDACTED_IBAN]")

    def test_limit_phone_without_plus_is_not_detected(self):
        self.check("0151 2345678", "0151 2345678")

    def test_limit_unicode_email_is_not_fully_handled(self):
        email = "j" + chr(0xFC) + "rgen@bank.de"
        self.assertNotEqual(self.tool._sanitize(email), "[REDACTED_EMAIL]")

    def test_limit_ssn_without_hyphens_is_not_detected(self):
        self.check("123456789", "123456789")

    def test_limit_card_pattern_has_no_luhn_check(self):
        self.check("order 1234567890123456", "order [REDACTED_CREDIT_CARD]")

    def test_limit_sequences_outside_13_to_16_digits_are_not_matched(self):
        for text in ("123456789012", "12345678901234567"):
            with self.subTest(text=text):
                self.check(text, text)


class TestLogging(TempDirCase):
    def test_single_entry_fields_and_hashes(self):
        tool = self.make_log(1)
        (entry,) = self.read_entries(tool.log_path)
        self.assertEqual(entry["previous_entry_hash"], GENESIS_HASH)
        self.assertEqual(entry["payload_hash"], sha(entry["sanitized_payload"]))
        core = {k: v for k, v in entry.items() if k not in ("entry_hash", "signature_ed25519")}
        self.assertEqual(entry["entry_hash"], compute_entry_hash(GENESIS_HASH, core))
        self.assertTrue(self.verify(tool)[0])

    def test_several_entries_chain_to_each_other(self):
        tool = self.make_log(4)
        entries = self.read_entries(tool.log_path)
        self.assertEqual(entries[0]["previous_entry_hash"], GENESIS_HASH)
        for before, after in zip(entries, entries[1:]):
            self.assertEqual(after["previous_entry_hash"], before["entry_hash"])
        self.assertTrue(self.verify(tool)[0])

    def test_return_value_equals_logged_payload(self):
        tool = PromptSanitizer(self.path("a.jsonl"), self.path("a.key"))
        returned = tool.process_prompt("u", "write to x@example.org, SSN 123-45-6789")
        (entry,) = self.read_entries(tool.log_path)
        self.assertEqual(returned, entry["sanitized_payload"])
        self.assertEqual(returned, "write to [REDACTED_EMAIL], SSN [REDACTED_SSN_US]")

    def test_raw_prompt_is_not_written_to_the_log(self):
        tool = PromptSanitizer(self.path("a.jsonl"), self.path("a.key"))
        tool.process_prompt("alice", "SSN 123-45-6789")
        with open(tool.log_path, encoding="utf-8") as f:
            content = f.read()
        self.assertNotIn("123-45-6789", content)
        self.assertNotIn("alice", content)

    def test_log_records_only_what_the_function_produced(self):
        tool = PromptSanitizer(self.path("a.jsonl"), self.path("a.key"))
        raw = "SSN 123-45-6789"
        tool.process_prompt("u", raw)  # return value discarded
        caller_sends = raw  # nothing ties the log to what a caller sends
        (entry,) = self.read_entries(tool.log_path)
        self.assertNotEqual(entry["sanitized_payload"], caller_sends)
        self.assertTrue(self.verify(tool)[0])

    def test_second_instance_loads_same_key_and_extends_log(self):
        first = self.make_log(2)
        second = PromptSanitizer(first.log_path, first.key_path)
        self.assertEqual(second.public_key_bytes(), first.public_key_bytes())
        second.process_prompt("usr_3", "later")
        self.assertEqual(len(self.read_entries(first.log_path)), 3)
        self.assertTrue(self.verify(second)[0])

    def test_user_id_is_unsalted_and_linkable(self):
        tool = PromptSanitizer(self.path("a.jsonl"), self.path("a.key"))
        tool.process_prompt("usr_7", "one")
        tool.process_prompt("usr_7", "two")
        first, second = self.read_entries(tool.log_path)
        self.assertEqual(first["user_id"], sha("usr_7"))
        self.assertEqual(first["user_id"], second["user_id"])

    def test_key_file_is_32_raw_bytes(self):
        tool = self.make_log(1)
        self.assertEqual(os.path.getsize(tool.key_path), 32)

    @unittest.skipUnless(os.name == "posix", "permission bits are only meaningful on POSIX")
    def test_key_file_is_not_group_or_world_accessible(self):
        tool = self.make_log(1)
        self.assertEqual(os.stat(tool.key_path).st_mode & 0o077, 0)

    def test_appends_after_a_final_line_without_newline(self):
        tool = self.make_log(2)
        with open(tool.log_path, encoding="utf-8") as f:
            content = f.read()
        with open(tool.log_path, "w", encoding="utf-8", newline="") as f:
            f.write(content.rstrip("\r\n"))
        tool.process_prompt("u", "next")
        self.assertEqual(len(self.read_entries(tool.log_path)), 3)
        self.assertTrue(self.verify(tool)[0])


class TestTampering(TempDirCase):
    def setUp(self):
        super().setUp()
        self.tool = self.make_log(5)
        self.pristine = self.read_entries(self.tool.log_path)

    def assert_detected(self, entries):
        self.write_entries(self.tool.log_path, entries)
        result, err = self.verify(self.tool)
        self.assertFalse(result)
        self.assertTrue(err.strip())

    def mutated(self, field, new_value, index=1):
        entries = copy.deepcopy(self.pristine)
        entries[index][field] = new_value
        return entries

    def test_pristine_log_verifies(self):
        self.assertTrue(self.verify(self.tool)[0])

    def test_edited_fields_are_detected(self):
        flip = lambda h: ("0" if h[0] != "0" else "1") + h[1:]
        edits = {
            "sanitized_payload": self.pristine[1]["sanitized_payload"] + " x",
            "timestamp": "2020-01-01T00:00:00+00:00",
            "user_id": flip(self.pristine[1]["user_id"]),
            "payload_hash": flip(self.pristine[1]["payload_hash"]),
            "previous_entry_hash": flip(self.pristine[1]["previous_entry_hash"]),
            "entry_hash": flip(self.pristine[1]["entry_hash"]),
        }
        for field, value in edits.items():
            with self.subTest(field=field):
                self.assert_detected(self.mutated(field, value))

    def test_flipped_signature_digit_is_detected(self):
        sig = self.pristine[1]["signature_ed25519"]
        self.assert_detected(self.mutated("signature_ed25519", ("0" if sig[0] != "0" else "1") + sig[1:]))

    def test_invalid_signature_hex_is_detected(self):
        self.assert_detected(self.mutated("signature_ed25519", "zz" + self.pristine[1]["signature_ed25519"][2:]))

    def test_reordered_entries_are_detected(self):
        entries = copy.deepcopy(self.pristine)
        entries[1], entries[2] = entries[2], entries[1]
        self.assert_detected(entries)

    def test_duplicated_entry_is_detected(self):
        entries = copy.deepcopy(self.pristine)
        entries.insert(2, copy.deepcopy(entries[1]))
        self.assert_detected(entries)

    def test_arbitrary_inserted_object_is_detected(self):
        entries = copy.deepcopy(self.pristine)
        entries.insert(2, {"anything": 1})
        self.assert_detected(entries)

    def test_inserted_entry_without_the_key_is_detected(self):
        entries = copy.deepcopy(self.pristine)
        forged = copy.deepcopy(entries[1])
        forged["sanitized_payload"] = "forged"
        forged["payload_hash"] = sha("forged")
        entries.insert(2, forged)
        self.assert_detected(entries)

    def test_front_deletion_is_detected(self):
        self.assert_detected(self.pristine[1:])

    def test_middle_deletion_is_detected(self):
        self.assert_detected(self.pristine[:2] + self.pristine[3:])


class TestTruncationLimit(TempDirCase):
    def setUp(self):
        super().setUp()
        self.tool = self.make_log(5)
        self.pristine = self.read_entries(self.tool.log_path)
        self.head = self.tool.current_head_hash()

    def truncated(self, keep):
        self.write_entries(self.tool.log_path, self.pristine[:keep])

    def test_head_hash_is_the_last_entry_hash(self):
        self.assertEqual(self.head, self.pristine[-1]["entry_hash"])

    def test_pristine_log_matches_its_checkpoint(self):
        self.assertTrue(self.verify(self.tool, self.head)[0])

    def test_suffix_removal_verifies_without_a_checkpoint(self):
        for keep in (4, 3, 2, 1):
            with self.subTest(kept=keep):
                self.truncated(keep)
                self.assertTrue(self.verify(self.tool)[0])

    def test_suffix_removal_fails_against_the_retained_checkpoint(self):
        for keep in (4, 3, 2, 1):
            with self.subTest(kept=keep):
                self.truncated(keep)
                result, err = self.verify(self.tool, self.head)
                self.assertFalse(result)
                self.assertIn("head", err)

    def test_emptied_log_verifies_without_a_checkpoint_and_fails_with_one(self):
        self.truncated(0)
        self.assertTrue(self.verify(self.tool)[0])
        self.assertFalse(self.verify(self.tool, self.head)[0])

    def test_deleted_log_verifies_without_a_checkpoint_and_fails_with_one(self):
        os.remove(self.tool.log_path)
        self.assertTrue(self.verify(self.tool)[0])
        self.assertFalse(self.verify(self.tool, self.head)[0])

    def test_empty_history_matches_the_genesis_checkpoint(self):
        os.remove(self.tool.log_path)
        self.assertEqual(self.tool.current_head_hash(), GENESIS_HASH)
        self.assertTrue(self.verify(self.tool, GENESIS_HASH)[0])

    def test_malformed_checkpoint_is_a_caller_error(self):
        for bad in ("abc", "G" * 64, "A" * 64, 5, b"0" * 64):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    self.tool.verify_log(bad)


class TestKeyTrust(TempDirCase):
    def setUp(self):
        super().setUp()
        self.tool = self.make_log(3)
        self.pinned = self.tool.public_key_bytes()

    def test_pinned_public_key_verifies_original_log(self):
        self.assertTrue(verify_log_file(self.tool.log_path, self.pinned))

    def test_replacement_public_key_fails_original_log(self):
        other = ed25519.Ed25519PrivateKey.generate()
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertFalse(verify_log_file(self.tool.log_path, raw_public_key(other)))
        self.assertIn("signature", err.getvalue())

    def test_rewritten_history_verifies_only_under_the_replacement_key(self):
        replacement = PromptSanitizer(self.path("evil.jsonl"), self.path("evil.key"))
        for i in range(3):
            replacement.process_prompt("someone", f"fabricated {i}")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertTrue(verify_log_file(replacement.log_path, replacement.public_key_bytes()))
            self.assertFalse(verify_log_file(replacement.log_path, self.pinned))

    def test_public_key_only_verification_creates_no_files(self):
        before = sorted(os.listdir(self.dir))
        self.assertTrue(verify_log_file(self.tool.log_path, self.pinned, self.tool.current_head_hash()))
        self.assertTrue(verify_log_file(self.path("absent.jsonl"), self.pinned))
        self.assertEqual(sorted(os.listdir(self.dir)), before)

    def test_malformed_public_key_is_rejected_clearly(self):
        for bad in (b"", b"x" * 31, b"x" * 33, "a" * 32, None, 5):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    verify_log_file(self.tool.log_path, bad)

    def test_missing_private_key_with_existing_log_is_refused(self):
        os.remove(self.tool.key_path)
        with self.assertRaises(FileNotFoundError):
            PromptSanitizer(self.tool.log_path, self.tool.key_path)
        self.assertFalse(os.path.exists(self.tool.key_path))

    def test_missing_private_key_is_created_for_a_new_history(self):
        key = self.path("new.key")
        PromptSanitizer(self.path("new.jsonl"), key)
        self.assertEqual(os.path.getsize(key), 32)

    def test_missing_private_key_is_created_when_the_log_has_no_entries(self):
        log, key = self.path("blank.jsonl"), self.path("blank.key")
        with open(log, "w", encoding="utf-8") as f:
            f.write("\n  \n")
        PromptSanitizer(log, key)
        self.assertTrue(os.path.exists(key))

    def test_malformed_private_key_file_is_rejected(self):
        for size in (0, 31, 33):
            with self.subTest(size=size):
                key = self.path(f"bad{size}.key")
                with open(key, "wb") as f:
                    f.write(b"x" * size)
                with self.assertRaises(ValueError):
                    PromptSanitizer(self.path("k.jsonl"), key)


class TestMalformedInput(TempDirCase):
    def setUp(self):
        super().setUp()
        self.tool = self.make_log(3)
        self.pristine = self.read_entries(self.tool.log_path)

    def assert_false_cleanly(self, content):
        with open(self.tool.log_path, "w", encoding="utf-8", newline="") as f:
            f.write(content)
        result, err = self.verify(self.tool)
        self.assertFalse(result)
        self.assertNotIn("Traceback", err)
        for secret in ("prompt ", "example.org", "REDACTED"):
            self.assertNotIn(secret, err)

    def lines(self):
        return [json.dumps(e) + "\n" for e in self.pristine]

    def test_malformed_json_line(self):
        lines = self.lines()
        self.assert_false_cleanly(lines[0] + lines[1][:250] + "\n" + lines[2])

    def test_non_object_json_lines(self):
        for bad in ("[1, 2]", "5", '"text"', "null", "true"):
            with self.subTest(bad=bad):
                self.assert_false_cleanly(self.lines()[0] + bad + "\n")

    def test_each_missing_field(self):
        for field in self.pristine[0]:
            with self.subTest(field=field):
                entries = copy.deepcopy(self.pristine)
                del entries[1][field]
                self.assert_false_cleanly("".join(json.dumps(e) + "\n" for e in entries))

    def test_unexpected_extra_field(self):
        entries = copy.deepcopy(self.pristine)
        entries[1]["extra"] = "x"
        self.assert_false_cleanly("".join(json.dumps(e) + "\n" for e in entries))

    def test_wrong_field_types(self):
        for field in self.pristine[0]:
            for value in (5, None, ["x"], {"a": 1}):
                with self.subTest(field=field, value=value):
                    entries = copy.deepcopy(self.pristine)
                    entries[1][field] = value
                    self.assert_false_cleanly("".join(json.dumps(e) + "\n" for e in entries))

    def test_badly_shaped_hex_and_timestamp(self):
        for field, value in (
            ("entry_hash", "ab"),
            ("entry_hash", self.pristine[1]["entry_hash"].upper()),
            ("previous_entry_hash", "g" * 64),
            ("signature_ed25519", "ab" * 10),
            ("signature_ed25519", " " + self.pristine[1]["signature_ed25519"][1:]),
            ("timestamp", "yesterday"),
        ):
            with self.subTest(field=field, value=value[:8]):
                entries = copy.deepcopy(self.pristine)
                entries[1][field] = value
                self.assert_false_cleanly("".join(json.dumps(e) + "\n" for e in entries))

    def test_invalid_utf8(self):
        with open(self.tool.log_path, "wb") as f:
            f.write(b"\xff\xfe\x00 not utf-8\n")
        result, err = self.verify(self.tool)
        self.assertFalse(result)
        self.assertNotIn("Traceback", err)

    def surrogate_line(self):
        """A record whose payload is the JSON escape for a lone surrogate. The
        escape is built from ASCII so no surrogate appears in the test source."""
        line = json.dumps(self.pristine[1])
        payload = json.dumps(self.pristine[1]["sanitized_payload"])
        self.assertIn(payload, line)
        return line.replace(payload, '"bad\\ud800"')

    def test_lone_surrogate_payload_is_invalid_log_content(self):
        lines = self.lines()
        content = lines[0] + self.surrogate_line() + "\n" + lines[2]
        with open(self.tool.log_path, "w", encoding="utf-8", newline="") as f:
            f.write(content)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            result = self.tool.verify_log()
        self.assertFalse(result)
        self.assertEqual(out.getvalue(), "")
        self.assertIn("Line 2", err.getvalue())
        self.assertIn("UTF-8", err.getvalue())
        self.assertNotIn("bad", err.getvalue())
        self.assertNotIn("Traceback", err.getvalue())

    def test_lone_surrogate_history_is_corrupt_for_head_and_append(self):
        lines = self.lines()
        with open(self.tool.log_path, "w", encoding="utf-8", newline="") as f:
            f.write(lines[0] + self.surrogate_line() + "\n" + lines[2])
        with open(self.tool.log_path, "rb") as f:
            before = f.read()
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(ValueError):
                self.tool.current_head_hash()
            with self.assertRaises(ValueError):
                self.tool.process_prompt("u", "more")
        with open(self.tool.log_path, "rb") as f:
            self.assertEqual(f.read(), before)

    def test_deeply_nested_json(self):
        self.assert_false_cleanly("[" * 100000 + "\n")

    def test_blank_lines_are_ignored(self):
        lines = self.lines()
        with open(self.tool.log_path, "w", encoding="utf-8", newline="") as f:
            f.write("\n" + lines[0] + "\n \n" + "".join(lines[1:]) + "\n\n")
        self.assertTrue(self.verify(self.tool)[0])

    def test_empty_and_whitespace_only_files_are_an_empty_history(self):
        for content in ("", "  \n\t\n"):
            with self.subTest(content=content):
                with open(self.tool.log_path, "w", encoding="utf-8", newline="") as f:
                    f.write(content)
                self.assertTrue(self.verify(self.tool)[0])

    def test_diagnostic_names_the_line(self):
        entries = copy.deepcopy(self.pristine)
        entries[2]["sanitized_payload"] += "x"
        self.write_entries(self.tool.log_path, entries)
        self.assertIn("Line 3", self.verify(self.tool)[1])


class TestSemanticConsistency(TempDirCase):
    def setUp(self):
        super().setUp()
        self.key = ed25519.Ed25519PrivateKey.generate()
        self.public = raw_public_key(self.key)

    def verify_forged(self, builders):
        log = self.forge(self.key, builders)
        with contextlib.redirect_stderr(io.StringIO()) as err:
            return verify_log_file(log, self.public), err.getvalue()

    def test_consistent_signed_log_verifies(self):
        result, _ = self.verify_forged([lambda p: good_record("a", p), lambda p: good_record("b", p)])
        self.assertTrue(result)

    def test_signed_payload_hash_mismatch_fails(self):
        mismatched = lambda p: {**good_record("real text", p), "payload_hash": sha("different text")}
        result, err = self.verify_forged([lambda p: good_record("a", p), mismatched])
        self.assertFalse(result)
        self.assertIn("payload_hash", err)

    def test_signed_wrong_previous_entry_hash_fails(self):
        bogus = lambda p: {**good_record("b", p), "previous_entry_hash": "f" * 64}
        result, err = self.verify_forged([lambda p: good_record("a", p), bogus])
        self.assertFalse(result)
        self.assertIn("previous_entry_hash", err)

    def test_signed_first_entry_must_use_the_genesis_hash(self):
        result, _ = self.verify_forged([lambda p: {**good_record("a", p), "previous_entry_hash": "a" * 64}])
        self.assertFalse(result)

    def test_signed_empty_object_fails(self):
        self.assertFalse(self.verify_forged([lambda p: {}])[0])

    def test_signed_record_with_extra_field_fails(self):
        self.assertFalse(self.verify_forged([lambda p: {**good_record("a", p), "extra": "x"}])[0])


class TestAppendOnCorruptHistory(TempDirCase):
    def test_corrupted_history_refuses_append(self):
        tool = self.make_log(3)
        entries = self.read_entries(tool.log_path)
        entries[1]["sanitized_payload"] += " tampered"
        self.write_entries(tool.log_path, entries)
        with open(tool.log_path, "rb") as f:
            before = f.read()
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(ValueError):
                tool.process_prompt("u", "more")
        with open(tool.log_path, "rb") as f:
            self.assertEqual(f.read(), before)

    def test_partial_final_line_refuses_append(self):
        tool = self.make_log(2)
        with open(tool.log_path, "a", encoding="utf-8") as f:
            f.write('{"half": ')
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(ValueError):
                tool.process_prompt("u", "more")

    def test_valid_prefix_still_accepts_append(self):
        tool = self.make_log(4)
        self.write_entries(tool.log_path, self.read_entries(tool.log_path)[:2])
        tool.process_prompt("u", "after truncation")
        self.assertEqual(len(self.read_entries(tool.log_path)), 3)
        self.assertTrue(self.verify(tool)[0])

    def test_current_head_hash_refuses_a_corrupt_log(self):
        tool = self.make_log(2)
        entries = self.read_entries(tool.log_path)
        entries[0]["timestamp"] = "2020-01-01T00:00:00+00:00"
        self.write_entries(tool.log_path, entries)
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(ValueError):
                tool.current_head_hash()


if __name__ == "__main__":
    unittest.main()
