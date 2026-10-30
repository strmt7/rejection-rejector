"""Enron miner privacy and containment tests (security review findings 2 and 9).

The fixtures are synthetic PII-SHAPED strings only: no live identifiers from
any corpus are reproduced here. The tests pin (a) every observed redaction
bypass class, (b) that validation uses independent detectors rather than the
redaction grammars, (c) that reports never claim absolute redaction, and
(d) that directory mining cannot follow symlinks out of the selected root or
read files swapped after validation.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import mine_enron as m  # noqa: E402


class RedactionBypassClasses(unittest.TestCase):
    """Every observed evasion shape is now redacted at source."""

    def setUp(self):
        """Create a fresh redactor with a synthetic name lexicon."""
        self.scrubber = m.Redactor({"jane", "garcia", "neil", "smith"})

    def test_bare_domain_mail_identifiers_are_redacted(self):
        """why: the dotted-domain requirement let user@host forms survive."""
        out = self.scrubber.redact("contact jane.doe@enron about it")
        self.assertNotIn("jane.doe@enron", out)

    def test_newline_split_phones_are_redacted(self):
        """why: phones split across line boundaries evaded the loose grammar."""
        out = self.scrubber.redact("call +44\n(20) 7330\n3000 today")
        self.assertNotIn("7330", out)
        self.assertNotIn("3000", out)

    def test_escaped_boundary_phones_are_redacted(self):
        """The escaped newline form in serialized text is treated alike."""
        out = self.scrubber.redact("call +1\\n(212) 555\\n0100 today")
        self.assertNotIn("555", out)

    def test_punctuation_bearing_and_lowercase_slot_names_are_redacted(self):
        """why: capitalised-only name grammars missed these slot shapes."""
        out = self.scrubber.redact("Dear jane o'neil-smith,\nRegards, m. garcia")
        self.assertNotIn("o'neil", out.lower())
        self.assertNotIn("garcia", out.lower())

    def test_account_like_identifiers_are_redacted(self):
        """why: account identifiers hid below the long-digit threshold."""
        out = self.scrubber.redact("acct no. 4471123 and employee id 114863")
        self.assertNotIn("4471123", out)
        self.assertNotIn("114863", out)


class IndependentValidation(unittest.TestCase):
    """Validation detectors are separate from the redaction grammars."""

    def test_scanner_shapes_differ_from_redaction_grammars(self):
        """why: shared detectors cannot catch their own blind spots; the
        independent scanner patterns must not be the redaction objects.
        """
        self.assertIsNot(m.SCAN_EMAIL_ANY_RE, m.EMAIL_RE)
        self.assertIsNot(m.SCAN_DIGIT_CHAIN_RE, m.PHONE_LOOSE_RE)
        self.assertIsNot(m.SCAN_ACCOUNT_ANY_RE, m.ACCOUNT_ID_RE)

    def test_independent_scanner_flags_unredacted_leaks(self):
        """The scanner rejects bare-domain mail and split phones outright."""
        sweep = m.redaction_sweep("write jane@enron or call 212\n555\n0100", set())
        self.assertGreater(sweep["emails_remaining"], 0)
        self.assertGreater(sweep["phones_remaining"], 0)

    def test_sweep_results_are_counts_only(self):
        """The pipeline drops rows with any nonzero leftover; values must be
        counts so that contract cannot be broken by metadata fields.
        """
        sweep = m.redaction_sweep("clean prose with no leaks", set())
        self.assertTrue(all(isinstance(v, int) for v in sweep.values()))
        self.assertTrue(all(v == 0 for v in sweep.values()), sweep)

    def test_report_language_never_claims_absolute_redaction(self):
        """why: the generated report advertised zero leftovers while real
        identifiers remained; permanent limits must be disclosed.
        """
        self.assertTrue(m.KNOWN_DETECTOR_LIMITS)
        self.assertTrue(any("Absolute anonymization cannot be supported" in line for line in m.KNOWN_DETECTOR_LIMITS))


class ContainedDirectoryMining(unittest.TestCase):
    """why (security review finding 9): symlinks must never leave the root."""

    def _corpus(self, tmp: str) -> Path:
        """Build a small corpus with escapes and one valid member."""
        root = Path(tmp) / "corpus"
        (root / "nested").mkdir(parents=True)
        (root / "nested" / "ok.txt").write_bytes(b"normal message")
        outside = Path(tmp) / "outside.txt"
        outside.write_bytes(b"secret outside content")
        os.symlink(outside, root / "escape_file.txt")
        os.symlink(outside, root / "nested" / "escape_nested.txt")
        os.symlink(Path(tmp), root / "escape_dir")
        return root

    def test_file_and_directory_symlink_escapes_are_rejected(self):
        """Only regular, contained members are yielded."""
        with tempfile.TemporaryDirectory() as tmp:
            root = self._corpus(tmp)
            yielded = sorted(name for name, _ in m._iter_directory_messages(root))
            self.assertEqual(yielded, ["ok.txt"])

    def test_file_swapped_after_validation_is_rejected(self):
        """An identity mismatch between lstat and fstat fails closed."""
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "swap.bin"
            target.write_bytes(b"original bytes")
            expected = os.stat(target, follow_symlinks=False)
            stale = os.stat_result((expected.st_mode, 0, expected.st_dev, 0, 0, 0, 0, 0, 0, 0))
            with self.assertRaises(OSError):
                m._read_contained(target, stale, 1024)

    def test_normal_nested_files_stay_streamable(self):
        """Contained regular files of any depth remain readable."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "corpus"
            deep = root / "a" / "b" / "c"
            deep.mkdir(parents=True)
            (deep / "deep.txt").write_bytes(b"deep content")
            yielded = list(m._iter_directory_messages(root))
            self.assertEqual([name for name, _ in yielded], ["deep.txt"])
            self.assertEqual(yielded[0][1], b"deep content")


if __name__ == "__main__":
    unittest.main()
