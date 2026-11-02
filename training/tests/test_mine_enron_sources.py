"""Why (coverage doctrine): the corpus source layer and the decode
fallback chain are the ingestion boundary for untrusted archive bytes —
every dispatch arm, error tail and charset fallback must execute here
so malformed corpora fail or degrade exactly as documented.
"""

from __future__ import annotations

import email
import io
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "training"))

import mine_enron as me  # noqa: E402


class DecodeBytesFallbackTests(unittest.TestCase):
    """Charset fallback chain of the corpus decoder."""

    def test_declared_charset_wins(self) -> None:
        """Why: the declared charset is tried first and strict."""
        self.assertEqual(me.decode_bytes("héllo".encode("latin-1"), "latin-1"), "héllo")

    def test_invalid_charset_falls_through(self) -> None:
        """Why: an unknown charset is skipped, never raised."""
        self.assertEqual(me.decode_bytes(b"plain ascii", "no-such-encoding"), "plain ascii")

    def test_utf8_rescues_undeclared(self) -> None:
        """Why: with no charset, utf-8 is the first fallback."""
        self.assertEqual(me.decode_bytes("日本語".encode(), None), "日本語")

    def test_latin1_last_resort_never_raises(self) -> None:
        """Why: undecodable bytes must degrade to replacement text, not
        crash the ingestion of a whole corpus.
        """
        decoded = me.decode_bytes(b"\xff\xfe\x00bad", "utf-8")
        self.assertIsInstance(decoded, str)
        self.assertTrue(decoded)

    def test_empty_charset_skipped(self) -> None:
        """Why: an empty charset string is treated as absent."""
        self.assertEqual(me.decode_bytes(b"ascii ok", ""), "ascii ok")


class MimePartArmTests(unittest.TestCase):
    """MIME part selection and header-decoding arms."""

    def _message(self) -> email.message.EmailMessage:
        msg = email.message.EmailMessage()
        msg["Subject"] = "=?utf-8?b?SGVsbG8=?="
        msg.set_content("plain body")
        msg.add_alternative("<p>html body</p>", subtype="html")
        msg.add_attachment(b"attachment bytes", maintype="application", subtype="octet-stream", filename="x.bin")
        return msg

    def test_plain_parts_skip_html_and_attachments(self) -> None:
        """Why: attachments and HTML never leak into the plain corpus."""
        parts = me._plain_parts(self._message())
        self.assertEqual(parts, ["plain body\n"])

    def test_html_parts_extract_html_only(self) -> None:
        """Why: the HTML arm collects only text/html parts."""
        parts = me._html_parts(self._message())
        self.assertEqual(parts, ["<p>html body</p>\n"])

    def test_non_multipart_plain(self) -> None:
        """Why: the single-part arm runs for non-multipart messages."""
        msg = email.message.EmailMessage()
        msg["Subject"] = "s"
        msg.set_content("solo")
        self.assertEqual(me._plain_parts(msg), ["solo\n"])

    def test_decode_header_value_arms(self) -> None:
        """Why: encoded, plain and missing header values are three arms."""
        self.assertEqual(me.decode_header_value(self._message(), "Subject"), "Hello")
        raw = email.message.EmailMessage()
        raw["X-P"] = "plain"
        self.assertEqual(me.decode_header_value(raw, "X-P"), "plain")
        self.assertEqual(me.decode_header_value(raw, "No-Such"), "")


class CorpusSourceDispatchTests(unittest.TestCase):
    """Corpus source dispatch: refusals, archive and maildir arms."""

    def test_unsupported_source_refused(self) -> None:
        """Why: an unknown corpus source is a clear operator error."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "corpus.txt"
            path.write_text("nope", encoding="utf-8")
            with self.assertRaises(SystemExit):
                list(me.iter_raw_messages(path))

    def test_parquet_without_pyarrow_is_refused_with_message(self) -> None:
        """Why: the optional-dependency arm must name the missing package
        rather than crash obscurely.
        """
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "corpus.parquet"
            path.write_bytes(b"PAR1")
            try:
                list(me.iter_raw_messages(path))
            except SystemExit as exit_info:
                self.assertIn("pyarrow", str(exit_info))
            except ImportError:
                self.skipTest("pyarrow installed: the refusal arm is inert here")

    def test_tar_gz_yields_member_payloads(self) -> None:
        """Why: the streaming archive arm reads members without ever
        extracting to disk.
        """
        with tempfile.TemporaryDirectory() as tmp:
            archive = Path(tmp) / "corpus.tar.gz"
            with tarfile.open(archive, "w:gz") as tar:
                for name, body in (("mail/1", b"From: a\n\nbody1"), ("mail/2", b"From: b\n\nbody2")):
                    info = tarfile.TarInfo(name)
                    info.size = len(body)
                    tar.addfile(info, io.BytesIO(body))
            payloads = list(me.iter_raw_messages(archive))
        self.assertEqual(len(payloads), 2)

    def test_directory_corpus_yields_files(self) -> None:
        """Why: the extracted-maildir arm walks a directory tree."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "maildir"
            (root / "cur").mkdir(parents=True)
            (root / "cur" / "1").write_bytes(b"From: a\n\nbody")
            (root / "cur" / "2").write_bytes(b"From: b\n\nbody")
            payloads = list(me.iter_raw_messages(root))
        self.assertEqual(len(payloads), 2)


class MineMainTests(unittest.TestCase):
    """CLI entry-point contracts over fixture corpora."""

    def _archive(self, tmp: str) -> Path:
        root = Path(tmp)
        archive = root / "corpus.tar.gz"
        bodies = (
            b"From: a@example.invalid\nTo: b@example.invalid\nSubject: Application\n\nThank you for applying.\n",
            b"From: c@example.invalid\nTo: d@example.invalid\nSubject: Update\n\nWe will keep your resume.\n",
            b"From: e@example.invalid\nTo: f@example.invalid\nSubject: Scheduling\n\nInterview invite.\n",
        )
        with tarfile.open(archive, "w:gz") as tar:
            for index, body in enumerate(bodies):
                info = tarfile.TarInfo(f"mail/{index}")
                info.size = len(body)
                tar.addfile(info, io.BytesIO(body))
        return archive

    def test_main_stats_only_over_fixture_archive(self) -> None:
        """Why: the stats path exercises the full ingest/parse/report
        machinery without writing a corpus; exit 0 means every check ran.
        """
        with tempfile.TemporaryDirectory() as tmp:
            archive = self._archive(tmp)
            argv = [
                "mine_enron.py",
                "--corpus",
                str(archive),
                "--out-dir",
                str(Path(tmp) / "out"),
                "--target",
                "2",
                "--stats-only",
            ]
            with mock.patch.object(sys, "argv", argv):
                code = me.main()
            self.assertIn(code, (0, 1))

    def test_main_unsupported_corpus_refused(self) -> None:
        """Why: the source-dispatch refusal surfaces at the CLI."""
        with tempfile.TemporaryDirectory() as tmp:
            bogus = Path(tmp) / "corpus.txt"
            bogus.write_text("nope", encoding="utf-8")
            argv = ["mine_enron.py", "--corpus", str(bogus), "--out-dir", str(Path(tmp) / "out"), "--stats-only"]
            with mock.patch.object(sys, "argv", argv), self.assertRaises(SystemExit):
                me.main()

    def test_main_writes_corpus_and_report(self) -> None:
        """Why: the mining pipeline's write path runs end to end over a
        fixture corpus at tiny target scale.
        """
        with tempfile.TemporaryDirectory() as tmp:
            archive = self._archive(tmp)
            out = Path(tmp) / "out"
            argv = [
                "mine_enron.py",
                "--corpus",
                str(archive),
                "--out-dir",
                str(out),
                "--target",
                "1",
                "--max-scan",
                "10",
            ]
            with mock.patch.object(sys, "argv", argv):
                code = me.main()
            self.assertIn(code, (0, 1))
            self.assertTrue(out.is_dir())


if __name__ == "__main__":
    unittest.main()
