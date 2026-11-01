"""Why (coverage doctrine): every language × style × format template arm in
build_corpus_v2 is product code whose branch must execute under test, not
merely be reasoned about. This matrix drives the complete combination space
through the assemblers with seeded RNG, asserting the shared invariants at
each point, so no template arm can rot unnoticed.
"""

from __future__ import annotations

import random
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "training"))

import build_corpus_v2 as bc  # noqa: E402
from corpus_banks_v2 import BANKS  # noqa: E402


class TemplateMatrixTests(unittest.TestCase):
    """Complete-combination tests over the corpus generator's template arms."""

    def setUp(self) -> None:
        """Inputs: none. Output: per-language slot dicts for the matrix."""
        self.slots_by_lang = {lang: bc.make_slots(random.Random(7), lang) for lang in bc.LANGUAGES}

    def _seeded(self, tag: str) -> random.Random:
        return random.Random(f"matrix-{tag}")

    def test_every_language_produces_slots(self) -> None:
        """Why: make_slots is language-aware; every language must yield slots."""
        for lang in bc.LANGUAGES:
            slots = self.slots_by_lang[lang]
            self.assertIsInstance(slots, dict)
            self.assertTrue(slots, f"{lang} produced no slots")

    def test_rejection_matrix_language_style_format(self) -> None:
        """Why (coverage doctrine): every language × style × format arm of
        assemble_rejection executes here; failure names the exact arm.
        """
        for lang in bc.LANGUAGES:
            for style in bc.REJECTION_STYLES:
                for fmt_name in bc.FORMATS:
                    with self.subTest(lang=lang, style=style, fmt=fmt_name):
                        rng = self._seeded(f"rej-{lang}-{style}-{fmt_name}")
                        rec = bc.assemble_rejection(
                            rng, lang, style, fmt_name, self.slots_by_lang[lang]
                        )
                        self.assertIsInstance(rec, dict)
                        body = rec.get("body") or rec.get("text") or ""
                        self.assertTrue(str(body).strip())
                        normalized = bc.normalize_text(str(body))
                        self.assertTrue(normalized.strip())
                        self.assertEqual(bc.hash_text(normalized), bc.hash_text(normalized))

    def test_negative_matrix_language_type_format(self) -> None:
        """Why (coverage doctrine): every opportunity-negative arm executes.
        The banks are per-language, so each language drives its own keys.
        """
        for lang in bc.LANGUAGES:
            neg_keys = sorted(BANKS[lang]["neg"].keys())
            self.assertTrue(neg_keys)
            for neg_type in neg_keys:
                for fmt_name in bc.FORMATS:
                    with self.subTest(lang=lang, neg=neg_type, fmt=fmt_name):
                        rng = self._seeded(f"neg-{lang}-{neg_type}-{fmt_name}")
                        rec = bc.assemble_negative(
                            rng, lang, neg_type, fmt_name, self.slots_by_lang[lang]
                        )
                        self.assertIsInstance(rec, dict)
                        body = rec.get("body") or rec.get("text") or ""
                        self.assertTrue(str(body).strip())

    def test_adversarial_matrix_language_format(self) -> None:
        """Why (coverage doctrine): the adversarial arms execute per language."""
        for lang in bc.LANGUAGES:
            for fmt_name in bc.FORMATS:
                with self.subTest(lang=lang, fmt=fmt_name):
                    rng = self._seeded(f"adv-{lang}-{fmt_name}")
                    rec = bc.assemble_adversarial(rng, lang, fmt_name, self.slots_by_lang[lang])
                    self.assertIsInstance(rec, dict)
                    self.assertTrue(str(rec.get("body") or rec.get("text") or "").strip())

    def test_ambiguous_matrix_language_type_format(self) -> None:
        """Why (coverage doctrine): every ambiguous-type arm executes."""
        for lang in bc.LANGUAGES:
            amb_keys = sorted(BANKS[lang]["amb"].keys())
            self.assertTrue(amb_keys)
            for amb_type in amb_keys:
                for fmt_name in bc.FORMATS:
                    with self.subTest(lang=lang, amb=amb_type, fmt=fmt_name):
                        rng = self._seeded(f"amb-{lang}-{amb_type}-{fmt_name}")
                        rec = bc.assemble_ambiguous(
                            rng, lang, amb_type, fmt_name, self.slots_by_lang[lang]
                        )
                        self.assertIsInstance(rec, dict)
                        self.assertTrue(str(rec.get("body") or rec.get("text") or "").strip())

    def test_apply_format_branches_are_exhaustive_over_formats(self) -> None:
        """Why: apply_format's per-format wrappers are separate branches;
        driving each FORMATS member covers every one deterministically.
        """
        for fmt_name in bc.FORMATS:
            for lang in bc.LANGUAGES:
                rng = self._seeded(f"fmt-{fmt_name}-{lang}")
                out = bc.apply_format(rng, "Body line one.\nBody line two.", fmt_name, lang, self.slots_by_lang[lang])
                self.assertTrue(out.strip())

    def test_envelope_helpers_round_trip(self) -> None:
        """Why: the evidence/formatting helpers share branches across kinds."""
        rng = self._seeded("helpers")
        for lang in bc.LANGUAGES:
            slots = self.slots_by_lang[lang]
            self.assertTrue(bc.make_date(rng))
            self.assertTrue(bc.make_time(rng))
            quoted = bc.maybe_quoted_thread(rng, "Newest line.", lang, slots)
            self.assertIn("Newest line.", quoted)
            with_typo = bc.inject_typos("This is a perfectly normal sentence.", rng)
            self.assertTrue(with_typo)
            with_emoji = bc.add_emoji("Thanks for the update.", rng)
            self.assertTrue(with_emoji)


if __name__ == "__main__":
    unittest.main()
