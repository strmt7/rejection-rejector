"""Behavioral regressions for all six NLTK model-artifact sandbox bypasses.

Run with the installed crawler interpreter. No pretrained models, training
backends, network access or GPU execution are needed.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "tools"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))


class TrainingArray:
    """Small typed-array interface for reaching the model serialization boundary."""

    def __init__(self):
        """Purpose: Avoid real training. Inputs: None. Outputs: Minimal array attributes."""
        self.indices = self
        self.indptr = self

    def astype(self, *_arguments, **_keywords):
        """Purpose: Preserve training control flow. Inputs: Requested dtype. Outputs: Same tiny fixture."""
        return self


class TrainingModel:
    """Picklable model fixture; no computation or external model data."""

    def fit(self, *_arguments, **_keywords):
        """Purpose: Reach the production save sink. Inputs: Tiny arrays. Outputs: Same model."""
        return self


class ModelSecurityTests(unittest.TestCase):
    """Check refusal, side effects and legitimate operations at the real API boundary."""

    def setUp(self):
        """Purpose: Enforce one owned root. Inputs: NLTK runtime. Outputs: Isolated allowed/outside paths."""
        import nltk.data
        from nltk import pathsec

        directory = tempfile.TemporaryDirectory(prefix="flitzzip-nltk-model-")
        self.addCleanup(directory.cleanup)
        self.allowed = Path(directory.name, "allowed").resolve()
        self.outside = Path(directory.name, "outside").resolve()
        self.allowed.mkdir()
        self.outside.mkdir()
        for module, name, value in (
            (pathsec, "ENFORCE", True),
            (pathsec, "_get_allowed_roots", lambda: {self.allowed}),
            (nltk.data, "path", [str(self.allowed)]),
            (nltk.data, "_STAGING_TEMPDIR", None),
        ):
            patched = patch.object(module, name, value, create=True)
            patched.start()
            self.addCleanup(patched.stop)
        # Prove the outside target actually exercises an enforcing sandbox.
        with self.assertRaises(PermissionError):
            pathsec.open(self.outside / "canary", "w")

    def test_perceptron_save_refuses_outside_without_writing(self):
        """Purpose: Prevent arbitrary model writes. Inputs: Outside path. Outputs: Refusal and no file."""
        from nltk.tag.perceptron import AveragedPerceptron

        destination = self.outside / "weights.json"
        with self.assertRaises(PermissionError):
            AveragedPerceptron({"word": {"NN": 1.0}}).save(destination)
        self.assertFalse(destination.exists())

    def test_perceptron_load_refuses_existing_outside_file(self):
        """Purpose: Prevent arbitrary model reads. Inputs: Existing outside JSON. Outputs: Refusal/state intact."""
        from nltk.tag.perceptron import AveragedPerceptron

        source = self.outside / "weights.json"
        source.write_text(json.dumps({"word": {"NN": 1.0}}), encoding="utf-8")
        model = AveragedPerceptron()
        with self.assertRaises(PermissionError):
            model.load(source)
        self.assertEqual(model.weights, {})

    def test_tagger_save_refuses_outside_directory(self):
        """Purpose: Contain multi-file model exports. Inputs: Outside directory. Outputs: Refusal/no files."""
        from nltk.tag.perceptron import PerceptronTagger

        with self.assertRaises(PermissionError):
            PerceptronTagger(load=False).save_to_json(lang="eng", loc=str(self.outside))
        self.assertEqual(list(self.outside.iterdir()), [])

    def test_maxent_save_refuses_outside_directory(self):
        """Purpose: Contain classifier exports. Inputs: Outside directory. Outputs: Refusal/no files."""
        import numpy
        from nltk.classify.maxent import save_maxent_params

        with self.assertRaises(PermissionError):
            save_maxent_params(numpy.array([0.25]), {}, ["NN"], {}, tab_dir=str(self.outside))
        self.assertEqual(list(self.outside.iterdir()), [])

    def test_transition_train_refuses_outside_model(self):
        """Purpose: Contain trained model writes. Inputs: Backend fixture/outside path. Outputs: Refusal/no file."""
        from nltk.parse import transitionparser as module

        parser = module.TransitionParser(module.TransitionParser.ARC_STANDARD)
        outside = self.outside / "parser.model"
        with (
            patch.object(module, "load_svmlight_file", return_value=(TrainingArray(), []), create=True),
            patch.object(module, "svm", SimpleNamespace(SVC=lambda **_options: TrainingModel()), create=True),
            patch.object(parser, "_create_training_examples_arc_std"),
            self.assertRaises(PermissionError),
        ):
            parser.train([], str(outside), verbose=False)
        self.assertFalse(outside.exists())

    def test_transition_parse_refuses_existing_outside_model(self):
        """Purpose: Contain parser model reads. Inputs: Existing harmless outside pickle. Outputs: Refusal."""
        from nltk.parse.transitionparser import TransitionParser

        source = self.outside / "parser.model"
        source.write_bytes(b"\x80\x04}\x94.")  # Harmless empty dictionary, never an execution gadget.
        parser = TransitionParser(TransitionParser.ARC_STANDARD)
        with self.assertRaises(PermissionError):
            parser.parse([], str(source))

    def test_inside_perceptron_roundtrip_preserves_weights(self):
        """Purpose: Reject fixes that block all I/O. Inputs: Allowed weights. Outputs: Exact roundtrip."""
        from nltk.tag.perceptron import AveragedPerceptron

        weights = {"word": {"NN": 1.0, "VB": -0.5}}
        destination = self.allowed / "weights.json"
        AveragedPerceptron(weights).save(destination)
        restored = AveragedPerceptron()
        restored.load(destination)
        self.assertEqual(restored.weights, weights)

    def test_inside_tagger_roundtrip_preserves_model(self):
        """Purpose: Preserve legitimate tagger exports. Inputs: Allowed directory/tiny model. Outputs: Roundtrip."""
        from nltk.tag.perceptron import PerceptronTagger

        model = PerceptronTagger(load=False)
        model.classes = {"NN"}
        model.model.classes = model.classes
        model.model.weights = {"word": {"NN": 1.0}}
        model.tagdict = {"example": "NN"}
        destination = self.allowed / "tagger"
        model.save_to_json(lang="eng", loc=str(destination))
        restored = PerceptronTagger(load=False)
        restored.load_from_json(lang="eng", loc=str(destination))
        self.assertEqual(restored.model.weights, model.model.weights)
        self.assertEqual(restored.tagdict, model.tagdict)
        self.assertEqual(restored.classes, model.classes)

    def test_crawler_bm25_consumer_preserves_stemming_and_selection(self):
        """Purpose: Verify the actual dependency consumer. Inputs: Tiny HTML/query. Outputs: Relevant extraction."""
        from crawl4ai.content_filter_strategy import BM25ContentFilter
        from nltk.stem.snowball import SnowballStemmer

        self.assertEqual(SnowballStemmer("english").stem("compressing"), "compress")
        paragraphs = (
            "Lossless compression reduces archive storage while preserving every original byte in the files.",
            "Garden vegetables need sunlight and water every day during summer to grow new healthy leaves.",
            "The evening concert features talented musicians playing classical songs "
            "and modern compositions for the audience.",
            "Road safety requires careful driving and proper maintenance of vehicles and streets throughout the city.",
        )
        html = "<main>" + "".join(f"<p>{paragraph}</p>" for paragraph in paragraphs) + "</main>"
        selected = BM25ContentFilter(user_query="compression archive", bm25_threshold=0.1).filter_content(
            html,
            min_word_threshold=3,
        )
        self.assertEqual(selected, [f"<p>{paragraphs[0]}</p>"])


if __name__ == "__main__":
    unittest.main()
