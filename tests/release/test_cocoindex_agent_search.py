"""External index mirror and freshness contracts, with no package or network.

Adapted from strmt7/VulnerabilityScreener tests/test_cocoindex_agent_search.py (MIT).
"""

import contextlib
import io
import json
import math
import os
import runpy
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "tools"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from tools import cocoindex_agent_search as agent_search  # noqa: E402
from tools.cocoindex_agent_search import (  # noqa: E402
    CONFIG_DIGEST,
    ROOT,
    home,
    paths,
    prepare_mirror,
    search,
    source_digest,
    tracked_files,
    validate_search_results,
)


class CocoIndexAgentSearchTests(unittest.TestCase):
    """CocoIndex agent-search routing, freshness and admission contracts; no package or network access."""

    def test_successful_search_records_real_use_without_query_text(self):
        """Purpose: Prove routing receipt semantics.
        Inputs: fresh source/real wrapper/mock package.
        Outputs: deduplicated use record.
        """
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            source = base / "source.py"
            source.write_text("pass\n", encoding="utf-8")
            entries = [("source.py", source)]
            digest = source_digest(entries)
            mirror = paths(base, base)[1]
            marker = base / "active" / (mirror.name + ".json")
            marker.parent.mkdir()
            marker.write_text(
                json.dumps(
                    {"source_digest": digest, "config_digest": CONFIG_DIGEST, "cocoindex_code": agent_search.VERSION}
                ),
                encoding="utf-8",
            )
            hit = dict(file_path="source.py", start_line=1, end_line=1, score=0.9, content="pass")
            result = subprocess.CompletedProcess([], 0, stdout=json.dumps({"success": True, "results": [hit, hit]}))
            query = "private conceptual question"
            with (
                patch("tools.cocoindex_agent_search.tracked_files", return_value=entries),
                patch("tools.cocoindex_agent_search._run", return_value=result) as package,
                contextlib.redirect_stdout(io.StringIO()) as output,
            ):
                search(base, query, 1, repo=base, path="source.py")
            self.assertIn("results=1", output.getvalue())
            self.assertIn("--path", package.call_args.args[0])
            receipt = marker.with_name(mirror.name + ".usage.json").read_text()
            self.assertNotIn(query, receipt)
            self.assertEqual(json.loads(receipt)["source_digest"], digest)
            self.assertEqual(json.loads(receipt)["hit_count"], 1)
            source.write_text("changed\n", encoding="utf-8")
            original = receipt
            with (
                patch("tools.cocoindex_agent_search.tracked_files", return_value=entries),
                self.assertRaisesRegex(RuntimeError, "index is stale"),
            ):
                search(base, query, 5, repo=base)
            self.assertEqual(marker.with_name(mirror.name + ".usage.json").read_text(), original)

    def test_source_changed_during_search_cannot_record_current_use(self):
        """Purpose: Close the search freshness race.
        Inputs: source mutation during the package call. Outputs: explicit failure without a new receipt.
        """
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            source = base / "source.py"
            source.write_text("pass\n", encoding="utf-8")
            entries = [("source.py", source)]
            mirror = paths(base, base)[1]
            marker = base / "active" / (mirror.name + ".json")
            marker.parent.mkdir()
            marker.write_text(
                json.dumps(
                    {
                        "source_digest": source_digest(entries),
                        "config_digest": CONFIG_DIGEST,
                        "cocoindex_code": agent_search.VERSION,
                    }
                ),
                encoding="utf-8",
            )

            def mutate_source(*args, **kwargs):
                """Purpose: Inject source drift. Inputs: package argv. Outputs: successful stale search data."""
                source.write_text("changed\n", encoding="utf-8")
                return subprocess.CompletedProcess([], 0, stdout=json.dumps({"success": True, "results": []}))

            with (
                patch("tools.cocoindex_agent_search.tracked_files", return_value=entries),
                patch("tools.cocoindex_agent_search._run", side_effect=mutate_source),
                self.assertRaisesRegex(RuntimeError, "source changed during semantic search"),
            ):
                search(base, "conceptual question", 5, repo=base)
            self.assertFalse(marker.with_name(mirror.name + ".usage.json").exists())

    def test_home_requires_absolute_override(self):
        """Purpose: Refuse relative state roots.
        Inputs: Relative AGENT_CODE_HOME.
        Outputs: ValueError before state access.
        """
        with patch.dict("os.environ", {"AGENT_CODE_HOME": "relative"}), self.assertRaisesRegex(ValueError, "absolute"):
            home()

    def test_home_uses_external_platform_default(self):
        """Purpose: Route default state. Inputs: Owned data root. Outputs: External FlitzZip path."""
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch.dict(os.environ, {"LOCALAPPDATA": temporary}, clear=True),
        ):
            self.assertEqual(home(), (Path(temporary) / "FlitzZip/agent-code").resolve())

    def test_home_rejects_checkout_state(self):
        """Purpose: Keep index state outside the checkout.
        Inputs: In-checkout AGENT_CODE_HOME.
        Outputs: ValueError refusal.
        """
        with (
            patch.dict("os.environ", {"AGENT_CODE_HOME": str(ROOT / "index-state")}),
            self.assertRaisesRegex(ValueError, "outside the checkout"),
        ):
            home()

    def test_mirror_copies_exact_bytes_and_prunes_stale_generated_file(self):
        """Purpose: Verify mirror byte fidelity and pruning.
        Inputs: Owned source and stale mirror file.
        Outputs: Exact copies and a live-only mirror.
        """
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source.py"
            source.write_bytes(b"print('safe')\n")
            mirror = root / "index-mirror"
            mirror.mkdir()
            stale = mirror / "stale.py"
            stale.write_text("old", encoding="utf-8")
            entries = [("nested/source.py", source)]
            prepare_mirror(mirror, entries)
            self.assertEqual((mirror / "nested/source.py").read_bytes(), source.read_bytes())
            self.assertFalse(stale.exists())
            first = source_digest(entries)
            source.write_bytes(b"print('changed')\n")
            self.assertNotEqual(first, source_digest(entries))
            prepare_mirror(mirror, entries)
            self.assertEqual((mirror / "nested/source.py").read_bytes(), source.read_bytes())

    def test_search_rejects_missing_index_without_starting_package(self):
        """Purpose: Fail closed without an active index.
        Inputs: Owned empty home.
        Outputs: RuntimeError before package start.
        """
        with tempfile.TemporaryDirectory() as temp, self.assertRaisesRegex(RuntimeError, "no active index"):
            search(Path(temp), "training labels", 5, repo=Path(temp))

    def test_search_rejects_unreliable_wildcard_filter(self):
        """Purpose: Refuse wildcard path filters.
        Inputs: Wildcard filter string.
        Outputs: ValueError before search.
        """
        with tempfile.TemporaryDirectory() as temp, self.assertRaisesRegex(ValueError, "wildcard path filters"):
            search(Path(temp), "training labels", 5, repo=Path(temp), path="scanner/*")

    def test_search_rejects_stale_source_before_package_call(self):
        """Purpose: Reject stale source before routing.
        Inputs: Mismatched source digest marker.
        Outputs: RuntimeError without a package call.
        """
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            source = base / "source.py"
            source.write_text("pass\n", encoding="utf-8")
            mirror = paths(base, base)[1]
            marker = base / "active" / (mirror.name + ".json")
            marker.parent.mkdir()
            marker.write_text(
                json.dumps({"source_digest": "incorrect", "cocoindex_code": agent_search.VERSION}), encoding="utf-8"
            )
            with (
                patch("tools.cocoindex_agent_search.tracked_files", return_value=[("source.py", source)]),
                self.assertRaisesRegex(RuntimeError, "index is stale"),
            ):
                search(base, "training labels", 5, repo=base)

    def test_mirror_paths_are_per_repository(self):
        """Purpose: Scope external state per repository.
        Inputs: Two repositories under one base.
        Outputs: Distinct mirror and versioned runtime paths.
        """
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            self.assertNotEqual(paths(base, base / "a")[1], paths(base, base / "b")[1])
            environment, _mirror, _config, runtime = paths(base, base / "a")
            self.assertEqual(environment.name, f"venv-{agent_search.VERSION}")
            self.assertEqual(runtime.parent.name, agent_search.VERSION)

    def test_tracked_files_rejects_escape_and_real_env(self):
        """Purpose: Refuse escaping and secret inventory names.
        Inputs: Hostile NUL-terminated names.
        Outputs: ValueError before mirroring.
        """
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for unsafe in (b"../outside\0", b".env\0", b"secrets/key.txt\0", b"tls/private.pem\0"):
                with (
                    self.subTest(unsafe=unsafe),
                    patch("tools.cocoindex_agent_search.subprocess.run") as run,
                    self.assertRaises(ValueError),
                ):
                    run.return_value.stdout = unsafe
                    tracked_files(root)

    def test_tracked_files_uses_code_only_freshness(self):
        """Purpose: Bound freshness to code files.
        Inputs: Mixed code and documentation inventory.
        Outputs: Code-only entries with the git inventory flags.
        """
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "source.py").write_text("pass\n", encoding="utf-8")
            (root / "README.md").write_text("documentation\n", encoding="utf-8")
            with patch("tools.cocoindex_agent_search.subprocess.run") as run:
                run.return_value.stdout = b"README.md\0source.py\0"
                entries = tracked_files(root)
            self.assertEqual([name for name, _ in entries], ["source.py"])
            self.assertIn("--others", run.call_args.args[0])
            self.assertIn("--exclude-standard", run.call_args.args[0])

    def test_context_and_index_share_secret_and_alias_boundaries(self):
        """Purpose: Keep code mirroring behind the context reader's path policy.
        Inputs: Real mixed-case and environment-prefix fixtures plus Windows aliases. Outputs: Refusal before mirroring.
        """
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in ("SECRETS/source.py", ".env.py", "key.PEM"):
                source = root / name
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text("controlled fixture only\n", encoding="utf-8")
            for name in ("SECRETS/source.py", ".env.py", "key.PEM", "secrets./source.py", "source.py."):
                with (
                    self.subTest(name=name),
                    patch("tools.cocoindex_agent_search.subprocess.run") as run,
                    self.assertRaises(ValueError),
                ):
                    run.return_value.stdout = name.encode("utf-8") + b"\0"
                    tracked_files(root)

    def test_flitzzip_headers_and_build_files_are_indexed_without_vendored_code(self):
        """Purpose: Index headers and build files without vendored code.
        Inputs: Mixed tracked inventory.
        Outputs: Non-vendored entries only.
        """
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in ("src/codec.hpp", "CMakeLists.txt", "third_party/lib/codec.cpp"):
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("code\n", encoding="utf-8")
            with patch("tools.cocoindex_agent_search.subprocess.run") as run:
                run.return_value.stdout = b"src/codec.hpp\0CMakeLists.txt\0third_party/lib/codec.cpp\0"
                entries = tracked_files(root)
            self.assertEqual([name for name, _ in entries], ["src/codec.hpp", "CMakeLists.txt"])

    def test_tracked_files_omits_only_git_confirmed_deletions(self):
        """Purpose: Check deletion admission. Inputs: Git inventories. Outputs: only confirmed deletions omitted."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for deleted in (b"removed.py\0", b""):
                with self.subTest(deleted=deleted), patch("tools.cocoindex_agent_search.subprocess.run") as run:
                    run.side_effect = [
                        subprocess.CompletedProcess([], 0, stdout=b"removed.py\0"),
                        subprocess.CompletedProcess([], 0, stdout=deleted),
                    ]
                    if deleted:
                        self.assertEqual(tracked_files(root), [])
                    else:
                        with self.assertRaisesRegex(ValueError, "not a regular file"):
                            tracked_files(root)
                    self.assertIn("--deleted", run.call_args.args[0])

    def test_tracked_files_handles_real_unstaged_deletion_and_mirror_pruning(self):
        """Purpose: Exercise Git deletion. Inputs: temporary checkout. Outputs: exact live mirror and digest."""
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            repo = base / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "--quiet", str(repo)], check=True, timeout=30)
            for name in ("live.py", "removed.py"):
                (repo / name).write_text("pass\n", encoding="utf-8")
            subprocess.run(["git", "add", "--", "live.py", "removed.py"], cwd=repo, check=True, timeout=30)
            mirror = base / "mirror"
            before = tracked_files(repo)
            before_digest = source_digest(before)
            prepare_mirror(mirror, before)
            (repo / "removed.py").unlink()
            (repo / "new.py").write_text("value = 1\n", encoding="utf-8")
            after = tracked_files(repo)
            self.assertEqual({name for name, _ in after}, {"live.py", "new.py"})
            self.assertNotEqual(before_digest, source_digest(after))
            prepare_mirror(mirror, after)
            self.assertFalse((mirror / "removed.py").exists())
            self.assertEqual((mirror / "new.py").read_bytes(), (repo / "new.py").read_bytes())

    def test_staging_new_source_preserves_fingerprint_until_live_bytes_change(self):
        """Purpose: Prevent needless refresh after Git staging.
        Inputs: a real checkout moving an unchanged file from untracked to staged.
        Outputs: stable digest across ordering changes, invalidated by source mutation.
        """
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            subprocess.run(["git", "init", "--quiet", str(repo)], check=True, timeout=30)
            (repo / "a.py").write_text("a = 1\n", encoding="utf-8")
            subprocess.run(["git", "add", "--", "a.py"], cwd=repo, check=True, timeout=30)
            (repo / "z.py").write_text("z = 1\n", encoding="utf-8")
            before = tracked_files(repo)
            original_digest = source_digest(before)
            subprocess.run(["git", "add", "--", "z.py"], cwd=repo, check=True, timeout=30)
            after = tracked_files(repo)
            self.assertEqual({name for name, _ in before}, {name for name, _ in after})
            self.assertNotEqual([name for name, _ in before], [name for name, _ in after])
            self.assertEqual(original_digest, source_digest(after))
            (repo / "z.py").write_text("z = 2\n", encoding="utf-8")
            self.assertNotEqual(original_digest, source_digest(tracked_files(repo)))

    def test_install_routes_and_verifies_exact_version(self):
        """Purpose: Exercise pinned installation reuse, both installers and post-install version admission without
        network.
        Inputs: Owned external homes, inert CLI fixtures and bounded process results for uv and pip.
        Outputs: Exact versions reuse/install; stale existing and mismatched new installations fail explicitly.
        """
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cached = root / "cached"
            command = agent_search.ccc_path(paths(cached)[0])
            command.parent.mkdir(parents=True)
            command.write_bytes(b"inert CLI fixture")
            exact = subprocess.CompletedProcess([], 0, stdout=agent_search.VERSION + "\n")
            with (
                patch.object(agent_search, "_run", return_value=exact) as run,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                agent_search.install(cached)
            run.assert_called_once_with([str(command), "version"], timeout=30)
            stale = subprocess.CompletedProcess([], 0, stdout="0.0.0\n")
            with (
                patch.object(agent_search, "_run", return_value=stale),
                self.assertRaisesRegex(RuntimeError, "existing CocoIndex version"),
            ):
                agent_search.install(cached)

            for label, uv in (("uv", str(root / "uv.exe")), ("pip", None)):
                base = root / label
                responses = [
                    subprocess.CompletedProcess([], 0, stdout=""),
                    subprocess.CompletedProcess([], 0, stdout=""),
                    exact,
                ]
                with (
                    self.subTest(installer=label),
                    patch.object(agent_search.shutil, "which", return_value=uv),
                    patch.object(agent_search, "_run", side_effect=responses) as run,
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    agent_search.install(base)
                install_command = run.call_args_list[1].args[0]
                if uv:
                    self.assertEqual(install_command[:3], [uv, "pip", "install"])
                else:
                    self.assertEqual(install_command[1:4], ["-m", "pip", "install"])
                self.assertIn(f"cocoindex-code[full]=={agent_search.VERSION}", install_command)
            base = root / "mismatch"
            responses = [
                subprocess.CompletedProcess([], 0, stdout=""),
                subprocess.CompletedProcess([], 0, stdout=""),
                stale,
            ]
            with (
                patch.object(agent_search.shutil, "which", return_value=None),
                patch.object(agent_search, "_run", side_effect=responses),
                self.assertRaisesRegex(RuntimeError, "version verification failed"),
            ):
                agent_search.install(base)

    def test_search_result_schema_and_resource_admission(self):
        """Purpose: Reject malformed provider output before receipts, paths or snippets become trusted agent evidence.
        Inputs: One exact hit plus independent response, collection, path, range, score and content mutations.
        Outputs: The exact hit passes; every ambiguous or unbounded shape raises a controlled
        RuntimeError/ValueError.
        """
        hit = {"file_path": "source.py", "start_line": 1, "end_line": 2, "score": 0.5, "content": "source"}
        self.assertEqual(validate_search_results({"success": True, "results": [hit]}, 5), [hit])
        failures = (
            None,
            {"success": "true", "results": []},
            {"success": False, "message": "provider failure"},
            {"success": True, "results": None},
            {"success": True, "results": [hit] * 6},
            {"success": True, "results": [None]},
        )
        for payload in failures:
            with self.subTest(payload=payload), self.assertRaises(RuntimeError):
                validate_search_results(payload, 5)
        mutations = (
            ("file_path", "../outside.py"),
            ("start_line", True),
            ("start_line", 0),
            ("end_line", 0),
            ("score", True),
            ("score", math.inf),
            ("content", None),
            ("content", "x" * (1024 * 1024 + 1)),
        )
        for field, value in mutations:
            changed = dict(hit)
            changed[field] = value
            with self.subTest(field=field, value=type(value).__name__), self.assertRaises((RuntimeError, ValueError)):
                validate_search_results({"success": True, "results": [changed]}, 5)

    def test_index_admission_migration_and_publication(self):
        """Purpose: Validate index settings, v1 migration, stable-source success and error output without package
        execution.
        Inputs: Owned external state, one source file, inert CLI and controlled index process output.
        Outputs: Missing tools/changed settings/errors fail; v1 state stops its daemon and publishes a fresh marker.
        """
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / "repo"
            repo.mkdir()
            source = repo / "source.py"
            source.write_text("value = 1\n", encoding="utf-8")
            entries = [("source.py", source)]
            missing = root / "missing"
            with self.assertRaisesRegex(RuntimeError, "run install"):
                agent_search.index(missing, repo)

            changed_global = root / "changed-global"
            venv, _mirror, config, _runtime = paths(changed_global, repo)
            command = agent_search.ccc_path(venv)
            command.parent.mkdir(parents=True)
            command.write_bytes(b"CLI")
            (config / "global_settings.yml").parent.mkdir(parents=True)
            (config / "global_settings.yml").write_text("changed", encoding="utf-8")
            with (
                patch.object(agent_search, "tracked_files", return_value=entries),
                self.assertRaisesRegex(RuntimeError, "settings changed"),
            ):
                agent_search.index(changed_global, repo)

            changed_project = root / "changed-project"
            venv, mirror, _config, _runtime = paths(changed_project, repo)
            command = agent_search.ccc_path(venv)
            command.parent.mkdir(parents=True)
            command.write_bytes(b"CLI")
            project = mirror / ".cocoindex_code/settings.yml"
            project.parent.mkdir(parents=True)
            project.write_text("changed", encoding="utf-8")
            with (
                patch.object(agent_search, "tracked_files", return_value=entries),
                self.assertRaisesRegex(RuntimeError, "project settings changed"),
            ):
                agent_search.index(changed_project, repo)

            migrated = root / "migrated"
            venv, mirror, _config, _runtime = paths(migrated, repo)
            command = agent_search.ccc_path(venv)
            command.parent.mkdir(parents=True)
            command.write_bytes(b"CLI")
            project = mirror / ".cocoindex_code/settings.yml"
            project.parent.mkdir(parents=True)
            project.write_text(agent_search.PROJECT_SETTINGS_V1, encoding="utf-8")
            responses = (
                subprocess.CompletedProcess([], 0, stdout="stopped"),
                subprocess.CompletedProcess([], 0, stdout="Indexing: complete error: 0"),
            )
            with (
                patch.object(agent_search, "tracked_files", return_value=entries),
                patch.object(agent_search, "_run", side_effect=responses) as run,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                agent_search.index(migrated, repo)
            self.assertEqual(run.call_args_list[0].args[0][-2:], ["daemon", "stop"])
            marker = migrated / "active" / (mirror.name + ".json")
            self.assertEqual(json.loads(marker.read_text())["source_digest"], source_digest(entries))

            failed = root / "failed"
            venv, mirror, _config, _runtime = paths(failed, repo)
            command = agent_search.ccc_path(venv)
            command.parent.mkdir(parents=True)
            command.write_bytes(b"CLI")
            result = subprocess.CompletedProcess([], 0, stdout="Indexing: complete error: 1")
            with (
                patch.object(agent_search, "tracked_files", return_value=entries),
                patch.object(agent_search, "_run", return_value=result),
                self.assertRaisesRegex(RuntimeError, "index errors"),
            ):
                agent_search.index(failed, repo)
            self.assertFalse((failed / "active" / (mirror.name + ".json")).exists())

    def test_mirror_and_source_resource_boundaries(self):
        """Purpose: Exercise mirror escape/link checks and the tracked-file logical size ceiling without large disk
        writes.
        Inputs: Owned source/stale files plus narrowly scoped path-method doubles for hostile filesystem states.
        Outputs: Escaping names, redirected targets/stale files and oversized source metadata fail before copying.
        """
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mirror = root / "mirror"
            source = root / "source.py"
            source.write_text("pass\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "escapes target"):
                prepare_mirror(mirror, [("../outside.py", source)])
            target = mirror / "source.py"
            concrete_path = type(target)
            original_is_symlink = concrete_path.is_symlink

            def redirected(path):
                return path == target or original_is_symlink(path)

            with (
                patch.object(concrete_path, "is_symlink", autospec=True, side_effect=redirected),
                self.assertRaisesRegex(ValueError, "mirror path is a link"),
            ):
                prepare_mirror(mirror, [("source.py", source)])
            stale = mirror / "stale.py"
            stale.write_text("stale", encoding="utf-8")
            original_resolve = concrete_path.resolve

            def escaped(path, *args, **kwargs):
                if path == stale:
                    return root.parent / "outside.py"
                return original_resolve(path, *args, **kwargs)

            with (
                patch.object(concrete_path, "resolve", autospec=True, side_effect=escaped),
                self.assertRaisesRegex(ValueError, "stale mirror path escapes"),
            ):
                prepare_mirror(mirror, [])
            repo = root / "repo"
            repo.mkdir()
            oversized = repo / "large.py"
            oversized.write_text("pass\n", encoding="utf-8")
            canonical_oversized = oversized.resolve()
            original_stat = concrete_path.stat

            def large_stat(path, *args, **kwargs):
                if path == canonical_oversized:
                    return SimpleNamespace(st_mode=stat.S_IFREG, st_size=32 * 1024 * 1024 + 1)
                return original_stat(path, *args, **kwargs)

            with (
                patch.object(agent_search.subprocess, "run") as run,
                patch.object(concrete_path, "stat", autospec=True, side_effect=large_stat),
                self.assertRaisesRegex(ValueError, "exceeds 32 MiB"),
            ):
                run.return_value.stdout = b"large.py\0"
                tracked_files(repo)

    def test_main_routing_and_script_failure_boundary(self):
        """Purpose: Route each public action and retain bounded child diagnostics at the script error boundary.
        Inputs: Direct parser calls plus a module run whose installer child raises CalledProcessError with output.
        Outputs: Actions dispatch exactly; invalid search is parser-visible; script failures exit three with
        diagnostics.
        """
        base = Path(tempfile.gettempdir()) / "cocoindex-agent-test-home"
        with patch.object(agent_search, "home", return_value=base), patch.object(agent_search, "install") as install:
            self.assertEqual(agent_search.main(["install"]), 0)
        install.assert_called_once_with(base)
        with patch.object(agent_search, "home", return_value=base), patch.object(agent_search, "index") as index:
            self.assertEqual(agent_search.main(["index"]), 0)
        index.assert_called_once_with(base)
        with patch.object(agent_search, "home", return_value=base), patch.object(agent_search, "search") as search_call:
            self.assertEqual(agent_search.main(["search", "conceptual query", "--limit", "2"]), 0)
        search_call.assert_called_once_with(base, "conceptual query", 2, path=None)
        with patch.object(agent_search, "home", return_value=base), self.assertRaises(SystemExit) as invalid:
            agent_search.main(["search", " ", "--limit", "0"])
        self.assertEqual(invalid.exception.code, 2)
        with tempfile.TemporaryDirectory() as temporary:
            failure = subprocess.CalledProcessError(7, ["owned child"], output="retained child output")
            with (
                patch.dict(os.environ, {"AGENT_CODE_HOME": str(Path(temporary).resolve())}),
                patch.object(subprocess, "run", side_effect=failure),
                patch("sys.argv", ["cocoindex_agent_search", "install"]),
                patch.object(sys, "path", [str(agent_search.ROOT / "tools"), *sys.path]),
                contextlib.redirect_stderr(io.StringIO()) as errors,
                self.assertRaises(SystemExit) as stopped,
            ):
                runpy.run_path(str(Path(agent_search.__file__).resolve()), run_name="__main__")
        self.assertEqual(stopped.exception.code, 3)
        self.assertIn("retained child output", errors.getvalue())
        self.assertIn("error: CocoIndex agent search", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
