# Crawl4AI 0.9.5 Source Provenance

`build.json` identifies the original source distribution on PyPI. The adjacent
SHA-256 sidecar pins its exact bytes and the build recipe pins its complete
length. The installer downloads it into an ignored per-user tool cache, verifies
both properties before extracting, then applies the documented portable
download repair. The canonical downstream wheel has a separate pinned SHA-256
sidecar. No upstream archive or installed binary is committed.

The original complete LICENSE, including its appended attribution requirement,
remains in the upstream source and every built wheel. The downstream build adds
its own source-change notice. See `docs/crawl4ai.md` for installation and
qualification commands.
