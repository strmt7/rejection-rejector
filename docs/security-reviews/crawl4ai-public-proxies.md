# Crawl4AI Public Proxy Example Review, 5 October 2026

Status: the maintainer explicitly approved these four exact public examples on
5 October 2026. The ledger and bounded source consumer implement only those
identities; hosted qualification remains separate.

The original NLTK ledger bytes and their earlier metadata bindings are preserved.
These approvals live in the independent
`.github/scanner-secret-reviews-crawl4ai.json` cohort, whose normalized SHA-256 is
`4ef7c35541ad8296e33f318df5606382398bf67986e858996b1cdb1478a3757d`.
Its six distinct archive/member/match digest values are the exact public
integrity identities approved here. DevSkim metadata reviews bind only those
values to this complete cohort hash; changes expire those bindings. This does
not admit source-code findings or change earlier approval identities.

The secret-history job for commit
`e56becc7db74453c2ea34b83fa96464dbf156020` failed with TruffleHog exit 183
and report-redaction exit 3. The original sanitized report retains five
results: the previously approved NLTK fixture and four unresolved Crawl4AI
URI reports. Neither the scanner nor its unknown-result gate was weakened.

The scanner identity is
`trufflesecurity/trufflehog:3.97.4@sha256:562bc231afa9de3d04de44cfe624252b08207de1fc3cebc5e7ed92bed7f279e4`.
All four new reports use detector 17 (`URI`), have `verified: false` and a
verification error, and originate in commit
`a04c3542f884dedab0071b765a82381c9bb19eb0`. Their common tracked archive is
`third_party/upstream/crawl4ai/0.9.4/crawl4ai-0.9.4.tar.gz`, SHA-256
`fd118861b1acff90ac0db4ceae4d529691fd1a0a0d4417c710de3c7d2114ae88`.
It remains byte-identical to the official published source.

## Individual Evidence

The original `crawl4ai/async_configs.py` member has SHA-256
`80cd70552d5d407c5eb089ded20cec5b88cd8de6a2b82e76a4619d95b2ae0a92`.
The [upstream configuration source](https://github.com/unclecode/crawl4ai/blob/v0.9.4/crawl4ai/async_configs.py)
contains these literal documentation examples:

- Reported line 838 is the `BrowserConfig` proxy argument docstring. It states
  that no proxy is used by default. The matched URI's complete SHA-256 is
  `f363b60a8ca4f7c62af67ba1470168a89a52d073fd36ed392856d1cbf0c63a48`.
- Reported line 699 is a supported-format example in `ProxyConfig.from_string`.
  The matched URI's complete SHA-256 is
  `0511b1a4e7811670fdc5a7ff9edefd2f389f468fd73d3cc298c4da6af9dd97ff`.
- Reported line 696 is a second report of that same match, attributed to the
  enclosing docstring's start. The actual source match is at line 699. Its
  complete URI hash is the same value above. A review must retain both the
  reported location and actual member location; it cannot silently widen a
  location match.

The original `crawl4ai/async_crawler_strategy.py` member has SHA-256
`19f2c1737adea0e82ee058662cc47f6cb3e7fd8651a9fd41b69761c935520719`.
The [upstream HTTP strategy](https://github.com/unclecode/crawl4ai/blob/v0.9.4/crawl4ai/async_crawler_strategy.py)
has an explanatory comment at reported/source line 2644 demonstrating insertion
of caller-provided proxy credentials into a URL. The comment's complete matched
URI SHA-256 is
`df5d0c0b6699181dcdecf0b5d53d60b7bc18ad36a9d306faa058306242584253`.
The executable function uses its caller's server, username and password; it does
not use the comment's example as a configuration default.

Each matched example uses literal placeholder username and password values.
The enclosing documentation/comment and actual credential consumer were
reviewed, rather than treating an unverified result as proof of harmlessness.
A bounded local scan of the introducing Git range with the exact scanner
reproduced the four locations and exact match identities. This diagnostic
disabled remote credential verification; the production scanner remains
unchanged and its original hosted report is retained.

## Approved Narrow Disposition

The authorized review binds each report to the exact archive, complete
member, reported and source locations, match bytes, detector and scanner
identity above. It preserves every raw sanitized finding, rejects source,
location or scanner changes, and leaves all other reports blocking. The existing
consumer now bounds gzip expansion before parsing TAR metadata, rejects
duplicate or linked members, and reads only the exact complete member. The
approved NLTK record and its ZIP/source checks remain unchanged. No archive,
detector or path exclusion, upstream-archive edit, credential obfuscation or
Git-history rewrite is used.

The reported line and actual source line are independently bound, including
the 696/699 attribution pair. Regression controls reproduce each match from its
original complete source and reject nearby reported/source locations, newly
verified findings, duplicate members, links, excess expansion and unsupported
formats. Original sanitized reports and unmatched findings remain visible.
This individual approval does not close a source-code vulnerability or qualify
the separate Windows crawler download repair.

Local evidence: `out/crawl4ai-e56-secret-artifact/`,
`out/crawl4ai-private-uri-diagnosis.json`, and the bounded diagnosis script.
