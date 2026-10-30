# Crawl4AI Public Test Review, 6 October 2026

Status: the maintainer authorized these four exact test-fixture dispositions and
their five exact integrity values on 6 October 2026. The production consumer now
loads this separate cohort; direct-consumer qualification passed. Existing
NLTK and Crawl4AI documentation cohorts remain byte-identical.

The hosted secret-history scan at
`e49459c687d8d947eb1a6d2222ef484d6cfe1bf0` retained seven results, admitted
five previously authorized examples and rejected two reports at lines 165 and
176. The introducing archive commit is
`a04c3542f884dedab0071b765a82381c9bb19eb0`. Its original archive remains
`third_party/upstream/crawl4ai/0.9.4/crawl4ai-0.9.4.tar.gz`, SHA-256
`fd118861b1acff90ac0db4ceae4d529691fd1a0a0d4417c710de3c7d2114ae88`.

The installed pinned scanner is
`trufflesecurity/trufflehog:3.97.4@sha256:562bc231afa9de3d04de44cfe624252b08207de1fc3cebc5e7ed92bed7f279e4`.
A bounded URI-only diagnostic scanned the original introducing Git range,
using the same detector with network access disabled. It reproduced all eight
URI report identities, including two additional URL-filter test attributions
that may become unknown when verification encounters network errors. This
diagnostic does not replace the production all-detector scan or its verification.
The preceding small-memory diagnostic failed with `signal: killed`; it provides
no clean-scan evidence. The successful attempt used the existing Windows/Docker
memory-admission policy, zero swap and a RAM-backed temporary clone. No member
was executed, no archive was edited and no history was rewritten.

## Individual Source Evidence

| Reported archive line | Original member | Actual source line | Exact matched-URI SHA-256 |
| --- | --- | --- | --- |
| 165 | `crawl4ai-0.9.4/tests/test_config_defaults.py` | 176 | `fd73a17568798cf91bb8eb66cac520c44f15018594616b1e19f8342f11deb808` |
| 176 | `crawl4ai-0.9.4/tests/test_config_defaults.py` | 176 | `fd73a17568798cf91bb8eb66cac520c44f15018594616b1e19f8342f11deb808` |
| 232 | `crawl4ai-0.9.4/tests/test_cloud_bugs_batch.py` | 232 | `e541fbb0c520248f573bb38d560f21a9dba6529dcaffddfdf804b4079eead4f6` |
| 292 | `crawl4ai-0.9.4/tests/test_cloud_bugs_batch.py` | 232 | `e541fbb0c520248f573bb38d560f21a9dba6529dcaffddfdf804b4079eead4f6` |

The complete defaults-test member has SHA-256
`56945c9ed9fbc5da20ad3971a94c83156c9ee715462826c5466892cf9e21fa5f`.
Its proxy-conversion test supplies literal placeholder username/password values
to `BrowserConfig.set_defaults`, constructs configuration and asserts the parsed
proxy server. The matched input is an adversarial configuration-parser fixture,
not a credential default installed by the crawler launcher.

The complete URL-filter test member has SHA-256
`def02d904294e36d081d869c2bff180512f64a942475d5b05ec12fcff7cd0927`.
It applies an existing `/docs/*` URL pattern to an example-domain URL containing
literal placeholder authentication. The tested operation is local URL filtering;
it does not use that authentication to download a resource. Both reported
attributions map to the exact same original input at source line 232.

Original public sources are the
[defaults tests](https://github.com/unclecode/crawl4ai/blob/v0.9.4/tests/test_config_defaults.py)
and [URL-filter tests](https://github.com/unclecode/crawl4ai/blob/v0.9.4/tests/test_cloud_bugs_batch.py).
Reported and actual locations remain separate, individually bound fields.
An unverified result alone is not the evidence for these decisions.

## Authorized Exact Dispositions

The authorized cohort `.github/scanner-secret-reviews-crawl4ai-tests.json` has
normalized complete-file SHA-256
`146d7340dade2e7db1696dbe8b2fa474cdab0633a75a954e9935551a02dd4bb0`.
Authorization admits only the four detector-17 reports listed above and
their five distinct archive/member/match integrity values, bound to that entire
cohort. A source, location, match, scanner or cohort change expires its relevant
binding. Verified reports and every unmatched report remain blocking. Sanitized
raw reports remain retained; these decisions do not establish a source fix.

The operating guide's Security Rules require an individually authorized public
test-fixture disposition. Removing useful tests or rewriting the immutable
archive to evade a scanner would violate the repository's remediation contract.
Admission requires that authorization and successful direct-consumer validation.

Evidence under ignored `out/` includes the hosted sanitized report,
`crawl4ai-uri-detector-complete-20261006.json`, the complete source-match inventory
and the successful bounded scanner diagnostic. These records establish the
current URI identities, not universal absence of future findings.

All eighteen secret-report contracts, fourteen metadata contracts and seven
hosted-review contracts passed. The source-backed archive loop reproduced all
eight authorized URI identities and rejected adjacent locations, changed actual
source lines and verified results. Independent cohort tests preserved earlier
ledger bytes, checked every complete cohort hash and rejected malformed policy.
The affected selector, CI projection, runner and publication-policy contracts
also passed. No native target was rebuilt for this approval batch. The initial
lint failure was a one-character comment-length violation; the corrected
affected checks passed. At that checkpoint, a fresh hosted all-detector run
was still required; its subsequent result is recorded below.

At commit `047629267cbf8dd866976ed6f4ddcf9b876b8389`, the normal hosted
secret-history scan passed. Its retained artifact reported five findings,
five individually reviewed public fixtures and zero unresolved results, with
the exact three cohort hashes and pinned scanner image. The URI-only diagnostic
and direct-consumer regressions retain the eight exact URI identities; the
different production finding count does not justify removing unmatched-report
controls or establish that network verification will always return the same
results. The twelve hosted DS173237 integrity-metadata alerts were separately
checked against this commit's original Git blob, complete cohort hash, exact
highlighted locations and the five authorized public values. Their existing
maintainer-authorized false-positive dispositions were applied individually;
raw SARIF and sanitized secret reports remain retained.
