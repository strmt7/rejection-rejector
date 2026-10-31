# NLTK SSRF Fixture Review, 5 October 2026

Status: the maintainer approved this exact public test fixture on 5 October 2026.

The secret-history job for commit `ef3ff5c223e7033355036148467ce36d1475f693`
failed with TruffleHog 3.97.4 exit 183. Its complete sanitized report contains
one unverified result with a verification error, detector 17 (`URI`), line
302, and path digest
`f8a3911752d4ea511465363ee1dc4d8d55e43aa6221f46ddc4a27651004a11fa`.
The path resolves to the original pinned NLTK source ZIP. It remains immutable.

Private, bounded inspection reproduced the result using the pinned scanner.
The match comes from `nltk/test/unit/test_attack_ssrf_expanded.py`, line 302,
in the [official upstream source](https://github.com/nltk/nltk/blob/1bd574cfd4e3bca82c6b145d9271a646df410707/nltk/test/unit/test_attack_ssrf_expanded.py#L302).
The archive SHA-256 is
`5dc19b964a2f0962b81908b8d494f36f20aca31d1a7f408e3f7e6e5180bd0f83`;
the complete member SHA-256 is
`4bfb64a7394949e1f210ac7caebce6581af3677a15e9d6fc39a1622628dbe625`.
The complete scanner-match SHA-256 is
`54a36e11bc7a3778764488651e5d3b938645f3eb577b68cabd375b12f013eedf`.
No matching value or auxiliary scanner response is published here.

The parametrized regression checks userinfo/fragment/whitespace host confusion.
Its complete URL parses to loopback `127.0.0.1`; the test asserts both that
hostname and refusal before any network access. A decoy in userinfo ends in
the reserved `.example` domain. The URI detector's regular expression matches
only a prefix ending at that decoy, rather than the full test URL. This is
public adversarial test input, with no authentication consumer or service
credential. An unverified flag alone would not establish that conclusion:
the original source, complete enclosing test, parsing behavior and exact
scanner match provide the evidence.

TruffleHog's latest published 3.97.9 retains the same matching expression;
its change to DNS-failure caching does not repair this interpretation. Removing
or obfuscating the upstream fixture, changing the immutable archive, excluding
the archive or detector, or removing unknown-result blocking would weaken
coverage and is not proposed.

The maintainer explicitly authorized an exception for this executable public
test finding. The narrow false-positive disposition must bind
the exact original archive, complete member, scanner identity, detector and
match, preserve every raw sanitized report, and reject changed or additional
findings. It does not close a source vulnerability or admit any historical
source approvals. The executable review ledger is
`.github/scanner-secret-reviews.json`; the redactor checks the historical Git
blob as well as current source bytes. Sanitized raw JSONL remains unchanged,
with a separate adjudication report. Unknown findings and scanner errors
still fail. Hosted qualification is pending for the new pushed source.

Local evidence: `out/nltk-hosted-secret-history/`,
`out/nltk-private-uri-diagnosis.json`, and the exact pinned/current detector
sources retained under `out/trufflehog-uri-*.go`.

DevSkim also labels the three integrity commitments in the approved review
ledger as possible secrets: archive digest at line 10, member digest at line
12, and public-match digest at line 14. They are the exact SHA-256 values
individually stated in this approved review, not authentication material.
Their metadata dispositions bind the complete LF-normalized ledger SHA-256
`60c0f9360f1d1888a0e17a34f0d83ae2c2e8d7579418a59585d056651b272b87`,
the exact value and highlighted region. Raw SARIF is retained. Any ledger
change expires those dispositions. This implements the same approved review;
it does not authorize a general secret-rule or source-file exception.
