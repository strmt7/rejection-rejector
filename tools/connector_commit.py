#!/usr/bin/env python3
"""Create a commit through the official GitHub connector (GitHub API).

The repository's commit-attribution policy (CONTRIBUTING.md, "Git Workflow")
requires agent-assisted publication through the authenticated official GitHub
connector so that GitHub assigns the contributor identity itself. This tool
builds commits via the REST git-data API (blobs -> tree -> commit -> update
ref) through the authenticated `gh` session. It NEVER supplies author or
committer fields: the identity is assigned by the connector and must be
verified from the returned commit.

Inputs:
    --repo OWNER/NAME   target repository (default: strmt7/rejection-rejector)
    --branch NAME       branch to advance (default: main)
    --message TEXT      commit message (required)
    --set PATH=FILE     add-or-update a file with FILE's content (use - for stdin)
    --delete PATH       remove a file
Output:
    prints the created commit SHA and the connector-assigned author/committer
    identity; exit code 0 on success, 2 on identity mismatch (policy
    violation), 1 on any other failure.
"""

import argparse
import json
import subprocess
import sys

EXPECTED_EMAIL_SUFFIX = "@users.noreply.github.com"


def gh_api(endpoint, method=None, payload=None):
    """Call the GitHub API through the authenticated gh session.

    Inputs: `endpoint` -- REST path under api.github.com; `method` -- optional
    HTTP method; `payload` -- optional JSON body. Output: parsed JSON response;
    raises RuntimeError on non-2xx exit.
    """
    args = ["gh", "api", endpoint]
    if method:
        args += ["-X", method]
    if payload is not None:
        args += ["--input", "-"]
    result = subprocess.run(
        args,
        check=False,
        capture_output=True,
        text=True,
        input=json.dumps(payload) if payload is not None else None,
    )
    if result.returncode != 0:
        raise RuntimeError(f"gh api {endpoint}: {result.stderr[:300]}")
    return json.loads(result.stdout) if result.stdout.strip() else {}


def normalize_text(content):
    """Normalize text content to the repository's committed line endings.

    Inputs: `content` -- decoded file text. Output: the text with CRLF and CR
    line endings converted to LF. The repository policy (.gitattributes
    `* text=auto eol=lf`) stores all text with LF; connector-created blobs
    bypass git's clean filters, so this function reproduces them exactly.
    """
    return content.replace("\r\n", "\n").replace("\r", "\n")


def parse_set(spec):
    """Parse one --set PATH=FILE argument.

    Inputs: `spec` -- "path=file" string (file may be "-" for stdin).
    Output: (path, content) tuple with line endings normalized to LF.
    """
    if "=" not in spec:
        raise ValueError(f"--set expects PATH=FILE, got {spec!r}")
    path, source = spec.split("=", 1)
    if not path:
        raise ValueError(f"--set path is empty in {spec!r}")
    if source == "-":
        return path, normalize_text(sys.stdin.read())
    with open(source, encoding="utf-8", newline="") as handle:
        return path, normalize_text(handle.read())


def build_entries(sets, deletes, blobs):
    """Assemble git tree entries for the requested file operations.

    Inputs: `sets` -- list of (path, content); `deletes` -- list of paths
    (each recorded as a None blob sha); `blobs` -- mapping path -> blob sha.
    Output: list of tree entry dicts with path, mode, type and sha fields.
    """
    entries = []
    for path, _content in sets:
        entries.append(
            {
                "path": path,
                "mode": "100644",
                "type": "blob",
                "sha": blobs[path],
            }
        )
    for path in deletes:
        entries.append({"path": path, "mode": "100644", "type": "blob", "sha": None})
    return entries


def verify_identity(commit):
    """Verify the connector assigned the contributor identity.

    Inputs: `commit` -- the created commit object from the API.
    Output: (author, committer) identity strings; raises SystemExit(2) when the
    identity is missing, mismatched between author and committer, or is an
    automation identity (policy violation per CONTRIBUTING.md).
    """
    author = commit.get("author") or {}
    committer = commit.get("committer") or {}
    author_id = f"{author.get('name', '')} <{author.get('email', '')}>"
    committer_id = f"{committer.get('name', '')} <{committer.get('email', '')}>"
    email = author.get("email", "")
    if not email or not email.endswith(EXPECTED_EMAIL_SUFFIX):
        sys.exit(f"POLICY VIOLATION: connector did not assign the contributor identity: {author_id}")
    if author_id != committer_id:
        sys.exit(f"POLICY VIOLATION: author/committer mismatch: {author_id} vs {committer_id}")
    return author_id, committer_id


def main():
    """Create one connector commit for the requested file operations.

    Inputs: command-line arguments (see module docstring). Output: prints the
    new commit SHA and verified identity; advances the branch ref.
    """
    parser = argparse.ArgumentParser(description="Commit via the official GitHub connector")
    parser.add_argument("--repo", default="strmt7/rejection-rejector")
    parser.add_argument("--branch", default="main")
    parser.add_argument("--message", required=True)
    parser.add_argument("--set", action="append", default=[], metavar="PATH=FILE")
    parser.add_argument("--delete", action="append", default=[])
    args = parser.parse_args()
    if not args.set and not args.delete:
        parser.error("at least one --set or --delete is required")

    sets = [parse_set(spec) for spec in args.set]
    base = f"repos/{args.repo}"
    head = gh_api(f"{base}/git/ref/heads/{args.branch}")["object"]["sha"]
    parent = gh_api(f"{base}/git/commits/{head}")
    blobs = {}
    for path, content in sets:
        blob = gh_api(f"{base}/git/blobs", "POST", {"content": content, "encoding": "utf-8"})
        blobs[path] = blob["sha"]
    entries = build_entries(sets, args.delete, blobs)
    tree = gh_api(f"{base}/git/trees", "POST", {"base_tree": parent["tree"]["sha"], "tree": entries})
    commit = gh_api(
        f"{base}/git/commits",
        "POST",
        {
            "message": args.message,
            "tree": tree["sha"],
            "parents": [head],
        },
    )
    gh_api(f"{base}/git/refs/heads/{args.branch}", "PATCH", {"sha": commit["sha"]})
    author_id, committer_id = verify_identity(commit)
    print(commit["sha"])
    print(f"author   : {author_id}")
    print(f"committer: {committer_id}")


if __name__ == "__main__":
    main()
