#!/usr/bin/env python3
"""Drop JavaScript "secret" hits that are provably not secrets.

The JS scan patterns are intentionally loose, and one of them is nothing but a
bare ``-----BEGIN ... PRIVATE KEY-----`` marker. That string is ordinary UI
copy: Grafana renders its TLS client-key field as

    placeholder="Begins with -----BEGIN RSA PRIVATE KEY-----"

Run #70 (2026-11-26) matched exactly that on
https://ffai.citymesh.com/public/build/app.0cd8deb042c68e8113e4.js, alerted
Discord, and drafted a High-severity Intigriti report for an "exposed RSA
private key" that does not exist. Every marker in that 3.3 MB bundle was a
form placeholder; not one had a key body after it.

A key marker is therefore only kept when

  * a base64 body of at least 60 characters follows it, and
  * the 60 bytes before it are not placeholder wording
    ("Begins with", "placeholder", "e.g.", "for example").

Hits whose bundle is no longer on disk (source maps are never downloaded, and
the download step caps at 100 files) are kept but tagged ``[unverified]`` so
they cannot be quoted as confirmed evidence.

Subcommands
  (default)  filter the hits file in place, write the rejects file
  selftest   assert placeholder rejection / real-key acceptance, exit 1 on fail

Exit codes
  0  filtered (or selftest passed)
  1  selftest failure or unreadable input
"""

import argparse
import os
import re
import sys
import tempfile

KEY_MARKER = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
# The body may be split by real newlines (PEM) or by literal "\n" escapes
# (a key embedded in a JS string literal).
KEY_BODY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\\]*[A-Za-z0-9+/=]{60,}")
PLACEHOLDER = re.compile(r"begins with|placeholder|for example|e\.g\.", re.I)

UNVERIFIED_TAG = " [unverified]"
BEFORE = 60          # bytes of context to inspect before a marker
AFTER = 400          # bytes to search for a key body after a marker


def redact(token):
    """Keep enough of a hit to identify it in logs, never the whole value."""
    token = token.replace("\n", "\\n")
    return token if len(token) <= 56 else token[:56] + "..."


def load_hashes(path):
    """hash -> url, from the ``sha1|url`` file written by the download step."""
    hashes = {}
    if not os.path.exists(path):
        return hashes
    with open(path, errors="ignore") as fh:
        for line in fh:
            if "|" in line:
                digest, url = line.rstrip("\n").split("|", 1)
                hashes.setdefault(url.strip(), digest.strip())
    return hashes


def classify_key_hit(url, token, bundle):
    """Verdict for a hit whose token contains a PRIVATE KEY marker.

    Returns (keep, reason). ``bundle`` is the file text, or None when the
    downloaded copy is unavailable.
    """
    if bundle is None:
        return True, "bundle not on disk - cannot verify"

    markers = list(KEY_MARKER.finditer(bundle))
    if not markers:
        # The regex matched in the file the scan used; if it is gone here the
        # bundle changed between download and analysis.
        return True, "marker no longer present in bundle - cannot verify"

    placeholder_only = True
    for match in markers:
        start = match.start()
        before = bundle[max(0, start - BEFORE):start]
        if PLACEHOLDER.search(before):
            continue
        placeholder_only = False
        if KEY_BODY.search(bundle[start:start + AFTER]):
            return True, "key marker with base64 body"

    if placeholder_only:
        return False, "marker is UI placeholder text (no key)"
    return False, "key marker without base64 body"


def filter_hits(secrets_path, hashes_path, jsdir, rejects_path):
    if not os.path.exists(secrets_path):
        print(f"verify_secret_hits: {secrets_path} missing, nothing to do")
        return 0, 0, 0

    hashes = load_hashes(hashes_path)
    bundles = {}
    kept, unverified, rejected = 0, 0, 0
    accepted_lines = []
    reject_lines = []

    with open(secrets_path, errors="ignore") as fh:
        lines = [l for l in fh if l.strip()]

    for line in lines:
        if " | " not in line:
            reject_lines.append(f"{line.strip()} | malformed hit line")
            rejected += 1
            continue
        url, token = line.rstrip("\n").split(" | ", 1)

        if "PRIVATE KEY" not in token:
            accepted_lines.append(line if line.endswith("\n") else line + "\n")
            kept += 1
            continue

        # Source-map hits are matched in memory and never written to disk.
        # Key matches are already redacted at match time (marker + body length
        # only) because results/ is committed to the repository.
        if token.startswith("SOURCEMAP-"):
            if "redacted" in token:
                accepted_lines.append(line if line.endswith("\n") else line + "\n")
                kept += 1
                continue
            if KEY_BODY.search(token):
                accepted_lines.append(line if line.endswith("\n") else line + "\n")
                kept += 1
            else:
                reject_lines.append(f"{url} | {redact(token)} | key marker without body in source map")
                rejected += 1
            continue

        digest = hashes.get(url.strip())
        path = os.path.join(jsdir, f"{digest}.js") if digest else None
        if path and path not in bundles:
            bundles[path] = open(path, errors="ignore").read() if os.path.exists(path) else None
        bundle = bundles.get(path) if path else None

        keep, reason = classify_key_hit(url, token, bundle)
        if keep:
            tag = "" if "cannot verify" not in reason else UNVERIFIED_TAG
            accepted_lines.append((url + " | " + token + tag).rstrip("\n") + "\n")
            kept += 1
            unverified += 1 if tag else 0
        else:
            reject_lines.append(f"{url} | {redact(token)} | {reason}")
            rejected += 1

    # Sorted and de-duplicated so the downstream `comm -13` diff against
    # results/js_secrets_previous.txt stays correct (comm needs sorted input;
    # the source-map pass appends after the initial sort).
    tmp = secrets_path + ".tmp"
    with open(tmp, "w") as out:
        out.writelines(sorted(set(accepted_lines)))
    os.replace(tmp, secrets_path)

    if rejects_path:
        with open(rejects_path, "w") as out:
            out.writelines(l + "\n" for l in sorted(set(reject_lines)))

    print(f"secret verification: {kept} kept ({unverified} unverified), {rejected} rejected")
    for line in reject_lines:
        print(f"  rejected: {line}")
    return kept, unverified, rejected


def selftest():
    """Fixture-based checks; runs in CI before the workflow is trusted."""
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB\n"
        "aFDrBz1rM4bWq0vGm8kQ0q1Zt3Kq8o0dQ1sQ0mQ0q1Zt3Kq8o0dQ1sQ0mQ0q1Zt3K\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    grafana = '<textarea placeholder="Begins with -----BEGIN RSA PRIVATE KEY-----" required></textarea>'
    placeholder_js = 'placeholder:"Begins with -----BEGIN RSA PRIVATE KEY-----"'

    cases = [
        ("placeholder attr", grafana, False),
        ("placeholder js string", placeholder_js, False),
        ("real pem", "var k = `" + pem + "`;", True),
        ("real pem escaped", "var k = '-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPBaaa\\n';", True),
        ("bare marker only", "-----BEGIN RSA PRIVATE KEY-----", False),
    ]

    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        secrets = os.path.join(tmp, "secrets.txt")
        hashes = os.path.join(tmp, "hashes.txt")
        jsdir = os.path.join(tmp, "js")
        os.makedirs(jsdir)
        rejects = os.path.join(tmp, "rejects.txt")

        for name, bundle, want_keep in cases:
            digest = "deadbeef"
            with open(os.path.join(jsdir, f"{digest}.js"), "w") as fh:
                fh.write(bundle)
            with open(hashes, "w") as fh:
                fh.write(f"{digest}|https://example.test/app.js\n")
            with open(secrets, "w") as fh:
                fh.write("https://example.test/app.js | -----BEGIN RSA PRIVATE KEY-----\n")
            filter_hits(secrets, hashes, jsdir, rejects)
            remaining = [l for l in open(secrets) if l.strip()]
            got = bool(remaining)
            if got != want_keep:
                failures.append(f"{name}: expected keep={want_keep}, got {got}")
            if want_keep is False and not open(rejects).read().strip():
                failures.append(f"{name}: rejected but no reason recorded")

        # A key found inside a source map is redacted at match time (results/ is
        # committed, so no key material is written); those lines must survive.
        with open(secrets, "w") as fh:
            fh.write(
                "https://example.test/app.js.map | SOURCEMAP-----BEGIN RSA PRIVATE KEY----- "
                "(body 1675 chars, redacted)\n"
            )
        filter_hits(secrets, hashes, jsdir, rejects)
        if not [l for l in open(secrets) if l.strip()]:
            failures.append("redacted source-map key: expected keep=True, got False")

    if failures:
        print("selftest FAILED")
        for f in failures:
            print("  " + f)
        return 1
    print(f"selftest OK ({len(cases)} fixtures + 1 source-map redaction)")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--secrets", default="results/js_secrets_current.txt")
    parser.add_argument("--hashes", default="results/js_hashes_current.txt")
    parser.add_argument("--jsdir", default="js_files")
    parser.add_argument("--rejects", default="results/js_secret_rejects.txt")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args(argv)

    if args.selftest:
        return selftest()
    if not os.path.exists(args.secrets):
        print(f"verify_secret_hits: {args.secrets} missing, nothing to filter")
        return 0
    filter_hits(args.secrets, args.hashes, args.jsdir, args.rejects)
    return 0


if __name__ == "__main__":
    sys.exit(main())
