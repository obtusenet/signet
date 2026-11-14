#!/bin/sh
# Copyright (c) 2026 Obtuse Networking LLC
# SPDX-License-Identifier: MIT
#
# The SBOM (contrib/packaging/sbom.sh) is valid SPDX 2.3 JSON and lists every
# module compiled in from vendor/, at its vendored version.  Run from the
# repository root; part of make test.  Needs python3.  With pyspdxtools
# (pip install spdx-tools) it is also checked against the SPDX specification.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 2
out=$(mktemp)
trap 'rm -f "$out"' EXIT

if ! contrib/packaging/sbom.sh . 0.0.0 > "$out"; then
	echo "FAIL - sbom.sh failed"
	exit 1
fi

# Each vendored module that has a directory, as "path version".
modules=$(sed -n 's/^# \([^ ]*\) \([^ ]*\)$/\1 \2/p' vendor/modules.txt | while read -r m v; do
	[ -d "vendor/$m" ] && echo "$m $v"
done)

printf '%s\n' "$modules" | python3 -I -c '
import json, re, sys
doc = json.load(open(sys.argv[1]))
failed = 0
def fail(msg):
    global failed
    failed += 1
    print("FAIL -", msg)

for key, want in (("spdxVersion", "SPDX-2.3"), ("dataLicense", "CC0-1.0"), ("SPDXID", "SPDXRef-DOCUMENT")):
    if doc.get(key) != want:
        fail("%s is %r, not %r" % (key, doc.get(key), want))
if not doc.get("documentNamespace", "").startswith("https://"):
    fail("documentNamespace is not a URI")
info = doc.get("creationInfo", {})
if not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", info.get("created", "")):
    fail("creationInfo.created is not a UTC time")
if not info.get("creators"):
    fail("no creators")

licences = {"MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "MIT AND Apache-2.0", "blessing"}
ids = set()
by_name = {}
for p in doc.get("packages", []):
    sid = p.get("SPDXID", "")
    if not re.fullmatch(r"SPDXRef-[A-Za-z0-9.-]+", sid):
        fail("bad SPDXID %r" % sid)
    if sid in ids:
        fail("SPDXID %s twice" % sid)
    ids.add(sid)
    for key in ("name", "versionInfo", "downloadLocation", "licenseConcluded", "licenseDeclared", "copyrightText"):
        if not p.get(key):
            fail("%s has no %s" % (sid, key))
    if p.get("licenseDeclared") not in licences:
        fail("%s: unexpected licence %r" % (sid, p.get("licenseDeclared")))
    purls = [r["referenceLocator"] for r in p.get("externalRefs", []) if r.get("referenceType") == "purl"]
    if len(purls) != 1:
        fail("%s has no purl" % sid)
    by_name[p.get("name")] = (p, purls[0] if purls else "")

for line in sys.stdin.read().split("\n"):
    if not line:
        continue
    module, version = line.split()
    if module not in by_name:
        fail("vendored module %s is missing" % module)
        continue
    p, purl = by_name[module]
    if p["versionInfo"] != version:
        fail("%s is %s, vendored %s" % (module, p["versionInfo"], version))
    if purl != "pkg:golang/%s@%s" % (module, version):
        fail("%s: purl %s" % (module, purl))

for want in ("signet", "go", "sqlite"):
    if want not in by_name:
        fail("no %s package" % want)

described = False
for r in doc.get("relationships", []):
    for key in ("spdxElementId", "relatedSpdxElement"):
        if r.get(key) not in ids | {"SPDXRef-DOCUMENT"}:
            fail("relationship to unknown %r" % r.get(key))
    if r.get("relationshipType") == "DESCRIBES" and r.get("spdxElementId") == "SPDXRef-DOCUMENT":
        described = True
if not described:
    fail("the document describes nothing")

print("sbom: %d packages, %d problems" % (len(ids), failed))
sys.exit(1 if failed else 0)
' "$out" || exit 1

if command -v pyspdxtools > /dev/null 2>&1; then
	cp "$out" "$out.spdx.json"
	if ! pyspdxtools -i "$out.spdx.json" > /dev/null; then
		rm -f "$out.spdx.json"
		echo "FAIL - pyspdxtools rejects it"
		exit 1
	fi
	rm -f "$out.spdx.json"
	echo "sbom: pyspdxtools accepts it"
else
	echo "sbom: pyspdxtools not installed; SPDX validation skipped"
fi
