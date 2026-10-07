#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Derive a CycloneDX 1.5 inventory of the Cargo workspace from Cargo.lock.

P07-D5 / P07-I05 fallback for `cargo cyclonedx`, which dependency-guard blocked
(Socket deep score 36, see docs/security/dependency-evidence-2026-10-06.md).
Standard library only. It never builds: it reads Cargo.lock and runs
`cargo metadata` and `cargo tree` with --locked --offline, so it fails closed
if the lockfile is stale or a needed crate is not already in the local cache.

  python3 docs/release/sbom/generate-cargo-cdx.py            # write cargo.cdx.json
  python3 docs/release/sbom/generate-cargo-cdx.py --check    # regenerate and compare

The output is deterministic for a given Cargo.lock and toolchain cache: the
serial number derives from the lock hash and no timestamp is recorded.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib
import uuid

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().with_name("cargo.cdx.json")
TARGETS = ("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu")
SPDX_ID = re.compile(r"^[A-Za-z0-9.+-]+$")


def run(*args):
    done = subprocess.run(args, cwd=ROOT, capture_output=True, text=True)
    if done.returncode != 0:
        sys.exit(f"{' '.join(args)}: {done.stderr.strip()[:400]}")
    return done.stdout


def normalise_license(value):
    """Return (SPDX expression, original or None). Cargo accepts the deprecated '/' form."""
    if value is None:
        return None, None
    expression = value.strip()
    normalised = re.sub(r"\s*/\s*", " OR ", expression) if "/" in expression else expression
    return normalised, (expression if normalised != expression else None)


def valid_expression(expression):
    tokens = re.findall(r"\(|\)|[^\s()]+", expression)
    if not tokens:
        return False
    depth = 0
    expect_term = True
    for token in tokens:
        if token == "(":
            if not expect_term:
                return False
            depth += 1
        elif token == ")":
            if expect_term or depth == 0:
                return False
            depth -= 1
        elif token in ("AND", "OR"):
            if expect_term:
                return False
            expect_term = True
        elif token == "WITH":
            if expect_term:
                return False
            expect_term = True
        else:
            if not expect_term or not SPDX_ID.match(token):
                return False
            expect_term = False
    return depth == 0 and not expect_term


def build():
    lock_bytes = (ROOT / "Cargo.lock").read_bytes()
    lock = tomllib.loads(lock_bytes.decode())
    packages = {(p["name"], p["version"]): p for p in lock["package"]}
    by_name = {}
    for name, version in packages:
        by_name.setdefault(name, []).append(version)

    metadata = {}
    compiled = {}
    for target in TARGETS:
        raw = json.loads(
            run("cargo", "metadata", "--locked", "--offline", "--filter-platform", target, "--format-version", "1")
        )
        for item in raw["packages"]:
            metadata.setdefault((item["name"], item["version"]), item)
        tree = run(
            "cargo", "tree", "--locked", "--offline", "--target", target, "--workspace",
            "-e", "normal,build,dev", "--prefix", "none", "--no-dedupe", "-f", "{p}",
        )
        for line in tree.splitlines():
            match = re.match(r"^(\S+) v(\S+)", line)
            if match:
                compiled.setdefault((match.group(1), match.group(2)), set()).add(target)

    def ref(name, version, package):
        if package.get("source", "").startswith("registry+"):
            return f"pkg:cargo/{name}@{version}"
        return f"{name}@{version}"

    def resolve(spec):
        parts = spec.split(" ")
        name = parts[0]
        version = parts[1] if len(parts) > 1 else None
        if version is None:
            candidates = by_name[name]
            if len(candidates) != 1:
                sys.exit(f"ambiguous lock dependency {spec}")
            version = candidates[0]
        return name, version

    components = []
    dependencies = []
    members = []
    for (name, version), package in sorted(packages.items()):
        bom_ref = ref(name, version, package)
        registry = package.get("source", "").startswith("registry+")
        meta = metadata.get((name, version))
        component = {"type": "library" if registry else "application", "bom-ref": bom_ref, "name": name, "version": version}
        properties = []
        if registry:
            component["purl"] = bom_ref
            checksum = package.get("checksum")
            if not checksum or not re.fullmatch(r"[0-9a-f]{64}", checksum):
                sys.exit(f"{name} {version}: registry package without a SHA-256 checksum")
            component["hashes"] = [{"alg": "SHA-256", "content": checksum}]
        else:
            members.append(bom_ref)
        targets = sorted(compiled.get((name, version), ()))
        component["scope"] = "required" if targets else "excluded"
        properties.append(
            {"name": "blindpass:compiled-targets", "value": ",".join(targets) if targets else "none"}
        )
        if meta is not None:
            expression, original = normalise_license(meta.get("license"))
            if expression and valid_expression(expression):
                component["licenses"] = [{"expression": expression}]
                if original:
                    properties.append({"name": "blindpass:license-as-declared", "value": original})
            else:
                properties.append({"name": "blindpass:license-evidence", "value": "declared value missing or not an SPDX expression"})
            if any("custom-build" in t["kind"] for t in meta["targets"]):
                properties.append({"name": "blindpass:build-script", "value": "true"})
            if any("proc-macro" in t["kind"] for t in meta["targets"]):
                properties.append({"name": "blindpass:proc-macro", "value": "true"})
            if meta.get("links"):
                properties.append({"name": "blindpass:links", "value": meta["links"]})
        else:
            properties.append({"name": "blindpass:license-evidence", "value": "crate metadata not in the offline cache (not compiled for the Linux targets)"})
        component["properties"] = properties
        components.append(component)
        edges = sorted({ref(*resolve(spec), packages[resolve(spec)]) for spec in package.get("dependencies", [])})
        dependencies.append({"ref": bom_ref, "dependsOn": edges})

    serial = uuid.uuid5(uuid.NAMESPACE_URL, "blindpass-cargo-sbom:" + hashlib.sha256(lock_bytes).hexdigest())
    document = {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "lifecycles": [{"phase": "pre-build"}],
            "tools": {"components": [{"type": "application", "name": "docs/release/sbom/generate-cargo-cdx.py"}]},
            "component": {
                "type": "application",
                "bom-ref": "blindpass-cargo-workspace",
                "name": "blindpass-cargo-workspace",
                "version": "0.1.0",
                "licenses": [{"license": {"id": "AGPL-3.0-only"}}],
            },
            "properties": [
                {"name": "blindpass:cargo-lock-sha256", "value": hashlib.sha256(lock_bytes).hexdigest()},
                {"name": "blindpass:compiled-targets-evidence", "value": "cargo tree --locked --offline --workspace -e normal,build,dev for " + ", ".join(TARGETS)},
            ],
        },
        "components": components,
        "dependencies": [{"ref": "blindpass-cargo-workspace", "dependsOn": sorted(members)}] + dependencies,
    }
    return document


def check(document):
    problems = []
    refs = [c["bom-ref"] for c in document["components"]] + [document["metadata"]["component"]["bom-ref"]]
    if len(set(refs)) != len(refs):
        problems.append("duplicate bom-ref")
    known = set(refs)
    for entry in document["dependencies"]:
        if entry["ref"] not in known:
            problems.append(f"dependency entry for unknown ref {entry['ref']}")
        for target in entry["dependsOn"]:
            if target not in known:
                problems.append(f"{entry['ref']} depends on unknown ref {target}")
    for component in document["components"]:
        for key in ("type", "bom-ref", "name", "version", "scope"):
            if not component.get(key):
                problems.append(f"{component.get('bom-ref')}: missing {key}")
        if "purl" in component and not re.fullmatch(r"pkg:cargo/[A-Za-z0-9_.-]+@[0-9A-Za-z.+-]+", component["purl"]):
            problems.append(f"{component['bom-ref']}: malformed purl")
        for entry in component.get("licenses", []):
            expression = entry.get("expression")
            if expression is not None and not valid_expression(expression):
                problems.append(f"{component['bom-ref']}: invalid SPDX expression {expression!r}")
    lock = tomllib.loads((ROOT / "Cargo.lock").read_text())
    if len(document["components"]) != len(lock["package"]):
        problems.append("component count differs from Cargo.lock")
    return problems


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="regenerate in memory and compare with the committed file")
    args = parser.parse_args()
    document = build()
    problems = check(document)
    if problems:
        sys.exit("SBOM self-check failed:\n  " + "\n  ".join(problems[:20]))
    rendered = json.dumps(document, indent=2, sort_keys=False) + "\n"
    if args.check:
        if OUT.read_text() != rendered:
            sys.exit("cargo.cdx.json is stale: regenerate with this script")
        print(f"cargo.cdx.json current: {len(document['components'])} components")
        return
    OUT.write_text(rendered)
    required = sum(1 for c in document["components"] if c["scope"] == "required")
    print(f"wrote {OUT.relative_to(ROOT)}: {len(document['components'])} components, {required} compiled for Linux")


if __name__ == "__main__":
    main()
