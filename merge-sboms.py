#!/usr/bin/env python3
"""Merge a Maven-generated CycloneDX SBOM with a syft container SBOM.

Maven SBOM provides accurate Java dependency metadata (correct groupIds, purls,
and test-scope dependencies). Syft SBOM provides OS packages and runtime components.

For Java components, the Maven SBOM takes priority. Non-Java components from
the syft SBOM are preserved as-is. Syft's dependency tree references are
rewritten to use Maven bom-refs where components were replaced.

Usage: merge-sboms.py <maven-sbom.json> <syft-sbom.json> <output.json>
"""

import json
import re
import sys


def strip_package_id(s):
    """Remove syft's package-id qualifier from a purl or bom-ref."""
    return re.sub(r'[?&]package-id=[a-f0-9]+', '', s)


def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <maven-sbom> <syft-sbom> <output>")
        sys.exit(1)

    maven_path, syft_path, output_path = sys.argv[1], sys.argv[2], sys.argv[3]

    with open(maven_path) as f:
        maven = json.load(f)

    with open(syft_path) as f:
        syft = json.load(f)

    # Index Maven components by (group, name, version)
    maven_components = {}
    for comp in maven.get("components", []):
        key = (comp.get("group", ""), comp.get("name", ""), comp.get("version", ""))
        maven_components[key] = comp

    # Build a mapping from syft bom-refs to Maven bom-refs for replaced components
    ref_map = {}
    syft_other = []
    for comp in syft.get("components", []):
        purl = comp.get("purl", "")
        if purl.startswith("pkg:maven/"):
            key = (comp.get("group", ""), comp.get("name", ""), comp.get("version", ""))
            if key in maven_components:
                old_ref = comp.get("bom-ref", "")
                new_ref = maven_components[key].get("bom-ref", "")
                if old_ref and new_ref:
                    ref_map[old_ref] = new_ref
        else:
            clean = comp.copy()
            if "purl" in clean:
                clean["purl"] = strip_package_id(clean["purl"])
            if "bom-ref" in clean:
                clean["bom-ref"] = strip_package_id(clean["bom-ref"])
            syft_other.append(clean)

    merged = syft.copy()
    merged["components"] = list(maven_components.values()) + syft_other

    # Rewrite dependency tree: replace old syft refs with Maven refs, strip package-id
    if "dependencies" in merged:
        new_deps = []
        known_refs = set()
        for comp in merged["components"]:
            known_refs.add(comp.get("bom-ref", ""))
        # Also include the top-level metadata component ref
        meta_ref = merged.get("metadata", {}).get("component", {}).get("bom-ref", "")
        if meta_ref:
            known_refs.add(strip_package_id(meta_ref))
            merged["metadata"]["component"]["bom-ref"] = strip_package_id(meta_ref)
            if "purl" in merged["metadata"]["component"]:
                merged["metadata"]["component"]["purl"] = strip_package_id(
                    merged["metadata"]["component"]["purl"])

        for dep in merged["dependencies"]:
            ref = dep.get("ref", "")
            ref = ref_map.get(ref, strip_package_id(ref))
            if ref not in known_refs:
                continue
            depends_on = []
            for d in dep.get("dependsOn", dep.get("depends_on", [])):
                d = ref_map.get(d, strip_package_id(d))
                if d in known_refs:
                    depends_on.append(d)
            new_deps.append({"ref": ref, "dependsOn": depends_on})
        merged["dependencies"] = new_deps

    maven_count = len(maven_components)
    os_count = len(syft_other)
    refs_rewritten = len(ref_map)
    print(f"  Maven components: {maven_count} (from cyclonedx-maven-plugin)")
    print(f"  OS/runtime components: {os_count} (from syft)")
    print(f"  Total: {maven_count + os_count}")
    print(f"  Dependency refs rewritten: {refs_rewritten}")

    with open(output_path, "w") as f:
        json.dump(merged, f, indent=2)

    print(f"  Written to: {output_path}")


if __name__ == "__main__":
    main()
