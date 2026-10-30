"""Make a CycloneDX JSON SBOM describe one release file, reproducibly.

    python3 -I normalize_sbom.py --sbom IN --artifact FILE --purl PURL \
        --epoch SOURCE_DATE_EPOCH --out OUT

Generators stamp the current time and a random serial number into the
SBOM, and cyclonedx-gomod records the hash of its own binary, which
depends on the Go build that made it. This sets instead:

- metadata.timestamp to SOURCE_DATE_EPOCH (the commit time);
- serialNumber to a UUID derived from the file's SHA-256, so a rebuild
  gives the same SBOM, and each file's SBOM has its own serial number;
- metadata.component's purl and version to PURL, and its hashes to the
  file's SHA-256, so the SBOM names the file it describes;
- no hashes for the tools (their names and versions stay).

The output is sorted JSON with a trailing newline. Standard library only.
"""

import argparse
import datetime
import hashlib
import json
import uuid


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--sbom", required=True)
    p.add_argument("--artifact", required=True)
    p.add_argument("--purl", required=True)
    p.add_argument("--epoch", required=True, type=int)
    p.add_argument("--out", required=True)
    a = p.parse_args()

    with open(a.sbom, encoding="utf-8") as f:
        bom = json.load(f)
    if bom.get("bomFormat") != "CycloneDX":
        raise SystemExit(f"{a.sbom}: not a CycloneDX SBOM")
    with open(a.artifact, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()

    bom["serialNumber"] = "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, "sha256:" + digest))
    meta = bom.setdefault("metadata", {})
    meta["timestamp"] = (
        datetime.datetime.fromtimestamp(a.epoch, datetime.timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )
    tools = meta.get("tools")
    for tool in tools.get("components", []) if isinstance(tools, dict) else tools or []:
        tool.pop("hashes", None)

    root = meta.get("component")
    if root is None:
        raise SystemExit(f"{a.sbom}: no metadata.component")
    root["purl"] = a.purl
    root["version"] = a.purl.split("@", 1)[1].split("?", 1)[0]
    root["hashes"] = [{"alg": "SHA-256", "content": digest}]

    with open(a.out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(bom, f, indent=2, sort_keys=True, ensure_ascii=False)
        f.write("\n")


if __name__ == "__main__":
    main()
