"""
Writes random receipts and inclusion proofs for the differential run.

Usage: python gen.py <out-dir> <cases> <seed>

Derives a throwaway Ed25519 key from the seed (public half in
<out-dir>/public.pem), signs receipts with it, and writes
<out-dir>/cases.jsonl: one object per
line, {"id", "kind": "receipt" | "inclusion", "raw": <JSON text>}. Each
verifier parses "raw" with its own language's JSON parser, as a caller
would. Most cases start valid and get one or two mutations, so they sit
near the edge of what a verifier accepts. Some nest a receipt or its
canonical near the depth limit of 64 (VAOS 2.0 section 7) or far past it,
up to 20,000 deep; their JSON text is built by hand, since json.dumps
cannot write it. A few are Guardian attestations shaped like runGuardian's,
whose runId or unsigned evidence nests near the limit or past it. Some
repeat a field, once shallow and once deep, in either order: the parser
keeps the last copy, but the depth counted on the text includes both.

About one receipt in ten is an Ed25519 edge case (VAOS 2.0 section 7.3)
under a key of its own, given as PEM in the case's "pem" field: the key
is ordinary, of mixed or small order, off the curve or non-canonical;
R is honest, the identity, of small or mixed order, non-canonical, off
the curve or random bytes; S is r + k*a, k*a, 0, plus L or random. The
signatures are built with the Python verifier's edwards25519 arithmetic,
so some of them pass the cofactorless check and not the strict profile.

The seed decides everything: the same seed and count give byte-identical
public.pem and cases.jsonl (Ed25519 signing is deterministic), so a
failing run is reproduced by running it again with its seed.
"""

from __future__ import annotations

import base64
import hashlib
import json
import random
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sovereign_matrix.verifiable_receipts import edwards25519 as ed

B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def canonical_json(obj: object) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False, sort_keys=True)


def leaf(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def inner(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def fold(leaf_hash: bytes, idx: int, size: int, path: list[bytes]) -> bytes:
    """The root that `path` proves `leaf_hash` against (RFC 9162 2.1.3)."""
    n_inner = (idx ^ (size - 1)).bit_length()
    h = leaf_hash
    for i in range(n_inner):
        h = inner(h, path[i]) if (idx >> i) & 1 == 0 else inner(path[i], h)
    for sib in path[n_inner:]:
        h = inner(sib, h)
    return h


def path_len(idx: int, size: int) -> int:
    n_inner = (idx ^ (size - 1)).bit_length()
    return n_inner + bin(idx >> n_inner).count("1")


def rand_value(rng: random.Random, depth: int = 0) -> object:
    pick = rng.randrange(9 if depth < 2 else 6)
    if pick == 0:
        return rng.randrange(-10, 10**6)
    if pick == 1:
        return rng.choice([0.5, 1.25, -3.0e-3, 1e21])
    if pick == 2:
        return rng.choice(["pass", "fail", "", "é", "日本", 'a"b', "\\", " ", "emoji \U0001f600"])
    if pick == 3:
        return rng.choice([True, False, None])
    if pick == 4:
        return "".join(rng.choice("abc xyz") for _ in range(rng.randrange(8)))
    if pick == 5:
        return rng.randrange(2**53 - 4, 2**53 + 4)
    if pick == 6:
        return [rand_value(rng, depth + 1) for _ in range(rng.randrange(3))]
    return {
        rng.choice("abcdef") + str(i): rand_value(rng, depth + 1) for i in range(rng.randrange(3))
    }


def respell_signature(rng: random.Random, sig: str) -> str:
    b64 = sig[3:]
    choice = rng.randrange(12)
    pos = rng.randrange(len(b64) + 1)
    if choice == 0:
        return "v2=" + b64[:pos] + rng.choice(["\n", "\r", "\r\n", " ", "\t"]) + b64[pos:]
    if choice == 1:  # non-zero padding bits
        last = B64.index(b64[-3])
        return "v2=" + b64[:-3] + B64[last ^ rng.randrange(1, 16)] + "=="
    if choice == 2:
        return "v2=" + b64.rstrip("=")
    if choice == 3:
        return "v2=" + b64 + "="
    if choice == 4:
        return "v2=" + b64.replace("+", "-").replace("/", "_")
    if choice == 5:
        return rng.choice(["V2=", "v2:", "v3=", "v1=", " v2=", ""]) + b64
    if choice == 6 and pos < len(b64):
        return "v2=" + b64[:pos] + rng.choice(B64) + b64[pos + 1 :]
    if choice == 7:
        return "v2=" + b64 + rng.choice(["A", "AA==", "\n"])
    if choice == 8:
        return "v2=" + base64.b64encode(base64.b64decode(b64)[:-1]).decode()
    return sig


def receipt_case(rng: random.Random, key: Ed25519PrivateKey) -> str:
    body = {"overall": rng.choice(["pass", "fail"]), "runId": f"run_{rng.randrange(10**6)}"}
    for _ in range(rng.randrange(4)):
        body[rng.choice("abcdefgh") + str(rng.randrange(3))] = rand_value(rng)
    canonical = canonical_json(body)
    signed_text = canonical
    if rng.random() < 0.1:  # a canonical that is not sorted or compact
        signed_text = json.dumps(body, ensure_ascii=rng.random() < 0.5)
    if rng.random() < 0.05:  # a canonical that is not a JSON object
        signed_text = json.dumps(rng.choice([[1, 2], "text", 3, None]))
    sig = "v2=" + base64.b64encode(key.sign(signed_text.encode())).decode()
    receipt: dict[str, object] = {
        "canonical": signed_text,
        "contentHash": "sha256:" + hashlib.sha256(signed_text.encode()).hexdigest(),
        "signature": sig,
    }
    # Envelope fields beside canonical: copies, numeric respellings, and claims.
    if isinstance(body, dict):
        for k, v in body.items():
            if rng.random() < 0.3:
                receipt[k] = v
                if isinstance(v, int) and not isinstance(v, bool) and rng.random() < 0.5:
                    receipt[k] = float(v)
    r = rng.random()
    if r < 0.15:
        receipt["signature"] = respell_signature(rng, sig)
    elif r < 0.25:
        ch = receipt["contentHash"]
        assert isinstance(ch, str)
        receipt["contentHash"] = rng.choice(
            [
                ch.upper(),
                ch[7:],
                ch[7:].upper(),
                "SHA256:" + ch[7:],
                "",
                None,
                0,
                ch + " ",
                "sha256:" + "0" * 64,
            ]
        )
    elif r < 0.35:
        receipt[rng.choice(["overall", "runId", "approvedBy", "x"])] = rand_value(rng)
    elif r < 0.42:
        receipt["canonical"] = signed_text.replace(",", ", ", 1)
    elif r < 0.47:
        del receipt[rng.choice(["canonical", "signature", "contentHash"])]
    elif r < 0.52:
        receipt["canonical"] = rand_value(rng)
    raw = json.dumps(receipt, ensure_ascii=rng.random() < 0.5)
    if rng.random() < 0.05:  # duplicate key: parsers disagree on which wins
        raw = raw[:-1] + ', "overall": ' + json.dumps(rng.choice(["pass", "fail"])) + "}"
    return raw


def nest(rng: random.Random, levels: int) -> str:
    """JSON text nested `levels` deep: arrays and objects, mixed at random."""
    opens, closes = [], []
    for _ in range(levels):
        if rng.random() < 0.5:
            opens.append("[")
            closes.append("]")
        else:
            opens.append('{"k":')
            closes.append("}")
    return "".join(opens) + "0" + "".join(reversed(closes))


def depth_case(rng: random.Random, key: Ed25519PrivateKey) -> str:
    """A signed receipt whose canonical, or a field beside it, nests deep.

    The canonical {"d": X} nests one deeper than X, and so does a receipt
    with the field "d": X; 63 levels in X is the deepest every verifier
    accepts.
    """
    levels = rng.choice(
        [rng.randrange(1, 63), 62, 63, 63, 64, 64, 65, rng.randrange(65, 300), 1000, 5000, 20000]
    )
    value = nest(rng, levels)
    shape = rng.randrange(6)
    if shape == 0:  # brackets inside strings do not count
        hidden = json.dumps("[" * levels + '\\"' + "{" * levels)
        canonical = '{"s":' + hidden + ',"d":' + value + "}"
    elif shape == 1:  # deep and not valid JSON
        canonical = '{"d":' + value[: rng.randrange(len(value))]
    elif shape == 2:  # a shallow canonical; the depth is beside it
        canonical = '{"a":1}'
    else:
        canonical = '{"d":' + value + "}"
    sig = "v2=" + base64.b64encode(key.sign(canonical.encode())).decode()
    fields = [
        '"canonical":' + json.dumps(canonical),
        '"contentHash":"sha256:' + hashlib.sha256(canonical.encode()).hexdigest() + '"',
        '"signature":"' + sig + '"',
    ]
    beside = rng.randrange(4)
    if beside == 1 or shape == 2:  # the same value beside the canonical
        fields.append('"d":' + value)
    elif beside == 2:  # a value nested another depth
        fields.append('"d":' + nest(rng, rng.choice([levels - 1, levels + 1, 64, 65]) or 1))
    rng.shuffle(fields)
    return "{" + ",".join(fields) + "}"


def duplicate_deep_case(rng: random.Random, key: Ed25519PrivateKey) -> str:
    """A receipt whose field "d" appears twice: once 1, once nested deep.

    JSON parsers keep the last copy, so the deep one is discarded when it
    comes first. A verifier reading the text still counts it (VAOS 2.0
    section 7.2): 63 levels make the receipt 64 deep, 64 levels 65.
    """
    canonical = '{"d":1}'
    sig = "v2=" + base64.b64encode(key.sign(canonical.encode())).decode()
    deep = '"d":' + nest(rng, rng.choice([62, 63, 64, 65, 1000, 20000]))
    copies = [deep, '"d":1'] if rng.random() < 0.5 else ['"d":1', deep]
    return (
        '{"canonical":'
        + json.dumps(canonical)
        + ',"contentHash":"sha256:'
        + hashlib.sha256(canonical.encode()).hexdigest()
        + '","signature":"'
        + sig
        + '",'
        + ",".join(copies)
        + "}"
    )


def guardian_case(rng: random.Random, key: Ed25519PrivateKey) -> str:
    """A Guardian attestation shaped like runGuardian's, nested near the limit.

    Its canonical is runGuardian's JSON.stringify, which the TypeScript
    library re-derives; the runId may nest deep (the canonical one level
    deeper) and so may a rule's unsigned evidence (the attestation three
    levels deeper: the attestation, rules and the rule).
    """
    run_levels = rng.choice([0, 0, rng.randrange(1, 63), 62, 63, 64, 65, 1000, 20000])
    evidence_levels = rng.choice([0, 0, rng.randrange(1, 61), 60, 61, 62, 63, 1000, 20000])
    run_id = nest(rng, run_levels) if run_levels else json.dumps(f"run_{rng.randrange(10**6)}")
    overall = rng.choice(["pass", "warn", "block"])
    rule = {"ruleId": "r1", "verdict": overall, "reason": rng.choice([None, "why"])}
    canonical = (
        '{"v":1,"type":"guardian-verdict","verdictId":"v1","runId":'
        + run_id
        + ',"agentSlug":"agent","tokenId":null,"overall":'
        + json.dumps(overall)
        + ',"rules":['
        + json.dumps(rule, separators=(",", ":"))
        + '],"issuedAt":"2026-10-24T00:00:00.000Z"}'
    )
    sig = "v2=" + base64.b64encode(key.sign(canonical.encode())).decode()
    evidence = nest(rng, evidence_levels) if evidence_levels else '{"n":1}'
    envelope_rule = (
        '{"ruleId":"r1","verdict":'
        + json.dumps(overall)
        + ',"reason":'
        + json.dumps(rule["reason"])
        + ',"evidence":'
        + evidence
        + ',"durationMs":2}'
    )
    if rng.random() < 0.1:  # an envelope that disagrees with its canonical
        overall = "pass" if overall != "pass" else "block"
    return (
        '{"verdictId":"v1","overall":'
        + json.dumps(overall)
        + ',"rules":['
        + envelope_rule
        + '],"totalMs":3,"issuedAt":"2026-10-24T00:00:00.000Z","canonical":'
        + json.dumps(canonical)
        + ',"contentHash":"'
        + hashlib.sha256(canonical.encode()).hexdigest()
        + '","signature":"'
        + sig
        + '"}'
    )


def inclusion_case(rng: random.Random) -> str:
    size = rng.choice(
        [
            rng.randrange(1, 70),
            rng.randrange(1, 2**20),
            rng.randrange(2**31 - 3, 2**31 + 3),
            rng.randrange(2**32 - 3, 2**32 + 3),
            rng.randrange(2**53 - 3, 2**53 + 3),
            2**63 - 1,
        ]
    )
    idx = rng.randrange(size)
    lf = leaf(rng.randbytes(8))
    path = [rng.randbytes(32) for _ in range(path_len(idx, size))]
    proof: dict[str, object] = {
        "leafHashHex": lf.hex(),
        "leafIndex": idx,
        "treeSize": size,
        "auditPath": [p.hex() for p in path],
        "rootHashHex": fold(lf, idx, size, path).hex(),
    }
    r = rng.random()
    if r < 0.1:
        proof["leafHashHex"] = rng.choice(
            [lf.hex().upper(), "0x" + lf.hex(), lf.hex()[:-2], lf.hex() + "00", ""]
        )
    elif r < 0.2 and path:
        i = rng.randrange(len(path))
        ap = list(proof["auditPath"])  # type: ignore[arg-type]
        ap[i] = rng.choice([ap[i].upper(), "0x" + ap[i], ap[i][:62], "", 7, None])
        proof["auditPath"] = ap
    elif r < 0.3:
        proof[rng.choice(["leafIndex", "treeSize"])] = rng.choice(
            [idx + 0.5, -1, True, False, str(idx), None, size, size + 1, 2**53, 2**64, -0]
        )
    elif r < 0.37:
        proof["rootHashHex"] = rng.choice([proof["rootHashHex"].upper(), "", "00" * 32])  # type: ignore[union-attr]
    elif r < 0.43 and path:
        ap = list(proof["auditPath"])  # type: ignore[arg-type]
        ap.pop(rng.randrange(len(ap))) if rng.random() < 0.5 else ap.append(ap[0])
        proof["auditPath"] = ap
    elif r < 0.46:
        proof["auditPath"] = rng.choice(["", None, {}, 3])
    return json.dumps(proof)


SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
TORSION = [
    ed.decode(bytes.fromhex(h))[0]
    for h in (
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  # order 2
        "0000000000000000000000000000000000000000000000000000000000000000",  # order 4
        "0000000000000000000000000000000000000000000000000000000000000080",  # order 4
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",  # order 8
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",  # order 8
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",  # order 8
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",  # order 8
    )
]


def edge_pem(raw: bytes) -> str:
    return (
        "-----BEGIN PUBLIC KEY-----\n"
        + base64.b64encode(SPKI_PREFIX + raw).decode()
        + "\n-----END PUBLIC KEY-----\n"
    )


def off_curve(rng: random.Random) -> bytes:
    """An encoding whose y has no x on the curve."""
    while True:
        data = rng.randrange(ed.P).to_bytes(32, "little")
        if ed.decode(data)[1] == ed.NOT_ON_CURVE:
            return data


def non_canonical(rng: random.Random) -> bytes:
    """y + p for y < 19, or x = 0 with the sign bit set."""
    if rng.random() < 0.3:
        return (rng.choice([1, ed.P - 1]) | (1 << 255)).to_bytes(32, "little")
    return (ed.P + rng.randrange(19) | (rng.randrange(2) << 255)).to_bytes(32, "little")


def edge_case(rng: random.Random, i: int) -> tuple[str, str]:
    """A receipt whose key, R or S sits on an edge of Ed25519; returns (raw, pem)."""
    a = rng.randrange(1, ed.L)
    a_point = ed.scalar_mult(a, ed.BASE)
    key_kind = rng.choice(["ordinary"] * 4 + ["mixed"] * 3 + ["small", "off", "noncanonical"])
    if key_kind == "ordinary":
        pub = ed.encode(a_point)
    elif key_kind == "mixed":
        pub = ed.encode(ed.point_add(a_point, rng.choice(TORSION)))
    elif key_kind == "small":
        pub = ed.encode(rng.choice([ed.IDENTITY, *TORSION]))
    elif key_kind == "off":
        pub = off_curve(rng)
    else:
        pub = non_canonical(rng)
    r = rng.randrange(1, ed.L)
    r_kinds = ["identity", "small", "mixed", "mixed", "nc", "off", "bytes"]
    r_kind = rng.choice(["honest"] * 3 + r_kinds)
    if r_kind == "honest":
        r_enc = ed.encode(ed.scalar_mult(r, ed.BASE))
    elif r_kind == "identity":
        r_enc = ed.encode(ed.IDENTITY)
    elif r_kind == "small":
        r_enc = ed.encode(rng.choice(TORSION))
    elif r_kind == "mixed":
        r_enc = ed.encode(ed.point_add(ed.scalar_mult(r, ed.BASE), rng.choice(TORSION)))
    elif r_kind == "nc":
        r_enc = non_canonical(rng)
    elif r_kind == "off":
        r_enc = off_curve(rng)
    else:
        r_enc = rng.randbytes(32)
    canonical = canonical_json({"edge": i, "key": key_kind, "overall": "pass", "r": r_kind})
    k = int.from_bytes(hashlib.sha512(r_enc + pub + canonical.encode()).digest(), "little") % ed.L
    s = rng.choice(
        [
            (r + k * a) % ed.L,
            (r + k * a) % ed.L,
            k * a % ed.L,
            0,
            (r + k * a) % ed.L + ed.L,
            rng.randrange(2**256),
        ]
    )
    sig = "v2=" + base64.b64encode(r_enc + s.to_bytes(32, "little")).decode()
    receipt = {
        "canonical": canonical,
        "contentHash": "sha256:" + hashlib.sha256(canonical.encode()).hexdigest(),
        "signature": sig,
        "overall": "pass",
    }
    return json.dumps(receipt), edge_pem(pub)


def seed_key(seed: int) -> Ed25519PrivateKey:
    """The signing key for a seed: SHA-256 of a label and the seed, as the private key."""
    return Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(f"verifiable-receipts differential key {seed}".encode()).digest()
    )


def main() -> int:
    out, count, seed = Path(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
    rng = random.Random(seed)
    key = seed_key(seed)
    out.mkdir(parents=True, exist_ok=True)
    (out / "public.pem").write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    with (out / "cases.jsonl").open("w", encoding="utf-8") as fh:
        for i in range(count):
            kind = "receipt" if rng.random() < 0.6 else "inclusion"
            if kind == "receipt" and rng.random() < 0.05:
                kind = "guardian"
            pem = None
            if kind == "guardian":
                raw = guardian_case(rng, key)
            elif kind == "inclusion":
                raw = inclusion_case(rng)
            elif rng.random() < 0.08:
                raw = depth_case(rng, key) if rng.random() < 0.85 else duplicate_deep_case(rng, key)
            elif rng.random() < 0.1:
                raw, pem = edge_case(rng, i)
            else:
                raw = receipt_case(rng, key)
            case: dict[str, object] = {"id": i, "kind": kind, "raw": raw}
            if pem is not None:
                case["pem"] = pem  # the case's own key, used instead of public.pem
            fh.write(json.dumps(case) + "\n")
    print(f"{count} cases, seed {seed}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
