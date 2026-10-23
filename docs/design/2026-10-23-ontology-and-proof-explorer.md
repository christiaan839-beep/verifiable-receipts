# Design: the ontology and the proof explorer

23 October 2026. Agreed with Christiaan in the session that built the
release pipeline. Two pieces, built in this order: the ontology first, in
this repository; then the proof explorer, in a new public repository,
`receipts-explorer`, which uses the ontology's terms and schemas.

## Why

The stack (verifiable-receipts, receipts-log, verify-receipts-action and
the private sovereign-agents) lets anyone check what an AI agent did
without trusting the agent, its host or Sovereign Matrix. Two things stand
between that and the people it is for:

1. The terms are used loosely and differently across the specs, READMEs
   and code, and they do not line up with the published standard for this
   architecture, SCITT (RFC 9943, June 2026, with receipts and proofs in
   RFC 9942).
2. Checking a receipt today needs a library or a GitHub workflow. A
   business owner, an accountant or an auditor needs a page.

## Part 1: the ontology

### Deliverables

- `docs/ontology.md`: every concept, defined once; its relations; its
  SCITT equivalent; one diagram of the chain of trust.
- `schemas/`: a JSON Schema (draft 2020-12) for each wire object:
  `receipt.schema.json` (v2), `tree-head.schema.json`,
  `inclusion-proof.schema.json`, `consistency-proof.schema.json`,
  `cosignature.schema.json`, and `fixture.schema.json` for the
  conformance fixtures.
- A CI step that validates every conformance fixture against its schema
  and fails on any fixture that does not match. The schemas describe
  shape (fields, types, the 64-lowercase-hex pattern, the `v2=` prefix
  and base64 alphabet, integer ranges); the verifiers still decide
  validity, because a schema cannot check a signature.

### Concepts

| Term | Definition | SCITT (RFC 9943) |
|---|---|---|
| Issuer | The party that signs receipts: a business, or the host acting for it | Issuer |
| Issuer key | The issuer's Ed25519 key pair (and ML-DSA-65 for `v3=`); verifiers pin the public half | the key behind `iss` |
| Action | What an agent did, after the owner approved it | the event the Statement is about |
| Canonical | The exact UTF-8 text the issuer signed, a JSON object | Statement |
| Receipt | `canonical`, `contentHash`, `signature`, and fields repeated from the canonical | Signed Statement |
| Repeated field | A top-level field beside `canonical` that must equal the same field inside it | (unprotected header content, which SCITT does not bind; here it is bound) |
| Transparency log | An append-only RFC 9162 Merkle tree whose leaves are receipts | Transparency Service, Append-only Log |
| Leaf | `SHA-256(0x00 ‖ canonical)` | an entry in the Verifiable Data Structure |
| Tree head | The log's signed statement of its size and root at a time | the Transparency Service's endorsed state |
| Inclusion proof | The audit path linking a leaf to a tree head's root | Receipt, inclusion Proof Type (RFC 9942) |
| Consistency proof | The hashes showing one tree head extends an earlier one | consistency Proof Type (RFC 9942) |
| Logged receipt | A receipt with its inclusion proof and tree head | Transparent Statement |
| Witness | An independent party that cosigns a tree head only if it extends the last one it cosigned | a specialised Auditor |
| Cosignature | A witness's signature over a tree head | (not in RFC 9943) |
| Fork | Two different roots for one log at one size | Equivocation |
| Verifier | Software that checks receipts, proofs and cosignatures: the three libraries, the action, the explorer | Relying Party |

sovereign-agents' terms (job, run, staged change, approval, cap, applier,
fence) get their own section, as the source of an Action. Only the receipt
crosses from that side to this one.

### Relations

- An Issuer signs a Receipt with an Issuer key.
- A Receipt carries one Canonical; its Repeated fields must equal fields
  of that Canonical.
- A Transparency log holds Leaves in order; each Leaf is the hash of one
  Receipt's Canonical. A Canonical submitted twice is one Leaf.
- A Tree head commits to a Transparency log at one size; the log signs it.
- An Inclusion proof links one Leaf to one Tree head.
- A Consistency proof links an earlier Tree head to a later one of the same
  log.
- A Witness issues Cosignatures over Tree heads, and issues none once it
  sees a Fork.

### The name clash

SCITT's "Receipt" is the log's signed inclusion proof. Ours is the
issuer's signed record. We keep "receipt": it is in the wire format, the
package names and every spec, and renaming it before the first release
would touch all four repositories for no change in behaviour. The
ontology says "receipt (a SCITT Signed Statement)" on first use, and
calls the log's proof an "inclusion proof", never a receipt. Our encoding
(JSON, Ed25519, `v2=`) is not SCITT's (COSE, CBOR), so every document says
the model is "aligned with RFC 9943" and none says it complies.

## Part 2: the proof explorer

### Repository and hosting

`christiaan839-beep/receipts-explorer`, public, Apache-2.0. Static, served
from GitHub Pages and deployed by a workflow that attests the build. It is
held to the same bar as the other three repositories: actions pinned to
full SHAs from releases at least 14 days old, zizmor pedantic, CodeQL,
Scorecard, Dependabot with a 14-day cooldown, rulesets, merge commits
only.

### Build

- Pages: Christiaan's zero-dependency Python stack (`content.py`,
  `layout.py`, `pages.py`, `serve.py`, `build.py`, output in `dist/`), with
  `lang="en-ZA"`, full metadata and structured data. Every page is readable
  without JavaScript.
- Checks: one TypeScript bundle, built with esbuild, with no runtime
  dependencies. It contains the vendored verifier (`receipt.ts` and
  `transparency.ts`, the same code verify-receipts-action vendors), and uses
  WebCrypto's Ed25519.
- A CI job keeps the vendored code and fixtures identical to
  verifiable-receipts at a pinned commit, as the action's `vendor` job
  does.

### Pages

1. **Check a receipt**, the main page.
2. **How it works**: the chain of trust, from Issuer to Witness, in one
   diagram and plain language.
3. **One page per ontology term**, generated from `docs/ontology.md` at
   the pinned commit. Every check result links to the term it uses.

### Check a receipt

Inputs:

- the receipt, dropped as a file or pasted as JSON (an array of receipts
  is checked one by one);
- the issuer's public key, pasted or dropped as PEM;
- optionally, a receipts-log address, the log's public key, and witness
  public keys.

Checks, in order, each shown as passed, failed or not run, with one
sentence on what it proves and one on what it does not:

1. **Format**: a v2 receipt, its signature in the one valid spelling.
2. **Signature**: valid under the given key, named by fingerprint.
3. **Content hash**: matches the signed text.
4. **Repeated fields**: each equals the signed canonical; a mismatch
   names the field and both values.
5. **Tree head** (with a log address): the page fetches the log's latest
   tree head (`GET /v1/sth`) and checks that the log's key signed it.
6. **In the log**: the page computes the leaf hash from the receipt's
   canonical itself, fetches the inclusion proof for it at that tree head's
   size (`GET /v1/proof/inclusion?leafHash=…&treeSize=…`), and checks the
   proof against the root in the signed tree head. The `rootHashHex` in
   the proof response is never trusted on its own.
7. **Witnesses** (with witness keys): the page fetches the cosignatures
   for that tree size (`GET /v1/cosignatures?treeSize=…`) and shows how
   many of the given witnesses cosigned this exact tree head.

Then the signed action itself, formatted, with the repeated fields aligned
beside it.

A check that cannot run (no log address, the log unreachable, no witness
keys) shows as not run, never as passed. A network error is reported as a
network error, never as a failed or passed check.

### Privacy and security

- Nothing is uploaded. Receipts and keys stay in the browser; the page
  makes requests only to the log address the visitor types, and only
  `GET` requests.
- No cookies, no storage of receipts or keys, no analytics, and nothing
  from the inputs in URLs.
- Content Security Policy as a meta tag (GitHub Pages sets no headers):
  `default-src 'none'`; scripts and styles from the site only, no inline
  code; `connect-src https:`; `img-src 'self' data:`; `base-uri 'none'`;
  `form-action 'none'`.
- Subresource Integrity on the bundle; the release workflow attests every
  file it deploys.
- A browser without WebCrypto Ed25519 sees a message saying so, and no
  checks run.

### receipts-log change

Its read-only `GET` routes (`/v1/sth`, `/v1/proof/inclusion`,
`/v1/proof/consistency`, `/v1/public-key`, `/v1/cosignatures`,
`/v1/entries/{index}`) send `Access-Control-Allow-Origin: *`. They serve
public data and take no credentials. `POST` routes stay same-origin.

### Quality bar

- WCAG 2.2 AA: full keyboard use, results announced to screen readers
  (`aria-live`), visible focus, `prefers-reduced-motion` respected,
  contrast checked in light and dark modes.
- Layout from 320 px wide, without horizontal scrolling.
- The bundle under 40 KB compressed; Largest Contentful Paint under 1.5 s
  on a mid-range phone over a fast 3G profile.
- Every message tells the visitor what is wrong and what to do; for
  example, "This key does not match the signature. Check that you have
  the issuer's key, not the log's."

### Testing

- Unit: every conformance fixture through the bundle, with the same
  verdicts as the three verifiers.
- Property tests (fast-check) on input parsing: the page never throws on
  any input, and rejects what the verifiers reject.
- End to end: Playwright (development only, never shipped) for every flow,
  including an unreachable log and a forged tree head, with axe
  accessibility checks on every page.
- Visual: screenshots at 320, 768 and 1440 px, in light and dark.

## Order of work

1. The ontology and schemas in this repository, with the fixture check in
   CI.
2. The CORS change in receipts-log.
3. `receipts-explorer`: repository and pipeline, then the verification
   bundle and its drift check, then the pages, then the tests.

Each step lands as its own pull request, green before it merges.

## Out of scope for the first version

- Listing or searching a log's entries, tree-head history, and fork alerts.
- The owner approval inbox for sovereign-agents (the next UI, on the same
  visual language).
- Sample receipts from sovereign-agents' demo business.
- RDF or JSON-LD forms of the ontology.
