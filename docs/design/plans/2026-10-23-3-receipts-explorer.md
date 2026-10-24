# receipts-explorer: implementation plan

> **For agentic workers:** use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to carry out this plan task by task. Steps use checkboxes (`- [ ]`).

**Goal:** a public, static site, `christiaan839-beep/receipts-explorer` on GitHub Pages, where anyone can check a verifiable receipt in their browser: its format, signature, content hash and repeated fields, and, given a receipts-log address, the log's signed tree head, the receipt's inclusion proof against that tree head, and the witnesses' cosignatures. Nothing is uploaded.

**Architecture:** two halves that meet in `dist/`. The pages are rendered by Python's standard library (`app/content.py` → `app/ontology.py` → `app/layout.py` → `app/pages.py`, served live by `serve.py`, written to `dist/` by `build.py`), and read in full without JavaScript. The checks are one TypeScript bundle, `static/check.js`, built by esbuild from `src/` with no runtime dependencies; its verifier is a browser port (WebCrypto, no Node APIs) of verifiable-receipts' `verify-v2.mjs` and `transparency.ts` at the commit in `third_party/verifiable-receipts/VR_REF`. The only code that reaches the network is `src/log-client.ts`, which sends `GET` requests to the log address the visitor typed. The seven checks live in `src/checks.ts`; their names, terms and "what it proves" sentences live once, in `content/checks.json`, read by both halves. CI keeps every vendored file byte-identical to `VR_REF`, and runs the port beside the original verifier on random receipts.

**Tech stack:** Python 3.9+ standard library (CI pins 3.12); TypeScript 5.9.3, esbuild 0.28.2, ESLint 10.12.0 with typescript-eslint 8.71.1, `node --test` on Node 22.18+ and 24; fast-check 4.10.2; Playwright 1.64.0 with @axe-core/playwright 4.13.0 (development only); ruff 0.17.0 by hash; GitHub Actions and Pages.

**Design:** `docs/design/2026-10-23-ontology-and-proof-explorer.md` (verifiable-receipts), Part 2.

**Prototype:** every file below was written and run in a scratch copy on 23 and 24 October 2026, task by task in this order, against verifiable-receipts `main` at `fd2390b`, the `VR_REF`: 116 node tests passed (and the property tests at `FC_NUM_RUNS=2000`), 18 Python tests on 3.12 and on 3.9, 32 Playwright tests on Chromium (Largest Contentful Paint 1.27 to 1.29 s under the fast 3G profile), ruff and ESLint clean, zizmor pedantic with no findings, and `scripts/check-vendor.sh` passed against an export and a clone of `fd2390b` while failing, each with its `::error` line, in 21 broken copies (bad, missing, empty or extra `SHA256SUMS` lines, a wrong hash, an extra, missing or changed file in each vendored directory, an empty or missing `src/vendor/`, a wrong upstream path, the wrong directory, and an upstream clone at the wrong `HEAD`). `static/check.js` is 26,282 bytes, 8,973 compressed. Not run: Playwright on Firefox and WebKit, the GitHub workflows, the deploy, and the `gh` steps of Task 17.

**Repository:** `~/Projects/receipts-explorer` (new), published in Task 17 as github.com/christiaan839-beep/receipts-explorer.

**Precondition, met:** verifiable-receipts' `fix/empty-contenthash` merged into `main` as `fd2390b` (PR #20). It makes `verify-v2.mjs` reject `"contentHash": ""` (a present contentHash must be the hash) and adds two fixtures: `v2-invalid-empty-contenthash.json` (rejected, `reasonContains: "contentHash mismatch"`) and `v2-valid-null-contenthash.json` (`null` means no hash; accepted). The corpus is 25 fixtures, 12 of them v2. `VR_REF` is `fd2390b5cd30fb3c31c41810195ab7ec5ed51702`, the value `git -C ~/Projects/verifiable-receipts rev-parse origin/main` gave after that merge; Task 2, Step 2 checks it.

**Prerequisites already met:** Plan 1 merged into verifiable-receipts `main` as `dc2bcec` (PR #19), which holds `docs/ontology.md` and `schemas/`. Plan 2 merged into receipts-log as `1a667f0` (PR #12, CORS on the read routes), and PR #13 (`d364a8d`) added the CORS header to the server's own 503, 414 and 500 answers on those routes.

---

## Decisions the design leaves open

| Question | Decision | Why |
|---|---|---|
| How the bundle gets the verifier | **Vendor and port**, pinned by `third_party/verifiable-receipts/VR_REF`, not the npm package. | `@sovereign-matrix/verifiable-receipts` and the action's vendored copies import `node:crypto` (`createHash`, `verify`, `KeyObject`) and `Buffer`, which no browser has, and the package also pulls `@noble/post-quantum`. The port swaps those for WebCrypto (`crypto.subtle.digest`, `importKey("spki", …, "Ed25519")`, `verify`) and `atob`/`btoa`/`TextEncoder` in `src/bytes.ts`; `verifyV2Receipt`, `leafHash`, `innerHash` and `verifyInclusionProof` become async. Nothing else changes: same checks, order and reasons. |
| How drift is caught | `scripts/check-vendor.sh`, run by CI's `vendor` job against verifiable-receipts at `VR_REF`: every copied file is compared byte for byte, the two ported sources by SHA-256 (`SHA256SUMS`), and `VR_REF` must be on `main`. The original `verify-v2.mjs` is vendored unchanged so `test/port.properties.test.ts` can run it beside the port. | The action's `vendor` job can compare its copies; a port cannot be compared, so its sources are hashed and it is tested against the original instead. |
| Python version | **3.12 in CI** (`actions/setup-python`, as verifiable-receipts pins); the code runs on 3.9+, so `/usr/bin/python3` works for `serve.py` and `build.py`. Run the tests with `/opt/homebrew/bin/python3.12`. | Same pin as the other repositories; no 3.10+ syntax, so the stock macOS Python still serves the site. |
| Python tests and tools | stdlib `unittest` (no pytest), and ruff 0.17.0 hash-pinned in `.github/tools/python-ci/` as the only Python tool. | The site stays zero-dependency; ruff is the only tool worth installing. |
| Hosting URL (confirmed by Christiaan) | `https://christiaan839-beep.github.io/receipts-explorer/`. Every link carries the `/receipts-explorer` base path; `serve.py` serves under it too, so development and production paths match. `build.py` still writes `robots.txt`, but it has no effect on a project path: crawlers read it only at the host root, and there is no `christiaan839-beep.github.io` site. `sitemap.xml` works when submitted to a search console. A custom domain would fix both. | GitHub Pages project site; no custom domain exists. |
| How the log address and key are chosen (key confirmed by Christiaan) | The visitor types it: no default, `https://` only (CSP `connect-src https:` enforces it too), no user name, query or fragment; never stored, never put in the page URL. The log's public key must be pasted; the page never fetches `/v1/public-key`. | There is no public log yet, and receipts-log's `API.md` says a key fetched from the log proves nothing. |
| Optional inputs | No issuer key: Signature is not run. A log address without a log key: checks 5 to 7 are not run, and the log is not asked. Witness keys without an address: an input error. | "A check that cannot run shows as not run." |
| Network errors and log errors | A request that does not complete (unreachable, DNS, TLS, CORS refusal, a redirect, 15 s timeout) is a network error: shown as **Network error**, counted as not run, with a **Try the log again** button. A 5xx answer (503 busy, 500) is not run, quoting the log's error, with the same button. Any other non-200 answer (400, 414) is not run, with no retry. A 404 from the inclusion route is a failed check. | Since receipts-log PR #13 its 503, 414 and 500 carry the CORS header, so the page reads and explains them instead of seeing an opaque failure. |
| Requests per check | One `GET /v1/sth` and one `GET /v1/cosignatures` per run, one `GET /v1/proof/inclusion` per receipt. | A pasted array may hold many receipts; they share one tree head. |
| Witnesses passed or failed (**chosen by Christiaan**, 24 October 2026) | A cosignature counts when the tree head it covers has the same `logId`, `treeSize` and `rootHash` as the tree head the page fetched; its timestamp may differ. Its `sthCanonical` is never trusted as sent: it must parse to a well-formed tree head whose canonical text, rebuilt from its own fields, equals it byte for byte, and its signature must verify over it under that witness's key. Passed when at least one given witness has such a cosignature, with "k of n" in the message; failed when none does. | The design says "this exact tree head", but receipts-log re-signs its tree head hourly with a new timestamp, so an exact match would often read 0 of n while witnesses lag. The same log, size and root is what rules out a fork. This deviates from the design's wording on purpose. |
| contentHash | A present contentHash (anything but absent or `null`) must be a string and is checked, so `""` fails; absent or `null` is "not run". | The rule verifiable-receipts adopts in `fix/empty-contenthash`; the port follows it. |
| v3 | A v3 receipt fails Format with a message; a v3 tree head is "not run". | WebCrypto has no ML-DSA-65, and receipts-log signs tree heads `v2=` only. |
| Fingerprint | `sha256:` and the first 16 hex digits of the SHA-256 of the SPKI DER. | The same name verify-receipts-action reports. |
| Limits | 5 MB of receipt text, 1,000 receipts per run, 1 MB per log answer. | Bound the work a pasted file or a log can cause. |
| Visual tests | Screenshots at 320, 768 and 1440 px in light and dark, attached to the Playwright report and checked for horizontal overflow; not compared against stored baselines. | Baselines differ between machines; the design asks for screenshots, not a diff. |
| Performance test | Chromium only: DevTools "Fast 3G" (562.5 ms round trip, 1.44 Mbit/s down, 675 kbit/s up) and 4× CPU slowdown on a 412×915 phone viewport; LCP must be under 1500 ms. | The design's "mid-range phone over fast 3G". |
| Size budget | `scripts/check_budget.py`: `static/check.js` ≤ 40 KB gzip (the design), `static/styles.css` ≤ 8 KB, each page ≤ 12 KB. | The LCP target leaves room for one page and one stylesheet. |
| SEO | Unique title, description and canonical; Open Graph and Twitter `summary` cards (no image); JSON-LD `WebApplication`, `TechArticle`, `DefinedTermSet` and `DefinedTerm`; `sitemap.xml` and `robots.txt`; no web fonts. | The standing rules; CSP `default-src 'none'` blocks font and image hosts. |
| Deploy | `deploy.yml` on every push to `main`: CI, build, budget, `attest-build-provenance` over `dist/**`, `upload-pages-artifact`, `deploy-pages`. The `github-pages` environment allows `main` only, with no reviewer. | Pages has no tags or releases; `main` is already behind a pull request rule. |
| gitleaks | Run locally before each commit (`gitleaks git --pre-commit --staged`), as in Plan 2; GitHub secret scanning with push protection on the repository. | The other repositories run no gitleaks job in CI either. |
| Landing the work | Tasks 1 to 16 commit on branch `feat/explorer` over a root commit on `main` that holds only `LICENSE`. Task 17 creates the repository, sets it up, pushes `main`, then opens the pull request and merges it once green. | A new repository has no `main` to open a pull request against; this way the explorer still lands as one green pull request under the ruleset. |

---

## File map

| File | Responsibility | Task |
|---|---|---|
| `package.json`, `package-lock.json` | Development tools at exact versions; scripts | 1 |
| `tsconfig.json`, `src/tsconfig.json` | Strict types: tests and tools with Node's types; `src/` without them, so Node APIs in the page fail to compile | 1 |
| `eslint.config.js` | Lint rules that keep `src/` a page that parses no HTML, stores nothing, loads no code, uses no Node API and talks only to the log | 1 |
| `pyproject.toml` | ruff settings | 1 |
| `.gitignore`, `.npmrc`, `.claude/launch.json`, `LICENSE` | Housekeeping: ignored files, exact saves and enforced engines | 1 |
| `.gitattributes` | No line-ending conversion for vendored and fixture files | 1 |
| `test/lint.test.ts` | Proves every lint rule on `src/` bites | 3 |
| `third_party/verifiable-receipts/` | `VR_REF`, `LICENSE`, `README.md`, `SHA256SUMS`, `verify-v2.mjs`, `verify-v2.d.mts`, `ontology.md` | 2 |
| `test/fixtures/conformance/`, `test/fixtures/schemas/` | Test vectors copied from `VR_REF` | 2 |
| `scripts/check-vendor.sh` | The drift check, which fails closed; Task 3 adds the ports to it | 2, 3 |
| `src/bytes.ts` | UTF-8, hex, base64, SHA-256 and Ed25519 verify on WebCrypto | 3 |
| `src/vendor/verifiable-receipts/receipt.ts` | The browser port of `verify-v2.mjs` | 3 |
| `src/vendor/verifiable-receipts/transparency.ts` | The browser port of the inclusion-proof verifier | 3 |
| `src/keys.ts` | PEM to WebCrypto keys, with fingerprints | 3 |
| `test/helpers.ts` | Fixture reading, keys and signing for tests | 3 |
| `test/mutations.ts` | Signed receipts with changes, for property tests | 4 |
| `scripts/make-stub-log.mjs`, `test/fixtures/log/` | The recorded log answers | 5 |
| `src/signature.ts` | The `v2=` wire format | 5 |
| `src/tree-head.ts` | Check 5's tree head check | 5 |
| `src/log-client.ts` | The only network code | 6 |
| `src/input.ts` | Reading the pasted receipt text | 6 |
| `src/checks.ts` | The seven checks | 7 |
| `test/stub-log.ts` | A fetch that answers from `test/fixtures/log` | 7 |
| `content/checks.json` | Each check's name, term and sentences, for both halves | 9 |
| `src/ed25519-support.ts`, `src/ui.ts`, `src/main.ts` | Feature detection, the page's behaviour, the entry point | 9 |
| `scripts/bundle.mjs` | esbuild to `build/check.js` | 9 |
| `app/content.py` | Site settings and words | 10 |
| `app/ontology.py` | Terms from the vendored `ontology.md` | 10 |
| `app/assets.py` | Subresource Integrity hashes | 11 |
| `app/layout.py` | The HTML shell: CSP, SEO head, JSON-LD | 11 |
| `app/pages.py` | Page bodies and routes | 11 |
| `static/styles.css`, `static/img/favicon.svg` | The one stylesheet; the icon | 11 |
| `build.py`, `serve.py` | Static export; the development server | 12 |
| `scripts/check_budget.py` | The size budget | 12 |
| `tests/` | Python tests | 10–12 |
| `playwright.config.ts`, `e2e/` | End-to-end, accessibility, CSP, visual and performance tests | 13–14 |
| `.github/` | CI, CodeQL, zizmor, Scorecard, deploy, Dependabot, hash-pinned ruff | 15 |
| `README.md`, `CONTRIBUTING.md`, `SECURITY.md` | Docs | 16 |

---

## Conventions for every task

- Work in `~/Projects/receipts-explorer`; Task 1 creates it. From Task 1 on, commit on branch `feat/explorer`.
- git, gh, `npm install` and Playwright's browser download need the Bash sandbox off, as do Playwright runs (they bind a local port). If the Write and Edit tools fail on a security-guidance hook error, write files with a heredoc or a short Python script.
- The shell is zsh. Commands here use only syntax that zsh and bash share; `scripts/check-vendor.sh` runs under bash.
- Node 22.18 or later (`node --version`). If `npm` fails with `EACCES` on `~/.npm`, add `--cache "$TMPDIR/npm-cache"`.
- Python tests: `PY=/opt/homebrew/bin/python3.12`; ruff: `uvx ruff@0.17.0`; zizmor: `uvx zizmor@1.30.1`.
- `VR=~/Projects/verifiable-receipts` and, from Task 2, `VR_REF=$(cat third_party/verifiable-receipts/VR_REF)`.
- Every TypeScript task ends with `npm run typecheck && npx eslint . && npm test`, which must print nothing from tsc and ESLint and `# fail 0` from the tests. `npm run typecheck` runs `tsc` twice: on `tsconfig.json` (tests, end-to-end tests and tools, with Node's types) and on `src/tsconfig.json` (the page, without them).
- Commit with this identity; no global git identity is set:

```bash
export GIT_COMMITTER_NAME='Christiaan de Wet' GIT_COMMITTER_EMAIL='259622211+christiaan839-beep@users.noreply.github.com'
A='Christiaan de Wet <259622211+christiaan839-beep@users.noreply.github.com>'
git commit --author="$A" -m "<subject>" -m "<body>" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

- Before every commit run `gitleaks git --pre-commit --staged --no-banner`; it must report `no leaks found`.

---

### Task 1: the repository and its tools

**Files:**
- Create: `LICENSE` (copied), `.gitignore`, `.gitattributes`, `.npmrc`, `package.json`, `package-lock.json` (by npm), `tsconfig.json`, `src/tsconfig.json`, `eslint.config.js`, `pyproject.toml`, `.claude/launch.json`

- [ ] **Step 1:** create the repository with a root commit that holds only the licence, then branch:

```bash
mkdir ~/Projects/receipts-explorer && cd ~/Projects/receipts-explorer
git init -b main
cp ~/Projects/verifiable-receipts/LICENSE LICENSE
git add LICENSE
gitleaks git --pre-commit --staged --no-banner
git commit --author="$A" -m "Licence: Apache-2.0" -m "The root commit; the explorer lands on it as one pull request." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
git checkout -b feat/explorer
```

- [ ] **Step 2:** create the files:

`.gitignore`:

```text
node_modules/
build/
dist/
test-results/
playwright-report/
__pycache__/
.DS_Store
.ruff_cache/
blob-report/
coverage/
.venv/
npm-debug.log*
.env
.env.*
*.key
.claude/settings.local.json
src/lint-probe-*.ts
```

`.gitattributes`:

```text
# Vendored and fixture files are compared byte for byte with verifiable-receipts:
# git must never convert their line endings.
test/fixtures/** -text
third_party/** -text
```

`.npmrc`:

```text
engine-strict=true
save-exact=true
```

`package.json`:

```json
{
  "name": "receipts-explorer",
  "version": "0.1.0",
  "private": true,
  "description": "A page that checks verifiable receipts, and their place in a transparency log, in the browser.",
  "license": "Apache-2.0",
  "type": "module",
  "engines": {
    "node": ">=22.18"
  },
  "scripts": {
    "bundle": "node scripts/bundle.mjs",
    "typecheck": "tsc -p tsconfig.json && tsc -p src/tsconfig.json",
    "lint": "eslint .",
    "test": "node --test \"test/**/*.test.ts\"",
    "build": "npm run bundle && python3 build.py",
    "e2e": "playwright test",
    "check": "npm run typecheck && npm run lint && npm test && npm run build && python3 scripts/check_budget.py"
  },
  "devDependencies": {
    "@axe-core/playwright": "4.13.0",
    "@eslint/js": "10.0.1",
    "@playwright/test": "1.64.0",
    "@types/node": "22.20.5",
    "esbuild": "0.28.2",
    "eslint": "10.12.0",
    "fast-check": "4.10.2",
    "typescript": "5.9.3",
    "typescript-eslint": "8.71.1"
  },
  "overrides": {
    "playwright-core": "1.64.0"
  }
}
```

`tsconfig.json`:

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "lib": ["ES2022", "DOM", "DOM.Iterable"],
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "types": ["node"],
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "exactOptionalPropertyTypes": true,
    "noImplicitOverride": true,
    "noImplicitReturns": true,
    "noFallthroughCasesInSwitch": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "useUnknownInCatchVariables": true,
    "verbatimModuleSyntax": true,
    "erasableSyntaxOnly": true,
    "allowImportingTsExtensions": true,
    "resolveJsonModule": true,
    "noEmit": true,
    "isolatedModules": true,
    "forceConsistentCasingInFileNames": true,
    "skipLibCheck": true
  },
  "include": ["test/**/*.ts", "e2e/**/*.ts", "content/*.json", "*.config.ts"]
}
```

`src/tsconfig.json`:

```json
{
  "extends": "../tsconfig.json",
  "compilerOptions": {
    "types": []
  },
  "include": ["**/*.ts", "../content/*.json"]
}
```

`eslint.config.js`:

```js
// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

import { builtinModules } from "node:module";

import js from "@eslint/js";
import tseslint from "typescript-eslint";

// What the page must never do with a visitor's receipts and keys: parse
// them as HTML, store them, run code it did not ship, or send them anywhere
// but the log they typed. Properties are banned by name on any object, so
// globalThis.x, window.x and self.x are caught as well as a bare x.
const banned = (message, ...names) => names.map((property) => ({ property, message }));
const PROPERTIES = [
  ...banned(
    "Build elements with textContent; never parse input as HTML.",
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "setHTMLUnsafe",
    "createContextualFragment",
  ),
  ...banned("The page stores nothing.", "localStorage", "sessionStorage", "indexedDB", "cookie"),
  ...banned("Nothing from the inputs goes in the address bar.", "pushState", "replaceState"),
  ...banned("The page talks only to the log, through src/log-client.ts.", "navigator", "sendBeacon"),
  { object: "document", property: "write", message: "Build elements with textContent." },
];
const GLOBALS = [
  ...[
    "localStorage",
    "sessionStorage",
    "indexedDB",
    "caches",
    "XMLHttpRequest",
    "WebSocket",
    "EventSource",
    "navigator",
    "DOMParser",
    "Worker",
    "SharedWorker",
    "open",
  ].map((name) => ({ name, message: "The page stores nothing, parses no HTML and talks only to the log, through src/log-client.ts." })),
  // src/ is bundled for the browser, which has none of Node's globals.
  ...["Buffer", "process", "require", "global", "__dirname", "__filename"].map((name) => ({
    name,
    message: "src/ runs in the browser: use src/bytes.ts and WebCrypto, not Node.",
  })),
];
const FETCH = "Only src/log-client.ts makes requests.";

export default tseslint.config(
  {
    ignores: [
      "build/**",
      "dist/**",
      "node_modules/**",
      "third_party/**",
      "test-results/**",
      "playwright-report/**",
      "blob-report/**",
      "coverage/**",
    ],
  },
  js.configs.recommended,
  {
    rules: { "no-eval": "error", "no-implied-eval": "error", "no-new-func": "error" },
  },
  {
    files: ["**/*.ts"],
    extends: [...tseslint.configs.strictTypeChecked, ...tseslint.configs.stylisticTypeChecked],
    languageOptions: {
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
    rules: {
      "@typescript-eslint/restrict-template-expressions": ["error", { allowNumber: false }],
      "@typescript-eslint/no-floating-promises": [
        "error",
        { allowForKnownSafeCalls: [{ from: "package", package: "node:test", name: ["describe", "it"] }] },
      ],
    },
  },
  {
    files: ["src/**/*.ts"],
    rules: {
      "no-restricted-properties": ["error", ...PROPERTIES],
      "no-restricted-globals": ["error", ...GLOBALS],
      "no-restricted-imports": [
        "error",
        {
          paths: builtinModules.map((name) => ({ name, message: "src/ runs in the browser: no Node modules." })),
          patterns: [{ group: ["node:*"], message: "src/ runs in the browser: no Node modules." }],
        },
      ],
      "no-restricted-syntax": [
        "error",
        { selector: "ImportExpression", message: "The page loads no code at run time; import statically." },
      ],
    },
  },
  {
    // ESLint replaces a rule's options per block, so these repeat the full lists and add fetch.
    files: ["src/**/*.ts"],
    ignores: ["src/log-client.ts"],
    rules: {
      "no-restricted-properties": ["error", ...PROPERTIES, { property: "fetch", message: FETCH }],
      "no-restricted-globals": ["error", ...GLOBALS, { name: "fetch", message: FETCH }],
    },
  },
  {
    files: ["**/*.js", "**/*.mjs"],
    languageOptions: {
      globals: { process: "readonly", console: "readonly", Buffer: "readonly", URL: "readonly" },
    },
  },
);
```

`pyproject.toml`:

```toml
# Settings for ruff, the only Python tool CI installs (hash-pinned in
# .github/tools/python-ci). The site itself needs nothing beyond the
# standard library of Python 3.9 or later; CI runs Python 3.12.
[tool.ruff]
required-version = "==0.17.0"
line-length = 140
target-version = "py39"
extend-exclude = ["third_party", "node_modules", "dist", "build"]

[tool.ruff.lint]
select = ["E", "F", "W", "I", "B", "UP", "N", "A", "S", "SIM", "RUF"]
ignore = ["S101", "S603"]

[tool.ruff.lint.per-file-ignores]
"tests/*" = ["S"]
```

`.claude/launch.json`:

```json
{
  "version": "0.0.1",
  "configurations": [
    {
      "name": "receipts-explorer: dev server (live render)",
      "runtimeExecutable": "python3",
      "runtimeArgs": ["serve.py", "8000"],
      "port": 8000,
      "url": "http://127.0.0.1:8000"
    },
    {
      "name": "receipts-explorer: built site (dist)",
      "runtimeExecutable": "python3",
      "runtimeArgs": ["serve.py", "--dist", "8080"],
      "port": 8080,
      "url": "http://127.0.0.1:8080"
    }
  ]
}
```

Two type-check projects: `tsconfig.json` covers the tests, the end-to-end tests and the tools, with Node's types, and type-checks the `src/` files they import under those types too; `src/tsconfig.json` covers `src/` alone with `"types": []`, so `node:crypto`, `Buffer` or `process` in the page fails to compile. ESLint's project service picks the nearest `tsconfig.json`, so `src/` is linted without Node's types as well. In `eslint.config.js`, banned properties are matched by name on any object, so `globalThis.fetch`, `window.fetch` and `self.fetch` are caught as well as `fetch`; ESLint replaces a rule's options per block, so the block for everything but `src/log-client.ts` repeats the full lists and adds `fetch`. `test/lint.test.ts` (Task 3) proves each rule bites. `*.pem` is deliberately not ignored: the test fixtures are public keys. `.gitattributes` is here, not in Task 2, so that it is in force before the first vendored or fixture file is added; those files are compared byte for byte, and must never have their line endings converted.
The versions are the newest releases published by 10 October 2026, 14 days before this plan; `overrides` holds `playwright-core` at 1.64.0, because `@axe-core/playwright` would otherwise pull 1.64.1, released on 14 October.

- [ ] **Step 3:** install, and check what was installed:

```bash
npm install
npm ls --depth=0
npm ls playwright-core
npm audit --audit-level=moderate
npm config get save-exact && npm config get engine-strict
```

Expected: `npm ls --depth=0` lists exactly `@axe-core/playwright@4.13.0`, `@eslint/js@10.0.1`, `@playwright/test@1.64.0`, `@types/node@22.20.5`, `esbuild@0.28.2`, `eslint@10.12.0`, `fast-check@4.10.2`, `typescript-eslint@8.71.1`, `typescript@5.9.3`; `npm ls playwright-core` shows `1.64.0 overridden` and `1.64.0 deduped`, nothing else; `found 0 vulnerabilities`; `true` and `true`. The type checks and lint rules have nothing to check until Task 3, which proves they bite.

- [ ] **Step 4:** commit:

```bash
gitleaks git --pre-commit --staged --no-banner   # expect: no leaks found
git commit --author="$A" -m "Tools: TypeScript, esbuild, ESLint, fast-check, Playwright, ruff settings" -m "Development tools at exact versions, all at least 14 days old, with exact saves and enforced engines. src/ is type-checked without Node's types, and ESLint forbids it to parse HTML, store anything, load code at run time, use Node APIs, or make requests outside src/log-client.ts. Nothing from npm is shipped except what esbuild bundles from src/." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 2: vendor verifiable-receipts at VR_REF, with the drift check

**Files:**
- Create: `scripts/check-vendor.sh`, `third_party/verifiable-receipts/README.md`, `third_party/verifiable-receipts/SHA256SUMS`, `test/fixtures/conformance/README.md`, `test/fixtures/schemas/README.md`
- Copy from `VR_REF`: `third_party/verifiable-receipts/{VR_REF,LICENSE,verify-v2.mjs,verify-v2.d.mts,ontology.md}`, `test/fixtures/conformance/*.json`, `test/fixtures/conformance/public-key.pem`, `test/fixtures/schemas/{tree-head.json,cosignature.json}`

- [ ] **Step 1:** create the drift check, and make it executable:

`scripts/check-vendor.sh`:

```bash
#!/usr/bin/env bash
# Checks every file copied from verifiable-receipts against a checkout of it
# at the commit in third_party/verifiable-receipts/VR_REF, and fails closed:
# each vendored directory must hold exactly the files listed here, and
# SHA256SUMS must list exactly the two sources the browser ports are made
# from. CI runs it in the vendor job; run it locally, from the repository
# root, against an export of that commit.
#
# Usage: bash scripts/check-vendor.sh <verifiable-receipts checkout at VR_REF>
set -euo pipefail
export LC_ALL=C

fail() { echo "::error file=$1::$2" >&2; exit 1; }
# The files directly in a directory, one per line, sorted; dotfiles included.
listing() { (cd "$1" && find . -mindepth 1 -maxdepth 1 -print | sed 's|^\./||' | sort); }
# Fails unless directory $1 holds exactly the names on stdin.
exactly() {
  local want got
  [[ -d "$1" ]] || fail "$1" "is missing"
  want=$(sort)
  got=$(listing "$1")
  [[ -n "$want" ]] || fail "$1" "the expected listing is empty"
  [[ "$got" == "$want" ]] || fail "$1" "holds $(echo "$got" | tr '\n' ' ')but must hold exactly $(echo "$want" | tr '\n' ' ')"
}

upstream="${1:?usage: check-vendor.sh <verifiable-receipts checkout at VR_REF>}"
tp=third_party/verifiable-receipts
up="$upstream/packages/verifiable-receipts"

# Preflight: run from this repository's root, against a verifiable-receipts tree.
[[ -f package.json && -f "$tp/VR_REF" ]] && grep -q '"name": "receipts-explorer"' package.json ||
  fail scripts/check-vendor.sh "run it from the receipts-explorer repository root"
[[ -d "$up/conformance/fixtures" ]] || fail scripts/check-vendor.sh "$upstream is not a verifiable-receipts tree"

ref=$(cat "$tp/VR_REF")
[[ "$ref" =~ ^[0-9a-f]{40}$ ]] || fail "$tp/VR_REF" "must be one full commit SHA"
if [[ -e "$upstream/.git" ]]; then
  head=$(git -C "$upstream" rev-parse HEAD)
  [[ "$head" == "$ref" ]] || fail "$tp/VR_REF" "the upstream checkout is at $head, not $ref"
fi

# SHA256SUMS: exactly the two ported sources, each with a matching hash.
# sha256sum skips lines it cannot read and passes an empty file, so the
# listed paths are checked first.
[[ -f "$tp/SHA256SUMS" ]] || fail "$tp/SHA256SUMS" "is missing"
sums_paths=$(sed -E 's/^[0-9a-f]{64}  //' "$tp/SHA256SUMS" | sort)
[[ "$sums_paths" == "$(printf '%s\n' packages/verifiable-receipts/conformance/verify-v2.mjs packages/verifiable-receipts/src/transparency.ts | sort)" ]] ||
  fail "$tp/SHA256SUMS" "must list exactly conformance/verify-v2.mjs and src/transparency.ts, one '<sha256>  <path>' line each"
(cd "$upstream" && sha256sum --strict -c --quiet "$OLDPWD/$tp/SHA256SUMS") ||
  fail "$tp/SHA256SUMS" "a ported source changed; update the port"

# Exactly these files, each identical to VR_REF.
printf '%s\n' LICENSE README.md SHA256SUMS VR_REF ontology.md verify-v2.d.mts verify-v2.mjs | exactly "$tp"
cmp "$up/conformance/verify-v2.mjs" "$tp/verify-v2.mjs" || fail "$tp/verify-v2.mjs" "differs from VR_REF"
cmp "$up/conformance/verify-v2.d.mts" "$tp/verify-v2.d.mts" || fail "$tp/verify-v2.d.mts" "differs from VR_REF"
cmp "$up/LICENSE" "$tp/LICENSE" || fail "$tp/LICENSE" "differs from VR_REF"
cmp "$upstream/docs/ontology.md" "$tp/ontology.md" || fail "$tp/ontology.md" "differs from VR_REF"

{ listing "$up/conformance/fixtures"; printf '%s\n' README.md public-key.pem; } | exactly test/fixtures/conformance
for f in "$up"/conformance/fixtures/*.json; do
  cmp "$f" "test/fixtures/conformance/$(basename "$f")" || fail "test/fixtures/conformance/$(basename "$f")" "differs from VR_REF"
done
cmp "$up/conformance/public-key.pem" test/fixtures/conformance/public-key.pem || fail test/fixtures/conformance/public-key.pem "differs from VR_REF"

printf '%s\n' README.md cosignature.json tree-head.json | exactly test/fixtures/schemas
for f in tree-head.json cosignature.json; do
  cmp "$upstream/schemas/examples/$f" "test/fixtures/schemas/$f" || fail "test/fixtures/schemas/$f" "differs from VR_REF"
done

echo "every vendored file matches verifiable-receipts at $ref"
```

```bash
chmod 755 scripts/check-vendor.sh
```

It fails closed. `SHA256SUMS` must list exactly the two ported sources, because `sha256sum -c` skips lines it cannot read and passes an empty file; each directory must hold exactly the files named here, dotfiles included, compared as sorted `LC_ALL=C` listings; it must run from this repository's root, against a verifiable-receipts tree, and when that tree is a git checkout its `HEAD` must be `VR_REF`. It does not check `src/vendor/` yet: Task 3, which creates the ports, adds that check, so no version of the script ever accepts a missing or empty `src/vendor/`.
- [ ] **Step 2:** `VR_REF` is `fd2390b`, the merge of `fix/empty-contenthash` (PR #20). Confirm it is on `main` and holds what this plan copies:

```bash
git -C $VR fetch origin
VR_REF=fd2390b5cd30fb3c31c41810195ab7ec5ed51702
git -C $VR rev-parse origin/main
git -C $VR merge-base --is-ancestor "$VR_REF" origin/main && echo on-main
for f in docs/ontology.md schemas/examples/tree-head.json schemas/examples/cosignature.json \
         packages/verifiable-receipts/conformance/fixtures/v2-invalid-empty-contenthash.json \
         packages/verifiable-receipts/conformance/fixtures/v2-valid-null-contenthash.json; do
  git -C $VR cat-file -e "$VR_REF:$f" && echo "has $f"
done
```

Expected: `rev-parse` prints `fd2390b5cd30fb3c31c41810195ab7ec5ed51702` (if `main` has moved on, keep `VR_REF` at `fd2390b`: moving it is a separate change, made as `CONTRIBUTING.md` says), `on-main`, and five `has` lines.

- [ ] **Step 3:** run the drift check before anything is copied; it must fail:

```bash
mkdir -p third_party/verifiable-receipts test/fixtures/conformance test/fixtures/schemas
printf '%s\n' "$VR_REF" > third_party/verifiable-receipts/VR_REF
UP=$(mktemp -d) && git -C $VR archive "$VR_REF" | tar -x -C "$UP"
bash scripts/check-vendor.sh "$UP"
```

Expected: exit 1, with `::error file=third_party/verifiable-receipts/SHA256SUMS::`.

- [ ] **Step 4:** write the hashes of the two sources the ports are made from, and the READMEs:

`third_party/verifiable-receipts/SHA256SUMS`:

```text
04b4921ab45988fb54b269f8c78139bdc67762d92c85979cad8952c9ba243f0f  packages/verifiable-receipts/src/transparency.ts
deb44e0662536ba669583bc5b601dcf01166abcd150aa7ea977e0672978aba72  packages/verifiable-receipts/conformance/verify-v2.mjs
```

`third_party/verifiable-receipts/README.md`:

```markdown
# verifiable-receipts

Source: https://github.com/christiaan839-beep/verifiable-receipts, at the
commit in `VR_REF` beside this file.

Licence: Apache License 2.0, in `LICENSE` beside this file (copied from
`packages/verifiable-receipts/LICENSE`).

Copied unchanged, and checked byte for byte against `VR_REF` in CI
(`.github/workflows/ci.yml`, job `vendor`, which runs `scripts/check-vendor.sh`;
each directory must hold exactly these files and no others):

- `ontology.md`, from `docs/ontology.md`: the term pages are generated from it.
- `verify-v2.d.mts`, from `packages/verifiable-receipts/conformance/verify-v2.d.mts`:
  the types of the original verifier, so the tests import it without a type error.
- `verify-v2.mjs`, from `packages/verifiable-receipts/conformance/verify-v2.mjs`:
  the original receipt verifier, which `test/port.properties.test.ts` runs beside
  the browser port to check that both give the same verdict and reason.
- `test/fixtures/conformance/`, from `packages/verifiable-receipts/conformance/fixtures/`
  and `public-key.pem`.
- `test/fixtures/schemas/`, from `schemas/examples/tree-head.json` and `cosignature.json`.

Ported to the browser (WebCrypto, no Node APIs), each stating its changes in
its header:

- `src/vendor/verifiable-receipts/receipt.ts`, from `packages/verifiable-receipts/conformance/verify-v2.mjs`.
- `src/vendor/verifiable-receipts/transparency.ts`, from `packages/verifiable-receipts/src/transparency.ts`.

`SHA256SUMS` holds the SHA-256 of those two sources at `VR_REF`. When
`VR_REF` moves to a commit where either source changed, the `vendor` job
fails until the port is brought up to date and `SHA256SUMS` rewritten.
```

`test/fixtures/conformance/README.md`:

```markdown
# Conformance fixtures

Copied unchanged from verifiable-receipts
(https://github.com/christiaan839-beep/verifiable-receipts), at the commit in
`third_party/verifiable-receipts/VR_REF`:
`packages/verifiable-receipts/conformance/fixtures/*.json` and
`packages/verifiable-receipts/conformance/public-key.pem`.

Licence: Apache License 2.0, Copyright 2026 Christiaan de Wet / Sovereign Matrix;
see `third_party/verifiable-receipts/LICENSE`.

The v2 fixtures are signed by the key in `public-key.pem`. Its private half
was discarded when the corpus was made. `test/conformance.test.ts` runs every
fixture, and CI checks that the copies match that commit byte for byte
(`.github/workflows/ci.yml`, job `vendor`).
```

`test/fixtures/schemas/README.md`:

```markdown
# Schema examples

Copied unchanged from verifiable-receipts' `schemas/examples/`, at the commit
in `third_party/verifiable-receipts/VR_REF`, and checked byte for byte in CI.
Their signatures are not over their content, so the page must accept their
shape and reject their signatures (`test/tree-head.test.ts`).
```

These are the hashes at `fd2390b`: `transparency.ts` is unchanged since `04e459f`, and `verify-v2.mjs` has the empty-contentHash rule (it did not change in PR #20's last review round). Check them at `VR_REF`:

```bash
(cd "$UP" && sha256sum -c ~/Projects/receipts-explorer/third_party/verifiable-receipts/SHA256SUMS)
```

Expected: both `OK`. If either fails, `VR_REF` is not `fd2390b`: stop and check Step 2.

- [ ] **Step 5:** copy the files, unchanged:

```bash
show() { git -C $VR show "$VR_REF:$1"; }
show packages/verifiable-receipts/LICENSE > third_party/verifiable-receipts/LICENSE
show packages/verifiable-receipts/conformance/verify-v2.mjs > third_party/verifiable-receipts/verify-v2.mjs
show packages/verifiable-receipts/conformance/verify-v2.d.mts > third_party/verifiable-receipts/verify-v2.d.mts
show docs/ontology.md > third_party/verifiable-receipts/ontology.md
for f in $(git -C $VR ls-tree --name-only "$VR_REF" packages/verifiable-receipts/conformance/fixtures/); do
  show "$f" > "test/fixtures/conformance/$(basename "$f")"
done
show packages/verifiable-receipts/conformance/public-key.pem > test/fixtures/conformance/public-key.pem
show schemas/examples/tree-head.json > test/fixtures/schemas/tree-head.json
show schemas/examples/cosignature.json > test/fixtures/schemas/cosignature.json
ls test/fixtures/conformance | wc -l
bash scripts/check-vendor.sh "$UP"
```

Expected: `27` (25 fixtures, `public-key.pem`, `README.md`), then `every vendored file matches verifiable-receipts at <VR_REF>`.

- [ ] **Step 6:** prove the check catches a change: append a space to `third_party/verifiable-receipts/ontology.md`, rerun `bash scripts/check-vendor.sh "$UP"`, and confirm `::error file=third_party/verifiable-receipts/ontology.md::differs from VR_REF`; then `show docs/ontology.md > third_party/verifiable-receipts/ontology.md` and rerun to the `matches` line.
- [ ] **Step 7:** prove the guards bite. Run each case in a scratch copy of the repository, so the real files are never touched; each must exit 1 with the `::error` shown, and the unchanged copy must still pass:

```bash
case_() {
  local w; w=$(mktemp -d) && rsync -a --exclude node_modules ./ "$w/"
  (cd "$w" && eval "$1" && bash "$w/scripts/check-vendor.sh" "${2:-$UP}"); echo "exit $?"
}
S=third_party/verifiable-receipts/SHA256SUMS
case_ ":"                                                   # passes
case_ "sed -i '' '1s/^/x/' $S; echo junk >> $S"            # SHA256SUMS::must list exactly …
case_ "sed -i '' '/transparency/d' $S"                      # SHA256SUMS::must list exactly …
case_ ": > $S"                                              # SHA256SUMS::must list exactly …
case_ "touch third_party/verifiable-receipts/notes.txt"     # third_party/verifiable-receipts::holds … but must hold exactly …
case_ "touch test/fixtures/conformance/stray.txt"           # test/fixtures/conformance::holds …
case_ "touch test/fixtures/schemas/extra.json"              # test/fixtures/schemas::holds …
case_ ":" /nonexistent                                      # … is not a verifiable-receipts tree
case_ "cd scripts"                                          # run it from the receipts-explorer repository root
CLONE=$(mktemp -d) && git clone -q $VR "$CLONE" && git -C "$CLONE" checkout -q "$VR_REF~1"
case_ ":" "$CLONE"                                          # VR_REF::the upstream checkout is at …, not …
```

(`$VR_REF~1` is the commit before the merge, so the clone is at the wrong `HEAD`. The prototype ran each of these, and the `src/vendor/` cases of Task 3: 21 cases, each exited 1 with its `::error` line, and the unchanged copy passed.)

- [ ] **Step 8:** commit, and confirm the script is committed executable:

```bash
gitleaks git --pre-commit --staged --no-banner   # expect: no leaks found
git commit --author="$A" -m "Vendor verifiable-receipts at VR_REF, with a drift check" -m "The conformance fixtures and key, the schema examples, docs/ontology.md and the original verify-v2.mjs and its types, byte for byte; SHA-256 of the two sources the browser ports are made from. scripts/check-vendor.sh compares them all with a checkout at VR_REF and fails closed: exact file sets, exact SHA256SUMS paths, the upstream HEAD, and where it runs." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```
```bash
git ls-files -s scripts/check-vendor.sh   # expect: 100755 …
```

### Task 3: the browser port of the verifier, and keys

**Files:**
- Create: `test/helpers.ts`, `test/conformance.test.ts`, `test/keys.test.ts`, `test/lint.test.ts`
- Modify: `scripts/check-vendor.sh` (the check of the ports, before its last line)
- Create: `src/bytes.ts`, `src/vendor/verifiable-receipts/receipt.ts`, `src/vendor/verifiable-receipts/transparency.ts`, `src/keys.ts`

- [ ] **Step 1:** write the tests first:

`test/helpers.ts`:

```ts
// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";

import { parsePublicKeys, type PublicKey } from "../src/keys.ts";

export const CONFORMANCE = new URL("./fixtures/conformance/", import.meta.url);
export const LOG = new URL("./fixtures/log/", import.meta.url);

export function readText(dir: URL, name: string): string {
  return readFileSync(new URL(name, dir), "utf8");
}

export function readJson(dir: URL, name: string): unknown {
  return JSON.parse(readText(dir, name));
}

export async function keyFrom(dir: URL, name: string): Promise<PublicKey> {
  const [key] = await parsePublicKeys(readText(dir, name), name);
  if (key === undefined) throw new Error(`no key in ${name}`);
  return key;
}

export function fixtureReceipt(name: string): unknown {
  const fixture = readJson(CONFORMANCE, name) as { receipt: unknown };
  return fixture.receipt;
}

/** A fresh Ed25519 key pair, with the public half as PEM. */
export async function makeKey(): Promise<{ privateKey: CryptoKey; pem: string; publicKey: PublicKey }> {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const der = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
  const b64 = Buffer.from(der).toString("base64");
  const pem = `-----BEGIN PUBLIC KEY-----\n${b64}\n-----END PUBLIC KEY-----\n`;
  const [publicKey] = await parsePublicKeys(pem, "test key");
  if (publicKey === undefined) throw new Error("no key");
  return { privateKey: pair.privateKey, pem, publicKey };
}

/** Signs `body` as a v2 receipt: canonical, contentHash, signature, and the body's fields repeated beside them. */
export async function signReceipt(body: Record<string, unknown>, privateKey: CryptoKey): Promise<Record<string, unknown>> {
  const canonical = JSON.stringify(body);
  const bytes = new TextEncoder().encode(canonical);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, privateKey, bytes));
  const hash = Buffer.from(await crypto.subtle.digest("SHA-256", bytes)).toString("hex");
  return { ...body, canonical, contentHash: `sha256:${hash}`, signature: `v2=${Buffer.from(sig).toString("base64")}` };
}
```

`test/conformance.test.ts`:

```ts
// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

// Runs the verifiable-receipts conformance corpus (copied into
// test/fixtures/conformance, see its README) through the browser port of
// the verifier: it must give every fixture the verdict, and the reason,
// the three reference verifiers give.
import assert from "node:assert/strict";
import { readdirSync } from "node:fs";
import { describe, it } from "node:test";

import { verifyV2Receipt } from "../src/vendor/verifiable-receipts/receipt.ts";
import { verifyInclusionProof } from "../src/vendor/verifiable-receipts/transparency.ts";
import { CONFORMANCE, keyFrom, readJson } from "./helpers.ts";

interface Expected {
  ok: boolean;
  reasonContains?: string;
}

const files = readdirSync(CONFORMANCE).filter((f) => f.endsWith(".json")).sort();

describe("conformance corpus", () => {
  it("holds the 25 fixtures of the source corpus", () => {
    assert.equal(files.length, 25);
  });

  for (const name of files.filter((f) => f.startsWith("v2-"))) {
    it(`receipt ${name}`, async () => {
      const fixture = readJson(CONFORMANCE, name) as { receipt: unknown; expected: Expected };
      const key = await keyFrom(CONFORMANCE, "public-key.pem");
      const result = await verifyV2Receipt(fixture.receipt, key.key);
      assert.equal(result.ok, fixture.expected.ok, result.reason);
      if (fixture.expected.reasonContains !== undefined) {
        assert.match(result.reason ?? "", new RegExp(fixture.expected.reasonContains, "i"));
      }
    });
  }

  for (const name of files.filter((f) => f.startsWith("inclusion-"))) {
    it(`inclusion proof ${name}`, async () => {
      const f = readJson(CONFORMANCE, name) as Record<string, unknown> & { expected: Expected };
      assert.equal(await verifyInclusionProof(f.leafHashHex, f.leafIndex, f.treeSize, f.auditPath, f.rootHashHex), f.expected.ok);
    });
  }
});
```

`test/keys.test.ts`:

```ts
// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { KeyError, parsePublicKeys } from "../src/keys.ts";
import { CONFORMANCE, makeKey, readText } from "./helpers.ts";

const PEM = readText(CONFORMANCE, "public-key.pem");
const PRIVATE = ["PRIVATE", "KEY"].join(" ");

describe("parsePublicKeys", () => {
  it("reads the conformance key and names it as verify-receipts-action does", async () => {
    const [k, ...rest] = await parsePublicKeys(PEM, "The issuer key");
    assert.ok(k);
    assert.equal(rest.length, 0);
    // sha256 of the SPKI DER, first 16 hex characters.
    const der = Buffer.from(PEM.replace(/-----[A-Z ]+-----|\s/g, ""), "base64");
    const want = "sha256:" + Buffer.from(await crypto.subtle.digest("SHA-256", der)).toString("hex").slice(0, 16);
    assert.equal(k.fingerprint, want);
  });

  it("reads several blocks, drops repeats, and keeps their order", async () => {
    const [a, b] = [await makeKey(), await makeKey()];
    const keys = await parsePublicKeys(`${a.pem}\n${b.pem}\n${a.pem}`, "The witness keys");
    assert.deepEqual(
      keys.map((k) => k.fingerprint),
      [a.publicKey.fingerprint, b.publicKey.fingerprint],
    );
  });

  it("returns no keys for empty text", async () => {
    assert.deepEqual(await parsePublicKeys("  \n", "The log key"), []);
  });

  for (const [name, text, message] of [
    // Built from parts so secret scanners do not flag a key that has no key material.
    ["a private key", `-----BEGIN ${PRIVATE}-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END ${PRIVATE}-----`, /private key\. Paste the matching public key/],
    ["a certificate", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----", /is a "CERTIFICATE"/],
    ["a damaged key", PEM.replace("MCow", "MCox"), /not an Ed25519 public key, or is damaged/],
    ["no PEM block", "MCowBQYDK2VwAyEA", /has no PEM block/],
    ["an RSA key", "-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAMvvHOFlR0GdV+ZFzOPWHwm1yflxQHwRJuS1J8y6xG4w2zoV+NS3Me6U5w3XrN6gI0Hf6zWbfvK7w+6s5z6kGkECAwEAAQ==\n-----END PUBLIC KEY-----", /not an Ed25519 public key/],
  ] as const) {
    it(`rejects ${name} with a message that says what to do`, async () => {
      await assert.rejects(parsePublicKeys(text, "The issuer key"), (e: unknown) => e instanceof KeyError && message.test(e.message));
    });
  }
});
```

`test/lint.test.ts`:

```ts
// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

// The ESLint rules that keep src/ a browser page that stores nothing, parses
// no HTML, loads no code and talks only to the log: each line below breaks
// one of them, and each must be flagged. The probe is written into src/ so
// that the src/ tsconfig and rules apply to it, and removed afterwards.
import assert from "node:assert/strict";
import { rmSync, writeFileSync } from "node:fs";
import { describe, it } from "node:test";

import { ESLint } from "eslint";

const ROOT = new URL("../", import.meta.url);
const PROBE = new URL(`../src/lint-probe-${String(process.pid)}.ts`, import.meta.url);

const CASES: [string, string][] = [
  ["void globalThis.fetch(s);", "no-restricted-properties"],
  ["void window.fetch(s);", "no-restricted-properties"],
  ["void self.fetch(s);", "no-restricted-properties"],
  ["void fetch(s);", "no-restricted-globals"],
  ["void globalThis.localStorage;", "no-restricted-properties"],
  ["void window.navigator;", "no-restricted-properties"],
  ['window.history.replaceState(null, "", s);', "no-restricted-properties"],
  ["void window.document.cookie;", "no-restricted-properties"],
  ["el.setHTMLUnsafe(s);", "no-restricted-properties"],
  ["void r.createContextualFragment(s);", "no-restricted-properties"],
  ['void new DOMParser().parseFromString(s, "text/html");', "no-restricted-globals"],
  ["void (0, eval)(s);", "no-eval"],
  ["void import(s);", "no-restricted-syntax"],
  ["void new Worker(s);", "no-restricted-globals"],
  ['void caches.open("x");', "no-restricted-globals"],
  ["void open(s);", "no-restricted-globals"],
  ['void new Function("return 1");', "no-new-func"],
  ["void Buffer.from(s);", "no-restricted-globals"],
  ["void process.env;", "no-restricted-globals"],
  ["el.innerHTML = s;", "no-restricted-properties"],
];

describe("the src/ lint rules", () => {
  it("flag every way around them", async () => {
    const body = CASES.map(([line]) => `  ${line}`).join("\n");
    const code = `import { createHash } from "node:crypto";\nimport { readFileSync } from "fs";\n\nexport function probe(el: Element, s: string, r: Range): void {\n${body}\n  void createHash;\n  void readFileSync;\n}\n`;
    writeFileSync(PROBE, code);
    try {
      const [result] = await new ESLint({ cwd: ROOT.pathname }).lintFiles([PROBE.pathname]);
      assert.ok(result);
      const byLine = new Map<number, string[]>();
      for (const m of result.messages) byLine.set(m.line, [...(byLine.get(m.line) ?? []), m.ruleId ?? "parse"]);
      assert.ok(byLine.get(1)?.includes("no-restricted-imports"), "node:crypto");
      assert.ok(byLine.get(2)?.includes("no-restricted-imports"), "fs");
      CASES.forEach(([line, rule], i) => {
        assert.ok(byLine.get(i + 5)?.includes(rule), `${line} not flagged by ${rule}: ${JSON.stringify(byLine.get(i + 5))}`);
      });
    } finally {
      rmSync(PROBE, { force: true });
    }
  });
});
```

`lint.test.ts` writes a probe file into `src/` (ignored by `.gitignore`), so that `src/tsconfig.json` and the `src/` rules apply to it, lints it with ESLint's API, and removes it.
- [ ] **Step 2:** run them:

```bash
npm test
```

Expected: fails, `ERR_MODULE_NOT_FOUND` for `src/keys.ts`.

- [ ] **Step 3:** write the byte helpers and the two ports. Each port's header states what changed from its source:

`src/bytes.ts`:

```ts
// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

// Bytes for the browser: UTF-8, hex, base64 and SHA-256, with WebCrypto
// and no Buffer, so the same code runs in a page and under node --test.

const encoder = new TextEncoder();

/** The UTF-8 bytes of `text`; a lone surrogate becomes U+FFFD, as in Buffer.from. */
export function utf8(text: string): Uint8Array<ArrayBuffer> {
  return encoder.encode(text);
}

export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/** Decodes lowercase or uppercase hex of even length; callers check the spelling first. */
export function fromHex(hex: string): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

/** Decodes standard base64; callers check the alphabet and padding first. */
export function fromBase64(text: string): Uint8Array<ArrayBuffer> {
  const binary = atob(text);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

export function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

/** SHA-256 of the parts, concatenated, as 64 lowercase hex digits. */
export async function sha256Hex(...parts: readonly Uint8Array[]): Promise<string> {
  let length = 0;
  for (const p of parts) length += p.length;
  const all = new Uint8Array(length);
  let at = 0;
  for (const p of parts) {
    all.set(p, at);
    at += p.length;
  }
  return toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", all)));
}

/** Ed25519 verification that answers false, never throws, for a malformed signature. */
export async function ed25519Verify(key: CryptoKey, signature: Uint8Array<ArrayBuffer>, data: Uint8Array<ArrayBuffer>): Promise<boolean> {
  try {
    return await crypto.subtle.verify({ name: "Ed25519" }, key, signature, data);
  } catch {
    return false;
  }
}
```

`src/vendor/verifiable-receipts/receipt.ts`:

```ts
// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0
//
// Vendored from verifiable-receipts,
// packages/verifiable-receipts/conformance/verify-v2.mjs at the commit in
// third_party/verifiable-receipts/VR_REF. Licence:
// third_party/verifiable-receipts/LICENSE.
//
// Changed from the original, so that it runs in a browser: converted to
// TypeScript; node:crypto and Buffer replaced by WebCrypto and ../../bytes.ts,
// so verifyV2Receipt is async and takes a WebCrypto CryptoKey; the
// signature-mismatch reason exported as SIGNATURE_MISMATCH_REASON. No
// change to the checks, their order or their failure reasons.

/**
 * The v2 (Ed25519) receipt verifier of the verifiable-receipts conformance
 * corpus. It makes these checks, in this order:
 *
 *   1. `canonical` and `signature` are non-empty strings.
 *   2. `signature` is "v2=<base64>" with standard base64.
 *   3. `contentHash`, when present and not null, is a string equal to
 *      the hex SHA-256 of `canonical`'s UTF-8 bytes ("sha256:" prefix
 *      optional); an empty string is a mismatch, not an absent field.
 *   4. The Ed25519 signature verifies over `canonical`'s UTF-8 bytes,
 *      exactly as given.
 *   5. `canonical` parses as a JSON object.
 *   6. Every other top-level field of the receipt equals the same field
 *      of that object (deep JSON-value equality); a field that
 *      disagrees, or that the canonical lacks, is rejected.
 */
import { ed25519Verify, fromBase64, sha256Hex, toBase64, utf8 } from "../../bytes.ts";

const ENVELOPE_ONLY = new Set(["canonical", "contentHash", "signature"]);

const STANDARD_BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export const SIGNATURE_MISMATCH_REASON = "signature does not verify under the supplied public key";

export interface VerifyResult {
  ok: boolean;
  reason?: string;
}

function isObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/**
 * Deep JSON-value equality; object key order does not matter. A number of
 * magnitude 2^53 or more equals nothing: JSON.parse reads 2^53 + 1 as
 * 2^53, so such a number in a repeated field is rejected in every
 * verifier rather than compared differently.
 */
export function jsonEqual(a: unknown, b: unknown): boolean {
  if (Array.isArray(a) || Array.isArray(b)) {
    return (
      Array.isArray(a) &&
      Array.isArray(b) &&
      a.length === b.length &&
      a.every((x: unknown, i: number) => jsonEqual(x, b[i]))
    );
  }
  if (isObject(a) || isObject(b)) {
    if (!isObject(a) || !isObject(b)) return false;
    const ka = Object.keys(a);
    if (ka.length !== Object.keys(b).length) return false;
    return ka.every((k) => Object.hasOwn(b, k) && jsonEqual(a[k], b[k]));
  }
  if (typeof a === "number" && typeof b === "number") {
    return Math.abs(a) < 2 ** 53 && Math.abs(b) < 2 ** 53 && a === b;
  }
  return a === b; // null, booleans, strings
}

export async function verifyV2Receipt(receipt: unknown, publicKey: CryptoKey): Promise<VerifyResult> {
  if (!isObject(receipt)) return { ok: false, reason: "receipt must be an object" };
  const { canonical, signature, contentHash } = receipt;
  if (typeof canonical !== "string" || canonical === "") {
    return { ok: false, reason: "missing canonical projection" };
  }
  if (typeof signature !== "string" || signature === "") {
    return { ok: false, reason: "missing signature" };
  }
  if (!signature.startsWith("v2=")) {
    return { ok: false, reason: "signature is not v2 (expected 'v2=<base64>')" };
  }
  if (!STANDARD_BASE64.test(signature.slice(3))) {
    return { ok: false, reason: "signature base64 invalid" };
  }
  const sigBytes = fromBase64(signature.slice(3));
  // Reject non-canonical spellings (non-zero padding bits).
  if (toBase64(sigBytes) !== signature.slice(3)) {
    return { ok: false, reason: "signature base64 invalid: not canonical" };
  }
  const canonicalBytes = utf8(canonical);

  if (contentHash != null && typeof contentHash !== "string") {
    return { ok: false, reason: "contentHash must be a string" };
  }
  if (contentHash != null) {
    const actual = await sha256Hex(canonicalBytes);
    if (actual !== contentHash.replace(/^sha256:/, "")) {
      return { ok: false, reason: "contentHash mismatch with canonical bytes" };
    }
  }

  if (!(await ed25519Verify(publicKey, sigBytes, canonicalBytes))) {
    return { ok: false, reason: SIGNATURE_MISMATCH_REASON };
  }

  // Only now parse the canonical: these bytes are authenticated.
  let signed: unknown;
  try {
    signed = JSON.parse(canonical);
  } catch {
    return { ok: false, reason: "canonical is not valid JSON" };
  }
  if (!isObject(signed)) {
    return { ok: false, reason: "canonical is not a JSON object" };
  }
  for (const key of Object.keys(receipt).sort()) {
    if (ENVELOPE_ONLY.has(key)) continue;
    if (!Object.hasOwn(signed, key)) {
      return {
        ok: false,
        reason: `envelope field "${key}" is not in the signed canonical`,
      };
    }
    if (!jsonEqual(receipt[key], signed[key])) {
      return {
        ok: false,
        reason: `envelope field "${key}" disagrees with the signed canonical`,
      };
    }
  }
  return { ok: true };
}
```

`src/vendor/verifiable-receipts/transparency.ts`:

```ts
// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0
//
// Vendored from verifiable-receipts,
// packages/verifiable-receipts/src/transparency.ts at the commit in
// third_party/verifiable-receipts/VR_REF. Licence:
// third_party/verifiable-receipts/LICENSE.
//
// Changed from the original, so that it runs in a browser: only the
// verification half is kept (leafHash, innerHash, verifyInclusionProof,
// canonicalizeSth and the SignedTreeHead type); node:crypto and Buffer
// replaced by WebCrypto and ../../bytes.ts, so leafHash, innerHash and
// verifyInclusionProof are async; leafHash takes a string only;
// verifyInclusionProof's parameters are typed unknown, since a log's answer
// is untrusted, and it returns false when an audit-path entry is missing,
// which the original left to the length check alone; isHashHex and isCount
// are exported. No change to the checks or the algorithm.

/**
 * RFC 6962 / RFC 9162 Merkle tree primitives for checking that a receipt
 * is in a transparency log. Hash domains follow RFC 6962 §2.1:
 *   leaf  = SHA-256(0x00 || leaf_bytes)
 *   inner = SHA-256(0x01 || left || right)
 */
import { fromHex, sha256Hex, utf8 } from "../../bytes.ts";

const LEAF_PREFIX = new Uint8Array([0x00]);
const INNER_PREFIX = new Uint8Array([0x01]);

/** Leaf hash per RFC 6962 §2.1, over the UTF-8 bytes of `data`. */
export function leafHash(data: string): Promise<string> {
  return sha256Hex(LEAF_PREFIX, utf8(data));
}

/** Inner-node hash per RFC 6962 §2.1, of two 64-hex-digit hashes. */
export function innerHash(leftHex: string, rightHex: string): Promise<string> {
  return sha256Hex(INNER_PREFIX, fromHex(leftHex), fromHex(rightHex));
}

/** A hash on the wire: 32 bytes, written as exactly 64 lowercase hex digits. */
const HASH_HEX = /^[0-9a-f]{64}$/;

export function isHashHex(x: unknown): x is string {
  return typeof x === "string" && HASH_HEX.test(x);
}

/** A leaf index or tree size: a whole number that a double holds exactly. */
export function isCount(n: unknown): n is number {
  return Number.isSafeInteger(n) && (n as number) >= 0;
}

/** Number of bits required to represent `n` (with `bitsLen(0) === 0`). */
function bitsLen(n: number): number {
  let len = 0;
  let x = n;
  while (x > 0) {
    x = Math.floor(x / 2);
    len++;
  }
  return len;
}

/** Number of set bits in `n`. */
function onesCount(n: number): number {
  let x = n;
  let c = 0;
  while (x > 0) {
    c += x & 1;
    x = Math.floor(x / 2);
  }
  return c;
}

/**
 * Verify an inclusion proof. Resolves true iff folding `leafHashHex` with
 * `proof` along the bit-pattern of `idx` reproduces `rootHashHex`.
 * Algorithm: the standard CT (RFC 6962) verifier decomposition into an
 * "inner" segment that walks the bits of `idx` and a "border" segment of
 * left-siblings up the right edge.
 *
 * Resolves false, never rejects, for malformed input: `idx` and
 * `treeSize` must be safe integers with 0 <= idx < treeSize, and every
 * hash must be 64 lowercase hex digits (32 bytes).
 */
export async function verifyInclusionProof(
  leafHashHex: unknown,
  idx: unknown,
  treeSize: unknown,
  proof: unknown,
  rootHashHex: unknown,
): Promise<boolean> {
  if (!isCount(idx) || !isCount(treeSize)) return false;
  if (idx >= treeSize) return false;
  if (!isHashHex(leafHashHex) || !isHashHex(rootHashHex)) return false;
  if (!Array.isArray(proof) || !proof.every(isHashHex)) return false;
  if (treeSize === 1) {
    return proof.length === 0 && leafHashHex === rootHashHex;
  }
  // BigInt: `^` on numbers truncates to 32 bits, which breaks trees of
  // 2^31 leaves or more.
  const inner = bitsLen(Number(BigInt(idx) ^ BigInt(treeSize - 1)));
  const border = onesCount(Math.floor(idx / Math.pow(2, inner)));
  if (proof.length !== inner + border) return false;

  let hash = leafHashHex;
  for (let i = 0; i < inner; i++) {
    const sib: unknown = proof[i];
    if (!isHashHex(sib)) return false;
    if (Math.floor(idx / Math.pow(2, i)) % 2 === 0) {
      hash = await innerHash(hash, sib);
    } else {
      hash = await innerHash(sib, hash);
    }
  }
  for (let i = 0; i < border; i++) {
    const sib: unknown = proof[inner + i];
    if (!isHashHex(sib)) return false;
    hash = await innerHash(sib, hash);
  }
  return hash === rootHashHex;
}

/** Signed Tree Head: the log's commitment to its state at one point. */
export interface SignedTreeHead {
  v: 1;
  logId: string;
  treeSize: number;
  rootHash: string; // hex
  timestamp: string; // ISO 8601
  signature?: string; // v2= wire format
}

/**
 * Canonical byte projection of an STH, used as the signing input: keys
 * sorted, no whitespace, `signature` omitted.
 */
export function canonicalizeSth(sth: Omit<SignedTreeHead, "signature">): string {
  return JSON.stringify({
    logId: sth.logId,
    rootHash: sth.rootHash,
    timestamp: sth.timestamp,
    treeSize: sth.treeSize,
    v: sth.v,
  });
}
```

- [ ] **Step 4:** review the receipt port against the original, line by line:

```bash
diff third_party/verifiable-receipts/verify-v2.mjs src/vendor/verifiable-receipts/receipt.ts
git -C $VR show "$VR_REF:packages/verifiable-receipts/src/transparency.ts" | diff - src/vendor/verifiable-receipts/transparency.ts
```

Every difference must be one the header lists: types, the imports, `Buffer` and `createHash` replaced by `src/bytes.ts`, `nodeVerify` by `ed25519Verify`, `async`/`await`, and in `transparency.ts` the dropped tree building and consistency proofs. Any other difference is a bug in the port.

- [ ] **Step 5:** write the key reader:

`src/keys.ts`:

```ts
// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

// Reads Ed25519 public keys from PEM text into WebCrypto keys, each named
// by the same fingerprint verify-receipts-action reports.
import { fromBase64, sha256Hex } from "./bytes.ts";

/** An Ed25519 public key and the short name it is reported under. */
export interface PublicKey {
  key: CryptoKey;
  /** "sha256:" and the first 16 hex characters of the SHA-256 of the SPKI DER. */
  fingerprint: string;
}

export class KeyError extends Error {}

const PEM_BLOCK = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g;
const BASE64_BODY = /^[A-Za-z0-9+/]+={0,2}$/;

/**
 * Reads every PEM block in `text` and returns the Ed25519 public keys, in
 * order, without repeats. A private key, a block of another kind, an
 * unreadable block, or text with no PEM block at all is an error that
 * says what to do. `source` names the field in messages ("The issuer key").
 */
export async function parsePublicKeys(text: string, source: string): Promise<PublicKey[]> {
  const keys: PublicKey[] = [];
  let blocks = 0;
  for (const match of text.matchAll(PEM_BLOCK)) {
    blocks++;
    const label = match[1] ?? "";
    if (label.includes("PRIVATE")) {
      throw new KeyError(
        `${source}, block ${String(blocks)}, is a private key. Paste the matching public key instead (openssl pkey -pubout prints it), and keep the private key to yourself.`,
      );
    }
    if (label !== "PUBLIC KEY") {
      throw new KeyError(`${source}, block ${String(blocks)}, is a "${label}". Paste a "PUBLIC KEY" block.`);
    }
    const body = (match[2] ?? "").replace(/\s+/g, "");
    let key: CryptoKey;
    try {
      if (!BASE64_BODY.test(body)) throw new KeyError("not base64");
      key = await crypto.subtle.importKey("spki", fromBase64(body), { name: "Ed25519" }, true, ["verify"]);
    } catch {
      throw new KeyError(
        `${source}, block ${String(blocks)}, is not an Ed25519 public key, or is damaged. Copy the whole block again, from -----BEGIN to -----END.`,
      );
    }
    const der = new Uint8Array(await crypto.subtle.exportKey("spki", key));
    const fingerprint = "sha256:" + (await sha256Hex(der)).slice(0, 16);
    if (!keys.some((k) => k.fingerprint === fingerprint)) keys.push({ key, fingerprint });
  }
  if (blocks === 0 && text.trim() !== "") {
    throw new KeyError(
      `${source} has no PEM block. Include the -----BEGIN PUBLIC KEY----- and -----END PUBLIC KEY----- lines.`,
    );
  }
  return keys;
}
```

- [ ] **Step 6:** add the ports to the drift check. In `scripts/check-vendor.sh`, insert this just before the last line (`echo "every vendored file matches …"`):

```bash
# The ports: exactly these files, each naming VR_REF.
printf '%s\n' receipt.ts transparency.ts | exactly src/vendor/verifiable-receipts
for f in receipt.ts transparency.ts; do
  grep -q "third_party/verifiable-receipts/VR_REF" "src/vendor/verifiable-receipts/$f" ||
    fail "src/vendor/verifiable-receipts/$f" "does not name third_party/verifiable-receipts/VR_REF"
done
```

From now on `src/vendor/verifiable-receipts/` must exist and hold exactly these two files. Run it, then prove the new check bites, in scratch copies as in Task 2, Step 7 (define `case_` and `UP` as there):

```bash
bash scripts/check-vendor.sh "$UP"
case_ "touch src/vendor/verifiable-receipts/extra.ts"      # src/vendor/verifiable-receipts::holds extra.ts …
case_ "rm src/vendor/verifiable-receipts/*.ts"             # src/vendor/verifiable-receipts::holds  but must hold exactly …
case_ "rm -r src/vendor"                                   # src/vendor/verifiable-receipts::is missing
case_ "sed -i '' 's|VR_REF|REF|g' src/vendor/verifiable-receipts/receipt.ts"   # …/receipt.ts::does not name …
```

Expected: the `matches` line, then `exit 1` with each `::error`.

- [ ] **Step 7:** run the whole check:

```bash
npm run typecheck && npx eslint . && npm test 2>&1 | grep -E '^# (pass|fail)'
```

Expected: tsc and ESLint print nothing; `# pass 35`, `# fail 0` (26 conformance: the count and 25 fixtures; 8 keys; 1 lint).

- [ ] **Step 8:** prove the type and lint guards bite.
  - Lint: delete `"setHTMLUnsafe",` from `eslint.config.js`, run `node --test test/lint.test.ts`, and confirm `# fail 1` with `el.setHTMLUnsafe(s); not flagged by no-restricted-properties`. Restore the line.
  - Types: write `src/tsc-probe.ts` holding `import { createHash } from "node:crypto"; export const h = createHash("sha256"); export const b = Buffer.from("x"); export const e = process.env;`, run `npx tsc -p src/tsconfig.json`, and confirm `TS2307: Cannot find module 'node:crypto'` and `TS2591: Cannot find name 'Buffer'` and `'process'`. Move the probe to `~/.Trash/`.

- [ ] **Step 9:** commit:

```bash
gitleaks git --pre-commit --staged --no-banner   # expect: no leaks found
git commit --author="$A" -m "Browser port of the v2 verifier and the inclusion-proof verifier" -m "verify-v2.mjs and transparency.ts from verifiable-receipts at VR_REF, on WebCrypto instead of node:crypto and Buffer, so they run in a page; same checks, order and reasons. PEM keys become WebCrypto keys named by the fingerprint verify-receipts-action reports. Every conformance fixture gets the reference verdict and reason." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 4: the port against the original, on random receipts

**Files:**
- Create: `test/mutations.ts`, `test/port.properties.test.ts`

- [ ] **Step 1:** write the generators and the property tests:

`test/mutations.ts`:

```ts
// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

// Signed receipts with one or two changes, of the kinds verifiable-receipts'
// differential corpus makes, for the property tests.
import fc from "fast-check";

/** A body like a real receipt's, with keys in a random order. */
export const body = fc.dictionary(fc.string({ minLength: 1, maxLength: 8 }), fc.jsonValue({ maxDepth: 2 }), { maxKeys: 5 }).map((d) => ({ receiptId: "r", ...d }));

/** One change to a signed receipt, of the kinds the differential corpus makes. */
export const mutation = fc.oneof(
  fc.record({ kind: fc.constant("none" as const) }),
  fc.record({ kind: fc.constant("char" as const), field: fc.constantFrom("canonical", "signature", "contentHash"), pos: fc.nat(), delta: fc.integer({ min: 1, max: 0x7f }) }),
  fc.record({ kind: fc.constant("drop" as const), field: fc.constantFrom("canonical", "signature", "contentHash") }),
  fc.record({ kind: fc.constant("set" as const), field: fc.string({ maxLength: 8 }), value: fc.jsonValue({ maxDepth: 2 }) }),
  fc.record({ kind: fc.constant("respell" as const), suffix: fc.constantFrom("\n", " ", "=", "A") }),
  fc.record({ kind: fc.constant("hash" as const), value: fc.constantFrom("", null, 0, false, "sha256:", "SHA256:", []) }),
);

export type Mutation = { kind: "none" } | { kind: "char"; field: string; pos: number; delta: number } | { kind: "drop"; field: string } | { kind: "set"; field: string; value: unknown } | { kind: "respell"; suffix: string } | { kind: "hash"; value: unknown };

export function mutate(receipt: Record<string, unknown>, m: Mutation): Record<string, unknown> {
  const r = { ...receipt };
  switch (m.kind) {
    case "none":
      return r;
    case "char": {
      const current = r[m.field];
      const text = typeof current === "string" ? current : "";
      if (text === "") return r;
      const i = m.pos % text.length;
      r[m.field] = text.slice(0, i) + String.fromCharCode((text.charCodeAt(i) + m.delta) % 0x80) + text.slice(i + 1);
      return r;
    }
    case "drop":
      return Object.fromEntries(Object.entries(r).filter(([k]) => k !== m.field));
    case "set":
      r[m.field] = m.value;
      return r;
    case "respell":
      r.signature = String(r.signature) + m.suffix;
      return r;
    case "hash":
      r.contentHash = m.value;
      return r;
  }
}
```

`test/port.properties.test.ts`:

```ts
// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

// Property tests (fast-check) of the browser port: it gives the same verdict
// and reason as the original verify-v2.mjs (third_party/verifiable-receipts,
// byte-identical to VR_REF) on signed receipts with one or two changes, and
// accepts an inclusion proof only as built. FC_NUM_RUNS raises the number of
// cases per property (default 200).
import assert from "node:assert/strict";
import { createPublicKey } from "node:crypto";
import { describe, it } from "node:test";

import fc from "fast-check";

import { verifyV2Receipt } from "../src/vendor/verifiable-receipts/receipt.ts";
import { innerHash, leafHash, verifyInclusionProof } from "../src/vendor/verifiable-receipts/transparency.ts";
import { verifyV2Receipt as original } from "../third_party/verifiable-receipts/verify-v2.mjs";
import { makeKey, signReceipt } from "./helpers.ts";
import { body, mutate, mutation } from "./mutations.ts";

const NUM_RUNS = Number(process.env.FC_NUM_RUNS ?? "200");
fc.configureGlobal({ numRuns: Number.isSafeInteger(NUM_RUNS) && NUM_RUNS > 0 ? NUM_RUNS : 200 });

const issuer = await makeKey();
const originalKey = createPublicKey(issuer.pem);

describe("the browser port agrees with the original verifier", () => {
  it("same verdict and reason on signed receipts with changes", async () => {
    await fc.assert(
      fc.asyncProperty(body, mutation, mutation, async (b, m1, m2) => {
        const receipt = mutate(mutate(await signReceipt(b, issuer.privateKey), m1), m2);
        assert.deepEqual(await verifyV2Receipt(receipt, issuer.publicKey.key), original(receipt, originalKey));
      }),
    );
  });
});
describe("inclusion proofs", () => {
  /** Builds the RFC 9162 tree over `n` leaves; returns the root and the audit path of `idx`. */
  async function tree(leaves: string[], idx: number): Promise<{ root: string; path: string[] }> {
    if (leaves.length === 1) return { root: leaves[0] ?? "", path: [] };
    let k = 1;
    while (k * 2 < leaves.length) k *= 2;
    const left = leaves.slice(0, k);
    const right = leaves.slice(k);
    const l = await tree(left, idx < k ? idx : 0);
    const r = await tree(right, idx < k ? 0 : idx - k);
    const root = await innerHash(l.root, r.root);
    return idx < k ? { root, path: [...l.path, r.root] } : { root, path: [...r.path, l.root] };
  }

  it("accepts a proof as built, and rejects it with one hash changed or an index out of range", async () => {
    await fc.assert(
      fc.asyncProperty(fc.integer({ min: 1, max: 40 }), fc.nat(), fc.nat(), async (n, i, j) => {
        const leaves = await Promise.all(Array.from({ length: n }, (_, x) => leafHash(`entry ${String(x)}`)));
        const idx = i % n;
        const { root, path } = await tree(leaves, idx);
        assert.equal(await verifyInclusionProof(leaves[idx], idx, n, path, root), true);
        if (path.length > 0) {
          const bad = [...path];
          const at = j % bad.length;
          bad[at] = await leafHash(`changed ${String(at)}`);
          assert.equal(await verifyInclusionProof(leaves[idx], idx, n, bad, root), false);
        }
        assert.equal(await verifyInclusionProof(leaves[idx], n, n, path, root), false);
        assert.equal(await verifyInclusionProof(leaves[idx], idx + 0.5, n, path, root), false);
      }),
    );
  });
});
```

`port.properties.test.ts` imports the unchanged original, `third_party/verifiable-receipts/verify-v2.mjs`, which uses `node:crypto`, with its upstream types from `verify-v2.d.mts`, so the import needs no `@ts-expect-error`: the two verifiers judge the same receipts and must give the same verdict and reason.

- [ ] **Step 2:** run, with ten times the default cases:

```bash
FC_NUM_RUNS=2000 node --test test/port.properties.test.ts 2>&1 | grep -E '^# (pass|fail)'
```

Expected: `# pass 2`, `# fail 0`, in about three seconds.

- [ ] **Step 3:** prove the property catches a broken port. In `src/vendor/verifiable-receipts/receipt.ts`, change `if (toBase64(sigBytes) !== signature.slice(3))` to `if (false)`, rerun the command, and confirm `# fail 1`, with a counterexample that changes one character of the signature: a spelling with a non-zero padding bit, which the original rejects and the broken port accepts. Restore the line and rerun to `# fail 0`. Then change `if (contentHash != null) {` to `if (contentHash) {`, the rule before `fix/empty-contenthash`, rerun `node --test test/port.properties.test.ts`, and confirm `# fail 1` with a counterexample ending `{"kind":"hash","value":""}`; restore it.
- [ ] **Step 4:** run the whole check (npm run typecheck && npx eslint . && npm test 2>&1 | grep -E '^# (pass|fail)'): `# pass 37`, `# fail 0`.
- [ ] **Step 5:** commit:

```bash
gitleaks git --pre-commit --staged --no-banner   # expect: no leaks found
git commit --author="$A" -m "Property tests: the port agrees with the original verifier" -m "fast-check signs random receipts, changes one or two things the way the differential corpus does, and requires the browser port and the vendored verify-v2.mjs to give the same verdict and reason; inclusion proofs are accepted only as built." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 5: v2= signatures, tree heads, and the recorded log

**Files:**
- Create: `scripts/make-stub-log.mjs`, `test/fixtures/log/README.md`; generated: `test/fixtures/log/*.json`, `test/fixtures/log/*.pem`
- Create: `test/signature.test.ts`, `test/tree-head.test.ts`, `src/signature.ts`, `src/tree-head.ts`

- [ ] **Step 1:** write the generator of the recorded log answers and its README, then run it:

`scripts/make-stub-log.mjs`:

```js
// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

// Writes test/fixtures/log/: the answers a receipts-log would give for a
// three-entry log whose entry 1 is the conformance receipt
// v2-valid-001.json, signed with throwaway keys whose private halves are
// discarded. The unit tests and the Playwright tests serve these files in
// place of a live log, so CI never calls one.
//
// Usage: node scripts/make-stub-log.mjs
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";

const OUT = new URL("../test/fixtures/log/", import.meta.url);
const receipt = JSON.parse(readFileSync(new URL("../test/fixtures/conformance/v2-valid-001.json", import.meta.url), "utf8")).receipt;
mkdirSync(OUT, { recursive: true });

const leaf = (text) => createHash("sha256").update(Buffer.from([0])).update(text, "utf8").digest("hex");
const inner = (l, r) =>
  createHash("sha256").update(Buffer.from([1])).update(Buffer.from(l, "hex")).update(Buffer.from(r, "hex")).digest("hex");
const keyPair = () => generateKeyPairSync("ed25519");
const pem = (k) => k.export({ type: "spki", format: "pem" });
const v2 = (privateKey, text) => "v2=" + sign(null, Buffer.from(text, "utf8"), privateKey).toString("base64");
const canonicalSth = (h) =>
  JSON.stringify({ logId: h.logId, rootHash: h.rootHash, timestamp: h.timestamp, treeSize: h.treeSize, v: h.v });
const write = (name, value) => writeFileSync(new URL(name, OUT), typeof value === "string" ? value : JSON.stringify(value, null, 2) + "\n");

// The tree: three entries; entry 1 is the conformance receipt.
const leaves = [leaf('{"note":"entry 0"}'), leaf(receipt.canonical), leaf('{"note":"entry 2"}')];
const root = inner(inner(leaves[0], leaves[1]), leaves[2]);

const log = keyPair();
const witnesses = [keyPair(), keyPair(), keyPair()];
write("log-public-key.pem", pem(log.publicKey));
witnesses.forEach((w, i) => write(`witness-${String(i + 1)}.pem`, pem(w.publicKey)));
write("other-public-key.pem", pem(keyPair().publicKey));

const head = { v: 1, logId: "stub-log", treeSize: 3, rootHash: root, timestamp: "2026-10-23T12:00:00.000Z" };
const canonical = canonicalSth(head);
write("sth.json", { ...head, signature: v2(log.privateKey, canonical), canonical });

// A forged tree head: another root, under the log's old signature.
const forgedRoot = inner(leaves[0], leaves[1]);
write("sth-forged.json", { ...head, rootHash: forgedRoot, signature: v2(log.privateKey, canonical), canonical: canonicalSth({ ...head, rootHash: forgedRoot }) });

write("inclusion.json", {
  kind: "inclusion",
  logId: "stub-log",
  leafHashHex: leaves[1],
  leafIndex: 1,
  treeSize: 3,
  auditPath: [leaves[0], leaves[2]],
  rootHashHex: root,
});
// A proof that agrees with its own rootHashHex but not with the signed root.
const fakeSibling = leaf('{"note":"not in the log"}');
write("inclusion-lying-root.json", {
  kind: "inclusion",
  logId: "stub-log",
  leafHashHex: leaves[1],
  leafIndex: 1,
  treeSize: 3,
  auditPath: [leaves[0], fakeSibling],
  rootHashHex: inner(inner(leaves[0], leaves[1]), fakeSibling),
});
write("not-found.json", { error: "leaf hash not in the log" });
write("busy.json", { error: "server busy" });

// Witness 1 cosigned this tree head. Witness 2 cosigned only an earlier
// signing of the same tree (same size and root, another timestamp), which
// counts. Witness 3 cosigned only things that must not count: a tree head
// of the same size with another root (a fork), and this tree head's text
// with a space added, which is not canonical.
const earlier = canonicalSth({ ...head, timestamp: "2026-10-23T11:00:00.000Z" });
const fork = canonicalSth({ ...head, rootHash: forgedRoot, timestamp: "2026-10-23T11:30:00.000Z" });
const spaced = canonical.replace(":3,", ": 3,");
const cosig = (w, id, text) => ({
  witnessId: id,
  treeSize: 3,
  rootHash: root,
  timestamp: JSON.parse(text).timestamp,
  sthCanonical: text,
  signature: v2(w.privateKey, text),
  publicKeyUrl: `https://witness.example/${id}.pem`,
  receivedAt: "2026-10-23T12:00:05.000Z",
});
write("cosignatures.json", {
  treeSize: 3,
  cosignatures: [
    cosig(witnesses[0], "w1", canonical),
    cosig(witnesses[1], "w2", earlier),
    cosig(witnesses[2], "w3", fork),
    cosig(witnesses[2], "w3", spaced),
  ],
});
console.log(`wrote ${OUT.pathname}`);
```

`test/fixtures/log/README.md`:

```markdown
# Recorded log answers

What a receipts-log would answer (its `API.md`) for a log `stub-log` of three
entries, whose entry 1 is the receipt in
`test/fixtures/conformance/v2-valid-001.json`. Written by
`node scripts/make-stub-log.mjs` with throwaway Ed25519 keys whose private
halves were discarded; rerunning it writes new keys and signatures.

| File | Answer to |
|---|---|
| `sth.json` | `GET /v1/sth`, signed by `log-public-key.pem` |
| `sth-forged.json` | `GET /v1/sth`, with another root under the old signature |
| `inclusion.json` | `GET /v1/proof/inclusion` for entry 1 at size 3 |
| `inclusion-lying-root.json` | the same, with a wrong audit path and a `rootHashHex` that agrees with it |
| `not-found.json` | the 404 body for a leaf hash the log does not hold |
| `busy.json` | the 503 body when the log is at its in-flight limit |
| `cosignatures.json` | `GET /v1/cosignatures?treeSize=3`: witness 1 over `sth.json`; witness 2 over an earlier signing of the same tree (same size and root, another timestamp), which counts; witness 3 over a fork (same size, another root) and over `sth.json`'s text with a space added, neither of which counts |
| `witness-1.pem`, `witness-2.pem`, `witness-3.pem` | the witnesses' keys |
| `other-public-key.pem` | a key that signed nothing here |

The unit tests (`test/checks.test.ts`) and the Playwright tests (`e2e/`) serve
these in place of a live log, so CI never calls one.
```

```bash
node scripts/make-stub-log.mjs
ls test/fixtures/log
```

Expected: `wrote …/test/fixtures/log/`, then `README.md`, `busy.json`, `cosignatures.json`, `inclusion-lying-root.json`, `inclusion.json`, `log-public-key.pem`, `not-found.json`, `other-public-key.pem`, `sth-forged.json`, `sth.json`, `witness-1.pem`, `witness-2.pem`, `witness-3.pem`. The keys are new on every run; commit the files the run wrote, and never rerun it without committing the new files together.

- [ ] **Step 2:** write the tests:

`test/signature.test.ts`:

```ts
// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { parseV2Signature, verifyV2Text } from "../src/signature.ts";
import { LOG, keyFrom, readJson } from "./helpers.ts";

const SCHEMA_EXAMPLES = new URL("./fixtures/schemas/", import.meta.url);
const cosignature = readJson(SCHEMA_EXAMPLES, "cosignature.json") as { sthCanonical: string; signature: string };
const sth = readJson(LOG, "sth.json") as { canonical: string; signature: string };

describe("v2= signatures", () => {
  it("reads the schema example's signature as well formed, but it is not over its text", async () => {
    assert.equal(parseV2Signature(cosignature.signature).ok, true);
    const w1 = await keyFrom(LOG, "witness-1.pem");
    assert.equal(await verifyV2Text(cosignature.signature, cosignature.sthCanonical, w1.key), false);
  });

  it("verifies the stub log's tree head under its key, and not under another", async () => {
    assert.equal(await verifyV2Text(sth.signature, sth.canonical, (await keyFrom(LOG, "log-public-key.pem")).key), true);
    assert.equal(await verifyV2Text(sth.signature, sth.canonical, (await keyFrom(LOG, "other-public-key.pem")).key), false);
  });

  for (const [name, value, problem] of [
    ["nothing", undefined, "missing"],
    ["an empty string", "", "missing"],
    ["a v3= signature", "v3=AAAA.BBBB", "v3"],
    ["another prefix", "v1=AAAA", "not-v2"],
    ["URL-safe base64", "v2=-_-_", "bad-base64"],
    ["a line break", "v2=AAAA\nAAAA", "bad-base64"],
    ["non-zero padding bits", "v2=AB==", "not-canonical"],
  ] as const) {
    it(`names the problem with ${name}`, () => {
      assert.deepEqual(parseV2Signature(value), { ok: false, problem });
    });
  }
});
```

`test/tree-head.test.ts`:

```ts
// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { canonicalTreeHead, checkTreeHead } from "../src/tree-head.ts";
import { LOG, keyFrom, readJson } from "./helpers.ts";

const SCHEMA_EXAMPLES = new URL("./fixtures/schemas/", import.meta.url);
const logKey = await keyFrom(LOG, "log-public-key.pem");
const sth = readJson(LOG, "sth.json") as Record<string, unknown>;

/** The same 64 bytes in a spelling no signer writes: a non-zero padding bit. */
function respell(signature: string): string {
  const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const i = signature.length - 3;
  return signature.slice(0, i) + (B64[B64.indexOf(signature.charAt(i)) | 1] ?? "") + signature.slice(i + 1);
}

describe("checkTreeHead", () => {
  it("passes the stub log's tree head under its key", async () => {
    const r = await checkTreeHead(sth, logKey.key);
    assert.equal(r.status, "passed");
  });

  it("passes it without the optional canonical field", async () => {
    const rest = Object.fromEntries(Object.entries(sth).filter(([k]) => k !== "canonical"));
    assert.equal((await checkTreeHead(rest, logKey.key)).status, "passed");
  });

  it("fails the schema example: right shape, but its signature is not over it", async () => {
    const r = await checkTreeHead(readJson(SCHEMA_EXAMPLES, "tree-head.json"), logKey.key);
    assert.ok(r.status === "failed");
    assert.match(r.reason, /does not verify under the log key/);
  });

  for (const [name, change, reason] of [
    ["an extra field", { extra: 1 }, /does not cover: "extra"/],
    ["version 2", { v: 2 }, /not version 1/],
    ["uppercase hex", { rootHash: (sth.rootHash as string).toUpperCase() }, /64 lowercase hex/],
    ["a fractional size", { treeSize: 1.5 }, /whole number/],
    ["a size beyond 2^53 - 1", { treeSize: 2 ** 53 }, /whole number/],
    ["a timestamp without milliseconds", { timestamp: "2026-10-23T12:00:00Z" }, /timestamp/],
    ["a canonical that is not its fields", { canonical: "{}" }, /canonical text does not match/],
    ["a non-canonical signature spelling", { signature: respell(sth.signature as string) }, /well-formed v2=/],
  ] as const) {
    it(`fails a tree head with ${name}`, async () => {
      const r = await checkTreeHead({ ...sth, ...change }, logKey.key);
      assert.ok(r.status === "failed");
      assert.match(r.reason, reason);
    });
  }

  it("does not run on a v3= tree head, rather than failing it", async () => {
    const r = await checkTreeHead({ ...sth, signature: "v3=AAAA.BBBB" }, logKey.key);
    assert.equal(r.status, "not-run");
  });

  it("fails anything that is not an object", async () => {
    for (const v of [null, [], "sth", 3]) assert.equal((await checkTreeHead(v, logKey.key)).status, "failed");
  });
});

describe("canonicalTreeHead", () => {
  const text = sth.canonical as string;
  it("reads the canonical text of a tree head", () => {
    assert.deepEqual(canonicalTreeHead(text), { v: 1, logId: "stub-log", treeSize: 3, rootHash: sth.rootHash, timestamp: sth.timestamp });
  });
  for (const [name, changed] of [
    ["a space added", text.replace(":3,", ": 3,")],
    ["keys in another order", JSON.stringify({ v: 1, logId: "stub-log", rootHash: sth.rootHash, timestamp: sth.timestamp, treeSize: 3 })],
    ["an extra field", text.replace('"v":1}', '"v":1,"x":0}')],
    ["uppercase hex", text.replace(sth.rootHash as string, (sth.rootHash as string).toUpperCase())],
    ["text that is not JSON", "{"],
  ] as const) {
    it(`rejects ${name}`, () => {
      assert.equal(canonicalTreeHead(changed), undefined);
    });
  }
});
```

- [ ] **Step 3:** run `npm test`. Expected: fails, `ERR_MODULE_NOT_FOUND` for `src/signature.ts`.
- [ ] **Step 4:** write the code:

`src/signature.ts`:

```ts
// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

// The v2= signature wire format (docs/specs/vaos-2.0.md section 7):
// "v2=" and the standard, padded base64 of a 64-byte Ed25519 signature,
// in its one valid spelling. Used for receipts, tree heads and
// cosignatures.
import { ed25519Verify, fromBase64, toBase64, utf8 } from "./bytes.ts";

const STANDARD_BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export type ParsedSignature =
  | { ok: true; bytes: Uint8Array<ArrayBuffer> }
  | { ok: false; problem: "missing" | "v3" | "not-v2" | "bad-base64" | "not-canonical" };

export function parseV2Signature(signature: unknown): ParsedSignature {
  if (typeof signature !== "string" || signature === "") return { ok: false, problem: "missing" };
  if (signature.startsWith("v3=")) return { ok: false, problem: "v3" };
  if (!signature.startsWith("v2=")) return { ok: false, problem: "not-v2" };
  const body = signature.slice(3);
  if (!STANDARD_BASE64.test(body)) return { ok: false, problem: "bad-base64" };
  const bytes = fromBase64(body);
  if (toBase64(bytes) !== body) return { ok: false, problem: "not-canonical" };
  return { ok: true, bytes };
}

/** True iff `signature` is a well-spelled v2= signature over the UTF-8 bytes of `text` under `key`. */
export async function verifyV2Text(signature: unknown, text: string, key: CryptoKey): Promise<boolean> {
  const parsed = parseV2Signature(signature);
  return parsed.ok && (await ed25519Verify(key, parsed.bytes, utf8(text)));
}
```

`src/tree-head.ts`:

```ts
// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

// Checks a signed tree head from a log: the shape that
// schemas/tree-head.schema.json (verifiable-receipts) states, the canonical
// text rebuilt from the fields, and the log's v2= signature over it.
import { verifyV2Text, parseV2Signature } from "./signature.ts";
import { canonicalizeSth, isCount, isHashHex, type SignedTreeHead } from "./vendor/verifiable-receipts/transparency.ts";

const FIELDS = new Set(["v", "logId", "treeSize", "rootHash", "timestamp", "signature", "canonical"]);
const TIMESTAMP = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/;

export type TreeHeadCheck =
  | { status: "passed"; sth: Required<SignedTreeHead>; canonical: string }
  | { status: "failed" | "not-run"; reason: string };

function isObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/**
 * The tree head that `text` is the canonical text of: it must parse to
 * exactly v, logId, treeSize, rootHash and timestamp, each well formed, and
 * be byte for byte the text canonicalizeSth rebuilds from them. Used for
 * the text a cosignature covers, which is never trusted as sent.
 */
export function canonicalTreeHead(text: string): Omit<SignedTreeHead, "signature"> | undefined {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return undefined;
  }
  if (!isObject(value)) return undefined;
  const { v, logId, treeSize, rootHash, timestamp } = value;
  if (v !== 1 || typeof logId !== "string" || logId === "" || !isCount(treeSize) || !isHashHex(rootHash)) return undefined;
  if (typeof timestamp !== "string" || !TIMESTAMP.test(timestamp)) return undefined;
  const fields = { v, logId, treeSize, rootHash, timestamp } as const;
  return canonicalizeSth(fields) === text ? fields : undefined;
}

/** Checks `value`, a log's answer to GET /v1/sth, against the log's key. */
export async function checkTreeHead(value: unknown, logKey: CryptoKey): Promise<TreeHeadCheck> {
  if (!isObject(value)) return { status: "failed", reason: "The log's answer is not a tree head: it is not a JSON object." };
  for (const field of Object.keys(value)) {
    if (!FIELDS.has(field)) {
      return { status: "failed", reason: `The tree head has a field its signature does not cover: "${field}".` };
    }
  }
  const { v, logId, treeSize, rootHash, timestamp, signature, canonical } = value;
  if (v !== 1) return { status: "failed", reason: "The tree head is not version 1." };
  if (typeof logId !== "string" || logId === "") return { status: "failed", reason: "The tree head has no logId." };
  if (!isCount(treeSize)) return { status: "failed", reason: "The tree head's treeSize is not a whole number from 0 to 2^53 − 1." };
  if (!isHashHex(rootHash)) return { status: "failed", reason: "The tree head's rootHash is not 64 lowercase hex digits." };
  if (typeof timestamp !== "string" || !TIMESTAMP.test(timestamp)) {
    return { status: "failed", reason: "The tree head's timestamp is not in the form 2026-10-23T12:00:00.000Z." };
  }
  const parsed = parseV2Signature(signature);
  if (!parsed.ok) {
    if (parsed.problem === "v3") {
      return {
        status: "not-run",
        reason: "This log signs its tree heads with v3= (Ed25519 and ML-DSA-65), which this page cannot check yet. Use the verifiable-receipts library to check it.",
      };
    }
    return { status: "failed", reason: "The tree head's signature is missing or is not a well-formed v2= signature." };
  }
  const rebuilt = canonicalizeSth({ v, logId, treeSize, rootHash, timestamp });
  if (canonical !== undefined && canonical !== rebuilt) {
    return { status: "failed", reason: "The tree head's canonical text does not match its own fields." };
  }
  if (typeof signature !== "string" || !(await verifyV2Text(signature, rebuilt, logKey))) {
    return {
      status: "failed",
      reason: "The tree head's signature does not verify under the log key you gave. Check that you have this log's key, not the issuer's.",
    };
  }
  return { status: "passed", sth: { v, logId, treeSize, rootHash, timestamp, signature }, canonical: rebuilt };
}
```

- [ ] **Step 5:** run the whole check:

```bash
npm run typecheck && npx eslint . && npm test 2>&1 | grep -E '^# (pass|fail)'
```

Expected: `# pass 65`, `# fail 0`.

- [ ] **Step 6:** commit:

```bash
gitleaks git --pre-commit --staged --no-banner   # expect: no leaks found
git commit --author="$A" -m "Tree heads: shape, canonical text and the log's v2= signature" -m "A tree head passes only with the fields its signature covers, in the shape schemas/tree-head.schema.json states, its canonical text rebuilt from them, and a v2= signature under the log key the visitor gave; a v3= tree head is not run. Recorded answers of a three-entry log, with throwaway keys, stand in for a live log in every test." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 6: the log client and the receipt input

**Files:**
- Create: `test/log-client.test.ts`, `test/input.test.ts`, `src/log-client.ts`, `src/input.ts`

- [ ] **Step 1:** write the tests:

`test/log-client.test.ts`:

```ts
// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { LogClient, logError, type Fetcher } from "../src/log-client.ts";

const BASE = new URL("https://example.org/log/");

function answering(body: string, status = 200, seen: { url: string; init: RequestInit }[] = []): Fetcher {
  return (url, init) => {
    seen.push({ url, init });
    return Promise.resolve(new Response(body, { status }));
  };
}

describe("LogClient", () => {
  it("asks with GET only, no credentials, no referrer, no cache and no redirects, under the base path", async () => {
    const seen: { url: string; init: RequestInit }[] = [];
    const client = new LogClient(BASE, answering("{}", 200, seen));
    await client.sth();
    await client.inclusion("ab".repeat(32), 7);
    await client.cosignatures(7);
    assert.deepEqual(
      seen.map((s) => s.url),
      [
        "https://example.org/log/v1/sth",
        `https://example.org/log/v1/proof/inclusion?leafHash=${"ab".repeat(32)}&treeSize=7`,
        "https://example.org/log/v1/cosignatures?treeSize=7",
      ],
    );
    for (const { init } of seen) {
      assert.equal(init.method, "GET");
      assert.equal(init.credentials, "omit");
      assert.equal(init.referrerPolicy, "no-referrer");
      assert.equal(init.cache, "no-store");
      assert.equal(init.redirect, "error");
      assert.equal(init.mode, "cors");
      assert.ok(init.signal instanceof AbortSignal);
    }
  });

  it("reports a request that does not complete as a network error", async () => {
    const client = new LogClient(BASE, () => Promise.reject(new TypeError("Failed to fetch")));
    const answer = await client.sth();
    assert.ok(answer.kind === "network");
    assert.match(answer.detail, /Could not reach the log at example\.org/);
  });

  it("gives the status and the parsed body, or no body when it is not JSON or too long", async () => {
    assert.deepEqual(await new LogClient(BASE, answering('{"error":"busy"}', 503)).sth(), { kind: "answer", status: 503, body: { error: "busy" } });
    assert.deepEqual(await new LogClient(BASE, answering("<html>", 200)).sth(), { kind: "answer", status: 200, body: undefined });
    assert.deepEqual(await new LogClient(BASE, answering(`"${"x".repeat(1_000_001)}"`, 200)).sth(), { kind: "answer", status: 200, body: undefined });
  });

  it("quotes the log's error text, cut to 200 characters", () => {
    assert.equal(logError({ error: "leaf hash not in the log" }), "leaf hash not in the log");
    assert.equal(logError({ error: "x".repeat(300) }).length, 200);
    assert.equal(logError(undefined), "no reason given");
  });
});
```

`test/input.test.ts`:

```ts
// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { MAX_RECEIPTS, parseReceipts } from "../src/input.ts";
import { parseLogAddress } from "../src/log-client.ts";

describe("parseReceipts", () => {
  it("reads one receipt as a list of one", () => {
    assert.deepEqual(parseReceipts('{"canonical":"{}"}'), { ok: true, receipts: [{ canonical: "{}" }] });
  });
  it("reads an array as its receipts", () => {
    const r = parseReceipts("[{}, {}]");
    assert.ok(r.ok && r.receipts.length === 2);
  });
  for (const [name, text, reason] of [
    ["empty text", "  ", /Paste a receipt/],
    ["text that is not JSON", "{canonical:", /not valid JSON/],
    ["an empty list", "[]", /empty list/],
    ["too many receipts", JSON.stringify(Array.from({ length: MAX_RECEIPTS + 1 }, () => ({}))), /up to 1000/],
  ] as const) {
    it(`explains ${name}`, () => {
      const r = parseReceipts(text);
      assert.ok(!r.ok && reason.test(r.reason));
    });
  }
});

describe("parseLogAddress", () => {
  it("adds the trailing slash, so /v1/ routes resolve under a path", () => {
    const r = parseLogAddress(" https://example.org/log ");
    assert.ok(r.ok);
    assert.equal(new URL("v1/sth", r.base).href, "https://example.org/log/v1/sth");
  });
  for (const [text, reason] of [
    ["log.example.org", /not a web address/],
    ["http://log.example.org", /must start with https/],
    ["https://user:pw@log.example.org", /user name or password/],
    ["https://log.example.org/?x=1", /must not contain \? or #/],
  ] as const) {
    it(`rejects ${text}`, () => {
      const r = parseLogAddress(text);
      assert.ok(!r.ok && reason.test(r.reason));
    });
  }
});
```

- [ ] **Step 2:** run `npm test`. Expected: fails, `ERR_MODULE_NOT_FOUND` for `src/log-client.ts`.
- [ ] **Step 3:** write the code:

`src/log-client.ts`:

```ts
// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

// The only code that reaches the network: GET requests to the receipts-log
// address the visitor typed, with no credentials, no referrer and no cache.
// A request that does not complete is a network error, never a verdict.
// receipts-log sends its CORS header on every answer from a read route,
// its own 503 (busy), 414 and 500 included (receipts-log PR #13), so those
// arrive here as answers with a status, not as network errors.

export type Fetcher = (url: string, init: RequestInit) => Promise<Response>;

export type LogAnswer =
  | { kind: "answer"; status: number; body: unknown }
  | { kind: "network"; detail: string };

const MAX_BODY_CHARS = 1_000_000;

export type LogAddress = { ok: true; base: URL } | { ok: false; reason: string };

/** Reads the address the visitor typed: https only, no credentials, query or fragment. */
export function parseLogAddress(text: string): LogAddress {
  let url: URL;
  try {
    url = new URL(text.trim());
  } catch {
    return { ok: false, reason: "The log address is not a web address. Type it in full, starting with https://." };
  }
  if (url.protocol !== "https:") return { ok: false, reason: "The log address must start with https://." };
  if (url.username !== "" || url.password !== "") {
    return { ok: false, reason: "The log address must not contain a user name or password." };
  }
  if (url.search !== "" || url.hash !== "") {
    return { ok: false, reason: "The log address must not contain ? or #. Give the address the log's /v1/ routes are under." };
  }
  if (!url.pathname.endsWith("/")) url.pathname += "/";
  return { ok: true, base: url };
}

export class LogClient {
  readonly base: URL;
  readonly #fetch: Fetcher;
  readonly #timeoutMs: number;

  constructor(base: URL, fetcher: Fetcher = (url, init) => fetch(url, init), timeoutMs = 15_000) {
    this.base = base;
    this.#fetch = fetcher;
    this.#timeoutMs = timeoutMs;
  }

  sth(): Promise<LogAnswer> {
    return this.#get("v1/sth");
  }

  inclusion(leafHashHex: string, treeSize: number): Promise<LogAnswer> {
    return this.#get(`v1/proof/inclusion?leafHash=${leafHashHex}&treeSize=${String(treeSize)}`);
  }

  cosignatures(treeSize: number): Promise<LogAnswer> {
    return this.#get(`v1/cosignatures?treeSize=${String(treeSize)}`);
  }

  async #get(path: string): Promise<LogAnswer> {
    const url = new URL(path, this.base).href;
    let response: Response;
    let text: string;
    try {
      response = await this.#fetch(url, {
        method: "GET",
        mode: "cors",
        credentials: "omit",
        cache: "no-store",
        redirect: "error",
        referrerPolicy: "no-referrer",
        signal: AbortSignal.timeout(this.#timeoutMs),
      });
      text = await response.text();
    } catch {
      return {
        kind: "network",
        detail: `Could not reach the log at ${this.base.host}. It may be down or busy, or the address may be wrong. Check the address and try again.`,
      };
    }
    if (text.length > MAX_BODY_CHARS) return { kind: "answer", status: response.status, body: undefined };
    let body: unknown;
    try {
      body = JSON.parse(text);
    } catch {
      body = undefined;
    }
    return { kind: "answer", status: response.status, body };
  }
}

/** The log's own error text, when its answer has one. */
export function logError(body: unknown): string {
  if (body !== null && typeof body === "object" && "error" in body && typeof body.error === "string") {
    return body.error.slice(0, 200);
  }
  return "no reason given";
}
```

`src/input.ts`:

```ts
// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

// Reads what the visitor pasted or dropped as the receipt: one receipt (a
// JSON object) or an array of them. Never throws; a problem comes back as
// a sentence that says what to do.

export const MAX_INPUT_CHARS = 5_000_000;
export const MAX_RECEIPTS = 1000;

export type ParsedReceipts = { ok: true; receipts: unknown[] } | { ok: false; reason: string };

export function parseReceipts(text: string): ParsedReceipts {
  if (text.trim() === "") return { ok: false, reason: "Paste a receipt, or choose a receipt file." };
  if (text.length > MAX_INPUT_CHARS) {
    return { ok: false, reason: "The receipt text is longer than 5 million characters. Check one file of receipts at a time." };
  }
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return { ok: false, reason: "The receipt is not valid JSON. Paste the whole file, from the first { to the last }." };
  }
  if (Array.isArray(value)) {
    if (value.length === 0) return { ok: false, reason: "The file holds an empty list. Choose a file with at least one receipt." };
    if (value.length > MAX_RECEIPTS) {
      return { ok: false, reason: `The file holds ${String(value.length)} receipts; this page checks up to ${String(MAX_RECEIPTS)} at a time. Split the file.` };
    }
    return { ok: true, receipts: value };
  }
  return { ok: true, receipts: [value] };
}
```

- [ ] **Step 4:** run the whole check:

```bash
npm run typecheck && npx eslint . && npm test 2>&1 | grep -E '^# (pass|fail)'
```

Expected: `# pass 80`, `# fail 0`.

- [ ] **Step 5:** commit:

```bash
gitleaks git --pre-commit --staged --no-banner   # expect: no leaks found
git commit --author="$A" -m "Log client: GET only, no credentials, network errors are not verdicts" -m "src/log-client.ts is the only code that makes requests: GET to the https address the visitor typed, with no credentials, referrer, cache or redirects, and a 15 s timeout. A request that does not complete is a network error; an answer, 503 included, comes back with its status. Receipt text is read as one receipt or a list of up to 1000." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 7: the seven checks

**Files:**
- Create: `test/stub-log.ts`, `test/checks.test.ts`, `src/checks.ts`

- [ ] **Step 1:** write the stubbed log and the tests:

`test/stub-log.ts`:

```ts
// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

// A stand-in for a live receipts-log: answers from test/fixtures/log.
import type { Fetcher } from "../src/log-client.ts";
import { LOG, readText } from "./helpers.ts";

export const LOG_BASE = new URL("https://log.test/");

export interface StubAnswer {
  status: number;
  /** A file in test/fixtures/log, served as the body. */
  file?: string;
}

/**
 * A fetch that answers from test/fixtures/log by path and query, and
 * fails like an unreachable host for anything it does not know.
 * `requests` records every URL asked for.
 */
export function stubLog(routes: Record<string, StubAnswer | "unreachable">, requests: string[] = []): Fetcher {
  return (url, init) => {
    requests.push(`${init.method ?? "GET"} ${url}`);
    const u = new URL(url);
    const answer = routes[u.pathname + u.search] ?? "unreachable";
    if (answer === "unreachable") return Promise.reject(new TypeError("Failed to fetch"));
    const body = answer.file === undefined ? "" : readText(LOG, answer.file);
    return Promise.resolve(new Response(body, { status: answer.status, headers: { "Content-Type": "application/json" } }));
  };
}
```

`test/checks.test.ts`:

```ts
// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

// The seven checks against the conformance receipts and a stubbed log
// (test/fixtures/log, written by scripts/make-stub-log.mjs). No test
// reaches the network.
import assert from "node:assert/strict";
import { readdirSync } from "node:fs";
import { describe, it } from "node:test";

import { checkOffline, checkReceipts, type CheckResult, type Inputs, type ReceiptReport } from "../src/checks.ts";
import { LogClient } from "../src/log-client.ts";
import { leafHash } from "../src/vendor/verifiable-receipts/transparency.ts";
import { CONFORMANCE, LOG, fixtureReceipt, keyFrom, readJson } from "./helpers.ts";
import { LOG_BASE, stubLog, type StubAnswer } from "./stub-log.ts";

const valid = fixtureReceipt("v2-valid-001.json") as { canonical: string };
const LEAF = await leafHash(valid.canonical);
const INCLUSION = `/v1/proof/inclusion?leafHash=${LEAF}&treeSize=3`;
const GOOD: Record<string, StubAnswer> = {
  "/v1/sth": { status: 200, file: "sth.json" },
  [INCLUSION]: { status: 200, file: "inclusion.json" },
  "/v1/cosignatures?treeSize=3": { status: 200, file: "cosignatures.json" },
};

const issuer = await keyFrom(CONFORMANCE, "public-key.pem");
const logKey = await keyFrom(LOG, "log-public-key.pem");
const witnesses = [await keyFrom(LOG, "witness-1.pem"), await keyFrom(LOG, "witness-2.pem"), await keyFrom(LOG, "witness-3.pem")];

function inputs(routes: Record<string, StubAnswer | "unreachable"> | undefined, requests: string[] = []): Inputs {
  if (routes === undefined) return { issuerKeys: [issuer], log: undefined };
  return { issuerKeys: [issuer], log: { client: new LogClient(LOG_BASE, stubLog(routes, requests)), logKey, witnessKeys: witnesses } };
}

async function one(receipt: unknown, i: Inputs): Promise<ReceiptReport> {
  const [report] = await checkReceipts([receipt], i);
  assert.ok(report);
  return report;
}

function statuses(report: ReceiptReport): string[] {
  return report.checks.map((c) => `${c.id}:${c.status}`);
}

function check(report: ReceiptReport, id: CheckResult["id"]): CheckResult {
  const c = report.checks.find((x) => x.id === id);
  assert.ok(c, id);
  return c;
}

describe("checks 1 to 4 on the conformance receipts", () => {
  for (const name of readdirSync(CONFORMANCE).filter((f) => f.startsWith("v2-")).sort()) {
    it(`${name}: all pass, or the content hash is not run, exactly when the fixture is valid`, async () => {
      const fixture = readJson(CONFORMANCE, name) as { receipt: unknown; expected: { ok: boolean } };
      const report = await checkOffline(fixture.receipt, [issuer]);
      assert.equal(report.valid, fixture.expected.ok);
      const offlineOk = report.checks.every((c) => c.status === "passed" || (c.id === "content-hash" && c.status === "not-run"));
      assert.equal(offlineOk, fixture.expected.ok, JSON.stringify(report.checks));
    });
  }
});

describe("checks without a log", () => {
  it("a valid receipt passes 1 to 4; 5 to 7 are not run", async () => {
    const r = await one(valid, inputs(undefined));
    assert.deepEqual(statuses(r), [
      "format:passed",
      "signature:passed",
      "content-hash:passed",
      "repeated-fields:passed",
      "tree-head:not-run",
      "in-log:not-run",
      "witnesses:not-run",
    ]);
    assert.equal(r.valid, true);
    assert.equal(r.key, issuer.fingerprint);
    assert.match(check(r, "signature").detail, new RegExp(issuer.fingerprint));
    assert.equal(r.action?.overall, "pass");
  });

  it("a tampered receipt fails the signature and the content hash, and is not compared", async () => {
    const r = await one(fixtureReceipt("v2-invalid-tampered.json"), inputs(undefined));
    assert.equal(check(r, "signature").status, "failed");
    assert.match(check(r, "signature").detail, /issuer's key, not the log's/);
    assert.equal(check(r, "content-hash").status, "failed");
    assert.equal(check(r, "repeated-fields").status, "not-run");
    assert.equal(r.action, undefined);
    assert.equal(r.valid, false);
  });

  it("a null contentHash is valid, and check 3 is not run; an empty one fails check 3", async () => {
    const nul = await one(fixtureReceipt("v2-valid-null-contenthash.json"), inputs(undefined));
    assert.equal(nul.valid, true);
    assert.equal(check(nul, "content-hash").status, "not-run");
    const empty = await one(fixtureReceipt("v2-invalid-empty-contenthash.json"), inputs(undefined));
    assert.equal(empty.valid, false);
    assert.equal(check(empty, "content-hash").status, "failed");
    assert.match(check(empty, "content-hash").detail, /The contentHash is empty/);
  });

  it("a repeated field that disagrees names the field and both values", async () => {
    const r = await one(fixtureReceipt("v2-invalid-envelope-disagrees.json"), inputs(undefined));
    const c = check(r, "repeated-fields");
    assert.equal(c.status, "failed");
    assert.match(c.detail, /"overall" says "fail" beside the signed text, but the signed text says "pass"/);
  });

  it("no issuer key: the signature is not run, never passed", async () => {
    const [r] = await checkReceipts([valid], { issuerKeys: [], log: undefined });
    assert.ok(r);
    assert.equal(check(r, "signature").status, "not-run");
    assert.equal(r.valid, false);
  });

  it("an array is checked receipt by receipt", async () => {
    const reports = await checkReceipts([valid, fixtureReceipt("v2-invalid-wrong-key.json")], inputs(undefined));
    assert.deepEqual(
      reports.map((r) => r.valid),
      [true, false],
    );
  });
});

describe("checks with a stubbed log", () => {
  it("every check passes against an honest log, with 2 of 3 witnesses", async () => {
    const requests: string[] = [];
    const r = await one(valid, inputs(GOOD, requests));
    assert.ok(r.checks.every((c) => c.status === "passed"), JSON.stringify(r.checks));
    assert.match(check(r, "in-log").detail, /^Entry 1 of 3 in the log stub-log/);
    assert.match(check(r, "witnesses").detail, /^2 of 3 witnesses cosigned/);
    assert.ok(requests.every((x) => x.startsWith("GET https://log.test/")), requests.join("\n"));
    assert.equal(requests.length, 3);
  });

  it("an unreachable log is a network error: not run, never failed", async () => {
    const r = await one(valid, inputs({}));
    for (const id of ["tree-head", "in-log", "witnesses"] as const) assert.equal(check(r, id).status, "not-run");
    assert.equal(check(r, "tree-head").network, true);
    assert.equal(check(r, "tree-head").retry, true);
    assert.match(check(r, "tree-head").detail, /Could not reach the log at log\.test/);
  });

  it("a forged tree head fails check 5, and 6 and 7 are not run", async () => {
    const r = await one(valid, inputs({ ...GOOD, "/v1/sth": { status: 200, file: "sth-forged.json" } }));
    assert.equal(check(r, "tree-head").status, "failed");
    assert.equal(check(r, "in-log").status, "not-run");
    assert.equal(check(r, "witnesses").status, "not-run");
  });

  it("the wrong log key fails the tree head", async () => {
    const other = await keyFrom(LOG, "other-public-key.pem");
    const i = inputs(GOOD);
    assert.ok(i.log);
    const [r] = await checkReceipts([valid], { ...i, log: { ...i.log, logKey: other } });
    assert.ok(r);
    assert.match(check(r, "tree-head").detail, /does not verify under the log key you gave/);
  });

  it("a proof whose own rootHashHex agrees with it, but the signed root does not, fails", async () => {
    const r = await one(valid, inputs({ ...GOOD, [INCLUSION]: { status: 200, file: "inclusion-lying-root.json" } }));
    assert.equal(check(r, "in-log").status, "failed");
    assert.match(check(r, "in-log").detail, /does not lead to the root in its signed tree head/);
  });

  it("a receipt the log does not hold fails check 6", async () => {
    const r = await one(valid, inputs({ ...GOOD, [INCLUSION]: { status: 404, file: "not-found.json" } }));
    assert.equal(check(r, "in-log").status, "failed");
  });

  it("a log that is busy (503) on the proof: check 6 is not run, and can be retried", async () => {
    const r = await one(valid, inputs({ ...GOOD, [INCLUSION]: { status: 503, file: "busy.json" } }));
    assert.equal(check(r, "tree-head").status, "passed");
    const c = check(r, "in-log");
    assert.deepEqual([c.status, c.network, c.retry], ["not-run", false, true]);
    assert.match(c.detail, /busy or failing \(it answered 503: server busy\)/);
  });

  it("a 400 from the log is not run, and not offered as a retry", async () => {
    const r = await one(valid, inputs({ ...GOOD, "/v1/sth": { status: 400, file: "not-found.json" } }));
    const c = check(r, "tree-head");
    assert.deepEqual([c.status, c.retry], ["not-run", false]);
  });

  it("no log key: checks 5 to 7 are not run, and the log is not asked", async () => {
    const requests: string[] = [];
    const i = inputs(GOOD, requests);
    assert.ok(i.log);
    const [r] = await checkReceipts([valid], { ...i, log: { ...i.log, logKey: undefined } });
    assert.ok(r);
    assert.match(check(r, "tree-head").detail, /a key fetched from the log proves nothing/);
    assert.equal(requests.length, 0);
  });

  it("witness 2 cosigned an earlier signing of the same size and root, with another timestamp: it counts", async () => {
    const i = inputs(GOOD);
    assert.ok(i.log);
    const w2 = witnesses[1];
    assert.ok(w2);
    const [r] = await checkReceipts([valid], { ...i, log: { ...i.log, witnessKeys: [w2] } });
    assert.ok(r);
    assert.equal(check(r, "witnesses").status, "passed");
    assert.match(check(r, "witnesses").detail, /^1 of 1 witnesses cosigned a tree head of the log stub-log with 3 entries and this root: sha256:/);
  });

  it("only witness 3, which cosigned a fork and a non-canonical text: check 7 fails", async () => {
    const i = inputs(GOOD);
    assert.ok(i.log);
    const w3 = witnesses[2];
    assert.ok(w3);
    const [r] = await checkReceipts([valid], { ...i, log: { ...i.log, witnessKeys: [w3] } });
    assert.ok(r);
    assert.equal(check(r, "witnesses").status, "failed");
  });

  it("a cosignature's signature must be over its own text: witness 1's, moved onto witness 2's text, does not count", async () => {
    const i = inputs(GOOD);
    assert.ok(i.log);
    const w1 = witnesses[0];
    assert.ok(w1);
    const listed = readJson(LOG, "cosignatures.json") as { cosignatures: { sthCanonical: string; signature: string }[] };
    const [first, second] = listed.cosignatures;
    assert.ok(first && second);
    const swapped = JSON.stringify({ treeSize: 3, cosignatures: [{ ...second, signature: first.signature }] });
    const fetcher = (): Promise<Response> => Promise.resolve(new Response(swapped, { status: 200 }));
    const base = stubLog(GOOD);
    const client = new LogClient(LOG_BASE, (url, init) => (url.includes("/v1/cosignatures") ? fetcher() : base(url, init)));
    const [r] = await checkReceipts([valid], { ...i, log: { ...i.log, client, witnessKeys: [w1] } });
    assert.ok(r);
    assert.equal(check(r, "witnesses").status, "failed");
  });

  it("the log is asked for one tree head and one list of cosignatures for many receipts", async () => {
    const requests: string[] = [];
    await checkReceipts([valid, valid, valid], inputs(GOOD, requests));
    assert.equal(requests.filter((x) => x.endsWith("/v1/sth")).length, 1);
    assert.equal(requests.filter((x) => x.includes("/v1/cosignatures")).length, 1);
  });
});
```

- [ ] **Step 2:** run `npm test`. Expected: fails, `ERR_MODULE_NOT_FOUND` for `src/checks.ts`.
- [ ] **Step 3:** write the checks:

`src/checks.ts`:

```ts
// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

// The seven checks, in order. Each result is passed, failed or not run;
// a check that cannot run (no key, no log address, the log unreachable)
// is never shown as passed, and a network error is never a verdict.
// Checks 1 to 4 agree with the vendored verifier: a receipt passes all
// four exactly when verifyV2Receipt accepts it (test/checks.test.ts).
import { sha256Hex, utf8, ed25519Verify } from "./bytes.ts";
import type { PublicKey } from "./keys.ts";
import { logError, type LogClient } from "./log-client.ts";
import { parseV2Signature, verifyV2Text } from "./signature.ts";
import { canonicalTreeHead, checkTreeHead, type TreeHeadCheck } from "./tree-head.ts";
import { jsonEqual, verifyV2Receipt } from "./vendor/verifiable-receipts/receipt.ts";
import { leafHash, verifyInclusionProof } from "./vendor/verifiable-receipts/transparency.ts";

export type Status = "passed" | "failed" | "not-run";
export type CheckId = "format" | "signature" | "content-hash" | "repeated-fields" | "tree-head" | "in-log" | "witnesses";

export interface CheckResult {
  id: CheckId;
  status: Status;
  /** One sentence on this result: what passed, or what is wrong and what to do. */
  detail: string;
  /** True when the check did not run because a request to the log did not complete. */
  network: boolean;
  /** True when asking the log again may give an answer: a network error, or the log was busy or failing (5xx). */
  retry: boolean;
}

export interface RepeatedField {
  field: string;
  beside: unknown;
  signed: unknown;
  same: boolean;
}

export interface ReceiptReport {
  checks: CheckResult[];
  /** The vendored verifier's verdict, and the fingerprint of the key it passed under. */
  valid: boolean;
  key: string | undefined;
  /** The signed canonical, parsed; present only when the signature verified. */
  action: Record<string, unknown> | undefined;
  repeated: RepeatedField[];
}

export interface LogInputs {
  client: LogClient;
  logKey: PublicKey | undefined;
  witnessKeys: readonly PublicKey[];
}

export interface Inputs {
  issuerKeys: readonly PublicKey[];
  log: LogInputs | undefined;
}

const ENVELOPE_ONLY = new Set(["canonical", "contentHash", "signature"]);

function isObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function result(id: CheckId, status: Status, detail: string, network = false, retry = network): CheckResult {
  return { id, status, detail, network, retry };
}

/** Check `id` not run because the log answered `status` instead of 200; 5xx answers can be retried. */
function logAnswered(id: CheckId, status: number, body: unknown): CheckResult {
  if (status >= 500) {
    return result(id, "not-run", `Not run: the log is busy or failing (it answered ${String(status)}: ${logError(body)}). Try again in a minute.`, false, true);
  }
  return result(id, "not-run", `Not run: the log answered ${String(status)} (${logError(body)}). Check the log address.`);
}

/** A JSON value for a message: compact, and cut to 120 characters. */
export function show(value: unknown): string {
  const text = value === undefined ? "nothing" : JSON.stringify(value);
  return text.length > 120 ? text.slice(0, 117) + "..." : text;
}

function formatCheck(receipt: unknown): CheckResult {
  const id = "format";
  if (!isObject(receipt)) {
    return result(id, "failed", "This is not a receipt: a receipt is a JSON object with canonical and signature fields. Check that you pasted the receipt, not a key or a tree head.");
  }
  if (typeof receipt.canonical !== "string" || receipt.canonical === "") {
    return result(id, "failed", "The receipt has no canonical text, so there is nothing to check. Check that the file is a whole receipt.");
  }
  const parsed = parseV2Signature(receipt.signature);
  if (parsed.ok) return result(id, "passed", "A v2 receipt, with its signature in the one valid spelling.");
  switch (parsed.problem) {
    case "missing":
      return result(id, "failed", "The receipt has no signature. Check that the file is a whole receipt.");
    case "v3":
      return result(id, "failed", "This is a v3 receipt (Ed25519 and ML-DSA-65). This page checks v2 receipts; use the verifiable-receipts library for v3.");
    case "not-v2":
      return result(id, "failed", "The signature does not start with v2=, so this is not a v2 receipt.");
    case "bad-base64":
      return result(id, "failed", "The signature is not valid base64 after v2=. A copy that broke the line or dropped characters causes this; copy the receipt again.");
    case "not-canonical":
      return result(id, "failed", "The signature is spelled in a way no signer writes (non-zero padding bits). The bytes may be right, but the receipt was edited; get the original.");
  }
}

async function signatureCheck(receipt: unknown, format: CheckResult, keys: readonly PublicKey[]): Promise<{ check: CheckResult; key: string | undefined }> {
  const id = "signature";
  if (format.status !== "passed" || !isObject(receipt) || typeof receipt.canonical !== "string") {
    return { check: result(id, "not-run", "Not run: the receipt's format is wrong."), key: undefined };
  }
  if (keys.length === 0) {
    return { check: result(id, "not-run", "Not run: give the issuer's public key to check the signature."), key: undefined };
  }
  const parsed = parseV2Signature(receipt.signature);
  if (!parsed.ok) return { check: result(id, "not-run", "Not run: the receipt's format is wrong."), key: undefined };
  for (const k of keys) {
    if (await ed25519Verify(k.key, parsed.bytes, utf8(receipt.canonical))) {
      return { check: result(id, "passed", `Signed by the key ${k.fingerprint}.`), key: k.fingerprint };
    }
  }
  const tried = keys.map((k) => k.fingerprint).join(", ");
  return {
    check: result(id, "failed", `This key does not match the signature (tried ${tried}). Check that you have the issuer's key, not the log's, and that nobody changed the canonical text.`),
    key: undefined,
  };
}

async function contentHashCheck(receipt: unknown): Promise<CheckResult> {
  const id = "content-hash";
  if (!isObject(receipt) || typeof receipt.canonical !== "string" || receipt.canonical === "") {
    return result(id, "not-run", "Not run: the receipt has no canonical text.");
  }
  const { contentHash } = receipt;
  if (contentHash === undefined || contentHash === null) {
    return result(id, "not-run", "Not run: the receipt has no contentHash. The signature covers the text on its own.");
  }
  if (contentHash === "") {
    return result(id, "failed", "The contentHash is empty. A receipt either has no contentHash or has the hash of its signed text; this one was edited, so get the original.");
  }
  if (typeof contentHash !== "string") return result(id, "failed", "The contentHash is not text, so it cannot be a hash. The receipt was edited; get the original.");
  const actual = await sha256Hex(utf8(receipt.canonical));
  if (actual === contentHash.replace(/^sha256:/, "")) return result(id, "passed", `The SHA-256 of the signed text is ${actual}.`);
  return result(id, "failed", `The contentHash does not match the signed text: the text hashes to ${actual}. The text or the hash was changed after signing.`);
}

function repeatedFieldsCheck(receipt: unknown, signature: CheckResult): { check: CheckResult; action: Record<string, unknown> | undefined; repeated: RepeatedField[] } {
  const id = "repeated-fields";
  if (signature.status !== "passed" || !isObject(receipt) || typeof receipt.canonical !== "string") {
    return { check: result(id, "not-run", "Not run: the signature did not verify, so the signed text cannot be trusted to compare against."), action: undefined, repeated: [] };
  }
  let signed: unknown;
  try {
    signed = JSON.parse(receipt.canonical);
  } catch {
    return { check: result(id, "failed", "The signed text is not valid JSON, so no field can be compared. The issuer signed something that is not a receipt."), action: undefined, repeated: [] };
  }
  if (!isObject(signed)) {
    return { check: result(id, "failed", "The signed text is not a JSON object, so no field can be compared. The issuer signed something that is not a receipt."), action: undefined, repeated: [] };
  }
  const repeated: RepeatedField[] = [];
  let problem: string | undefined;
  for (const field of Object.keys(receipt).sort()) {
    if (ENVELOPE_ONLY.has(field)) continue;
    const present = Object.hasOwn(signed, field);
    const same = present && jsonEqual(receipt[field], signed[field]);
    repeated.push({ field, beside: receipt[field], signed: present ? signed[field] : undefined, same });
    if (problem !== undefined) continue;
    if (!present) {
      problem = `The field "${field}" beside the signed text is not in the signed text, so nothing vouches for it. Read the values from the signed text below.`;
    } else if (!same) {
      problem = `The field "${field}" says ${show(receipt[field])} beside the signed text, but the signed text says ${show(signed[field])}. Trust the signed text.`;
    }
  }
  if (problem !== undefined) return { check: result(id, "failed", problem), action: signed, repeated };
  const detail = repeated.length === 0 ? "The receipt repeats no fields beside the signed text." : `All ${String(repeated.length)} repeated fields equal the signed text.`;
  return { check: result(id, "passed", detail), action: signed, repeated };
}

/** Checks 1 to 4, which need no network. */
export async function checkOffline(receipt: unknown, keys: readonly PublicKey[]): Promise<ReceiptReport> {
  const format = formatCheck(receipt);
  const { check: signature, key } = await signatureCheck(receipt, format, keys);
  const contentHash = await contentHashCheck(receipt);
  const { check: repeatedCheck, action, repeated } = repeatedFieldsCheck(receipt, signature);
  let valid = false;
  for (const k of keys) {
    if ((await verifyV2Receipt(receipt, k.key)).ok) {
      valid = true;
      break;
    }
  }
  return { checks: [format, signature, contentHash, repeatedCheck], valid, key, action, repeated };
}

/** Check 5, once for all the receipts in one run. */
async function treeHeadCheck(log: LogInputs | undefined): Promise<{ check: CheckResult; head: TreeHeadCheck | undefined }> {
  const id = "tree-head";
  if (log === undefined) return { check: result(id, "not-run", "Not run: give a receipts-log address to check the log."), head: undefined };
  if (log.logKey === undefined) {
    return {
      check: result(id, "not-run", "Not run: give the log's public key. This page does not fetch the key from the log, because a key fetched from the log proves nothing."),
      head: undefined,
    };
  }
  const answer = await log.client.sth();
  if (answer.kind === "network") return { check: result(id, "not-run", answer.detail, true), head: undefined };
  if (answer.status !== 200) {
    return { check: logAnswered(id, answer.status, answer.body), head: undefined };
  }
  const head = await checkTreeHead(answer.body, log.logKey.key);
  if (head.status === "passed") {
    const { sth } = head;
    return { check: result(id, "passed", `The log ${sth.logId} signed a tree of ${String(sth.treeSize)} entries at ${sth.timestamp}, under the key ${log.logKey.fingerprint}.`), head };
  }
  return { check: result(id, head.status, head.reason), head };
}

/** Check 6, for one receipt, against a tree head that passed check 5. */
async function inLogCheck(receipt: unknown, log: LogInputs | undefined, head: TreeHeadCheck | undefined): Promise<CheckResult> {
  const id = "in-log";
  if (log === undefined) return result(id, "not-run", "Not run: give a receipts-log address to check the log.");
  if (head?.status !== "passed") return result(id, "not-run", "Not run: the tree head was not checked, so there is no signed root to check a proof against.");
  if (!isObject(receipt) || typeof receipt.canonical !== "string" || receipt.canonical === "") {
    return result(id, "not-run", "Not run: the receipt has no canonical text to look up.");
  }
  const { sth } = head;
  if (sth.treeSize === 0) return result(id, "failed", "The log is empty, so it does not hold this receipt. Check the log address.");
  const leaf = await leafHash(receipt.canonical);
  const answer = await log.client.inclusion(leaf, sth.treeSize);
  if (answer.kind === "network") return result(id, "not-run", answer.detail, true);
  if (answer.status === 404) {
    return result(id, "failed", "This log holds no entry for this receipt. Check the log address; if the receipt was submitted in the last few seconds, try again.");
  }
  if (answer.status !== 200) {
    return logAnswered(id, answer.status, answer.body);
  }
  const proof = answer.body;
  if (!isObject(proof)) return result(id, "failed", "The log's answer is not an inclusion proof. Keep the receipt and the tree head: the log may be misbehaving.");
  if (proof.leafHashHex !== leaf) return result(id, "failed", "The log answered with a proof for a different entry. Keep the receipt and the tree head: the log may be misbehaving.");
  if (proof.treeSize !== sth.treeSize) return result(id, "failed", "The log answered with a proof for a different tree size than its signed tree head. Try again; if it happens again, the log may be misbehaving.");
  // The proof's own rootHashHex is never trusted: the root comes from the signed tree head.
  if (await verifyInclusionProof(leaf, proof.leafIndex, sth.treeSize, proof.auditPath, sth.rootHash)) {
    return result(id, "passed", `Entry ${String(proof.leafIndex)} of ${String(sth.treeSize)} in the log ${sth.logId}, with leaf hash ${leaf}.`);
  }
  return result(id, "failed", "The log's proof does not lead to the root in its signed tree head. Keep the receipt and the tree head as evidence: the log may be misbehaving.");
}

/** Check 7, once for all the receipts in one run. */
async function witnessesCheck(log: LogInputs | undefined, head: TreeHeadCheck | undefined): Promise<CheckResult> {
  const id = "witnesses";
  if (log === undefined) return result(id, "not-run", "Not run: give a receipts-log address to check the log.");
  if (log.witnessKeys.length === 0) return result(id, "not-run", "Not run: give one or more witness public keys to check cosignatures.");
  if (head?.status !== "passed") return result(id, "not-run", "Not run: the tree head was not checked, so there is no tree head to look for cosignatures on.");
  const answer = await log.client.cosignatures(head.sth.treeSize);
  if (answer.kind === "network") return result(id, "not-run", answer.detail, true);
  if (answer.status !== 200) {
    return logAnswered(id, answer.status, answer.body);
  }
  const body = answer.body;
  if (!isObject(body) || !Array.isArray(body.cosignatures)) return result(id, "failed", "The log's answer is not a list of cosignatures. Try again; if it happens again, the log may be misbehaving.");
  // A cosignature counts when the tree head it covers has this log, size
  // and root; its timestamp may differ, since the log re-signs the same
  // tree. Its text is rebuilt from its own fields and must match byte for
  // byte, and its signature must verify over that text under the witness key.
  const { sth } = head;
  const signedBy: string[] = [];
  for (const w of log.witnessKeys) {
    for (const c of body.cosignatures as unknown[]) {
      if (!isObject(c) || typeof c.sthCanonical !== "string") continue;
      const covered = canonicalTreeHead(c.sthCanonical);
      if (covered?.logId !== sth.logId || covered.treeSize !== sth.treeSize || covered.rootHash !== sth.rootHash) continue;
      if (await verifyV2Text(c.signature, c.sthCanonical, w.key)) {
        signedBy.push(w.fingerprint);
        break;
      }
    }
  }
  const n = log.witnessKeys.length;
  const what = `a tree head of the log ${sth.logId} with ${String(sth.treeSize)} entries and this root`;
  if (signedBy.length === 0) {
    return result(id, "failed", `None of the ${String(n)} witness keys you gave cosigned ${what}. Witnesses cosign on their own schedule, so try again later; if it stays at none, check that you have the witnesses' keys.`);
  }
  return result(id, "passed", `${String(signedBy.length)} of ${String(n)} witnesses cosigned ${what}: ${signedBy.join(", ")}.`);
}

/** All seven checks for every receipt; the log is asked for one tree head and one list of cosignatures per run. */
export async function checkReceipts(receipts: readonly unknown[], inputs: Inputs): Promise<ReceiptReport[]> {
  const { check: treeHead, head } = await treeHeadCheck(inputs.log);
  const witnesses = await witnessesCheck(inputs.log, head);
  const reports: ReceiptReport[] = [];
  for (const receipt of receipts) {
    const report = await checkOffline(receipt, inputs.issuerKeys);
    report.checks.push(treeHead, await inLogCheck(receipt, inputs.log, head), witnesses);
    reports.push(report);
  }
  return reports;
}
```

- [ ] **Step 4:** run the whole check:

```bash
npm run typecheck && npx eslint . && npm test 2>&1 | grep -E '^# (pass|fail)'
```

Expected: `# pass 111`, `# fail 0`.

- [ ] **Step 5:** prove check 6 never trusts the log's own root. In `inLogCheck`, change `sth.rootHash)` in the `verifyInclusionProof` call to `proof.rootHashHex)`, run `node --test test/checks.test.ts`, and confirm `a proof whose own rootHashHex agrees with it, but the signed root does not, fails` fails. Restore it and rerun to `# fail 0`.
- [ ] **Step 6:** commit:

```bash
gitleaks git --pre-commit --staged --no-banner   # expect: no leaks found
git commit --author="$A" -m "The seven checks: passed, failed or not run, never a guess" -m "Format, signature, content hash and repeated fields agree with the vendored verifier on every conformance receipt. The tree head is fetched once per run and checked under the log key given; each receipt's leaf hash is computed here and its proof checked against the signed root, never the proof's own rootHashHex; witnesses count cosignatures over a tree head with the same log, size and root, whose canonical text is rebuilt and whose signature verifies under that witness's key; the timestamp may differ." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 8: input handling never throws, and checks 1 to 4 match the verifier

**Files:**
- Create: `test/parsing.properties.test.ts`

- [ ] **Step 1:** write the property tests:

`test/parsing.properties.test.ts`:

```ts
// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

// Property tests (fast-check) of the page's input handling: it never throws
// on any input, and checks 1 to 4 pass exactly when the vendored verifier
// accepts. FC_NUM_RUNS raises the number of cases per property (default 200).
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import fc from "fast-check";

import { checkOffline } from "../src/checks.ts";
import { parseReceipts } from "../src/input.ts";
import { parsePublicKeys } from "../src/keys.ts";
import { parseLogAddress } from "../src/log-client.ts";
import { checkTreeHead } from "../src/tree-head.ts";
import { verifyV2Receipt } from "../src/vendor/verifiable-receipts/receipt.ts";
import { makeKey, signReceipt } from "./helpers.ts";
import { body, mutate, mutation } from "./mutations.ts";

const NUM_RUNS = Number(process.env.FC_NUM_RUNS ?? "200");
fc.configureGlobal({ numRuns: Number.isSafeInteger(NUM_RUNS) && NUM_RUNS > 0 ? NUM_RUNS : 200 });

const issuer = await makeKey();
const anyText = fc.oneof(fc.string(), fc.json(), fc.jsonValue().map((v) => JSON.stringify(v)));

describe("parsing never throws", () => {
  it("parseReceipts", () => {
    fc.assert(fc.property(anyText, (t) => typeof parseReceipts(t).ok === "boolean"));
  });
  it("parseLogAddress", () => {
    fc.assert(fc.property(fc.oneof(fc.string(), fc.webUrl()), (t) => typeof parseLogAddress(t).ok === "boolean"));
  });
  it("parsePublicKeys throws only KeyError", async () => {
    await fc.assert(
      fc.asyncProperty(fc.oneof(fc.string(), fc.string().map((s) => `-----BEGIN PUBLIC KEY-----\n${s}\n-----END PUBLIC KEY-----`)), async (t) => {
        try {
          await parsePublicKeys(t, "The key");
        } catch (e) {
          assert.equal((e as Error).constructor.name, "KeyError");
        }
      }),
    );
  });
  it("checkTreeHead and checkOffline", async () => {
    await fc.assert(
      fc.asyncProperty(fc.jsonValue(), async (v) => {
        assert.ok(["passed", "failed", "not-run"].includes((await checkTreeHead(v, issuer.publicKey.key)).status));
        assert.equal(typeof (await checkOffline(v, [issuer.publicKey])).valid, "boolean");
      }),
    );
  });
});

describe("checks 1 to 4 agree with the vendored verifier", () => {
  it("they all pass, or the content hash is not run, exactly when verifyV2Receipt accepts", async () => {
    await fc.assert(
      fc.asyncProperty(body, mutation, mutation, async (b, m1, m2) => {
        const receipt = mutate(mutate(await signReceipt(b, issuer.privateKey), m1), m2);
        const port = await verifyV2Receipt(receipt, issuer.publicKey.key);
        const report = await checkOffline(receipt, [issuer.publicKey]);
        assert.equal(report.valid, port.ok);
        const offlineOk = report.checks.every((c) => c.status === "passed" || (c.id === "content-hash" && c.status === "not-run"));
        assert.equal(offlineOk, port.ok, JSON.stringify({ receipt, checks: report.checks }));
      }),
    );
  });
});
```

- [ ] **Step 2:** run them with ten times the default cases:

```bash
FC_NUM_RUNS=2000 node --test test/parsing.properties.test.ts 2>&1 | grep -E '^# (pass|fail)'
```

Expected: `# pass 5`, `# fail 0`.

- [ ] **Step 3:** run the whole check: `# pass 116`, `# fail 0`.
- [ ] **Step 4:** commit:

```bash
gitleaks git --pre-commit --staged --no-banner   # expect: no leaks found
git commit --author="$A" -m "Property tests: parsing never throws; checks 1 to 4 match the verifier" -m "On any text, JSON value or PEM-shaped input, the receipt reader, the log address reader, the key reader, the tree head check and the offline checks return a result and never throw; on signed receipts with changes, checks 1 to 4 pass exactly when the vendored verifier accepts." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 9: the page's script and its bundle

**Files:**
- Create: `content/checks.json`, `src/ed25519-support.ts`, `src/ui.ts`, `src/main.ts`, `scripts/bundle.mjs`

The page's behaviour is tested end to end in Tasks 13 and 14, against the built site; this task builds the bundle.

- [ ] **Step 1:** write the words for each check, once, for both the script and the pages:

`content/checks.json`:

```json
[
  {
    "id": "format",
    "name": "Format",
    "term": "receipt",
    "proves": "The receipt is a v2 receipt, and its signature is written in the one valid spelling.",
    "doesNotProve": "Nothing about who signed it or whether its content is true."
  },
  {
    "id": "signature",
    "name": "Signature",
    "term": "issuer-key",
    "proves": "The holder of this key signed exactly this text, and nobody changed it afterwards.",
    "doesNotProve": "That the key belongs to the issuer you think it does: that depends on where you got the key."
  },
  {
    "id": "content-hash",
    "name": "Content hash",
    "term": "canonical",
    "proves": "The contentHash beside the signed text is the SHA-256 of that text.",
    "doesNotProve": "Anything the signature does not already prove; it lets other tools find the receipt by its hash."
  },
  {
    "id": "repeated-fields",
    "name": "Repeated fields",
    "term": "repeated-field",
    "proves": "Every field beside the signed text says the same as the signed text.",
    "doesNotProve": "That the action happened as recorded; only that the receipt does not contradict itself."
  },
  {
    "id": "tree-head",
    "name": "Tree head",
    "term": "tree-head",
    "proves": "The log's key signed this tree head: the log committed to this size and root.",
    "doesNotProve": "That the log shows everyone the same tree head; witnesses check that."
  },
  {
    "id": "in-log",
    "name": "In the log",
    "term": "inclusion-proof",
    "proves": "The receipt is an entry in the tree the signed tree head commits to, so the log cannot later deny holding it.",
    "doesNotProve": "When the action happened, or that the log holds no other receipts that contradict this one."
  },
  {
    "id": "witnesses",
    "name": "Witnesses",
    "term": "cosignature",
    "proves": "Independent witnesses saw this log at this size with this same root, so the log would have to fool them too to show you a different one.",
    "doesNotProve": "That the witnesses are independent of the log; that depends on who runs them."
  }
]
```

- [ ] **Step 2:** write the feature check, the page code and the entry point:

`src/ed25519-support.ts`:

```ts
// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

// Whether this browser's WebCrypto verifies Ed25519: RFC 8032 section 7.1,
// test 1 (the empty message).
import { fromHex } from "./bytes.ts";

const PUBLIC = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const SIGNATURE =
  "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";

export async function hasEd25519(): Promise<boolean> {
  try {
    if (typeof crypto === "undefined" || typeof crypto.subtle === "undefined") return false;
    const key = await crypto.subtle.importKey("raw", fromHex(PUBLIC), { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "Ed25519" }, key, fromHex(SIGNATURE), new Uint8Array(0));
  } catch {
    return false;
  }
}
```

`src/ui.ts`:

```ts
// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

// The check page: reads the form, runs the checks, and shows the results.
// Everything is built with textContent, never parsed as HTML, and nothing
// the visitor gives is stored, put in the address bar or sent anywhere
// but the log address they typed.
import CHECKS from "../content/checks.json" with { type: "json" };
import { checkReceipts, show, type CheckResult, type Inputs, type ReceiptReport } from "./checks.ts";
import { hasEd25519 } from "./ed25519-support.ts";
import { MAX_INPUT_CHARS, parseReceipts } from "./input.ts";
import { KeyError, parsePublicKeys, type PublicKey } from "./keys.ts";
import { LogClient, parseLogAddress } from "./log-client.ts";

interface Problem {
  field: string;
  message: string;
}

const STATUS_LABEL: Record<CheckResult["status"], string> = { passed: "Passed", failed: "Failed", "not-run": "Not run" };

function byId(doc: Document, id: string): HTMLElement {
  const found = doc.getElementById(id);
  if (found === null) throw new Error(`missing #${id}`);
  return found;
}

function textField(doc: Document, id: string): HTMLInputElement | HTMLTextAreaElement {
  const found = byId(doc, id);
  if (!(found instanceof HTMLInputElement || found instanceof HTMLTextAreaElement)) throw new Error(`#${id} is not a text field`);
  return found;
}

function el<K extends keyof HTMLElementTagNameMap>(doc: Document, tag: K, className?: string, text?: string): HTMLElementTagNameMap[K] {
  const e = doc.createElement(tag);
  if (className !== undefined) e.className = className;
  if (text !== undefined) e.textContent = text;
  return e;
}

async function readKeys(text: string, field: string, source: string, problems: Problem[]): Promise<PublicKey[]> {
  try {
    return await parsePublicKeys(text, source);
  } catch (e) {
    problems.push({ field, message: e instanceof KeyError ? e.message : `${source} could not be read.` });
    return [];
  }
}

/** Reads the form into inputs for the checks, or the problems to show. */
async function readForm(doc: Document): Promise<{ receipts: unknown[]; inputs: Inputs } | { problems: Problem[] }> {
  const problems: Problem[] = [];
  const value = (id: string): string => textField(doc, id).value;
  const parsed = parseReceipts(value("receipt-text"));
  if (!parsed.ok) problems.push({ field: "receipt-text", message: parsed.reason });
  const issuerKeys = await readKeys(value("issuer-key"), "issuer-key", "The issuer key", problems);
  if (issuerKeys.length === 0 && !problems.some((p) => p.field === "issuer-key")) {
    problems.push({ field: "issuer-key", message: "Paste the issuer's public key (a PEM block), or choose its file." });
  }
  let log: Inputs["log"];
  const address = value("log-address").trim();
  const logKeyText = value("log-key");
  const witnessText = value("witness-keys");
  if (address !== "") {
    const parsedAddress = parseLogAddress(address);
    const logKeys = await readKeys(logKeyText, "log-key", "The log key", problems);
    const witnessKeys = await readKeys(witnessText, "witness-keys", "The witness keys", problems);
    if (logKeys.length > 1) problems.push({ field: "log-key", message: "Paste one log key: a log signs with one key." });
    if (!parsedAddress.ok) problems.push({ field: "log-address", message: parsedAddress.reason });
    else log = { client: new LogClient(parsedAddress.base), logKey: logKeys[0], witnessKeys };
  } else if (logKeyText.trim() !== "" || witnessText.trim() !== "") {
    problems.push({ field: "log-address", message: "Give the log's address too, or clear the log and witness keys." });
  }
  if (problems.length > 0 || !parsed.ok) return { problems };
  return { receipts: parsed.receipts, inputs: { issuerKeys, log } };
}

function renderProblems(doc: Document, problems: Problem[]): void {
  const box = byId(doc, "problems");
  box.replaceChildren(el(doc, "h2", undefined, problems.length === 1 ? "There is a problem" : `There are ${String(problems.length)} problems`));
  const list = el(doc, "ul");
  for (const p of problems) {
    const field = byId(doc, p.field);
    field.setAttribute("aria-invalid", "true");
    const a = el(doc, "a", undefined, p.message);
    a.href = `#${p.field}`;
    const li = el(doc, "li");
    li.append(a);
    list.append(li);
  }
  box.append(list);
  box.hidden = false;
  box.focus();
}

function renderCheck(doc: Document, c: CheckResult): HTMLLIElement {
  const info = CHECKS.find((x) => x.id === c.id);
  const li = el(doc, "li", `check check--${c.network ? "network" : c.status}`);
  const head = el(doc, "p", "check-head");
  head.append(el(doc, "span", "check-status", c.network ? "Network error" : STATUS_LABEL[c.status]), " ");
  const name = el(doc, "a", "check-name", info?.name ?? c.id);
  name.href = `terms/${info?.term ?? ""}/`;
  head.append(name);
  li.append(head, el(doc, "p", "check-detail", c.detail));
  if (info !== undefined) {
    li.append(el(doc, "p", "check-proves", `What it proves: ${info.proves}`), el(doc, "p", "check-limits", `What it does not prove: ${info.doesNotProve}`));
  }
  return li;
}

function renderReport(doc: Document, report: ReceiptReport, index: number, total: number): HTMLElement {
  const article = el(doc, "article", `report report--${report.valid ? "valid" : "invalid"}`);
  const label = total === 1 ? "The receipt" : `Receipt ${String(index + 1)} of ${String(total)}`;
  const firstFailure = report.checks.find((c) => c.status === "failed");
  const verdict = report.valid
    ? `${label} is valid: signed by ${report.key ?? "the issuer key"}, and unchanged since.`
    : `${label} is not valid. ${firstFailure?.detail ?? "A check did not pass."}`;
  article.append(el(doc, "h3", undefined, verdict));
  const list = el(doc, "ol", "checks");
  for (const c of report.checks) list.append(renderCheck(doc, c));
  article.append(list);
  if (report.action !== undefined) {
    article.append(el(doc, "h4", undefined, "The signed action"));
    article.append(el(doc, "pre", "action", JSON.stringify(report.action, null, 2)));
    if (report.repeated.length > 0) {
      const table = el(doc, "table", "repeated");
      table.append(el(doc, "caption", undefined, "Fields repeated beside the signed text"));
      const headRow = el(doc, "tr");
      for (const h of ["Field", "Beside the signed text", "In the signed text", "Same"]) {
        const th = el(doc, "th", undefined, h);
        th.scope = "col";
        headRow.append(th);
      }
      const thead = el(doc, "thead");
      thead.append(headRow);
      table.append(thead);
      const tbody = el(doc, "tbody");
      for (const r of report.repeated) {
        const row = el(doc, "tr");
        const th = el(doc, "th", undefined, r.field);
        th.scope = "row";
        row.append(th, el(doc, "td", undefined, show(r.beside)), el(doc, "td", undefined, r.signed === undefined ? "(not there)" : show(r.signed)), el(doc, "td", undefined, r.same ? "Yes" : "No"));
        tbody.append(row);
      }
      table.append(tbody);
      const wrap = el(doc, "div", "table-wrap");
      wrap.tabIndex = 0;
      wrap.setAttribute("role", "region");
      wrap.setAttribute("aria-label", "Fields repeated beside the signed text");
      wrap.append(table);
      article.append(wrap);
    }
  }
  return article;
}

async function run(doc: Document): Promise<void> {
  const status = byId(doc, "status");
  const results = byId(doc, "results");
  const list = byId(doc, "results-list");
  const problemsBox = byId(doc, "problems");
  problemsBox.hidden = true;
  for (const f of doc.querySelectorAll("[aria-invalid]")) f.removeAttribute("aria-invalid");
  status.textContent = "Checking…";
  const form = await readForm(doc);
  if ("problems" in form) {
    status.textContent = "";
    renderProblems(doc, form.problems);
    return;
  }
  const reports = await checkReceipts(form.receipts, form.inputs);
  list.replaceChildren(...reports.map((r, i) => renderReport(doc, r, i, reports.length)));
  const retry = reports.some((r) => r.checks.some((c) => c.retry));
  byId(doc, "retry").hidden = !retry;
  results.hidden = false;
  const validCount = reports.filter((r) => r.valid).length;
  status.textContent = `Checked ${String(reports.length)} ${reports.length === 1 ? "receipt" : "receipts"}: ${String(validCount)} valid.${retry ? " The log could not be reached, or was busy; you can try it again." : ""}`;
  byId(doc, "results-heading").focus();
}

/** Reads a chosen or dropped file into a text field. */
function loadFileInto(doc: Document, file: File, target: HTMLTextAreaElement): void {
  if (file.size > MAX_INPUT_CHARS) {
    byId(doc, "status").textContent = `${file.name} is larger than 5 MB, so it was not read.`;
    return;
  }
  void file.text().then((text) => {
    target.value = text;
    byId(doc, "status").textContent = `Read ${file.name}.`;
  });
}

function wireFiles(doc: Document): void {
  for (const input of doc.querySelectorAll<HTMLInputElement>("input[type=file][data-into]")) {
    const target = byId(doc, input.dataset.into ?? "");
    if (!(target instanceof HTMLTextAreaElement)) throw new Error(`${input.id} must load into a textarea`);
    input.addEventListener("change", () => {
      const file = input.files?.[0];
      if (file !== undefined) loadFileInto(doc, file, target);
    });
    target.addEventListener("dragover", (e) => {
      e.preventDefault();
    });
    target.addEventListener("drop", (e) => {
      const file = e.dataTransfer?.files[0];
      if (file === undefined) return;
      e.preventDefault();
      loadFileInto(doc, file, target);
    });
  }
}

export async function start(doc: Document): Promise<void> {
  const form = byId(doc, "check-form");
  if (!(await hasEd25519())) {
    byId(doc, "no-ed25519").hidden = false;
    return;
  }
  wireFiles(doc);
  let running = false;
  const go = (): void => {
    if (running) return;
    running = true;
    void run(doc).finally(() => {
      running = false;
    });
  };
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    go();
  });
  byId(doc, "retry").addEventListener("click", go);
  form.hidden = false;
}
```

`src/main.ts`:

```ts
// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

// The entry point of static/check.js, the one script the site loads.
import { start } from "./ui.ts";

void start(document);
```

- [ ] **Step 3:** write the bundler:

`scripts/bundle.mjs`:

```js
// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

// Bundles src/main.ts into build/check.js for the browser: one ES module,
// minified, with no runtime dependencies. The output is deterministic;
// build.py copies it into dist/static/ and writes its integrity hash.
import { mkdirSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
rmSync(join(root, "build"), { recursive: true, force: true });
mkdirSync(join(root, "build"));

const result = await build({
  absWorkingDir: root,
  entryPoints: ["src/main.ts"],
  outfile: "build/check.js",
  bundle: true,
  platform: "browser",
  target: ["es2022", "chrome137", "firefox129", "safari17"],
  format: "esm",
  minify: true,
  legalComments: "none",
  banner: { js: "// receipts-explorer. Apache-2.0. Source: https://github.com/christiaan839-beep/receipts-explorer" },
  metafile: true,
  logLevel: "warning",
});

const outside = Object.keys(result.metafile.inputs).filter((f) => !f.startsWith("src/") && !f.startsWith("content/"));
if (outside.length > 0) {
  console.error(`check.js must have no dependencies; it includes ${outside.join(", ")}`);
  process.exit(1);
}
```

- [ ] **Step 4:** run the whole check, then bundle:

```bash
npm run typecheck && npx eslint . && npm test 2>&1 | grep -E '^# (pass|fail)'
npm run bundle
wc -c build/check.js && gzip -9 -c build/check.js | wc -c
npm run bundle && shasum -a 256 build/check.js && npm run bundle && shasum -a 256 build/check.js
```

Expected: `# pass 116`, `# fail 0`; `build/check.js` about 26.3 KB and about 9.0 KB compressed; the two hashes equal (the bundle is deterministic). `bundle.mjs` exits 1 if anything outside `src/` and `content/` is bundled.

- [ ] **Step 5:** prove the lint rules hold: add `document.body.innerHTML = "";` to the end of `start` in `src/ui.ts` and run `npx eslint src/ui.ts`; confirm `Build elements with textContent; never parse input as HTML`. Remove the line.
- [ ] **Step 6:** commit:

```bash
gitleaks git --pre-commit --staged --no-banner   # expect: no leaks found
git commit --author="$A" -m "The page script: one bundle, no dependencies, nothing stored or sent" -m "src/ui.ts reads the form, runs the checks and renders each with textContent, linking it to its term; problems are listed and focused, results announced and focused, and a network error offers a retry. A browser without WebCrypto Ed25519 is told so and runs nothing. esbuild bundles it to build/check.js, about 9 KB compressed." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 10: the site's words and the terms

**Files:**
- Create: `tests/__init__.py` (empty), `tests/test_ontology.py`, `app/__init__.py`, `app/content.py`, `app/ontology.py`

- [ ] **Step 1:** write the test, and an empty `tests/__init__.py`:

`tests/test_ontology.py`:

```python
"""The terms read from the vendored docs/ontology.md."""

from __future__ import annotations

import unittest

from app.content import CHAIN, CHECKS, VR_REF
from app.ontology import BY_SLUG, NAME_NOTE, RELATIONS, TERMS, inline, resolve, slugify


class OntologyTest(unittest.TestCase):
    def test_every_term_the_site_links_to_exists(self) -> None:
        for slug in [c["term"] for c in CHECKS] + [s for s, _, _ in CHAIN]:
            self.assertIn(slug, BY_SLUG)

    def test_protocol_terms_have_a_scitt_equivalent_and_agent_terms_do_not(self) -> None:
        protocol = [t for t in TERMS if t.group == "protocol"]
        agent = [t for t in TERMS if t.group == "agent"]
        self.assertGreaterEqual(len(protocol), 15)
        self.assertGreaterEqual(len(agent), 7)
        self.assertTrue(all(t.scitt for t in protocol))
        self.assertTrue(all(t.scitt == "" for t in agent))

    def test_slugs_are_unique(self) -> None:
        self.assertEqual(len(BY_SLUG), len(TERMS))
        self.assertEqual(slugify("Issuer key"), "issuer-key")

    def test_the_sections_the_pages_quote_are_there(self) -> None:
        self.assertTrue(NAME_NOTE)
        self.assertTrue(RELATIONS)

    def test_inline_markdown_is_escaped_then_formatted(self) -> None:
        self.assertEqual(inline("a <b> `c<d>`"), "a &lt;b&gt; <code>c&lt;d&gt;</code>")
        self.assertEqual(inline("**x**"), "<strong>x</strong>")

    def test_relative_links_point_to_the_pinned_commit(self) -> None:
        base = "https://github.com/christiaan839-beep/verifiable-receipts"
        self.assertEqual(resolve("../schemas/receipt.schema.json"), f"{base}/blob/{VR_REF}/schemas/receipt.schema.json")
        self.assertEqual(resolve("../schemas"), f"{base}/tree/{VR_REF}/schemas")
        self.assertEqual(resolve("specs/vaos-2.0.md"), f"{base}/blob/{VR_REF}/docs/specs/vaos-2.0.md")
        self.assertIn(f"/blob/{VR_REF}/schemas/receipt.schema.json", BY_SLUG["receipt"].definition)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2:** run `PY=/opt/homebrew/bin/python3.12; $PY -m unittest discover -s tests -t .`. Expected: `ModuleNotFoundError: No module named 'app'`.
- [ ] **Step 3:** write the code:

`app/__init__.py`:

```python
"""receipts-explorer: the site, in the Python standard library only.

`content.py`   the words and settings: site, navigation, the seven checks.
`ontology.py`  the terms, read from the vendored docs/ontology.md.
`assets.py`    the Subresource Integrity hashes of the stylesheet and script.
`layout.py`    the HTML shell: CSP, SEO head, JSON-LD, header and footer.
`pages.py`     the page bodies and the ROUTES map.

Rendered live by ../serve.py and written to ../dist by ../build.py.
"""
```

`app/content.py`:

```python
"""The words and settings of the site, each stated once."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VENDORED = ROOT / "third_party" / "verifiable-receipts"
VR_REF = (VENDORED / "VR_REF").read_text(encoding="utf-8").strip()

SITE = {
    "name": "Receipts explorer",
    "base_url": "https://christiaan839-beep.github.io/receipts-explorer",
    "base_path": "/receipts-explorer",
    "locale": "en-ZA",
    "og_locale": "en_ZA",
    "description": (
        "Check a verifiable receipt in your browser: its signature, its content, and its place in a "
        "transparency log. Nothing you paste leaves your device."
    ),
    "repo": "https://github.com/christiaan839-beep/receipts-explorer",
    "vr_repo": "https://github.com/christiaan839-beep/verifiable-receipts",
    "author": "Christiaan de Wet / Sovereign Matrix",
}

NAV = [
    {"label": "Check a receipt", "path": "/", "key": "check"},
    {"label": "How it works", "path": "/how-it-works/", "key": "how"},
    {"label": "Terms", "path": "/terms/", "key": "terms"},
]

# The seven checks, shared with the script (src/ui.ts imports the same file).
CHECKS = json.loads((ROOT / "content" / "checks.json").read_text(encoding="utf-8"))

# The chain of trust, from issuer to witness, for the How it works page.
CHAIN = [
    ("issuer", "Issuer", "A business, or the host acting for it, signs a receipt for each action with its issuer key."),
    ("receipt", "Receipt", "The exact text that was signed, its hash and its signature. Change one character and it fails."),
    ("leaf", "Leaf", "The receipt's hash, appended to a transparency log, which can only grow."),
    ("tree-head", "Tree head", "The log signs its size and root from time to time, committing to every entry so far."),
    ("inclusion-proof", "Inclusion proof", "A few hashes that link one receipt to the root in a signed tree head."),
    ("witness", "Witness", "Independent parties cosign a tree head only if it extends the last one they saw."),
    ("verifier", "Verifier", "This page, or a library: it checks each link itself, and trusts none of them on its own."),
]

PRIVACY = [
    "Your receipts and keys stay in this browser tab. The page uploads nothing.",
    "If you give a log address, the page sends only GET requests, and only to that address. "
    "The log learns the hash of each receipt you look up.",
    "No cookies, no storage, no analytics. Nothing you type goes in the address bar.",
    "The page's script is checked by its hash before it runs, and every release is attested.",
]
```

`app/ontology.py`:

````python
"""The terms, read from docs/ontology.md of verifiable-receipts.

The file is vendored byte-for-byte at the commit in
third_party/verifiable-receipts/VR_REF, so the term pages say exactly what
the ontology says at that commit. Relative links in it point to the same
commit on GitHub.
"""

from __future__ import annotations

import html
import posixpath
import re
from dataclasses import dataclass

from .content import SITE, VENDORED, VR_REF

SOURCE = VENDORED / "ontology.md"


@dataclass(frozen=True)
class Term:
    name: str
    slug: str
    definition: str  # HTML
    scitt: str  # HTML; empty for the agent terms
    group: str  # "protocol" or "agent"


def slugify(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def resolve(href: str) -> str:
    """A link in docs/ontology.md, as an absolute URL at VR_REF."""
    if href.startswith(("https://", "http://", "#")):
        return href
    path = posixpath.normpath(posixpath.join("docs", href))
    kind = "blob" if posixpath.splitext(path)[1] else "tree"
    return f"{SITE['vr_repo']}/{kind}/{VR_REF}/{path}"


_CODE = re.compile(r"`([^`]+)`")
_LINK = re.compile(r"\[([^\]]+)\]\(([^)\s]+)\)")
_BOLD = re.compile(r"\*\*([^*]+)\*\*")


def inline(markdown: str) -> str:
    """The inline Markdown the ontology uses (code, links, bold) as HTML, escaped."""
    out = html.escape(markdown, quote=False)
    out = _CODE.sub(lambda m: f"<code>{m.group(1)}</code>", out)
    out = _LINK.sub(lambda m: f'<a href="{html.escape(resolve(html.unescape(m.group(2))))}">{m.group(1)}</a>', out)
    return _BOLD.sub(lambda m: f"<strong>{m.group(1)}</strong>", out)


def sections(text: str) -> dict[str, str]:
    """The body of each level-two section, by its heading."""
    out: dict[str, str] = {}
    heading = ""
    lines: list[str] = []
    for line in text.splitlines():
        if line.startswith("## "):
            out[heading] = "\n".join(lines).strip()
            heading, lines = line[3:].strip(), []
        else:
            lines.append(line)
    out[heading] = "\n".join(lines).strip()
    return out


def table(body: str) -> list[list[str]]:
    """The rows of the first Markdown table in `body`, without its header."""
    rows = [line for line in body.splitlines() if line.startswith("|")]
    return [[cell.strip() for cell in row.strip().strip("|").split("|")] for row in rows[2:]]


def paragraphs(body: str) -> list[str]:
    """The prose paragraphs of `body` (no tables, lists or code), as HTML."""
    out: list[str] = []
    for block in re.split(r"\n\s*\n", body):
        if block.strip() == "" or block.lstrip().startswith(("|", "-", "```")):
            continue
        out.append(inline(" ".join(line.strip() for line in block.splitlines() if line.strip())))
    return out


def bullets(body: str) -> list[str]:
    """The items of the Markdown list in `body`, as HTML."""
    items: list[str] = []
    for line in body.splitlines():
        if line.startswith("- "):
            items.append(line[2:].strip())
        elif line.startswith("  ") and items:
            items[-1] += " " + line.strip()
    return [inline(i) for i in items]


def load() -> tuple[list[Term], dict[str, str]]:
    text = SOURCE.read_text(encoding="utf-8")
    parts = sections(text)
    terms: list[Term] = []
    for name, definition, scitt in table(parts["Protocol terms"]):
        terms.append(Term(name, slugify(name), inline(definition), inline(scitt), "protocol"))
    for name, definition in table(parts["Agent terms (sovereign-agents)"]):
        terms.append(Term(name, slugify(name), inline(definition), "", "agent"))
    return terms, parts


TERMS, SECTIONS = load()
BY_SLUG = {t.slug: t for t in TERMS}
INTRO = paragraphs(SECTIONS[""].split("\n", 1)[1])
NAME_NOTE = paragraphs(SECTIONS["One name to read carefully"])
RELATIONS = bullets(SECTIONS["Relations"])
AGENT_INTRO = paragraphs(SECTIONS["Agent terms (sovereign-agents)"])
````

- [ ] **Step 4:** run:

```bash
$PY -m unittest discover -s tests -t .
uvx ruff@0.17.0 check . && uvx ruff@0.17.0 format --check .
```

Expected: `Ran 6 tests`, `OK`; ruff `All checks passed!` and every file already formatted.

- [ ] **Step 5:** commit:

```bash
gitleaks git --pre-commit --staged --no-banner   # expect: no leaks found
git commit --author="$A" -m "Site content, and the terms read from docs/ontology.md" -m "app/content.py states the site's settings and words once; the checks come from content/checks.json, shared with the script. app/ontology.py reads every term from the vendored ontology.md, escapes it, and points its relative links at the same commit on GitHub." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 11: the HTML shell and the pages

**Files:**
- Create: `tests/test_pages.py`, `app/assets.py`, `app/layout.py`, `app/pages.py`, `static/styles.css`, `static/img/favicon.svg`

- [ ] **Step 1:** write the test:

`tests/test_pages.py`:

```python
"""Every page: one h1, lang en-ZA, the CSP, SEO metadata, no inline code, working links."""

from __future__ import annotations

import json
import unittest
from html.parser import HTMLParser

from app.layout import CSP
from app.pages import all_routes, render_not_found, render_route

ASSETS = {"styles": "sha384-styles", "script": "sha384-script"}
BASE = "/receipts-explorer"
STATIC = {f"{BASE}/static/styles.css", f"{BASE}/static/check.js", f"{BASE}/static/img/favicon.svg"}


class Page(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[tuple[str, dict[str, str]]] = []
        self.data: dict[str, list[str]] = {}
        self._open: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append((tag, {k: v or "" for k, v in attrs}))
        self._open.append(tag)

    def handle_endtag(self, tag: str) -> None:
        if tag in self._open:
            self._open.remove(tag)

    def handle_data(self, data: str) -> None:
        if self._open:
            self.data.setdefault(self._open[-1], []).append(data)

    def all(self, tag: str) -> list[dict[str, str]]:
        return [a for t, a in self.tags if t == tag]

    def meta(self, key: str, value: str) -> str:
        return next(a["content"] for a in self.all("meta") if a.get(key) == value)


def parse(html: str) -> Page:
    p = Page()
    p.feed(html)
    return p


PAGES = {route: render_route(route, ASSETS) or "" for route in all_routes()}
PAGES["/404.html"] = render_not_found(ASSETS)


class PagesTest(unittest.TestCase):
    def test_every_page_has_the_shell(self) -> None:
        for route, html in PAGES.items():
            with self.subTest(route=route):
                p = parse(html)
                self.assertEqual(p.all("html")[0]["lang"], "en-ZA")
                self.assertEqual(len(p.all("h1")), 1)
                self.assertEqual(p.meta("http-equiv", "Content-Security-Policy"), CSP)
                self.assertEqual(p.meta("name", "referrer"), "no-referrer")
                self.assertTrue(p.all("main")[0]["id"] == "main")
                self.assertEqual(p.all("a")[0]["href"], "#main")

    def test_the_csp_forbids_inline_code(self) -> None:
        self.assertIn("default-src 'none'", CSP)
        self.assertIn("script-src 'self';", CSP)
        self.assertIn("style-src 'self';", CSP)
        self.assertNotIn("unsafe", CSP)
        for route, html in PAGES.items():
            with self.subTest(route=route):
                for tag, attrs in parse(html).tags:
                    self.assertNotIn("style", attrs, f"<{tag} style>")
                    self.assertFalse([k for k in attrs if k.startswith("on")], f"<{tag}> has an event handler")
                    if tag == "script":
                        self.assertTrue(attrs.get("type") == "application/ld+json" or "src" in attrs)
                    if tag == "style":
                        self.fail("inline <style>")

    def test_titles_descriptions_and_canonicals_are_unique(self) -> None:
        seen: dict[str, set[str]] = {"title": set(), "description": set(), "canonical": set()}
        for route, html in PAGES.items():
            p = parse(html)
            title = "".join(p.data["title"])
            description = p.meta("name", "description")
            canonical = next(a["href"] for a in p.all("link") if a.get("rel") == "canonical")
            self.assertLessEqual(len(description), 160, route)
            for key, value in (("title", title), ("description", description), ("canonical", canonical)):
                self.assertNotIn(value, seen[key], f"{route}: repeated {key}")
                seen[key].add(value)

    def test_json_ld_parses(self) -> None:
        for route, html in PAGES.items():
            with self.subTest(route=route):
                blocks = parse(html).data["script"]
                data = json.loads("".join(blocks))
                self.assertEqual(data["@context"], "https://schema.org")

    def test_only_the_check_page_loads_the_script_and_it_carries_its_hash(self) -> None:
        for route, html in PAGES.items():
            scripts = [a for a in parse(html).all("script") if "src" in a]
            if route == "/":
                self.assertEqual(scripts, [{"type": "module", "src": f"{BASE}/static/check.js", "integrity": "sha384-script"}])
            else:
                self.assertEqual(scripts, [], route)

    def test_every_internal_link_resolves(self) -> None:
        targets = {BASE + r for r in all_routes()} | STATIC
        for route, html in PAGES.items():
            p = parse(html)
            ids = {a["id"] for _, a in p.tags if "id" in a}
            for _, attrs in p.tags:
                href = attrs.get("href") or attrs.get("src") or ""
                if href.startswith("#"):
                    self.assertIn(href[1:], ids, f"{route}: {href}")
                elif href.startswith("/"):
                    self.assertIn(href.split("#")[0], targets, f"{route}: {href}")

    def test_every_form_field_has_a_label(self) -> None:
        p = parse(PAGES["/"])
        labelled = {a["for"] for a in p.all("label")}
        for tag in ("input", "textarea"):
            for attrs in p.all(tag):
                self.assertIn(attrs["id"], labelled)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2:** run `$PY -m unittest discover -s tests -t .`. Expected: `ModuleNotFoundError: No module named 'app.layout'`.
- [ ] **Step 3:** write the code and the styles:

`app/assets.py`:

```python
"""Subresource Integrity for the stylesheet and the script."""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path

from .content import ROOT

STYLES = ROOT / "static" / "styles.css"
SCRIPT = ROOT / "build" / "check.js"


def integrity(path: Path) -> str:
    """The integrity attribute value of a file: sha384, base64."""
    digest = hashlib.sha384(path.read_bytes()).digest()
    return "sha384-" + base64.b64encode(digest).decode("ascii")


def hashes() -> dict[str, str]:
    """The integrity values the pages need. The script must be built first (npm run bundle)."""
    if not SCRIPT.is_file():
        raise SystemExit(f"{SCRIPT} is missing: run npm run bundle first")
    return {"styles": integrity(STYLES), "script": integrity(SCRIPT)}
```

`app/layout.py`:

```python
"""The HTML shell, once for every page.

Every page gets: lang="en-ZA"; a Content Security Policy as a meta tag
(GitHub Pages sends no headers) that allows scripts and styles from the
site only, no inline code, and connections only over https; no referrer;
a unique title, description and canonical URL; Open Graph and Twitter
metadata; JSON-LD; a skip link and landmarks. The stylesheet and the
script carry Subresource Integrity hashes.
"""

from __future__ import annotations

import html
import json

from .content import NAV, SITE

CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src https:; base-uri 'none'; form-action 'none'"
)


def url(path: str) -> str:
    """A site path under the base path, such as /receipts-explorer/terms/."""
    return SITE["base_path"] + path


def absolute(path: str) -> str:
    return SITE["base_url"] + path


def esc(text: str) -> str:
    return html.escape(text, quote=True)


def _json_ld(meta: dict) -> str:
    graph = [
        {
            "@type": "WebSite",
            "@id": absolute("/#website"),
            "url": absolute("/"),
            "name": SITE["name"],
            "inLanguage": SITE["locale"],
            "publisher": {"@type": "Person", "name": "Christiaan de Wet"},
        },
        {**meta["schema"], "url": absolute(meta["path"]), "isPartOf": {"@id": absolute("/#website")}},
    ]
    text = json.dumps({"@context": "https://schema.org", "@graph": graph}, ensure_ascii=False, sort_keys=True)
    # A JSON-LD block is data, not code; "</" is escaped so no text can end the element early.
    return text.replace("</", "<\\/")


def _head(meta: dict, assets: dict[str, str]) -> str:
    title = meta["title"] if meta["path"] == "/" else f"{meta['title']} | {SITE['name']}"
    canonical = absolute(meta["path"])
    script = ""
    if meta.get("script"):
        script = f'\n  <script type="module" src="{url("/static/check.js")}" integrity="{assets["script"]}"></script>'
    robots = "noindex" if meta.get("noindex") else "index, follow"
    return f"""  <meta charset="utf-8">
  <meta http-equiv="Content-Security-Policy" content="{CSP}">
  <meta name="referrer" content="no-referrer">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light dark">
  <title>{esc(title)}</title>
  <meta name="description" content="{esc(meta["description"])}">
  <meta name="robots" content="{robots}">
  <link rel="canonical" href="{canonical}">
  <meta property="og:type" content="website">
  <meta property="og:site_name" content="{esc(SITE["name"])}">
  <meta property="og:title" content="{esc(title)}">
  <meta property="og:description" content="{esc(meta["description"])}">
  <meta property="og:url" content="{canonical}">
  <meta property="og:locale" content="{SITE["og_locale"]}">
  <meta name="twitter:card" content="summary">
  <meta name="twitter:title" content="{esc(title)}">
  <meta name="twitter:description" content="{esc(meta["description"])}">
  <link rel="icon" href="{url("/static/img/favicon.svg")}" type="image/svg+xml">
  <link rel="stylesheet" href="{url("/static/styles.css")}" integrity="{assets["styles"]}">{script}
  <script type="application/ld+json">{_json_ld(meta)}</script>"""


def _header(active: str | None) -> str:
    items = []
    for n in NAV:
        current = ' aria-current="page"' if n["key"] == active else ""
        items.append(f'<li><a href="{url(n["path"])}"{current}>{n["label"]}</a></li>')
    return f"""<a class="skip-link" href="#main">Skip to content</a>
<header class="site-header">
  <div class="container header-inner">
    <a class="brand" href="{url("/")}">{SITE["name"]}</a>
    <nav aria-label="Main"><ul class="nav">{"".join(items)}</ul></nav>
  </div>
</header>"""


def _footer() -> str:
    return f"""<footer class="site-footer">
  <div class="container">
    <p>Open source, Apache-2.0: <a href="{SITE["repo"]}">receipts-explorer on GitHub</a>.
    The checks are those of <a href="{SITE["vr_repo"]}">verifiable-receipts</a>.</p>
    <p>{esc(SITE["author"])}.</p>
  </div>
</footer>"""


def render_page(meta: dict, body: str, assets: dict[str, str]) -> str:
    """Wraps a page body in the document shell."""
    return f"""<!doctype html>
<html lang="{SITE["locale"]}">
<head>
{_head(meta, assets)}
</head>
<body>
{_header(meta.get("active"))}
<main id="main" class="container">
{body}
</main>
{_footer()}
</body>
</html>
"""
```

`app/pages.py`:

```python
"""The page bodies and the ROUTES map.

Every page has one h1, reads in full without JavaScript, and links each
check to the term it relies on. Only the check page loads the script.
"""

from __future__ import annotations

import html
import re

from .content import CHAIN, CHECKS, PRIVACY, SITE, VR_REF
from .layout import esc, render_page, url
from .ontology import AGENT_INTRO, BY_SLUG, NAME_NOTE, RELATIONS, TERMS, Term


def plain(fragment: str, limit: int = 155) -> str:
    """HTML as plain text, cut at a word to `limit` characters, for a meta description."""
    text = html.unescape(re.sub(r"<[^>]+>", "", fragment))
    if len(text) <= limit:
        return text
    return text[: limit - 1].rsplit(" ", 1)[0] + "…"


def term_link(slug: str, label: str | None = None) -> str:
    return f'<a href="{url(f"/terms/{slug}/")}">{esc(label or BY_SLUG[slug].name)}</a>'


def file_field(id_: str, label: str, hint: str, file_label: str, rows: int) -> str:
    return f"""<div class="field">
    <label for="{id_}">{label}</label>
    <p class="hint" id="{id_}-hint">{hint}</p>
    <textarea id="{id_}" rows="{rows}" spellcheck="false" autocomplete="off" aria-describedby="{id_}-hint"></textarea>
    <label class="file-label" for="{id_}-file">{file_label}</label>
    <input type="file" id="{id_}-file" accept=".json,.pem,.txt,application/json" data-into="{id_}">
  </div>"""


def check_list() -> str:
    items = "".join(
        f"<li><h3>{term_link(c['term'], c['name'])}</h3><p>{esc(c['proves'])}</p>"
        f'<p class="limits">It does not prove: {esc(c["doesNotProve"])}</p></li>'
        for c in CHECKS
    )
    return f'<ol class="check-list">{items}</ol>'


RECEIPT_HINT = "Paste the receipt's JSON, or drop its file here. A list of receipts is checked one by one."
ISSUER_HINT = "Paste the PEM block, from -----BEGIN PUBLIC KEY----- to -----END PUBLIC KEY-----. Several keys may be pasted."
LOG_KEY_HINT = "The key the log signs its tree heads with. Get it from the log's operator, not from the log itself."


def page_check() -> tuple[dict, str]:
    meta = {
        "path": "/",
        "title": "Check a receipt: signature, content and transparency log",
        "description": SITE["description"],
        "active": "check",
        "script": True,
        "schema": {
            "@type": "WebApplication",
            "name": SITE["name"],
            "applicationCategory": "SecurityApplication",
            "operatingSystem": "Any, in a current web browser",
            "description": SITE["description"],
            "isAccessibleForFree": True,
        },
    }
    privacy = "".join(f"<li>{esc(p)}</li>" for p in PRIVACY)
    body = f"""<h1>Check a receipt</h1>
<p class="lede">A receipt is an issuer's signed record of something an AI agent did. Paste one with the issuer's public key,
and this page checks, in your browser, that the issuer signed exactly this text. Give a receipts-log address too,
and it checks that the receipt is in the log, and that witnesses saw the same log.</p>
<noscript><p class="notice">Checking needs JavaScript, which is off. The rest of this page explains the checks.</p></noscript>
<p id="no-ed25519" class="notice" hidden>This browser cannot check Ed25519 signatures, so no checks can run here.
Use a current version of Firefox, Chrome, Edge or Safari.</p>
<div id="problems" class="problems" tabindex="-1" role="alert" hidden></div>
<form id="check-form" class="check-form" novalidate hidden>
  {file_field("receipt-text", "Receipt", RECEIPT_HINT, "Or choose a receipt file", 8)}
  {file_field("issuer-key", "Issuer's public key", ISSUER_HINT, "Or choose a key file", 4)}
  <details class="optional">
    <summary>Also check the transparency log (optional)</summary>
    <div class="field">
      <label for="log-address">Log address</label>
      <p class="hint" id="log-address-hint">The receipts-log address the issuer uses, starting with https://.</p>
      <input type="url" id="log-address" inputmode="url" spellcheck="false" autocomplete="off" aria-describedby="log-address-hint">
    </div>
    {file_field("log-key", "Log's public key", LOG_KEY_HINT, "Or choose the log key file", 3)}
    {file_field("witness-keys", "Witness public keys", "Optional. One PEM block per witness.", "Or choose a witness key file", 4)}
  </details>
  <button type="submit" class="button">Check</button>
</form>
<p id="status" class="status" role="status" aria-live="polite"></p>
<section id="results" class="results" aria-labelledby="results-heading" hidden>
  <h2 id="results-heading" tabindex="-1">Results</h2>
  <div id="results-list"></div>
  <button type="button" id="retry" class="button button--secondary" hidden>Try the log again</button>
</section>
<section aria-labelledby="checks-heading">
  <h2 id="checks-heading">The seven checks</h2>
  <p>Each check is passed, failed or not run. A check that cannot run, because a key or the log address is missing or the
  log cannot be reached, is shown as not run, never as passed.</p>
  {check_list()}
</section>
<section aria-labelledby="privacy-heading">
  <h2 id="privacy-heading">What this page does with your receipt</h2>
  <ul>{privacy}</ul>
</section>"""
    return meta, body


def chain_figure() -> str:
    step, width, box = 64, 300, 44
    shapes = []
    for i, (_, name, _) in enumerate(CHAIN):
        y = i * step
        shapes.append(f'<rect class="chain-box" x="10" y="{y}" width="{width - 20}" height="{box}" rx="6"></rect>')
        shapes.append(f'<text class="chain-label" x="{width // 2}" y="{y + 28}" text-anchor="middle">{esc(name)}</text>')
        if i < len(CHAIN) - 1:
            top, bottom = y + box, y + step
            shapes.append(f'<path class="chain-arrow" d="M{width // 2} {top} V{bottom - 4} m-5 -6 l5 6 l5 -6"></path>')
    height = (len(CHAIN) - 1) * step + box
    names = ", ".join(name for _, name, _ in CHAIN)
    steps = "".join(f"<li>{term_link(slug, name)}: {esc(text)}</li>" for slug, name, text in CHAIN)
    return f"""<figure class="chain">
  <svg viewBox="0 0 {width} {height}" role="img" aria-labelledby="chain-title">
    <title id="chain-title">The chain of trust: {esc(names)}.</title>
    {"".join(shapes)}
  </svg>
  <figcaption>The chain of trust, from the issuer to the witnesses. Each link is checked on its own.</figcaption>
</figure>
<ol class="chain-steps">{steps}</ol>"""


def page_how() -> tuple[dict, str]:
    meta = {
        "path": "/how-it-works/",
        "title": "How it works: the chain of trust",
        "description": (
            "How a receipt is checked without trusting the agent, its host or the log: issuer, receipt, "
            "transparency log, tree head, inclusion proof and witnesses."
        ),
        "active": "how",
        "schema": {"@type": "TechArticle", "headline": "How it works: the chain of trust", "inLanguage": SITE["locale"]},
    }
    relations = "".join(f"<li>{r}</li>" for r in RELATIONS)
    note = "".join(f"<p>{p}</p>" for p in NAME_NOTE)
    body = f"""<h1>How it works</h1>
<p class="lede">An AI agent acts for a business. The business signs a receipt for each action, and appends it to a
transparency log that can only grow. Anyone can then check the receipt, and its place in the log, without trusting the
agent, its host or the log.</p>
{chain_figure()}
<h2>What each part promises</h2>
<ul>{relations}</ul>
<h2>One name to read carefully</h2>
{note}
<p>Every term has its own page: see <a href="{url("/terms/")}">the terms</a>.</p>"""
    return meta, body


def page_terms() -> tuple[dict, str]:
    meta = {
        "path": "/terms/",
        "title": "Terms: the ontology of verifiable receipts",
        "description": "Every term verifiable receipts uses, defined once, with its equivalent in SCITT (RFC 9943).",
        "active": "terms",
        "schema": {"@type": "DefinedTermSet", "name": "Verifiable receipts ontology", "inLanguage": SITE["locale"]},
    }
    protocol = "".join(
        f"<li>{term_link(t.slug)}<span class='term-scitt'>SCITT: {t.scitt}</span></li>" for t in TERMS if t.group == "protocol"
    )
    agent = "".join(f"<li>{term_link(t.slug)}</li>" for t in TERMS if t.group == "agent")
    note = "".join(f"<p>{p}</p>" for p in NAME_NOTE)
    intro = "".join(f"<p>{p}</p>" for p in AGENT_INTRO)
    body = f"""<h1>Terms</h1>
<p class="lede">The terms of verifiable receipts, each defined once, from
<a href="{SITE["vr_repo"]}/blob/{VR_REF}/docs/ontology.md">docs/ontology.md</a> at commit <code>{VR_REF[:12]}</code>.</p>
{note}
<h2>Protocol terms</h2>
<ul class="term-list">{protocol}</ul>
<h2>Agent terms</h2>
{intro}
<ul class="term-list">{agent}</ul>"""
    return meta, body


def page_term(term: Term) -> tuple[dict, str]:
    meta = {
        "path": f"/terms/{term.slug}/",
        "title": f"{term.name}: definition",
        "description": plain(term.definition),
        "active": "terms",
        "schema": {
            "@type": "DefinedTerm",
            "name": term.name,
            "description": plain(term.definition, 1000),
            "inDefinedTermSet": {"@type": "DefinedTermSet", "name": "Verifiable receipts ontology"},
        },
    }
    scitt = f"<h2>In SCITT (RFC 9943)</h2><p>{term.scitt}</p>" if term.scitt else ""
    checks = [c for c in CHECKS if c["term"] == term.slug]
    used = ""
    if checks:
        names = ", ".join(esc(c["name"]) for c in checks)
        used = f'<h2>Checked on this site</h2><p>The {names} check relies on this term. <a href="{url("/")}">Check a receipt</a>.</p>'
    body = f"""<p class="breadcrumb"><a href="{url("/terms/")}">Terms</a></p>
<h1>{esc(term.name)}</h1>
<p class="definition">{term.definition}</p>
{scitt}
{used}
<p class="source">From <a href="{SITE["vr_repo"]}/blob/{VR_REF}/docs/ontology.md">docs/ontology.md</a>
at commit <code>{VR_REF[:12]}</code>.</p>"""
    return meta, body


def not_found() -> tuple[dict, str]:
    meta = {
        "path": "/404.html",
        "title": "Page not found",
        "description": "There is no page at this address.",
        "noindex": True,
        "schema": {"@type": "WebPage", "name": "Page not found"},
    }
    body = f"""<h1>Page not found</h1>
<p>There is no page at this address. <a href="{url("/")}">Check a receipt</a>, or see the <a href="{url("/terms/")}">terms</a>.</p>"""
    return meta, body


ROUTES = {"/": page_check, "/how-it-works/": page_how, "/terms/": page_terms}
for _t in TERMS:
    ROUTES[f"/terms/{_t.slug}/"] = lambda t=_t: page_term(t)


def render_route(path: str, assets: dict[str, str]) -> str | None:
    fn = ROUTES.get(path)
    if fn is None:
        return None
    meta, body = fn()
    return render_page(meta, body, assets)


def render_not_found(assets: dict[str, str]) -> str:
    meta, body = not_found()
    return render_page(meta, body, assets)


def all_routes() -> list[str]:
    return list(ROUTES)
```

`static/styles.css`:

```css
/* receipts-explorer. One stylesheet, no fonts to download, light and dark.
   Colour pairs are checked for WCAG 2.2 AA contrast by the Playwright axe
   tests in both colour schemes. */
:root {
  color-scheme: light dark;
  --bg: #ffffff;
  --fg: #1a1d1f;
  --muted: #4a5257;
  --line: #c9cfd3;
  --panel: #f3f5f6;
  --link: #0b5f4a;
  --focus: #b3410e;
  --pass: #0b6b2f;
  --fail: #a4161a;
  --skip: #4a5257;
  --net: #7a4a00;
  --space: 1rem;
  font-family: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  line-height: 1.55;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #121516;
    --fg: #e8ecee;
    --muted: #b4bcc1;
    --line: #3a4247;
    --panel: #1c2124;
    --link: #6fd3b5;
    --focus: #ffb38a;
    --pass: #7ee0a0;
    --fail: #ff9b9b;
    --skip: #b4bcc1;
    --net: #ffd27a;
  }
}
*, *::before, *::after { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; text-size-adjust: 100%; }
body { margin: 0; background: var(--bg); color: var(--fg); overflow-wrap: anywhere; }
a { color: var(--link); text-underline-offset: 0.15em; }
:focus-visible { outline: 3px solid var(--focus); outline-offset: 2px; }
.container { max-width: 48rem; margin: 0 auto; padding: 0 var(--space); }
.skip-link { position: absolute; left: -999px; top: 0; padding: 0.5rem 1rem; background: var(--bg); }
.skip-link:focus { left: var(--space); z-index: 1; }
.site-header { border-bottom: 1px solid var(--line); }
.header-inner { display: flex; flex-wrap: wrap; gap: 0.5rem 1.5rem; align-items: center; justify-content: space-between; padding-top: 0.75rem; padding-bottom: 0.75rem; }
.brand { font-weight: 700; color: var(--fg); text-decoration: none; }
.nav { display: flex; flex-wrap: wrap; gap: 0.25rem 1rem; list-style: none; margin: 0; padding: 0; }
.nav a[aria-current="page"] { font-weight: 700; text-decoration-thickness: 2px; }
main { padding-top: 1.5rem; padding-bottom: 3rem; }
h1 { font-size: clamp(1.6rem, 5vw, 2.2rem); line-height: 1.2; margin: 0 0 0.75rem; }
h2 { font-size: 1.35rem; margin: 2rem 0 0.5rem; }
h3 { font-size: 1.1rem; margin: 1rem 0 0.25rem; }
.lede { font-size: 1.1rem; color: var(--muted); }
.notice, .problems { border: 2px solid var(--fail); padding: 0.75rem var(--space); border-radius: 6px; }
.problems h2 { margin-top: 0; font-size: 1.1rem; }
.check-form { display: grid; gap: 1.25rem; margin: 1.5rem 0; }
.field { display: grid; gap: 0.3rem; }
label { font-weight: 600; }
.hint { margin: 0; color: var(--muted); font-size: 0.95rem; }
textarea, input[type="url"] { width: 100%; font: 0.9rem/1.4 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; color: var(--fg); background: var(--bg); border: 1px solid var(--muted); border-radius: 4px; padding: 0.5rem; }
textarea[aria-invalid="true"], input[aria-invalid="true"] { border: 2px solid var(--fail); }
.file-label { font-weight: 400; font-size: 0.95rem; }
input[type="file"] { max-width: 100%; }
.optional { border: 1px solid var(--line); border-radius: 6px; padding: 0.75rem var(--space); }
.optional[open] { display: grid; gap: 1.25rem; }
summary { cursor: pointer; font-weight: 600; }
.button { justify-self: start; font: inherit; font-weight: 700; color: #fff; background: var(--link); border: 0; border-radius: 6px; padding: 0.65rem 1.4rem; cursor: pointer; min-height: 44px; }
@media (prefers-color-scheme: dark) { .button { color: #0b1a15; } }
.button--secondary { color: var(--link); background: transparent; border: 2px solid var(--link); }
.status { min-height: 1.5em; font-weight: 600; }
.report { border: 1px solid var(--line); border-radius: 8px; padding: 0 var(--space) var(--space); margin: 1rem 0; }
.report--valid { border-left: 6px solid var(--pass); }
.report--invalid { border-left: 6px solid var(--fail); }
.checks { list-style: none; padding: 0; margin: 0; display: grid; gap: 0.75rem; }
.check { border-top: 1px solid var(--line); padding-top: 0.75rem; }
.check p { margin: 0.2rem 0; }
.check-status { display: inline-block; min-width: 7.5rem; font-weight: 700; }
.check--passed .check-status { color: var(--pass); }
.check--failed .check-status { color: var(--fail); }
.check--not-run .check-status { color: var(--skip); }
.check--network .check-status { color: var(--net); }
.check-name { font-weight: 600; }
.check-proves, .check-limits, .limits { color: var(--muted); font-size: 0.95rem; }
.action { background: var(--panel); padding: 0.75rem; border-radius: 6px; overflow-x: auto; font-size: 0.85rem; white-space: pre-wrap; }
.table-wrap { overflow-x: auto; }
.repeated { border-collapse: collapse; width: 100%; font-size: 0.9rem; }
.repeated caption { text-align: left; font-weight: 600; padding: 0.5rem 0; }
.repeated th, .repeated td { border: 1px solid var(--line); padding: 0.35rem 0.5rem; text-align: left; vertical-align: top; }
.check-list, .chain-steps { padding-left: 1.25rem; }
.term-list { padding-left: 1.25rem; display: grid; gap: 0.4rem; }
.term-scitt { display: block; color: var(--muted); font-size: 0.95rem; }
.chain { margin: 1.5rem 0; }
.chain svg { display: block; width: 100%; max-width: 20rem; height: auto; margin: 0 auto; }
.chain-box { fill: var(--panel); stroke: var(--link); stroke-width: 2; }
.chain-label { fill: var(--fg); font: 600 16px system-ui, sans-serif; }
.chain-arrow { fill: none; stroke: var(--muted); stroke-width: 2; }
.chain figcaption { text-align: center; color: var(--muted); font-size: 0.95rem; }
.breadcrumb { margin: 0 0 0.5rem; }
.definition { font-size: 1.15rem; }
.source { color: var(--muted); font-size: 0.95rem; margin-top: 2rem; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.92em; }
.site-footer { border-top: 1px solid var(--line); color: var(--muted); font-size: 0.95rem; padding: 1rem 0 2rem; }
[hidden] { display: none !important; }
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation: none !important; transition: none !important; scroll-behavior: auto !important; }
}
```

`static/img/favicon.svg`:

```xml
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="6" fill="#0b5f4a"/><path d="M9 16.5l4.5 4.5L23 11.5" fill="none" stroke="#fff" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"/></svg>
```

- [ ] **Step 4:** run:

```bash
$PY -m unittest discover -s tests -t .
uvx ruff@0.17.0 check . && uvx ruff@0.17.0 format --check .
```

Expected: `Ran 13 tests`, `OK`; ruff clean.

- [ ] **Step 5:** commit:

```bash
gitleaks git --pre-commit --staged --no-banner   # expect: no leaks found
git commit --author="$A" -m "Pages: check, how it works, and one per term, with CSP and SEO" -m "Every page has lang en-ZA, one h1, a Content Security Policy meta tag with no inline code, no referrer, a unique title, description and canonical, Open Graph, Twitter and JSON-LD metadata, a skip link and landmarks, and reads in full without JavaScript. Only the check page loads the script, with its integrity hash." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 12: build, serve, and the size budget

**Files:**
- Create: `tests/test_build.py`, `tests/test_budget.py`, `build.py`, `serve.py`, `scripts/check_budget.py`

- [ ] **Step 1:** write the tests:

`tests/test_build.py`:

```python
"""build.py: the whole site, byte-identical on a rebuild."""

from __future__ import annotations

import hashlib
import subprocess
import sys
import unittest
from pathlib import Path

from app.pages import all_routes

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"


def snapshot() -> dict[str, str]:
    return {str(p.relative_to(DIST)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(DIST.rglob("*")) if p.is_file()}


class BuildTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        subprocess.run([sys.executable, str(ROOT / "build.py")], check=True, capture_output=True)
        cls.first = snapshot()

    def test_every_route_and_file_is_written(self) -> None:
        for route in all_routes():
            rel = "index.html" if route == "/" else route.strip("/") + "/index.html"
            self.assertIn(rel, self.first)
        for rel in ("404.html", "robots.txt", "sitemap.xml", "static/check.js", "static/styles.css"):
            self.assertIn(rel, self.first)

    def test_the_sitemap_lists_every_route(self) -> None:
        sitemap = (DIST / "sitemap.xml").read_text(encoding="utf-8")
        for route in all_routes():
            self.assertIn(f"<loc>https://christiaan839-beep.github.io/receipts-explorer{route}</loc>", sitemap)

    def test_a_rebuild_is_byte_identical(self) -> None:
        subprocess.run([sys.executable, str(ROOT / "build.py")], check=True, capture_output=True)
        self.assertEqual(snapshot(), self.first)


if __name__ == "__main__":
    unittest.main()
```

`tests/test_budget.py`:

```python
"""scripts/check_budget.py: passes the built site, fails a script over 40 KB compressed."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_budget.py"


class BudgetTest(unittest.TestCase):
    def run_on(self, dist: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run([sys.executable, str(SCRIPT), str(dist)], capture_output=True, text=True, check=False)

    def test_the_built_site_is_within_budget(self) -> None:
        subprocess.run([sys.executable, str(ROOT / "build.py")], check=True, capture_output=True)
        result = self.run_on(ROOT / "dist")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_script_over_40_kb_compressed_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp)
            shutil.copytree(ROOT / "static", dist / "static")
            (dist / "static" / "check.js").write_bytes(os.urandom(41 * 1024))
            result = self.run_on(dist)
            self.assertEqual(result.returncode, 1)
            self.assertIn("over budget: static/check.js", result.stderr)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2:** run `$PY -m unittest discover -s tests -t .`. Expected: fails, `CalledProcessError` from `tests/test_build.py` (there is no `build.py` yet) and exit status 2 from `tests/test_budget.py`.
- [ ] **Step 3:** write the code:

`build.py`:

```python
#!/usr/bin/env python3
"""Writes the site to ./dist, as GitHub Pages serves it under /receipts-explorer/.

Usage:  npm run bundle && python3 build.py

dist/ holds every page, 404.html, static/ (styles, images and check.js),
robots.txt and sitemap.xml. The output depends only on the
sources: no dates, no randomness, so a rebuild is byte-identical.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from app.assets import SCRIPT, hashes  # noqa: E402
from app.content import SITE  # noqa: E402
from app.pages import all_routes, render_not_found, render_route  # noqa: E402

DIST = ROOT / "dist"


def write(rel: str, content: str) -> None:
    path = DIST / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def sitemap() -> str:
    urls = "".join(f"<url><loc>{SITE['base_url']}{p}</loc></url>" for p in all_routes())
    return f'<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{urls}</urlset>\n'


def robots() -> str:
    return f"User-agent: *\nAllow: /\nSitemap: {SITE['base_url']}/sitemap.xml\n"


def main() -> None:
    assets = hashes()
    if DIST.exists():
        shutil.rmtree(DIST)
    DIST.mkdir()
    for route in all_routes():
        html = render_route(route, assets)
        assert html is not None
        write("index.html" if route == "/" else route.strip("/") + "/index.html", html)
    write("404.html", render_not_found(assets))
    shutil.copytree(ROOT / "static", DIST / "static")
    shutil.copyfile(SCRIPT, DIST / "static" / "check.js")
    write("robots.txt", robots())
    write("sitemap.xml", sitemap())
    print(f"Built {len(all_routes())} pages, 404.html, sitemap.xml and robots.txt in {DIST}")


if __name__ == "__main__":
    main()
```

`serve.py`:

```python
#!/usr/bin/env python3
"""The development server, in the standard library only.

Usage:  python3 serve.py [port]           render pages live from app/ (default port 8000)
        python3 serve.py --dist [port]    serve the built dist/, as GitHub Pages does

Both serve the site under /receipts-explorer/, as GitHub Pages does, and
answer unknown paths with the 404 page. Live mode reads static/ and
build/check.js (run npm run bundle first) on every request.
"""

from __future__ import annotations

import posixpath
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from app.assets import SCRIPT, hashes  # noqa: E402
from app.content import SITE  # noqa: E402
from app.pages import render_not_found, render_route  # noqa: E402
from build import DIST, robots, sitemap  # noqa: E402

BASE = SITE["base_path"]
TYPES = {
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".html": "text/html; charset=utf-8",
    ".txt": "text/plain; charset=utf-8",
    ".xml": "application/xml; charset=utf-8",
}


def inside(base: Path, rel: str) -> Path | None:
    """`rel` under `base`, or None if it escapes `base` or is not a file."""
    path = (base / rel).resolve()
    if base.resolve() not in path.parents or not path.is_file():
        return None
    return path


class Handler(BaseHTTPRequestHandler):
    server_version = "receipts-explorer-dev"
    dist = False

    def _send(self, body: bytes | str, status: int = 200, ctype: str = "text/html; charset=utf-8", location: str = "") -> None:
        data = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        if location:
            self.send_header("Location", location)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        path = unquote(urlparse(self.path).path)
        if path in ("/", BASE):
            return self._send("", status=301, location=BASE + "/")
        if not path.endswith("/") and "." not in posixpath.basename(path):
            return self._send("", status=301, location=path + "/")
        if not path.startswith(BASE + "/"):
            return self._not_found()
        rel = path[len(BASE) + 1 :]
        if self.dist:
            return self._file(DIST, rel + "index.html" if rel == "" or rel.endswith("/") else rel)
        if rel == "robots.txt":
            return self._send(robots(), ctype=TYPES[".txt"])
        if rel == "sitemap.xml":
            return self._send(sitemap(), ctype=TYPES[".xml"])
        if rel == "static/check.js":
            return self._send(SCRIPT.read_bytes(), ctype=TYPES[".js"])
        if rel.startswith("static/"):
            return self._file(ROOT, rel)
        html = render_route("/" + rel, hashes())
        if html is None:
            return self._not_found()
        return self._send(html)

    def _file(self, base: Path, rel: str) -> None:
        path = inside(base, rel)
        if path is None:
            return self._not_found()
        ext = posixpath.splitext(path.name)[1]
        return self._send(path.read_bytes(), ctype=TYPES.get(ext, "application/octet-stream"))

    def _not_found(self) -> None:
        if self.dist:
            return self._send((DIST / "404.html").read_bytes(), status=404)
        return self._send(render_not_found(hashes()), status=404)

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        sys.stderr.write("  " + (format % args) + "\n")


def main() -> None:
    args = sys.argv[1:]
    Handler.dist = "--dist" in args
    ports = [a for a in args if a != "--dist"]
    port = int(ports[0]) if ports else 8000
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    mode = "dist/" if Handler.dist else "live render"
    print(f"receipts-explorer ({mode}) -> http://127.0.0.1:{port}{BASE}/   (Ctrl+C to stop)", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.server_close()


if __name__ == "__main__":
    main()
```

`scripts/check_budget.py`:

```python
#!/usr/bin/env python3
"""Fails when the built site is over its size budget.

Usage:  python3 scripts/check_budget.py [dist]

The design's budget is the script: under 40 KB compressed (gzip, level 9,
as a lower bound on what GitHub Pages sends). The stylesheet and each page
have budgets too, because the Largest Contentful Paint target (1.5 s on
fast 3G) leaves room for little more than one page and one stylesheet.
"""

from __future__ import annotations

import gzip
import sys
from pathlib import Path

KB = 1024
BUDGETS = {"static/check.js": 40 * KB, "static/styles.css": 8 * KB}
PAGE_BUDGET = 12 * KB


def compressed(path: Path) -> int:
    return len(gzip.compress(path.read_bytes(), compresslevel=9, mtime=0))


def main() -> int:
    dist = Path(sys.argv[1] if len(sys.argv) > 1 else "dist")
    over = []
    for rel, budget in BUDGETS.items():
        size = compressed(dist / rel)
        print(f"{rel}: {size} bytes compressed (budget {budget})")
        if size > budget:
            over.append(rel)
    for page in sorted(dist.rglob("*.html")):
        size = compressed(page)
        if size > PAGE_BUDGET:
            print(f"{page.relative_to(dist)}: {size} bytes compressed (budget {PAGE_BUDGET})")
            over.append(str(page.relative_to(dist)))
    if over:
        print(f"over budget: {', '.join(over)}", file=sys.stderr)
        return 1
    print("every file is within its budget")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 4:** run:

```bash
npm run bundle
$PY -m unittest discover -s tests -t .
uvx ruff@0.17.0 check . && uvx ruff@0.17.0 format --check .
python3 build.py && python3 scripts/check_budget.py
```

Expected: `Ran 18 tests`, `OK`; ruff clean; `Built 27 pages, 404.html, sitemap.xml and robots.txt` (the count is 3 plus the number of terms in `ontology.md` at `VR_REF`); `static/check.js: 8973 bytes compressed (budget 40960)` (give or take a few bytes), `static/styles.css: 2032 bytes compressed (budget 8192)`, `every file is within its budget`.

- [ ] **Step 5:** look at it (with the sandbox off, since the server binds a port). `python3 serve.py`, then open <http://127.0.0.1:8000/receipts-explorer/>: paste `test/fixtures/conformance/v2-valid-001.json`'s `receipt` and `test/fixtures/conformance/public-key.pem`, press **Check**, and read the seven results (four passed, three not run). Then `python3 serve.py --dist 8080` and open <http://127.0.0.1:8080/receipts-explorer/terms/>. Stop both with Ctrl+C.
- [ ] **Step 6:** commit:

```bash
gitleaks git --pre-commit --staged --no-banner   # expect: no leaks found
git commit --author="$A" -m "build.py and serve.py, and a size budget the build must meet" -m "build.py writes dist/ as GitHub Pages serves it under /receipts-explorer/, byte-identical on a rebuild; serve.py renders live or serves dist/ under the same path. check_budget.py fails the build when check.js is over 40 KB compressed, the stylesheet over 8 KB or a page over 12 KB." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 13: Playwright, every flow of the check page

**Files:**
- Create: `playwright.config.ts`, `e2e/helpers.ts`, `e2e/check.spec.ts`

The tests run against the built `dist/`, served by `serve.py --dist` as GitHub Pages serves it. The log is stubbed with `page.route` from `test/fixtures/log`, with the CORS header receipts-log sends, so no test reaches a live log.

- [ ] **Step 1:** install the browsers (sandbox off):

```bash
npx playwright install chromium firefox webkit
```

- [ ] **Step 2:** write the configuration and the tests:

`playwright.config.ts`:

```ts
// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

// End-to-end tests of the built site (dist/), served as GitHub Pages
// serves it. Development only: nothing here is shipped. The log is
// stubbed with page.route, so no test reaches a live log.
import { defineConfig, devices } from "@playwright/test";

const PORT = 4173;

export default defineConfig({
  testDir: "e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  use: { baseURL: `http://127.0.0.1:${String(PORT)}/receipts-explorer/`, trace: "retain-on-failure" },
  webServer: {
    command: `python3 serve.py --dist ${String(PORT)}`,
    url: `http://127.0.0.1:${String(PORT)}/receipts-explorer/`,
    reuseExistingServer: !process.env.CI,
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "firefox", use: { ...devices["Desktop Firefox"] }, testIgnore: /performance|visual/ },
    { name: "webkit", use: { ...devices["Desktop Safari"] }, testIgnore: /performance|visual/ },
  ],
});
```

`e2e/helpers.ts`:

```ts
// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from "node:fs";

import type { Page, Request } from "@playwright/test";

const fixtures = new URL("../test/fixtures/", import.meta.url);

export function fixture(path: string): string {
  return readFileSync(new URL(path, fixtures), "utf8");
}

export const VALID = JSON.stringify((JSON.parse(fixture("conformance/v2-valid-001.json")) as { receipt: unknown }).receipt);
export const TAMPERED = JSON.stringify((JSON.parse(fixture("conformance/v2-invalid-tampered.json")) as { receipt: unknown }).receipt);
export const ISSUER = fixture("conformance/public-key.pem");
export const LOG_KEY = fixture("log/log-public-key.pem");
export const WITNESSES = ["log/witness-1.pem", "log/witness-2.pem", "log/witness-3.pem"].map(fixture).join("\n");
export const LOG = "https://log.test";

export type Answer = { status: number; file?: string } | "unreachable";

/** The stubbed log: answers by path (query ignored) from test/fixtures/log, with the CORS header receipts-log sends. */
export async function stubLog(page: Page, routes: Record<string, Answer>): Promise<void> {
  await page.unroute(`${LOG}/**`);
  await page.route(`${LOG}/**`, async (route) => {
    const answer = routes[new URL(route.request().url()).pathname] ?? "unreachable";
    if (answer === "unreachable") {
      await route.abort("connectionrefused");
      return;
    }
    await route.fulfill({
      status: answer.status,
      contentType: "application/json",
      headers: { "Access-Control-Allow-Origin": "*" },
      body: answer.file === undefined ? "" : fixture(`log/${answer.file}`),
    });
  });
}

export const HONEST: Record<string, Answer> = {
  "/v1/sth": { status: 200, file: "sth.json" },
  "/v1/proof/inclusion": { status: 200, file: "inclusion.json" },
  "/v1/cosignatures": { status: 200, file: "cosignatures.json" },
};

export async function fill(page: Page, receipt: string, opts: { log?: boolean } = {}): Promise<void> {
  await page.getByLabel("Receipt", { exact: true }).fill(receipt);
  await page.getByLabel("Issuer's public key").fill(ISSUER);
  if (opts.log === true) {
    await page.getByText("Also check the transparency log (optional)").click();
    await page.getByLabel("Log address").fill(LOG);
    await page.getByLabel("Log's public key").fill(LOG_KEY);
    await page.getByLabel("Witness public keys").fill(WITNESSES);
  }
}

/** The status shown for one check of one report, such as "Passed". */
export function statusOf(page: Page, check: string, report = 0): Promise<string> {
  return page
    .locator(".report")
    .nth(report)
    .locator(".check", { has: page.locator(".check-name", { hasText: new RegExp(`^${check}$`) }) })
    .locator(".check-status")
    .innerText();
}

export function recordRequests(page: Page): Request[] {
  const requests: Request[] = [];
  page.on("request", (r) => requests.push(r));
  return requests;
}
```

`e2e/check.spec.ts`:

```ts
// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

// Every flow of the check page, against the stubbed log.
import { expect, test } from "@playwright/test";

import { HONEST, ISSUER, LOG, TAMPERED, VALID, fill, recordRequests, statusOf, stubLog } from "./helpers.ts";

const CHECKS = ["Format", "Signature", "Content hash", "Repeated fields", "Tree head", "In the log", "Witnesses"];

test.beforeEach(async ({ page }) => {
  await page.goto("./");
  await expect(page.locator("#check-form")).toBeVisible();
});

test("a valid receipt, without a log: 1 to 4 pass, 5 to 7 are not run", async ({ page }) => {
  await fill(page, VALID);
  await page.getByRole("button", { name: "Check" }).click();
  await expect(page.getByRole("status")).toHaveText("Checked 1 receipt: 1 valid.");
  await expect(page.getByRole("heading", { name: /^The receipt is valid: signed by sha256:/ })).toBeVisible();
  const got = await Promise.all(CHECKS.map((c) => statusOf(page, c)));
  expect(got).toEqual(["Passed", "Passed", "Passed", "Passed", "Not run", "Not run", "Not run"]);
  await expect(page.locator("#results-heading")).toBeFocused();
  await expect(page.locator("pre.action")).toContainText('"overall": "pass"');
});

test("a tampered receipt is not valid, and the message says what to do", async ({ page }) => {
  await fill(page, TAMPERED);
  await page.getByRole("button", { name: "Check" }).click();
  await expect(page.getByRole("heading", { name: /^The receipt is not valid\./ })).toBeVisible();
  expect(await statusOf(page, "Signature")).toBe("Failed");
  await expect(page.locator(".check-detail").nth(1)).toContainText("Check that you have the issuer's key, not the log's");
  await expect(page.locator("pre.action")).toHaveCount(0);
});

test("missing inputs are listed, linked to their fields and focused", async ({ page }) => {
  await page.getByRole("button", { name: "Check" }).click();
  const problems = page.locator("#problems");
  await expect(problems).toBeFocused();
  await expect(problems.getByRole("link")).toHaveText(["Paste a receipt, or choose a receipt file.", /Paste the issuer's public key/]);
  await expect(page.getByLabel("Receipt", { exact: true })).toHaveAttribute("aria-invalid", "true");
});

test("an honest log: all seven pass, with 2 of 3 witnesses, and only GETs to the log", async ({ page }) => {
  const requests = recordRequests(page);
  await stubLog(page, HONEST);
  await fill(page, VALID, { log: true });
  await page.getByRole("button", { name: "Check" }).click();
  await expect(page.getByRole("status")).toHaveText("Checked 1 receipt: 1 valid.");
  const got = await Promise.all(CHECKS.map((c) => statusOf(page, c)));
  expect(got).toEqual(Array(7).fill("Passed"));
  await expect(page.locator(".check-detail").nth(6)).toHaveText(/^2 of 3 witnesses cosigned a tree head of the log stub-log with 3 entries and this root/);
  const toLog = requests.filter((r) => r.url().startsWith(LOG));
  expect(toLog.map((r) => `${r.method()} ${new URL(r.url()).pathname}`)).toEqual(["GET /v1/sth", "GET /v1/cosignatures", "GET /v1/proof/inclusion"]);
});

test("an unreachable log is a network error with a retry, never a failed check", async ({ page }) => {
  await stubLog(page, {});
  await fill(page, VALID, { log: true });
  await page.getByRole("button", { name: "Check" }).click();
  await expect(page.getByRole("status")).toContainText("The log could not be reached, or was busy; you can try it again.");
  expect(await statusOf(page, "Tree head")).toBe("Network error");
  expect(await statusOf(page, "In the log")).toBe("Not run");
  await stubLog(page, HONEST);
  await page.getByRole("button", { name: "Try the log again" }).click();
  await expect(page.getByRole("status")).toHaveText("Checked 1 receipt: 1 valid.");
  expect(await statusOf(page, "In the log")).toBe("Passed");
  await expect(page.getByRole("button", { name: "Try the log again" })).toBeHidden();
});

test("a busy log (503) is not run, with a retry, never a failed check", async ({ page }) => {
  await stubLog(page, { ...HONEST, "/v1/sth": { status: 503, file: "busy.json" } });
  await fill(page, VALID, { log: true });
  await page.getByRole("button", { name: "Check" }).click();
  await expect(page.getByRole("button", { name: "Try the log again" })).toBeVisible();
  expect(await statusOf(page, "Tree head")).toBe("Not run");
  await expect(page.locator(".check-detail").nth(4)).toContainText("the log is busy or failing (it answered 503: server busy)");
});

test("a forged tree head fails, and the proof and witnesses are not run", async ({ page }) => {
  await stubLog(page, { ...HONEST, "/v1/sth": { status: 200, file: "sth-forged.json" } });
  await fill(page, VALID, { log: true });
  await page.getByRole("button", { name: "Check" }).click();
  await expect(page.getByRole("status")).toHaveText("Checked 1 receipt: 1 valid.");
  expect(await statusOf(page, "Tree head")).toBe("Failed");
  expect(await statusOf(page, "In the log")).toBe("Not run");
  expect(await statusOf(page, "Witnesses")).toBe("Not run");
});

test("a proof that matches its own rootHashHex but not the signed root fails", async ({ page }) => {
  await stubLog(page, { ...HONEST, "/v1/proof/inclusion": { status: 200, file: "inclusion-lying-root.json" } });
  await fill(page, VALID, { log: true });
  await page.getByRole("button", { name: "Check" }).click();
  await expect(page.getByRole("status")).toHaveText("Checked 1 receipt: 1 valid.");
  expect(await statusOf(page, "In the log")).toBe("Failed");
});

test("an array of receipts is checked one by one", async ({ page }) => {
  await fill(page, `[${VALID}, ${TAMPERED}]`);
  await page.getByRole("button", { name: "Check" }).click();
  await expect(page.getByRole("status")).toHaveText("Checked 2 receipts: 1 valid.");
  await expect(page.locator(".report h3")).toHaveText([/^Receipt 1 of 2 is valid/, /^Receipt 2 of 2 is not valid/]);
});

test("a receipt file is read into the field", async ({ page }) => {
  await page.getByLabel("Or choose a receipt file").setInputFiles({ name: "receipt.json", mimeType: "application/json", buffer: Buffer.from(VALID) });
  await expect(page.getByLabel("Receipt", { exact: true })).toHaveValue(VALID);
  await expect(page.getByRole("status")).toHaveText("Read receipt.json.");
});

test("nothing is stored, nothing goes in the address bar, and nothing goes anywhere but the log", async ({ page, baseURL }) => {
  const requests = recordRequests(page);
  await stubLog(page, HONEST);
  const before = page.url();
  await fill(page, VALID, { log: true });
  await page.getByRole("button", { name: "Check" }).click();
  await expect(page.getByRole("status")).toHaveText("Checked 1 receipt: 1 valid.");
  expect(page.url()).toBe(before);
  const stored = await page.evaluate(async () => ({
    local: localStorage.length,
    session: sessionStorage.length,
    cookie: document.cookie,
    databases: "databases" in indexedDB ? (await indexedDB.databases()).length : 0,
  }));
  expect(stored).toEqual({ local: 0, session: 0, cookie: "", databases: 0 });
  const site = new URL(baseURL ?? "").origin;
  for (const r of requests) {
    expect(r.method()).toBe("GET");
    expect([site, LOG]).toContain(new URL(r.url()).origin);
  }
});

test("a browser without WebCrypto Ed25519 is told so, and no checks run", async ({ page }) => {
  await page.addInitScript(() => {
    const original = crypto.subtle.importKey.bind(crypto.subtle);
    crypto.subtle.importKey = ((...args: Parameters<SubtleCrypto["importKey"]>) => {
      const alg = args[2];
      if ((typeof alg === "string" ? alg : alg.name) === "Ed25519") return Promise.reject(new DOMException("NotSupportedError"));
      return original(...args);
    }) as SubtleCrypto["importKey"];
  });
  await page.goto("./");
  await expect(page.getByText("This browser cannot check Ed25519 signatures")).toBeVisible();
  await expect(page.locator("#check-form")).toBeHidden();
});

test("the whole flow works from the keyboard", async ({ page, browserName }) => {
  // WebKit, like Safari, moves Tab past links unless the visitor asks it not to.
  if (browserName !== "webkit") {
    await page.keyboard.press("Tab");
    await expect(page.getByRole("link", { name: "Skip to content" })).toBeFocused();
  }
  await page.getByLabel("Receipt", { exact: true }).focus();
  await page.keyboard.insertText(VALID);
  await page.getByLabel("Issuer's public key").focus();
  await page.keyboard.insertText(ISSUER);
  for (let i = 0; i < 5 && !(await page.getByRole("button", { name: "Check" }).evaluate((b) => b === document.activeElement)); i++) {
    await page.keyboard.press("Tab");
  }
  await expect(page.getByRole("button", { name: "Check" })).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("status")).toHaveText("Checked 1 receipt: 1 valid.");
  await expect(page.locator("#results-heading")).toBeFocused();
});
```

- [ ] **Step 3:** run them before building, so they fail:

```bash
rm -rf dist && npx playwright test --project=chromium e2e/check.spec.ts 2>&1 | tail -3
```

Expected, after a minute: `FileNotFoundError` for `dist/404.html` from the server, then `Error: Timed out waiting 60000ms from config.webServer.` (there is no `dist/` yet).

- [ ] **Step 4:** build and run them in all three browsers (sandbox off):

```bash
npm run typecheck && npx eslint .
npm run build
npx playwright test e2e/check.spec.ts
```

Expected: `39 passed` (13 tests in Chromium, Firefox and WebKit). The prototype ran Chromium only (`13 passed`). If a WebKit test fails in `beforeEach` because the form stays hidden, that WebKit build lacks WebCrypto Ed25519: confirm with `npx playwright test --project=webkit e2e/pages.spec.ts` after Task 14, and if so, skip the check-page flows on WebKit with `test.skip(browserName === "webkit", "this WebKit build has no WebCrypto Ed25519")` in `beforeEach`, keeping the no-Ed25519 test, and note it in the pull request.

- [ ] **Step 5:** commit:

```bash
gitleaks git --pre-commit --staged --no-banner   # expect: no leaks found
git commit --author="$A" -m "Playwright: every flow of the check page, against a stubbed log" -m "Valid, tampered, missing inputs, an honest log, an unreachable log and a busy (503) log, each with a retry, a forged tree head, a proof that lies about its root, an array, a file, keyboard only, no Ed25519; and nothing stored, nothing in the address bar, only GETs to the log." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 14: accessibility, CSP, no JavaScript, screenshots and LCP

**Files:**
- Create: `e2e/pages.spec.ts`, `e2e/visual.spec.ts`, `e2e/performance.spec.ts`

- [ ] **Step 1:** write the tests:

`e2e/pages.spec.ts`:

```ts
// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

// Every page, in light and dark: no axe violations (WCAG 2.2 AA), no
// horizontal scrolling at 320 px, no Content Security Policy violation;
// readable without JavaScript; the script runs only with its own hash.
import { readFileSync } from "node:fs";

import { AxeBuilder } from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import { HONEST, VALID, fill, stubLog } from "./helpers.ts";

const BASE = "/receipts-explorer";
const SITEMAP = readFileSync(new URL("../dist/sitemap.xml", import.meta.url), "utf8");
const ROUTES = [...SITEMAP.matchAll(/<loc>[^<]*?\/receipts-explorer(\/[^<]*)<\/loc>/g)].map((m) => m[1] ?? "/");
const WCAG = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];

async function axe(page: Page): Promise<void> {
  const { violations } = await new AxeBuilder({ page }).withTags(WCAG).analyze();
  expect(violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(" ")).join(", ")}`)).toEqual([]);
}

test("the sitemap lists the pages", () => {
  expect(ROUTES).toContain("/");
  expect(ROUTES).toContain("/terms/receipt/");
  expect(ROUTES.length).toBeGreaterThan(20);
});

for (const scheme of ["light", "dark"] as const) {
  test.describe(`${scheme} mode`, () => {
    test.use({ colorScheme: scheme });

    test("every page passes axe and has no horizontal scroll at 320 px", async ({ page }) => {
      await page.setViewportSize({ width: 320, height: 640 });
      for (const route of ROUTES) {
        await page.goto(`.${route}`);
        await axe(page);
        const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
        expect(overflow, route).toBeLessThanOrEqual(0);
      }
    });

    test("the results pass axe too", async ({ page }) => {
      await stubLog(page, { ...HONEST, "/v1/proof/inclusion": "unreachable" });
      await page.goto("./");
      await fill(page, `[${VALID}, {"canonical": "x"}]`, { log: true });
      await page.getByRole("button", { name: "Check" }).click();
      await expect(page.getByRole("status")).toContainText("Checked 2 receipts");
      await axe(page);
    });
  });
}

test("no page breaks its Content Security Policy, and inline script does not run", async ({ page }) => {
  await page.addInitScript(() => {
    (window as unknown as { violations: string[] }).violations = [];
    document.addEventListener("securitypolicyviolation", (e) => {
      (window as unknown as { violations: string[] }).violations.push(`${e.violatedDirective} ${e.blockedURI}`);
    });
  });
  for (const route of ROUTES) {
    await page.goto(`.${route}`);
    expect(await page.evaluate(() => (window as unknown as { violations: string[] }).violations), route).toEqual([]);
  }
  const ran = await page.evaluate(async () => {
    const s = document.createElement("script");
    s.textContent = "window.inlineRan = true";
    document.body.append(s);
    await new Promise((r) => setTimeout(r, 50));
    return (window as unknown as { inlineRan?: boolean }).inlineRan === true;
  });
  expect(ran).toBe(false);
});

test("a changed script is refused by its integrity hash, and the form stays hidden", async ({ page }) => {
  await page.route(`**${BASE}/static/check.js`, async (route) => {
    const response = await route.fetch();
    await route.fulfill({ response, body: (await response.text()) + "\n// changed" });
  });
  await page.goto("./");
  await expect(page.locator("#check-form")).toBeHidden();
});

test.describe("without JavaScript", () => {
  test.use({ javaScriptEnabled: false });

  test("the check page explains itself and says checking needs JavaScript", async ({ page }) => {
    await page.goto("./");
    await expect(page.getByRole("heading", { level: 1 })).toHaveText("Check a receipt");
    // Playwright turns script execution off but not the parser's scripting
    // flag, so <noscript> is not rendered here; check it is in the page.
    expect(await page.locator("noscript").innerHTML()).toContain("Checking needs JavaScript, which is off.");
    await expect(page.getByRole("heading", { name: "The seven checks" })).toBeVisible();
    await expect(page.locator("#check-form")).toBeHidden();
  });

  test("a term page reads in full", async ({ page }) => {
    await page.goto("./terms/inclusion-proof/");
    await expect(page.getByRole("heading", { level: 1 })).toHaveText("Inclusion proof");
    await expect(page.locator(".definition")).toContainText("audit path");
  });
});
```

`e2e/visual.spec.ts`:

```ts
// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

// Screenshots of the check page, with results, at 320, 768 and 1440 px in
// light and dark, attached to the report for review. Each must fit its
// width without horizontal scrolling.
import { expect, test } from "@playwright/test";

import { HONEST, TAMPERED, VALID, fill, stubLog } from "./helpers.ts";

for (const scheme of ["light", "dark"] as const) {
  for (const width of [320, 768, 1440]) {
    test(`check page at ${String(width)} px, ${scheme}`, async ({ page }, info) => {
      await page.emulateMedia({ colorScheme: scheme, reducedMotion: "reduce" });
      await page.setViewportSize({ width, height: 900 });
      await stubLog(page, HONEST);
      await page.goto("./");
      await fill(page, `[${VALID}, ${TAMPERED}]`, { log: true });
      await page.getByRole("button", { name: "Check" }).click();
      await expect(page.getByRole("status")).toHaveText("Checked 2 receipts: 1 valid.");
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
      expect(overflow).toBeLessThanOrEqual(0);
      await info.attach(`check-${String(width)}-${scheme}.png`, { body: await page.screenshot({ fullPage: true }), contentType: "image/png" });
    });
  }
}
```

`e2e/performance.spec.ts`:

```ts
// Copyright 2026 Christiaan de Wet / Sovereign Matrix
// SPDX-License-Identifier: Apache-2.0

// Largest Contentful Paint of every page under 1.5 s on a mid-range phone
// over fast 3G: Chrome DevTools' "Fast 3G" network profile (562.5 ms
// round trip, 1.44 Mbit/s down, 675 kbit/s up) and a CPU four times slower.
import { expect, test } from "@playwright/test";

const ROUTES = ["./", "./how-it-works/", "./terms/", "./terms/inclusion-proof/"];

test.use({ viewport: { width: 412, height: 915 }, deviceScaleFactor: 2.625, isMobile: true, hasTouch: true });

for (const route of ROUTES) {
  test(`LCP of ${route} is under 1.5 s on fast 3G`, async ({ page }) => {
    const cdp = await page.context().newCDPSession(page);
    await cdp.send("Network.enable");
    await cdp.send("Network.setCacheDisabled", { cacheDisabled: true });
    await cdp.send("Network.emulateNetworkConditions", {
      offline: false,
      latency: 562.5,
      downloadThroughput: (1.44 * 1_000_000) / 8,
      uploadThroughput: (675 * 1_000) / 8,
    });
    await cdp.send("Emulation.setCPUThrottlingRate", { rate: 4 });
    await page.goto(route, { waitUntil: "load" });
    const lcp = await page.evaluate(
      () =>
        new Promise<number>((resolve) => {
          new PerformanceObserver((list) => {
            const entries = list.getEntries();
            resolve(entries[entries.length - 1]?.startTime ?? Number.POSITIVE_INFINITY);
          }).observe({ type: "largest-contentful-paint", buffered: true });
        }),
    );
    console.log(`${route}: LCP ${lcp.toFixed(0)} ms`);
    expect(lcp).toBeLessThan(1500);
  });
}
```

- [ ] **Step 2:** run them (sandbox off):

```bash
npm run typecheck && npx eslint .
npm run build
npx playwright test
```

Expected: `76 passed`: Chromium 32 (13 flows, 9 page tests, 6 screenshots, 4 LCP), Firefox 22 and WebKit 22 (no screenshots or LCP). The LCP lines print about 1270 to 1290 ms each. The prototype ran Chromium only (`32 passed`).

- [ ] **Step 3:** prove the axe test catches a contrast failure: in `static/styles.css`, set `--muted: #9aa1a6;` in the light block, rebuild, run `npx playwright test --project=chromium e2e/pages.spec.ts`, and confirm `color-contrast` in the failure. Restore the value.
- [ ] **Step 4:** look at the screenshots: `npx playwright show-report`, open each `check page at … px` test, and read its attachment: no text cut off, nothing overlapping, focus outlines visible in both schemes.
- [ ] **Step 5:** commit:

```bash
gitleaks git --pre-commit --staged --no-banner   # expect: no leaks found
git commit --author="$A" -m "Playwright: axe on every page in light and dark, CSP, no JS, LCP" -m "Every page in the sitemap passes axe (WCAG 2.2 AA tags) in light and dark and has no horizontal scroll at 320 px; no page breaks its CSP, and injected inline script does not run; a changed check.js is refused by its integrity hash; the pages read without JavaScript; screenshots at 320, 768 and 1440 px in both schemes; LCP under 1.5 s on fast 3G with a 4x slower CPU." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 15: CI, the deploy and the supply chain

**Files:**
- Create: `.github/workflows/ci.yml`, `.github/workflows/codeql.yml`, `.github/workflows/zizmor.yml`, `.github/workflows/scorecard.yml`, `.github/workflows/deploy.yml`, `.github/dependabot.yml`, `.github/tools/python-ci/requirements.in`; generated: `.github/tools/python-ci/requirements.txt`

Actions are pinned to the same full SHAs as the other three repositories where they share an action. The Pages actions are pinned to their newest releases older than 14 days: `upload-pages-artifact` v5.0.0 (`fc324d3…`, 10 April 2026) and `deploy-pages` v5.0.1 (`368f825…`, 1 September 2026). `configure-pages` is not used: nothing reads its outputs.

- [ ] **Step 1:** write the workflows and the Dependabot settings:

`.github/workflows/ci.yml`:

```yaml
# The drift check against verifiable-receipts, the TypeScript checks, the
# Python site, the size budget and the Playwright tests, on every push and
# pull request. No job calls a live log: the tests serve recorded answers.
#
# Actions are pinned to full commit SHAs (the tag each SHA had when pinned is
# in the comment). The token is read-only and checkout does not keep it.
name: ci
on:
  push:
  pull_request:
  workflow_call:
permissions:
  contents: read # check out the code
# Keyed on the calling workflow too, so a push to main's own run never
# cancels the run deploy.yml makes; only pull request runs are superseded.
concurrency:
  group: ${{ github.workflow }}-ci-${{ github.ref }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}
jobs:
  vendor:
    name: Vendored copies match verifiable-receipts
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          repository: christiaan839-beep/verifiable-receipts
          ref: main
          fetch-depth: 0
          path: upstream
          persist-credentials: false
      - name: VR_REF is on main
        run: |
          set -euo pipefail
          ref=$(cat third_party/verifiable-receipts/VR_REF)
          [[ "$ref" =~ ^[0-9a-f]{40}$ ]] || { echo "::error::VR_REF must be one full commit SHA"; exit 1; }
          git -C upstream merge-base --is-ancestor "$ref" HEAD || { echo "::error::VR_REF $ref is not on main"; exit 1; }
          git -C upstream checkout -q "$ref"
      - run: bash scripts/check-vendor.sh upstream

  check:
    name: Check (Node ${{ matrix.node }})
    runs-on: ubuntu-latest
    timeout-minutes: 15
    strategy:
      fail-fast: false
      matrix:
        node: [22, 24] # the supported LTS lines; engines starts at 22.18
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1 # v7.1.0
        with:
          node-version: ${{ matrix.node }}
      - run: npm ci
      - run: npm run typecheck
      - run: npm run lint
      - name: Unit and property tests, 2000 cases per property
        env:
          FC_NUM_RUNS: "2000"
        run: npm test
      - run: npm audit --audit-level=moderate
      - run: npm run bundle

  site:
    name: Site (Python 3.12)
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1 # v7.1.0
        with:
          node-version: 24
      - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0
        with:
          python-version: "3.12"
      - run: python -m pip install --require-hashes --no-deps -r .github/tools/python-ci/requirements.txt
      - run: ruff check .
      - run: ruff format --check .
      - run: npm ci
      - run: npm run build
      - run: python -m unittest discover -s tests -t .
      - name: The script is under 40 KB compressed, and the pages and styles within budget
        run: python scripts/check_budget.py dist

  e2e:
    name: End to end (Playwright)
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1 # v7.1.0
        with:
          node-version: 24
      - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0
        with:
          python-version: "3.12"
      - run: npm ci
      - run: npx playwright install --with-deps chromium firefox webkit
      - run: npm run build
      - run: npx playwright test
      - if: ${{ !cancelled() }}
        uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        with:
          name: playwright-report
          path: playwright-report/
          retention-days: 14
```

`.github/workflows/deploy.yml`:

```yaml
# Publishes the site to GitHub Pages from main: runs CI, builds dist/,
# checks the size budget, attests the build provenance of every file it
# deploys, and deploys. Only main can deploy (the github-pages environment
# allows main only).
#
# Actions are pinned to full commit SHAs (the tag each SHA had when pinned
# is in the comment). Every job starts with no token permissions and asks
# only for what it uses.
name: deploy
on:
  push:
    branches: [main]
permissions: {}
concurrency:
  group: pages
  cancel-in-progress: false
jobs:
  ci:
    name: CI
    uses: $/.github/workflows/ci.yml
    permissions:
      contents: read # check out the code to test

  build:
    name: Build and attest
    needs: ci
    runs-on: ubuntu-latest
    timeout-minutes: 15
    permissions:
      contents: read # check out the code
      id-token: write # sign the provenance attestation (Sigstore)
      attestations: write # store the attestation on GitHub
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1 # v7.1.0
        with:
          node-version: 24
      - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0
        with:
          python-version: "3.12"
      - run: npm ci
      - run: npm run build
      - run: python scripts/check_budget.py dist
      - uses: actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8 # v4.2.2
        with:
          subject-path: dist/**
      - uses: actions/upload-pages-artifact@fc324d3547104276b827a68afc52ff2a11cc49c9 # v5.0.0
        with:
          path: dist

  deploy:
    name: Deploy to GitHub Pages
    needs: build
    runs-on: ubuntu-latest
    timeout-minutes: 10
    permissions:
      pages: write # deploy to Pages
      id-token: write # prove the deployment came from this workflow
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    steps:
      - id: deployment
        uses: actions/deploy-pages@368f82528645a54fb793d4d04e342629a3f51346 # v5.0.1
```

`.github/workflows/codeql.yml`:

```yaml
# CodeQL code scanning with the security-extended queries, for the
# TypeScript checks, the Python site and the workflows themselves.
name: codeql
on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: "17 3 * * 2"
permissions: {}
concurrency:
  group: codeql-${{ github.ref }}
  cancel-in-progress: true
jobs:
  analyze:
    name: Analyze (${{ matrix.language }})
    runs-on: ubuntu-latest
    timeout-minutes: 30
    permissions:
      contents: read # check out the code
      actions: read # read the workflow run for the analysis
      security-events: write # upload the results to code scanning
    strategy:
      fail-fast: false
      matrix:
        language: [actions, javascript-typescript, python]
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: github/codeql-action/init@24c54180a607b1449ed407dd24f251e4e9147c8d # v4.38.3
        with:
          languages: ${{ matrix.language }}
          build-mode: none
          queries: security-extended
      - uses: github/codeql-action/analyze@24c54180a607b1449ed407dd24f251e4e9147c8d # v4.38.3
        with:
          category: /language:${{ matrix.language }}
```

`.github/workflows/zizmor.yml`:

```yaml
# zizmor: static analysis of these workflows for injection, over-broad
# permissions, unpinned actions and credential leaks. Findings go to code
# scanning.
name: zizmor
on:
  push:
    branches: [main]
  pull_request:
permissions: {}
concurrency:
  group: zizmor-${{ github.ref }}
  cancel-in-progress: true
jobs:
  zizmor:
    name: Audit the workflows
    runs-on: ubuntu-latest
    timeout-minutes: 10
    permissions:
      contents: read # check out the workflows
      actions: read # read the workflow run for the upload
      security-events: write # upload the findings to code scanning
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: zizmorcore/zizmor-action@cc914d7f3750a2d13d75c7f184a1060aa0e9d482 # v0.6.4
        with:
          version: 1.30.1
          persona: pedantic
```

`.github/workflows/scorecard.yml`:

```yaml
# OpenSSF Scorecard: checks this repository's security practices weekly and
# on every push to main, publishes the result to the public Scorecard API
# (the README badge) and uploads it to code scanning.
name: scorecard
on:
  branch_protection_rule:
  schedule:
    - cron: "23 4 * * 1"
  push:
    branches: [main]
permissions: {}
concurrency:
  group: scorecard-${{ github.ref }}
  cancel-in-progress: true
jobs:
  analysis:
    name: Scorecard analysis
    runs-on: ubuntu-latest
    timeout-minutes: 15
    permissions:
      contents: read # check out the code
      actions: read # read workflow runs for the CI-Tests check
      security-events: write # upload the results to code scanning
      id-token: write # publish the results to the Scorecard API
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: ossf/scorecard-action@2d1146689b8cda280b9bc96326124645441f03bc # v2.4.4
        with:
          results_file: results.sarif
          results_format: sarif
          publish_results: true
      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        with:
          name: scorecard
          path: results.sarif
          retention-days: 5
      - uses: github/codeql-action/upload-sarif@24c54180a607b1449ed407dd24f251e4e9147c8d # v4.38.3
        with:
          sarif_file: results.sarif
```

`.github/dependabot.yml`:

```yaml
# Weekly updates, grouped per ecosystem. A release must be 14 days old
# before Dependabot proposes it, so a compromised release has time to be
# caught and pulled first. Security updates are not delayed. Every npm
# package is a development tool; nothing from npm is shipped except what
# esbuild bundles from src/, which has no dependencies.
version: 2
updates:
  - package-ecosystem: github-actions
    directory: /
    schedule:
      interval: weekly
    cooldown:
      default-days: 14
    groups:
      actions:
        patterns: ["*"]
  - package-ecosystem: npm
    directory: /
    schedule:
      interval: weekly
    cooldown:
      default-days: 14
    ignore:
      # The types follow the oldest Node the tests support (engines).
      - dependency-name: "@types/node"
        update-types: ["version-update:semver-major"]
    groups:
      npm-development:
        dependency-type: development
  - package-ecosystem: pip
    directory: /.github/tools/python-ci
    schedule:
      interval: weekly
    cooldown:
      default-days: 14
```

`zizmor.yml` and `scorecard.yml` are receipts-log's, unchanged. The `vendor` job checks that `VR_REF` is on `main`, checks it out, and runs `scripts/check-vendor.sh` against that checkout, which also requires the checkout's `HEAD` to be `VR_REF`.

- [ ] **Step 2:** pin ruff by hash, with packages at least 14 days old (replace the date with today minus 14 days):

`.github/tools/python-ci/requirements.in`:

```text
# The Python tools CI installs, by hash. The site itself needs only the
# standard library. Regenerate requirements.txt after a change here with:
#   uv pip compile --generate-hashes --python-version 3.12 --exclude-newer <14 days ago> -o requirements.txt requirements.in
ruff==0.17.0
```

```bash
cd .github/tools/python-ci
uv pip compile --generate-hashes --python-version 3.12 --exclude-newer 2026-10-10 -o requirements.txt requirements.in
grep -c -- '--hash=sha256:' requirements.txt
cd ../../..
VENV=$(mktemp -d)/venv && /opt/homebrew/bin/python3.12 -m venv $VENV
$VENV/bin/pip install --require-hashes --no-deps -r .github/tools/python-ci/requirements.txt
$VENV/bin/ruff check . && $VENV/bin/ruff format --check .
```

Expected (with 2026-10-10): `ruff==0.17.0` and `18` hashes; the install succeeds; ruff clean.

- [ ] **Step 3:** audit the workflows:

```bash
uvx zizmor@1.30.1 --persona pedantic --no-online-audits .github/
```

Expected: `No findings to report. Good job!`. (`deploy.yml` calls CI as `$/.github/workflows/ci.yml`, zizmor's self-repository syntax.)

- [ ] **Step 4:** run what CI's jobs run, locally (sandbox off):

```bash
UP=$(mktemp -d) && git -C $VR archive "$(cat third_party/verifiable-receipts/VR_REF)" | tar -x -C "$UP" && bash scripts/check-vendor.sh "$UP"
npm ci && npm run typecheck && npm run lint && FC_NUM_RUNS=2000 npm test 2>&1 | grep -E '^# (pass|fail)' && npm audit --audit-level=moderate
npm run build && $PY -m unittest discover -s tests -t . && python3 scripts/check_budget.py dist
npx playwright test 2>&1 | tail -1
```

Expected: the `matches` line; `# pass 116`, `# fail 0`, `found 0 vulnerabilities`; `Ran 18 tests` `OK`, `every file is within its budget`; `76 passed`.

- [ ] **Step 5:** commit:

```bash
gitleaks git --pre-commit --staged --no-banner   # expect: no leaks found
git commit --author="$A" -m "CI, deploy to Pages with provenance, CodeQL, zizmor, Scorecard" -m "ci.yml: the drift check against VR_REF, type check, lint, tests at 2000 cases per property and npm audit on Node 22 and 24, the Python site with ruff by hash, the size budget, and Playwright in three browsers. deploy.yml: on main only, CI, build, budget, provenance for every file in dist/, then Pages. Actions pinned to full SHAs at least 14 days old; Dependabot with a 14-day cooldown." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 16: the docs

**Files:**
- Create: `README.md`, `CONTRIBUTING.md`, `SECURITY.md`

- [ ] **Step 1:** write them:

`README.md`:

````markdown
# receipts-explorer

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/christiaan839-beep/receipts-explorer/badge)](https://scorecard.dev/viewer/?uri=github.com/christiaan839-beep/receipts-explorer)

A web page that checks a [verifiable receipt](https://github.com/christiaan839-beep/verifiable-receipts)
in your browser: that the issuer signed exactly this text, that the receipt
does not contradict itself, and, given a [receipts-log](https://github.com/christiaan839-beep/receipts-log)
address, that the receipt is in the log and that witnesses saw the same log.

**<https://christiaan839-beep.github.io/receipts-explorer/>**

Nothing is uploaded. Receipts and keys stay in the browser tab; the page
sends only GET requests, and only to the log address you type.

## The seven checks

1. **Format**: a v2 receipt, its signature in the one valid spelling.
2. **Signature**: valid under the issuer key you give, named by fingerprint.
3. **Content hash**: matches the signed text.
4. **Repeated fields**: each equals the signed text.
5. **Tree head**: the log's latest tree head (`GET /v1/sth`), signed by the log key you give.
6. **In the log**: an inclusion proof for the receipt (`GET /v1/proof/inclusion`), checked against the signed root.
7. **Witnesses**: how many of the witness keys you give cosigned a tree head with that log, size and root, at any timestamp (`GET /v1/cosignatures`).

Each is passed, failed or not run. A check that cannot run is never shown
as passed, and a network error is never shown as a verdict.

## How it is built

- **Pages**: Python 3 standard library only (`app/content.py`, `app/ontology.py`,
  `app/layout.py`, `app/pages.py`; `serve.py`; `build.py` writes `dist/`).
  Python 3.9 or later; CI uses 3.12.
- **Checks**: one TypeScript bundle, `static/check.js`, built with esbuild, with
  no runtime dependencies and WebCrypto's Ed25519. Its verifier is a browser
  port of verifiable-receipts' at a pinned commit (`third_party/verifiable-receipts/`).
- **Hosting**: GitHub Pages, deployed by `.github/workflows/deploy.yml`, which
  attests the build provenance of every file. A Content Security Policy
  allows scripts and styles from the site only, and no inline code.

## Run it

```bash
npm ci
npm run bundle            # build/check.js
python3 serve.py          # live render at http://127.0.0.1:8000/receipts-explorer/
npm run check             # type check, lint, unit tests, build, size budget
npx playwright install chromium firefox webkit
npm run e2e               # Playwright and axe against dist/
```

## Licence

Apache-2.0. See `LICENSE`, and `third_party/verifiable-receipts/` for the
vendored code.
````

`CONTRIBUTING.md`:

````markdown
# Contributing

Thank you for helping. receipts-explorer is a static page that checks
verifiable receipts in the browser.

## Reporting

- **A security flaw**: report it privately, as `SECURITY.md` says. Don't open a public issue.
- **A bug**: open an issue with the browser and its version, the receipt and keys
  that show it (test keys only), what you expected and what happened.

## Changing code

1. Fork, branch from `main`, and open a pull request. CI must pass and every
   review conversation must be resolved before it merges; `main` takes merge
   commits only.
2. `src/vendor/verifiable-receipts/` is a browser port of the verifiable-receipts
   verifier. Change the verifier there first; then move
   `third_party/verifiable-receipts/VR_REF` to the new commit, copy the files
   `third_party/verifiable-receipts/README.md` lists, bring the port up to date,
   and rewrite `SHA256SUMS`. The `vendor` job checks every copy against `VR_REF`.
3. The page sends nothing anywhere but the log address the visitor types, stores
   nothing, and never parses input as HTML. ESLint enforces this in `src/`; keep it so.

## The checks CI runs

```bash
npm ci
npm run check                                   # tsc, eslint, node --test, build, budget
python3 -m unittest discover -s tests -t .      # the Python site
ruff check . && ruff format --check .           # from .github/tools/python-ci, by hash
npx playwright test                             # needs the browsers: npx playwright install
uvx zizmor@1.30.1 --persona pedantic .github/
```

## Style

- Plain, declarative prose in docs, comments and messages; each fact once.
  Every message says what is wrong and what to do.
- Commit messages: a subject line under 72 characters, a blank line, then what
  changed and why.
- No runtime dependencies in the bundle, and none beyond the standard library in Python.

By contributing you agree that your contribution is licensed under the Apache
License 2.0 (`LICENSE`).
````

`SECURITY.md`:

```markdown
# Security

## Reporting a vulnerability

Report a suspected flaw privately, through a GitHub security advisory:
<https://github.com/christiaan839-beep/receipts-explorer/security/advisories/new>
(the repository's **Security** tab, then **Report a vulnerability**).
Don't open a public issue for it.

If you cannot use GitHub, email `sovereign.systems007@gmail.com` with
`[security]` at the start of the subject.

Please include the browser and its version, what you expected and what
happened, and the receipt, keys and log answers that show it, using test
keys only, never a key in real use.

You should get a first reply within seven days. A fix is developed in the
private advisory, and the advisory is published with the deploy that fixes
it, crediting you unless you ask otherwise.

## Scope

In scope: anything that makes the page show a check as passed when it
should fail or did not run; trust a log's own `rootHashHex`; send a
visitor's receipt, keys or anything else to a host other than the log
address they typed, or with a method other than GET; store or put in the
address bar anything a visitor gives; run script the build did not ship;
or hang on input a visitor or a log can supply.

Out of scope: a compromised issuer, log or witness key; a visitor given the
wrong key out of band; and browser or WebCrypto bugs (report those to the
browser's maker).

## Supported versions

Only the deployed site and `main` are supported. Every deploy is built
from `main` in CI with signed provenance for each file
(`.github/workflows/deploy.yml`).
```

- [ ] **Step 2:** check each claim against the code: the seven checks and their routes against `src/checks.ts` and `src/log-client.ts`; the commands against `package.json`; the scope in `SECURITY.md` against `e2e/check.spec.ts` ("nothing is stored …") and `test/checks.test.ts`.
- [ ] **Step 3:** commit:

```bash
gitleaks git --pre-commit --staged --no-banner   # expect: no leaks found
git commit --author="$A" -m "Docs: README, CONTRIBUTING and SECURITY" -m "What the page checks and what it does with a receipt, how it is built and tested, how to change the vendored verifier, and how to report a flaw." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 17: the GitHub repository, Pages and the ruleset (`gh`, sandbox off)

**Files:** none. Every step is an API call or a push. Settings match receipts-log's, read from its API on 23 October 2026.

- [ ] **Step 1:** create the repository, empty, and set it up before anything is pushed:

```bash
R=christiaan839-beep/receipts-explorer
gh repo create $R --public --disable-wiki \
  --description "Check a verifiable receipt, and its place in a transparency log, in your browser. Nothing is uploaded." \
  --homepage "https://christiaan839-beep.github.io/receipts-explorer/"
gh api -X PATCH repos/$R -F allow_merge_commit=true -F allow_squash_merge=false -F allow_rebase_merge=false \
  -F delete_branch_on_merge=true -F allow_auto_merge=false -F has_projects=false
gh api -X PATCH repos/$R --input - <<'EOF'
{"security_and_analysis": {"secret_scanning": {"status": "enabled"}, "secret_scanning_push_protection": {"status": "enabled"}}}
EOF
gh api -X PUT repos/$R/vulnerability-alerts
gh api -X PUT repos/$R/automated-security-fixes
gh api -X PUT repos/$R/private-vulnerability-reporting
gh api -X PUT repos/$R/actions/permissions -F enabled=true -f allowed_actions=all -F sha_pinning_required=true
gh api -X PUT repos/$R/actions/permissions/workflow -f default_workflow_permissions=read -F can_approve_pull_request_reviews=false
```

- [ ] **Step 2:** turn on Pages, deployed by workflow, and let only `main` deploy:

```bash
gh api -X POST repos/$R/pages -f build_type=workflow
gh api -X PUT repos/$R/environments/github-pages --input - <<'EOF'
{"deployment_branch_policy": {"protected_branches": false, "custom_branch_policies": true}}
EOF
gh api -X POST repos/$R/environments/github-pages/deployment-branch-policies -f name=main -f type=branch
gh api repos/$R/pages --jq '.build_type + " " + .html_url'
```

Expected: `workflow https://christiaan839-beep.github.io/receipts-explorer/`.

- [ ] **Step 3:** push `main` (the licence only) and set the rulesets, the same as receipts-log's with this repository's checks:

```bash
cd ~/Projects/receipts-explorer
git remote add origin https://github.com/$R.git
git push -u origin main
gh api -X POST repos/$R/rulesets --input - <<'EOF'
{
  "name": "main",
  "target": "branch",
  "enforcement": "active",
  "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
  "bypass_actors": [],
  "rules": [
    {"type": "deletion"},
    {"type": "non_fast_forward"},
    {"type": "pull_request", "parameters": {
      "allowed_merge_methods": ["merge"],
      "dismiss_stale_reviews_on_push": true,
      "require_code_owner_review": false,
      "require_last_push_approval": false,
      "required_approving_review_count": 0,
      "required_review_thread_resolution": true}},
    {"type": "required_status_checks", "parameters": {
      "strict_required_status_checks_policy": true,
      "do_not_enforce_on_create": false,
      "required_status_checks": [
        {"context": "Vendored copies match verifiable-receipts", "integration_id": 15368},
        {"context": "Check (Node 22)", "integration_id": 15368},
        {"context": "Check (Node 24)", "integration_id": 15368},
        {"context": "Site (Python 3.12)", "integration_id": 15368},
        {"context": "End to end (Playwright)", "integration_id": 15368},
        {"context": "Analyze (actions)", "integration_id": 15368},
        {"context": "Analyze (javascript-typescript)", "integration_id": 15368},
        {"context": "Analyze (python)", "integration_id": 15368},
        {"context": "Audit the workflows", "integration_id": 15368}]}},
    {"type": "code_scanning", "parameters": {"code_scanning_tools": [
      {"tool": "CodeQL", "alerts_threshold": "errors", "security_alerts_threshold": "high_or_higher"},
      {"tool": "zizmor", "alerts_threshold": "errors", "security_alerts_threshold": "high_or_higher"}]}}
  ]
}
EOF
gh api -X POST repos/$R/rulesets --input - <<'EOF'
{"name": "release tags", "target": "tag", "enforcement": "active",
 "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}}, "bypass_actors": [],
 "rules": [{"type": "deletion"}, {"type": "non_fast_forward"}, {"type": "update"}]}
EOF
gh api repos/$R/rulesets --jq '.[].name'
```

Expected: `main` and `release tags`. `integration_id` 15368 is GitHub Actions. `main` holds no workflows yet, so its push runs nothing.

- [ ] **Step 4:** push the branch and open the pull request:

```bash
git push -u origin feat/explorer
gh pr create --base main --head feat/explorer --title "receipts-explorer: check a receipt in the browser" --body-file - <<'EOF'
The proof explorer of verifiable-receipts' design (docs/design/2026-10-23-ontology-and-proof-explorer.md, Part 2), built by Plan 3.

- Seven checks in the browser: format, signature, content hash, repeated fields, the log's tree head, the receipt's inclusion proof against the signed root, and witness cosignatures. Each is passed, failed or not run; a network error is never a verdict.
- The verifier is a WebCrypto port of verifiable-receipts at VR_REF; CI keeps every vendored file byte-identical and runs the port beside the original on random receipts.
- Pages from the Python standard library, readable without JavaScript, with a CSP that allows no inline code, SRI on the script, lang en-ZA and full metadata.
- Tests: node --test with fast-check, Python unittest, Playwright with axe in Chromium, Firefox and WebKit against recorded log answers; LCP under 1.5 s on fast 3G; the script under 40 KB compressed.
- Deploys to GitHub Pages from main with build provenance for every file.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
```

- [ ] **Step 5:** wait for every required check, read any failure, fix it on the branch, and merge with a merge commit once green:

```bash
gh pr checks --watch
gh pr merge --merge
```

Never squash. The merge starts `deploy.yml` on `main`.

- [ ] **Step 6:** confirm the deploy and the provenance:

```bash
gh run watch "$(gh run list -R $R --workflow deploy.yml --branch main --limit 1 --json databaseId --jq '.[0].databaseId')" --exit-status
curl -sI https://christiaan839-beep.github.io/receipts-explorer/ | head -1
curl -s https://christiaan839-beep.github.io/receipts-explorer/static/check.js -o "$TMPDIR/check.js"
gh attestation verify "$TMPDIR/check.js" -R $R
```

Expected: the run succeeds; `HTTP/2 200`; `Verification succeeded!`. Then open the page, check `v2-valid-001.json` with `public-key.pem` from the conformance fixtures, and read four checks passed and three not run.

- [ ] **Step 7:** in verifiable-receipts, open a follow-up pull request that links the explorer from `README.md` and `docs/ontology.md`'s introduction; it is not part of this plan's repository.
