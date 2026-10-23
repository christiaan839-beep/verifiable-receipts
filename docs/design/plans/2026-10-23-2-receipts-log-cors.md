# receipts-log: cross-origin reads (CORS): implementation plan

> **For agentic workers:** use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to carry out this plan task by task. Steps use checkboxes (`- [ ]`).

**Goal:** let a page on any origin read receipts-log's public read routes, so the proof explorer can fetch tree heads, proofs and cosignatures in the visitor's browser.

**Architecture:** one wrapper, `anyOrigin`, in `internal/server/server.go`, sets `Access-Control-Allow-Origin: *` on the read routes when they are registered. The write routes (`POST /v1/entries`, `POST /v1/cosignatures`, `POST /api/transparency/witness`) and `GET /healthz` are not wrapped. These are simple `GET` requests with no custom headers, so browsers send no preflight and no `OPTIONS` route is needed.

**Tech stack:** Go 1.27, standard library.

**Design:** `docs/design/2026-10-23-ontology-and-proof-explorer.md` (verifiable-receipts), "receipts-log change".

**Prototype:** the test and the change below were run on receipts-log `main` at `4a897e8`: the test failed on 7 of the 8 read routes before the change (`/v1/public-key` already sent the header) and passed after it, and `go test -race ./...` stayed green.

**Repository:** `~/Projects/receipts-log` (github.com/christiaan839-beep/receipts-log). Start this only after its open PR #11 (`cleanup/no-generic-code`) has merged, since that PR also touches `internal/server`.

---

## Conventions

- Branch off `main`: `git checkout main && git pull && git checkout -b feat/cors-read-routes`.
- git and gh need the Bash sandbox off. If the Write and Edit tools fail on a security-guidance hook error, write files with a heredoc or a short Python script.
- Commit with this identity:

```bash
export GIT_COMMITTER_NAME='Christiaan de Wet' GIT_COMMITTER_EMAIL='259622211+christiaan839-beep@users.noreply.github.com'
A='Christiaan de Wet <259622211+christiaan839-beep@users.noreply.github.com>'
git commit --author="$A" -m "<subject>" -m "<body>" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 1: the failing test

**Files:**
- Modify: `internal/server/server_test.go` (append one test)

- [ ] **Step 1:** append to `internal/server/server_test.go` (it already imports `net/http` and `strings`, and has `setup`):

```go
// The read routes serve public data and take no credentials, so any page
// may read them; the proof explorer fetches them from its own origin. The
// write routes stay same-origin.
func TestReadRoutesAllowAnyOrigin(t *testing.T) {
	f := setup(t)
	for _, path := range []string{
		"/v1/entries/0",
		"/v1/sth",
		"/v1/proof/inclusion?index=0",
		"/v1/proof/consistency?old=0",
		"/v1/public-key",
		"/v1/cosignatures?treeSize=0",
		"/api/transparency/sth",
		"/api/transparency/proof?kind=consistency&old=0",
	} {
		resp, err := http.Get(f.srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "*" {
			t.Errorf("GET %s (status %d): Access-Control-Allow-Origin %q, want *", path, resp.StatusCode, got)
		}
	}
	for _, path := range []string{"/v1/entries", "/v1/cosignatures"} {
		resp, err := http.Post(f.srv.URL+path, "application/json", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("POST %s: Access-Control-Allow-Origin %q, want none", path, got)
		}
	}
}
```

- [ ] **Step 2:** run it:

```bash
go test -count=1 -run TestReadRoutesAllowAnyOrigin ./internal/server/
```

Expected: FAIL, with `Access-Control-Allow-Origin "", want *` for every path except `/v1/public-key`.

### Task 2: the change

**Files:**
- Modify: `internal/server/server.go` (route registration in `Handler`, a new `anyOrigin` function above `jsonErrors`, and `getPublicKey`)

- [ ] **Step 1:** apply this change (the read routes go through `anyOrigin`; `getPublicKey` no longer sets the header itself, because `anyOrigin` does):

```diff
diff --git a/internal/server/server.go b/internal/server/server.go
index 8517b27..f22277b 100644
--- a/internal/server/server.go
+++ b/internal/server/server.go
@@ -80,21 +80,32 @@ func New(l *translog.Log, opts Options) (*Server, error) {
 func (s *Server) Handler() http.Handler {
 	mux := http.NewServeMux()
 	mux.HandleFunc("POST /v1/entries", s.postEntry)
-	mux.HandleFunc("GET /v1/entries/{index}", s.getEntry)
-	mux.HandleFunc("GET /v1/sth", s.getSTH)
-	mux.HandleFunc("GET /v1/proof/inclusion", s.getInclusion)
-	mux.HandleFunc("GET /v1/proof/consistency", s.getConsistency)
-	mux.HandleFunc("GET /v1/public-key", s.getPublicKey)
+	mux.HandleFunc("GET /v1/entries/{index}", anyOrigin(s.getEntry))
+	mux.HandleFunc("GET /v1/sth", anyOrigin(s.getSTH))
+	mux.HandleFunc("GET /v1/proof/inclusion", anyOrigin(s.getInclusion))
+	mux.HandleFunc("GET /v1/proof/consistency", anyOrigin(s.getConsistency))
+	mux.HandleFunc("GET /v1/public-key", anyOrigin(s.getPublicKey))
 	mux.HandleFunc("POST /v1/cosignatures", s.postCosignature)
-	mux.HandleFunc("GET /v1/cosignatures", s.getCosignatures)
+	mux.HandleFunc("GET /v1/cosignatures", anyOrigin(s.getCosignatures))
 	mux.HandleFunc("GET /healthz", s.getHealth)
 	// The routes the verifiable-receipts witness CLI (bin/witness.mjs) calls.
-	mux.HandleFunc("GET /api/transparency/sth", s.getSTH)
-	mux.HandleFunc("GET /api/transparency/proof", s.getCompatProof)
+	mux.HandleFunc("GET /api/transparency/sth", anyOrigin(s.getSTH))
+	mux.HandleFunc("GET /api/transparency/proof", anyOrigin(s.getCompatProof))
 	mux.HandleFunc("POST /api/transparency/witness", s.postCosignature)
 	return s.middleware(jsonErrors(mux))
 }
 
+// anyOrigin lets a page on any origin read the response. The read routes
+// serve public data and take no credentials; a browser-based verifier
+// such as the proof explorer fetches them from its own origin. The write
+// routes stay same-origin.
+func anyOrigin(h http.HandlerFunc) http.HandlerFunc {
+	return func(w http.ResponseWriter, r *http.Request) {
+		w.Header().Set("Access-Control-Allow-Origin", "*")
+		h(w, r)
+	}
+}
+
 // jsonErrors answers the mux's own 404 and 405 responses with JSON.
 func jsonErrors(mux *http.ServeMux) http.Handler {
 	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
@@ -441,7 +452,6 @@ func (s *Server) getCompatProof(w http.ResponseWriter, r *http.Request) {
 
 func (s *Server) getPublicKey(w http.ResponseWriter, r *http.Request) {
 	w.Header().Set("Content-Type", "application/x-pem-file")
-	w.Header().Set("Access-Control-Allow-Origin", "*")
 	w.Header().Set("Cache-Control", "public, max-age=300")
 	_, _ = w.Write(s.pubPEM)
 }
```

- [ ] **Step 2:** run the test and the whole suite:

```bash
gofmt -l .
go vet ./...
go test -count=1 -run TestReadRoutesAllowAnyOrigin -v ./internal/server/
go test -race -count=1 ./...
GOTOOLCHAIN=go1.26.10 go run honnef.co/go/tools/cmd/staticcheck@2026.2.1 ./...
```

Expected: gofmt prints nothing; `--- PASS: TestReadRoutesAllowAnyOrigin`; every package `ok`; staticcheck prints nothing.

### Task 3: the docs

**Files:**
- Modify: `API.md` (the opening paragraph and the `GET /v1/public-key` section)

- [ ] **Step 1:** in `API.md`'s opening paragraph, after the sentence about `X-Request-Id`, add:

```markdown
The read routes (`GET /v1/entries/{{index}}`, `/v1/sth`, `/v1/proof/inclusion`,
`/v1/proof/consistency`, `/v1/public-key`, `/v1/cosignatures`, and the
`/api/transparency/` read routes) also send `Access-Control-Allow-Origin: *`, so a
browser-based verifier on any origin can read them. They serve public data and take
no credentials. The write routes and `/healthz` are same-origin only.
```

- [ ] **Step 2:** in the `GET /v1/public-key` section, change "(`application/x-pem-file`, `Access-Control-Allow-Origin: *`)" to "(`application/x-pem-file`)": the opening paragraph now covers it.
- [ ] **Step 3:** confirm every route named in the new paragraph is wrapped in `Handler`, and none of the write routes is.

### Task 4: commit and pull request

- [ ] **Step 1:** run the interop tests against verifiable-receipts at `VR_REF` (see `CONTRIBUTING.md`), then `uvx zizmor@1.30.1 --persona pedantic .github/` and `gitleaks git --staged`.
- [ ] **Step 2:** commit both files: `Read routes allow any origin (CORS), for browser verifiers` (body: which routes, why no preflight, that the write routes stay same-origin).
- [ ] **Step 3:** push, open the PR (`gh pr create --base main`, body ending with `🤖 Generated with [Claude Code](https://claude.com/claude-code)`), wait for every required check, and merge with a merge commit.
