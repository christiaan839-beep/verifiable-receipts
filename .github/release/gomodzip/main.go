// Command gomodzip writes the module zip for the Go module, from a git
// checkout, in the format the go command and proxy.golang.org use, and
// prints its go.sum hash:
//
//	go run . -repo ROOT -rev COMMIT -version VERSION -out FILE.zip
//
// VERSION is the tag's version (v0.2.0) or "pseudo", for the pseudo-version
// of COMMIT (built from the latest module tag before it, as the go command
// does). The zip is made with golang.org/x/mod/zip.CreateFromVCS, the code
// the go command uses, from `git archive` of the checkout: nothing is
// fetched. build.sh runs it; release.yml checks that the proxy serves the
// same bytes.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
	"golang.org/x/mod/sumdb/dirhash"
	modzip "golang.org/x/mod/zip"
)

const (
	modulePath = "github.com/christiaan839-beep/verifiable-receipts/packages/verifiable-receipts-go"
	subdir     = "packages/verifiable-receipts-go"
	tagPrefix  = subdir + "/"
)

func git(repo string, args ...string) string {
	out, err := exec.Command("git", append([]string{"-C", repo}, args...)...).Output()
	if err != nil {
		fail("git %s: %v", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out))
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "gomodzip: "+format+"\n", args...)
	os.Exit(1)
}

// pseudoVersion is the go command's pseudo-version for rev: the latest
// module tag that is an ancestor of rev, with the commit's time and hash.
func pseudoVersion(repo, rev string) string {
	older := ""
	for _, tag := range strings.Fields(git(repo, "tag", "--merged", rev, "--list", tagPrefix+"v*")) {
		v := strings.TrimPrefix(tag, tagPrefix)
		if semver.IsValid(v) && semver.Prerelease(v) == "" && semver.Build(v) == "" &&
			(older == "" || semver.Compare(v, older) > 0) {
			older = v
		}
	}
	secs, err := strconv.ParseInt(git(repo, "log", "-1", "--format=%ct", rev), 10, 64)
	if err != nil {
		fail("commit time: %v", err)
	}
	major := "v0"
	if older != "" {
		major = semver.Major(older)
	}
	return module.PseudoVersion(major, older, time.Unix(secs, 0), rev[:12])
}

func main() {
	repo := flag.String("repo", ".", "the repository's root")
	rev := flag.String("rev", "", "the commit to build")
	version := flag.String("version", "", `the module version, or "pseudo"`)
	out := flag.String("out", "", "the zip to write")
	flag.Parse()
	if *rev == "" || *version == "" || *out == "" {
		flag.Usage()
		os.Exit(2)
	}
	commit := git(*repo, "rev-parse", *rev+"^{commit}")
	v := *version
	if v == "pseudo" {
		v = pseudoVersion(*repo, commit)
	} else if tagged := git(*repo, "rev-parse", tagPrefix+v+"^{commit}"); tagged != commit {
		fail("%s%s is %s, not %s", tagPrefix, v, tagged, commit)
	}
	mv := module.Version{Path: modulePath, Version: v}
	if err := module.Check(mv.Path, mv.Version); err != nil {
		fail("%v", err)
	}
	f, err := os.Create(*out)
	if err != nil {
		fail("%v", err)
	}
	if err := modzip.CreateFromVCS(f, mv, *repo, commit, subdir); err != nil {
		fail("%v", err)
	}
	if err := f.Close(); err != nil {
		fail("%v", err)
	}
	h1, err := dirhash.HashZip(*out, dirhash.Hash1)
	if err != nil {
		fail("%v", err)
	}
	fmt.Printf("%s %s %s\n", modulePath, v, h1)
}
