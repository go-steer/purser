// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package purser_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const (
	purserModulePath            = "github.com/go-steer/purser"
	tailLineThreshold           = 150
	maxNonTestFuncsOver150Lines = 0 // none today; max is examples/cmd/hello-server/main.go:run (73 code lines)
)

// packageLayer defines strict acyclic architecture layers across purser
// (higher layers may only import strictly lower layers: dstLayer < srcLayer).
var packageLayer = map[string]int{
	// Layer 0: leaf foundation (caller/source contract and stdlib-only internal helpers).
	".":                   0,
	"internal/ca":         0,
	"internal/filereload": 0,
	"internal/tlsfloor":   0,

	// Layer 1: authenticator interfaces over the root identity contract.
	"authn": 1,

	// Layer 2: authenticators, authorizers, HTTP middleware, test harness, and example handler.
	"authn/bearer":            2,
	"authn/mtls":              2,
	"authn/oidc":              2,
	"authtest":                2,
	"authz":                   2,
	"examples/internal/hello": 2,
	"httpmw":                  2,

	// Layer 3: outbound mTLS client and example credential minting over authn/mtls.
	"client":                        3,
	"examples/internal/credentials": 3,

	// Layer 4: example profile flag/config wiring over authn/mtls + client.
	"examples/internal/profile": 4,

	// Layer 5: example CLI entrypoints.
	"examples/cmd/hello-client":     5,
	"examples/cmd/hello-server":     5,
	"examples/cmd/mint-credentials": 5,
}

func TestArchitectureLayeringAndComplexityTail(t *testing.T) {
	t.Parallel()

	repoRoot, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}

	fset := token.NewFileSet()
	seenPackages := make(map[string]bool, len(packageLayer))
	var over150 []string

	err = filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if shouldSkipArchDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, err := filepath.Rel(repoRoot, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if strings.HasSuffix(rel, "_test.go") {
			return nil
		}

		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		f, err := parser.ParseFile(fset, path, raw, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", rel, err)
		}

		pkgRel := filepath.ToSlash(filepath.Dir(rel))
		seenPackages[pkgRel] = true
		for _, violation := range validatePackageImports(rel, pkgRel, f, packageLayer) {
			t.Error(violation)
		}

		lines := strings.Split(string(raw), "\n")
		over150 = append(over150, functionsOverLineThreshold(rel, fset, f, lines, tailLineThreshold)...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, missing := range missingWalkedPackages(packageLayer, seenPackages) {
		t.Errorf("package %q is registered in packageLayer but has no walked non-test .go files", missing)
	}

	if len(over150) > maxNonTestFuncsOver150Lines {
		t.Errorf("non-test functions over %d code lines = %d (ratchet ceiling %d): %v",
			tailLineThreshold, len(over150), maxNonTestFuncsOver150Lines, over150)
	}
}

func shouldSkipArchDir(name string) bool {
	switch name {
	case ".git", ".worktrees", ".claude", "bin", "dist", "vendor", "testdata", "node_modules":
		return true
	default:
		return false
	}
}

func internalPackageRel(impPath string) (string, bool) {
	if impPath == purserModulePath {
		return ".", true
	}
	const prefix = purserModulePath + "/"
	if strings.HasPrefix(impPath, prefix) {
		return strings.TrimPrefix(impPath, prefix), true
	}
	return "", false
}

func validatePackageImports(relFile, pkgRel string, f *ast.File, layers map[string]int) []string {
	srcLayer, ok := layers[pkgRel]
	if !ok {
		return []string{fmt.Sprintf("%s: package %q is not registered in packageLayer architecture map", relFile, pkgRel)}
	}
	var errs []string
	for _, imp := range f.Imports {
		impPath, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: malformed import literal %s: %v", relFile, imp.Path.Value, err))
			continue
		}
		dstPkg, isInternal := internalPackageRel(impPath)
		if !isInternal {
			continue
		}
		dstLayer, known := layers[dstPkg]
		if !known {
			errs = append(errs, fmt.Sprintf("%s: imports unregistered internal package %q", relFile, dstPkg))
			continue
		}
		if dstLayer >= srcLayer {
			errs = append(errs, fmt.Sprintf("layering violation in %s (%s, layer %d): cannot import %s (layer %d)",
				relFile, pkgRel, srcLayer, dstPkg, dstLayer))
		}
	}
	return errs
}

func missingWalkedPackages(layers map[string]int, seen map[string]bool) []string {
	var missing []string
	for pkg := range layers {
		if !seen[pkg] {
			missing = append(missing, pkg)
		}
	}
	slices.Sort(missing)
	return missing
}

func functionsOverLineThreshold(relFile string, fset *token.FileSet, f *ast.File, lines []string, threshold int) []string {
	var over []string
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		start := fset.PositionFor(fn.Pos(), false).Line
		end := fset.PositionFor(fn.End(), false).Line
		if countCodeLines(lines, start, end) > threshold {
			over = append(over, relFile+":"+fn.Name.Name)
		}
	}
	return over
}

func countCodeLines(lines []string, startLine, endLine int) int {
	if startLine < 1 {
		startLine = 1
	}
	n := 0
	for i := startLine - 1; i < endLine && i < len(lines); i++ {
		s := strings.TrimSpace(lines[i])
		if s == "" || strings.HasPrefix(s, "//") {
			continue
		}
		n++
	}
	return n
}

func TestValidatePackageImports(t *testing.T) {
	t.Parallel()

	layers := map[string]int{
		".":           0,
		"internal/ca": 0,
		"authn":       1,
		"authn/mtls":  2,
		"client":      3,
	}

	parseSrc := func(t *testing.T, src string) *ast.File {
		t.Helper()
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, "sample.go", src, 0)
		if err != nil {
			t.Fatalf("ParseFile: %v", err)
		}
		return f
	}

	t.Run("allows strictly lower layers and ignores external modules", func(t *testing.T) {
		t.Parallel()
		f := parseSrc(t, `package client
import (
	"crypto/tls"
	"github.com/go-steer/purser"
	"github.com/go-steer/purser/authn"
	"github.com/go-steer/purser/authn/mtls"
	"github.com/go-steer/purser/internal/ca"
	"github.com/go-steer/purser-other/pkg"
)
`)
		if errs := validatePackageImports("client/mtls.go", "client", f, layers); len(errs) != 0 {
			t.Fatalf("unexpected errors: %v", errs)
		}
	})

	t.Run("rejects unregistered source package", func(t *testing.T) {
		t.Parallel()
		f := parseSrc(t, `package mystery`)
		errs := validatePackageImports("mystery/x.go", "mystery", f, layers)
		if len(errs) != 1 || !strings.Contains(errs[0], `package "mystery" is not registered`) {
			t.Fatalf("errs = %v, want unregistered source error", errs)
		}
	})

	t.Run("rejects unregistered internal target, same-layer, and upward imports", func(t *testing.T) {
		t.Parallel()
		f := parseSrc(t, `package authn
import (
	"github.com/go-steer/purser/unknown"
	"github.com/go-steer/purser/authn"
	"github.com/go-steer/purser/authn/mtls"
)
`)
		errs := validatePackageImports("authn/bad.go", "authn", f, layers)
		if len(errs) != 3 {
			t.Fatalf("errs = %v (len %d), want 3 (unregistered, same-layer, upward)", errs, len(errs))
		}
		if !strings.Contains(errs[0], `unregistered internal package "unknown"`) {
			t.Errorf("errs[0] = %q, want unregistered internal package", errs[0])
		}
		if !strings.Contains(errs[1], "layering violation") || !strings.Contains(errs[1], "cannot import authn (layer 1)") {
			t.Errorf("errs[1] = %q, want same-layer violation", errs[1])
		}
		if !strings.Contains(errs[2], "layering violation") || !strings.Contains(errs[2], "cannot import authn/mtls (layer 2)") {
			t.Errorf("errs[2] = %q, want upward-layer violation", errs[2])
		}
	})

	t.Run("rejects root package importing subpackages or itself", func(t *testing.T) {
		t.Parallel()
		f := parseSrc(t, `package purser
import (
	"github.com/go-steer/purser"
	"github.com/go-steer/purser/authn"
)
`)
		errs := validatePackageImports("caller.go", ".", f, layers)
		if len(errs) != 2 {
			t.Fatalf("errs = %v, want 2 violations on layer 0", errs)
		}
	})

	t.Run("rejects raw-string backtick upward imports", func(t *testing.T) {
		t.Parallel()
		f := parseSrc(t, "package authn\nimport `github.com/go-steer/purser/client`\n")
		errs := validatePackageImports("authn/raw.go", "authn", f, layers)
		if len(errs) != 1 || !strings.Contains(errs[0], "cannot import client (layer 3)") {
			t.Fatalf("errs = %v, want upward-layer violation on raw-string import", errs)
		}
	})
}

func TestMissingWalkedPackagesAndSkipDirs(t *testing.T) {
	t.Parallel()

	layers := map[string]int{".": 0, "authn": 1, "stale/pkg": 2}
	seen := map[string]bool{".": true, "authn": true}
	missing := missingWalkedPackages(layers, seen)
	if !slices.Equal(missing, []string{"stale/pkg"}) {
		t.Fatalf("missingWalkedPackages = %v, want [stale/pkg]", missing)
	}

	for _, skip := range []string{".git", ".worktrees", ".claude", "bin", "dist", "vendor", "testdata", "node_modules"} {
		if !shouldSkipArchDir(skip) {
			t.Errorf("shouldSkipArchDir(%q) = false, want true", skip)
		}
	}
	for _, keep := range []string{"authn", "internal", "examples", "httpmw"} {
		if shouldSkipArchDir(keep) {
			t.Errorf("shouldSkipArchDir(%q) = true, want false", keep)
		}
	}
}

func TestCountCodeLinesAndThresholdRatchet(t *testing.T) {
	t.Parallel()

	src := `package sample

// Doc comment outside function.
func externalDecl()

func atLimit() {
	// comment ignored

	x := 1
	_ = x
}

func overLimit() {
	// comment ignored
	a := 1

	b := 2
	_ = a + b
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "sample.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	lines := strings.Split(src, "\n")

	// atLimit has 4 code lines (`func atLimit() {`, `x := 1`, `_ = x`, `}`);
	// overLimit has 5 code lines (`func overLimit() {`, `a := 1`, `b := 2`, `_ = a + b`, `}`).
	got := functionsOverLineThreshold("sample.go", fset, f, lines, 4)
	if !slices.Equal(got, []string{"sample.go:overLimit"}) {
		t.Fatalf("functionsOverLineThreshold(..., 4) = %v, want [sample.go:overLimit]", got)
	}

	if c := countCodeLines([]string{"a := 1", "", "  // comment", "b := 2"}, 0, 99); c != 2 {
		t.Fatalf("countCodeLines with out-of-range bounds = %d, want 2", c)
	}

	// Verify //line directives do not shift physical line indexing.
	lineDirectiveSrc := "package sample\n\n//line fake.go:500\nfunc shifted() {\n\ta := 1\n\tb := 2\n\t_ = a + b\n}\n"
	fsetShifted := token.NewFileSet()
	fShifted, err := parser.ParseFile(fsetShifted, "shifted.go", lineDirectiveSrc, parser.ParseComments)
	if err != nil {
		t.Fatalf("ParseFile(shifted): %v", err)
	}
	gotShifted := functionsOverLineThreshold("shifted.go", fsetShifted, fShifted, strings.Split(lineDirectiveSrc, "\n"), 4)
	if !slices.Equal(gotShifted, []string{"shifted.go:shifted"}) {
		t.Fatalf("functionsOverLineThreshold with //line directive = %v, want [shifted.go:shifted]", gotShifted)
	}
}
