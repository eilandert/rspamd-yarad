package extract

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"testing"
)

// fetch-rules.sh prunes two classes of rules from the fetched bundle at build
// time so they are never compiled or run:
//
//   PERF-12 (2026-06-25): three yaraify rules that a libyara profiling run
//   found to account for 99.3% of all scan cost — unanchored short-atom
//   regexes on PE/ELF binary rules whose slow string phase runs on every text
//   buffer and matches nothing on the mail corpus.
//
//   FP/noise (2026-06-25): three rules confirmed in the compiled bundle that
//   fire on benign mail with no signal for the mail-attachment vector.
//
// These tests pin the denylist so the wins can't silently regress.

// deniedRules are the rule names fetch-rules.sh must prune. Keep in sync
// with SLOW_RULE_DENYLIST in docker/fetch-rules.sh.
var deniedRules = []string{
	// PERF-12: catastrophic-regex rules (99.3% of scan cost on the mail corpus)
	"Luckyware_Infection_Detection",
	"kryptina_encryptor",
	"DLL_DiceLoader_Fin7_Feb2024",
	// FP/noise: benign-mail false positives, no signal for mail-attachment vector
	"Cloaked_RAR_File",
	"SUSP_Encoded_Discord_Attachment_Oct21_1",
	"SIGNATURE_BASE_SUSP_Encoded_Discord_Attachment_Oct21_1",
}

func fetchRulesScript(t *testing.T) string {
	t.Helper()
	for _, p := range []string{
		"../../../../docker/fetch-rules.sh",
		"../../../docker/fetch-rules.sh",
		"../../docker/fetch-rules.sh",
	} {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	t.Skip("docker/fetch-rules.sh not found relative to test dir")
	return ""
}

// TestFetchRules_DenylistPresent lints the script source: every denied rule
// name must appear in the SLOW_RULE_DENYLIST assignment, so the list can't lose
// an entry under a refactor.
func TestFetchRules_DenylistPresent(t *testing.T) {
	b, err := os.ReadFile(fetchRulesScript(t))
	if err != nil {
		t.Fatalf("read fetch-rules.sh: %v", err)
	}
	reList := regexp.MustCompile(`SLOW_RULE_DENYLIST="([^"]*)"`)
	m := reList.FindSubmatch(b)
	if m == nil {
		t.Fatal("SLOW_RULE_DENYLIST= not found in fetch-rules.sh (PERF-12 denylist removed?)")
	}
	list := string(m[1])
	for _, name := range deniedRules {
		if !regexp.MustCompile(`(^|\s)` + regexp.QuoteMeta(name) + `(\s|$)`).MatchString(list) {
			t.Errorf("PERF-12: %q missing from SLOW_RULE_DENYLIST (%q)", name, list)
		}
	}
}

// TestFetchRules_DenylistPrunes runs the script's actual denylist block against
// a fixture rule dir (one file per denied rule plus a keeper) and asserts the
// denied files are removed and the keeper survives. Hermetic: no network, no
// libyara — it exercises the exact grep/rm loop the build relies on.
func TestFetchRules_DenylistPrunes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("sh-driven test")
	}
	script := fetchRulesScript(t)
	abs, err := filepath.Abs(script)
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	dir := t.TempDir()
	// one single-rule file per denied rule (mirrors yaraify's one-rule-per-file)
	for _, name := range deniedRules {
		f := filepath.Join(dir, "yaraify-"+name+".yar")
		if err := os.WriteFile(f, []byte("rule "+name+" {\n condition:\n  true\n}\n"), 0o644); err != nil {
			t.Fatalf("write %s: %v", f, err)
		}
	}
	// a keeper that must NOT be pruned (different rule name, substring-adjacent)
	keeper := filepath.Join(dir, "yaraify-Keep_Luckyware_Sibling.yar")
	if err := os.WriteFile(keeper, []byte("rule Keep_Luckyware_Sibling {\n condition:\n  true\n}\n"), 0o644); err != nil {
		t.Fatalf("write keeper: %v", err)
	}

	// Extract and run ONLY the denylist loop from the script so the test does not
	// fetch anything. The loop reads $OUT and $SLOW_RULE_DENYLIST; reproduce them
	// from the script's own definition so the test fails if the loop body drifts.
	src, err := os.ReadFile(abs)
	if err != nil {
		t.Fatalf("read script: %v", err)
	}
	loop := extractDenylistBlock(t, string(src))
	prog := "set -eu\nOUT='" + dir + "'\n" + loop
	cmd := exec.Command("sh", "-c", prog)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("denylist block failed: %v\n%s", err, out)
	}
	for _, name := range deniedRules {
		f := filepath.Join(dir, "yaraify-"+name+".yar")
		if _, err := os.Stat(f); !os.IsNotExist(err) {
			t.Errorf("PERF-12: %q file survived the denylist prune", name)
		}
	}
	if _, err := os.Stat(keeper); err != nil {
		t.Errorf("PERF-12: keeper file wrongly pruned: %v", err)
	}
}

// extractDenylistBlock pulls the `SLOW_RULE_DENYLIST=...` assignment through the
// closing `done` of its prune loop, so the test runs the real script logic.
func extractDenylistBlock(t *testing.T, src string) string {
	t.Helper()
	re := regexp.MustCompile(`(?s)SLOW_RULE_DENYLIST="[^"]*"\nfor bad in \$SLOW_RULE_DENYLIST; do.*?\ndone`)
	m := re.FindString(src)
	if m == "" {
		t.Fatal("could not locate the PERF-12 denylist loop in fetch-rules.sh")
	}
	return m
}
