package extract

import (
	"bytes"
	"os"
	"testing"
)

// powershell_cff.yara ships PS1_ControlFlowFlatten_CharSurgery, closing two live
// .ps1 corpus misses (1eb89fbb…, 77525609… — both 0-hit before this rule): a
// control-flow-flattening dispatcher (`while($v -ne -1){switch($v)}`) whose every
// literal is rebuilt from thousands of `.Insert(N,'..')` char-surgery calls.
//
// yarad's unit suite does not link libyara, so — like the js_obfuscation and
// vbs_charcode_dropper rule tests — this asserts the rule SOURCE is present and
// well-formed; the real compile+match runs in the Docker `full` CI stage
// (compile-rules.sh runs yarac over every local rule, then the runtime scanners
// job scans fixtures).

func loadPS1CFFRule(t *testing.T) []byte {
	t.Helper()
	paths := []string{
		"../../../../docker/local-rules/powershell_cff.yara",
		"../../../docker/local-rules/powershell_cff.yara",
		"../../docker/local-rules/powershell_cff.yara",
	}
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil {
			return b
		}
	}
	t.Skip("powershell_cff.yara not found relative to test dir")
	return nil
}

func TestPS1CFFRule_Present(t *testing.T) {
	data := loadPS1CFFRule(t)
	if !bytes.Contains(data, []byte("rule PS1_ControlFlowFlatten_CharSurgery")) {
		t.Errorf("powershell_cff.yara missing rule PS1_ControlFlowFlatten_CharSurgery")
	}
}

func TestPS1CFFRule_Anchors(t *testing.T) {
	data := loadPS1CFFRule(t)
	// the flattening + char-surgery primitives the rule keys on — if any of these
	// regex fragments changes the rule no longer matches the corpus samples.
	for _, anchor := range []string{
		"-ne -1",   // dispatcher loop sentinel
		"switch (", // state dispatch
		".Insert(", // char-surgery rebuild
	} {
		if !bytes.Contains(data, []byte(anchor)) {
			t.Errorf("powershell_cff.yara missing anchor %q", anchor)
		}
	}
}

func TestPS1CFFRule_HasWideModifier(t *testing.T) {
	// UTF-16LE scripts must match — strings carry `ascii wide`.
	data := loadPS1CFFRule(t)
	if !bytes.Contains(data, []byte("ascii wide")) {
		t.Errorf("powershell_cff.yara: strings must be `ascii wide` (UTF-16LE samples)")
	}
}

func TestPS1CFFRule_HasCountGuard(t *testing.T) {
	// the COUNT on the surgery primitive is the FP guard — without it ordinary
	// scripts with a stray switch/Insert would fire.
	data := loadPS1CFFRule(t)
	if !bytes.Contains(data, []byte("#ins >")) {
		t.Errorf("powershell_cff.yara: missing `#ins >` count guard (FP risk on benign .ps1)")
	}
}

func TestPS1CFFRule_NoBackreference(t *testing.T) {
	// yarac rejects backreferences; compile-rules.sh would then silently drop the
	// rule. Catch it at unit speed instead of as a missing rule on the live host.
	data := loadPS1CFFRule(t)
	for _, bad := range [][]byte{[]byte(`\1`), []byte(`\2`)} {
		if bytes.Contains(data, bad) {
			t.Errorf("powershell_cff.yara contains backreference %q (yarac rejects, rule silently skipped)", bad)
		}
	}
}

func TestPS1CFFRule_NoNestedUnboundedQuantifier(t *testing.T) {
	// The catastrophic-backtracking class (#174/#177): a `){N,}` after an
	// unbounded inner quantifier blows scan_timeout and fail-opens the file.
	data := loadPS1CFFRule(t)
	if bytes.Contains(data, []byte("){")) {
		t.Errorf("powershell_cff.yara has a `){...}` group-repeat — risks catastrophic backtracking; keep regexes linear")
	}
}
