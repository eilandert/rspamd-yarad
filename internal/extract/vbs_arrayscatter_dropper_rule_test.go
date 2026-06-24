package extract

import (
	"bytes"
	"os"
	"testing"
)

// vbs_arrayscatter_dropper.yara ships VBS_ArrayScatter_OffsetTable_Dropper,
// closing a live .vbs corpus miss (420b9bc8… MassLogger — 0-hit against current
// main): a char lookup table scattered across ~95 per-index single-char array
// assignments, reassembled via an offset-indexed decode loop
// (buf = buf & tbl(idx(i) - N)) then handed to WScript.Shell.Run.
//
// yarad's unit suite does not link libyara, so — like the other rule tests —
// this asserts the rule SOURCE is present and well-formed; the real compile+match
// runs in the Docker `full` CI stage (compile-rules.sh runs yarac over every
// local rule, then the runtime scanners job scans fixtures).

func loadVBSScatterRule(t *testing.T) []byte {
	t.Helper()
	paths := []string{
		"../../../../docker/local-rules/vbs_arrayscatter_dropper.yara",
		"../../../docker/local-rules/vbs_arrayscatter_dropper.yara",
		"../../docker/local-rules/vbs_arrayscatter_dropper.yara",
	}
	for _, p := range paths {
		if b, err := os.ReadFile(p); err == nil {
			return b
		}
	}
	t.Skip("vbs_arrayscatter_dropper.yara not found relative to test dir")
	return nil
}

func TestVBSScatterRule_Present(t *testing.T) {
	data := loadVBSScatterRule(t)
	if !bytes.Contains(data, []byte("rule VBS_ArrayScatter_OffsetTable_Dropper")) {
		t.Errorf("vbs_arrayscatter_dropper.yara missing rule VBS_ArrayScatter_OffsetTable_Dropper")
	}
}

func TestVBSScatterRule_Anchors(t *testing.T) {
	data := loadVBSScatterRule(t)
	// the decode primitives the rule keys on — if any fragment changes the rule
	// no longer matches the corpus sample.
	for _, anchor := range []string{
		`\(\d{1,3}\) = "[^"]"`, // single-char scattered table cell
		".Run",                 // WSH execution primitive
		"#scatter >",           // the COUNT FP guard
	} {
		if !bytes.Contains(data, []byte(anchor)) {
			t.Errorf("vbs_arrayscatter_dropper.yara missing anchor %q", anchor)
		}
	}
}

func TestVBSScatterRule_HasWideModifier(t *testing.T) {
	// UTF-16LE droppers must match — the sample is UTF-16LE (BOM ff fe).
	data := loadVBSScatterRule(t)
	if !bytes.Contains(data, []byte("ascii wide")) {
		t.Errorf("vbs_arrayscatter_dropper.yara: strings must be `ascii wide` (UTF-16LE samples)")
	}
}

func TestVBSScatterRule_NoBackreference(t *testing.T) {
	// yarac rejects backreferences; compile-rules.sh would then silently drop the
	// rule. Catch it at unit speed instead of as a missing rule on the live host.
	data := loadVBSScatterRule(t)
	for _, bad := range [][]byte{[]byte(`\1`), []byte(`\2`)} {
		if bytes.Contains(data, bad) {
			t.Errorf("vbs_arrayscatter_dropper.yara contains backreference %q (yarac rejects, rule silently skipped)", bad)
		}
	}
}

func TestVBSScatterRule_NoNestedUnboundedQuantifier(t *testing.T) {
	// The catastrophic-backtracking class (#174/#177): a `){N,}` after an
	// unbounded inner quantifier blows scan_timeout and fail-opens the file.
	data := loadVBSScatterRule(t)
	if bytes.Contains(data, []byte("){")) {
		t.Errorf("vbs_arrayscatter_dropper.yara has a `){...}` group-repeat — risks catastrophic backtracking; keep regexes linear")
	}
}
