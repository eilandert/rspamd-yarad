package extract

import (
	"bytes"
	"os"
	"testing"
)

// vbs_sibling_exe_launcher.yara lints — the unit suite does not link libyara;
// actual compile+match runs in the Docker `full` CI stage (compile-rules.sh).
// These guards pin the mechanic literals, the tiny-file FP gate and the
// hidden/async window-style gate so an edit cannot silently weaken the rule (a
// dropped gate or AND would FP on benign launcher wrappers; a mangled literal
// would stop matching the dropper stub). blacktop/yara 4.2.3: fires on the real
// sample f5952b16…, clean on a visible/wait launcher and a large admin script.

func loadVBSSiblingExeRule(t *testing.T) []byte {
	t.Helper()
	for _, p := range []string{
		"../../../../docker/local-rules/vbs_sibling_exe_launcher.yara",
		"../../../docker/local-rules/vbs_sibling_exe_launcher.yara",
		"../../docker/local-rules/vbs_sibling_exe_launcher.yara",
	} {
		if b, err := os.ReadFile(p); err == nil {
			return b
		}
	}
	t.Skip("vbs_sibling_exe_launcher.yara not found relative to test dir")
	return nil
}

func TestVBSSiblingExeRule_Present(t *testing.T) {
	data := loadVBSSiblingExeRule(t)
	for _, want := range []string{
		"rule VBS_Sibling_Exe_Hidden_Launcher",
		`"Wscript.Shell" nocase`,
		`"FileSystemObject" nocase`,
		`"GetParentFolderName" nocase`,
		`"ScriptFullName" nocase`,
		`".Run" nocase`,
		`".exe" nocase`,
	} {
		if !bytes.Contains(data, []byte(want)) {
			t.Errorf("vbs_sibling_exe_launcher.yara missing %q", want)
		}
	}
}

// The tiny-file gate AND the hidden/async window-style gate together are the FP
// firewall: without them the rule fires on legitimate visible launcher wrappers.
func TestVBSSiblingExeRule_Gates(t *testing.T) {
	data := loadVBSSiblingExeRule(t)
	if !bytes.Contains(data, []byte("filesize < 4096")) {
		t.Error("missing the filesize < 4096 tiny-file FP gate — would FP on large legitimate scripts")
	}
	if !bytes.Contains(data, []byte(`/,\s*0\s*,\s*False/`)) {
		t.Error("missing the hidden(0)/async(False) window-style gate — would FP on visible/wait launchers")
	}
	if !bytes.Contains(data, []byte("all of them")) {
		t.Error("condition is not the full conjunction (`all of them`) — a weaker OR would raise FP")
	}
}

func TestVBSSiblingExeRule_NoBackreference(t *testing.T) {
	data := loadVBSSiblingExeRule(t)
	for _, bad := range [][]byte{[]byte(`\1`), []byte(`\2`)} {
		if bytes.Contains(data, bad) {
			t.Errorf("vbs_sibling_exe_launcher.yara contains backreference %q — yarac rejects it", bad)
		}
	}
}
