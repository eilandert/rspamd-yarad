package extract

import (
	"encoding/base64"
	"testing"
	"time"
)

// EFFORT-4: PDFDeepen=false must skip the structural-indicator pass — only the
// inflated object streams are scanned, never the /OpenAction-/JS markers. The
// same PDF at full depth (PDFDeepen=true) DOES surface the marker, so the dial is
// what makes the difference, not the input.
func TestEffortPDFDeepenGate(t *testing.T) {
	buf := []byte("%PDF-1.7\n1 0 obj\n<< /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>\nendobj\n%%EOF")

	full := ExtractWithOptions(buf, &Options{Deadline: time.Time{}, DecodeDepth: 1, DecodeIterations: 64, PDFDeepen: true})
	if !streamsContain(full, "PDF-OPENACTION-JS") {
		t.Fatalf("PDFDeepen=true must surface the indicator; streams=%v", full.Streams)
	}

	low := ExtractWithOptions(buf, &Options{Deadline: time.Time{}, DecodeDepth: 1, DecodeIterations: 64, PDFDeepen: false})
	if streamsContain(low, "PDF-OPENACTION-JS") {
		t.Errorf("PDFDeepen=false must skip the indicator pass; streams=%v", low.Streams)
	}
}

// EFFORT-4: DecodeDepth caps the MSD multi-layer decode. A payload wrapped in two
// base64 layers is fully unwrapped at depth>=2 but only one layer is peeled at
// depth 1, so the inner cleartext stays hidden at the lowest effort.
func TestEffortDecodeDepthGate(t *testing.T) {
	const inner = "MULTILAYER-EFFORT-MARKER-PAYLOAD-STRING"
	l1 := base64.StdEncoding.EncodeToString([]byte(inner))
	l2 := base64.StdEncoding.EncodeToString([]byte(l1))
	buf := []byte(l2)

	deep := ExtractWithOptions(buf, &Options{Deadline: time.Time{}, DecodeDepth: 4, DecodeIterations: 256})
	if !streamsContain(deep, inner) {
		t.Fatalf("depth 4 must unwrap both layers to reach inner cleartext; streams=%v", deep.Streams)
	}

	shallow := ExtractWithOptions(buf, &Options{Deadline: time.Time{}, DecodeDepth: 1, DecodeIterations: 256})
	if streamsContain(shallow, inner) {
		t.Errorf("depth 1 must NOT reach the twice-wrapped inner cleartext; streams=%v", shallow.Streams)
	}
}

// A nil Options degrades to full depth (back-compat), matching Extract().
func TestEffortNilOptionsFullDepth(t *testing.T) {
	buf := []byte("%PDF-1.7\n1 0 obj\n<< /Launch << /F (cmd.exe) >> >>\nendobj\n%%EOF")
	res := ExtractWithOptions(buf, nil)
	if !streamsContain(res, "PDF-LAUNCH") {
		t.Errorf("nil opts must run full-depth; streams=%v", res.Streams)
	}
}
