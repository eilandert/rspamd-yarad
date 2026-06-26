package extract

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"
)

// --- synthetic SummaryInformation property-set builder -------------------------

// metaProp is one property: its PIDSI id and the fully-encoded value body
// (type uint32 followed by the type-specific value bytes), placed verbatim at
// the property's value offset.
type metaProp struct {
	id   uint32
	body []byte
}

// lpstrProp encodes a VT_LPSTR (0x1E) property: type(4) + size(4) + NUL-terminated bytes.
func lpstrProp(id uint32, s string) metaProp {
	v := append([]byte(s), 0)
	body := make([]byte, 8)
	binary.LittleEndian.PutUint32(body[0:], 0x1E)
	binary.LittleEndian.PutUint32(body[4:], uint32(len(v)))
	return metaProp{id, append(body, v...)}
}

// filetimeProp encodes a VT_FILETIME (0x40) property: type(4) + 8-byte value.
func filetimeProp(id uint32, ft uint64) metaProp {
	body := make([]byte, 12)
	binary.LittleEndian.PutUint32(body[0:], 0x40)
	binary.LittleEndian.PutUint64(body[4:], ft)
	return metaProp{id, body}
}

// buildSummaryStream constructs a minimal valid SummaryInformation property-set
// stream carrying the given properties in one section. Offsets are relative to
// the section start, matching summaryPropOffsets / docSecurityFlags.
func buildSummaryStream(props []metaProp) []byte {
	const secStart = 48
	header := make([]byte, secStart)
	header[0], header[1] = 0xFE, 0xFF             // ByteOrder 0xFFFE
	binary.LittleEndian.PutUint32(header[24:], 1) // cSections
	binary.LittleEndian.PutUint32(header[44:], secStart)

	n := len(props)
	valuesStart := 8 + n*8 // section header (8) + id/offset array (8 each)
	idoff := make([]byte, n*8)
	var values []byte
	off := valuesStart
	for i, p := range props {
		binary.LittleEndian.PutUint32(idoff[i*8:], p.id)
		binary.LittleEndian.PutUint32(idoff[i*8+4:], uint32(off))
		values = append(values, p.body...)
		off += len(p.body)
	}
	section := make([]byte, 8)
	binary.LittleEndian.PutUint32(section[0:], uint32(8+n*8+len(values))) // cbSection
	binary.LittleEndian.PutUint32(section[4:], uint32(n))                 // cProperties
	section = append(section, idoff...)
	section = append(section, values...)
	return append(header, section...)
}

func hasMetaMarker(got []string, want string) bool {
	for _, g := range got {
		if g == want {
			return true
		}
	}
	return false
}

// --- oleSummaryMetaMarkers tests ----------------------------------------------

func TestOLEMeta_TemplateInjectionRemote(t *testing.T) {
	for _, tmpl := range []string{"http://evil.example/t.dotm", "https://evil.example/t.dotm", `\\evil\share\t.dotm`} {
		got := oleSummaryMetaMarkers(buildSummaryStream([]metaProp{lpstrProp(pidsiTemplate, tmpl)}))
		if !hasMetaMarker(got, oleMetaTemplateInj) {
			t.Errorf("template %q: expected %s, got %v", tmpl, oleMetaTemplateInj, got)
		}
	}
}

func TestOLEMeta_TemplateLocalClean(t *testing.T) {
	got := oleSummaryMetaMarkers(buildSummaryStream([]metaProp{lpstrProp(pidsiTemplate, "Normal.dotm")}))
	if hasMetaMarker(got, oleMetaTemplateInj) {
		t.Errorf("local template should NOT flag injection, got %v", got)
	}
}

func TestOLEMeta_AppNameEquation(t *testing.T) {
	got := oleSummaryMetaMarkers(buildSummaryStream([]metaProp{lpstrProp(pidsiAppName, "Microsoft Equation 3.0")}))
	if !hasMetaMarker(got, oleMetaAppNameEquation) {
		t.Errorf("expected %s, got %v", oleMetaAppNameEquation, got)
	}
}

func TestOLEMeta_AppNameClean(t *testing.T) {
	got := oleSummaryMetaMarkers(buildSummaryStream([]metaProp{lpstrProp(pidsiAppName, "Microsoft Office Word")}))
	if hasMetaMarker(got, oleMetaAppNameEquation) {
		t.Errorf("benign AppName should NOT flag, got %v", got)
	}
}

func TestOLEMeta_FreshDocStompPair(t *testing.T) {
	got := oleSummaryMetaMarkers(buildSummaryStream([]metaProp{
		lpstrProp(pidsiRevNumber, "1"),
		filetimeProp(pidsiEditTime, 0),
	}))
	if !hasMetaMarker(got, oleMetaRevisionZero) || !hasMetaMarker(got, oleMetaEditTimeZero) {
		t.Errorf("expected both revision-zero and edittime-zero, got %v", got)
	}
}

func TestOLEMeta_EditedDocClean(t *testing.T) {
	got := oleSummaryMetaMarkers(buildSummaryStream([]metaProp{
		lpstrProp(pidsiRevNumber, "27"),
		filetimeProp(pidsiEditTime, 6000000000),
	}))
	if hasMetaMarker(got, oleMetaRevisionZero) || hasMetaMarker(got, oleMetaEditTimeZero) {
		t.Errorf("real edited doc should NOT flag fresh/stomp, got %v", got)
	}
}

func TestOLEMeta_MalformedFailOpen(t *testing.T) {
	for _, data := range [][]byte{nil, {0x00}, bytes.Repeat([]byte{0xFF}, 47)} {
		if got := oleSummaryMetaMarkers(data); got != nil {
			t.Errorf("malformed input should return nil, got %v", got)
		}
	}
}

// --- ole_meta.yara lint -------------------------------------------------------

func loadOLEMetaRule(t *testing.T) []byte {
	t.Helper()
	for _, p := range []string{
		"../../../../docker/local-rules/ole_meta.yara",
		"../../../docker/local-rules/ole_meta.yara",
		"../../docker/local-rules/ole_meta.yara",
	} {
		if b, err := os.ReadFile(p); err == nil {
			return b
		}
	}
	t.Skip("ole_meta.yara not found relative to test dir")
	return nil
}

func TestOLEMetaRule_PresentAndAnchored(t *testing.T) {
	data := loadOLEMetaRule(t)
	for _, want := range []string{
		"rule OLE_Meta_Template_Injection",
		"rule OLE_Meta_AppName_Equation",
		"rule OLE_Meta_FreshDoc_Stomp",
		oleMetaTemplateInj,
		oleMetaAppNameEquation,
		oleMetaRevisionZero,
		oleMetaEditTimeZero,
	} {
		if !bytes.Contains(data, []byte(want)) {
			t.Errorf("ole_meta.yara missing %q", want)
		}
	}
	for _, bad := range [][]byte{[]byte(`\1`), []byte(`\2`)} {
		if bytes.Contains(data, bad) {
			t.Errorf("ole_meta.yara contains backreference %q — yarac rejects it", bad)
		}
	}
}
