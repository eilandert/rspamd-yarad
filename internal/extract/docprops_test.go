package extract

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
	"time"
)

// makeTestZip builds an in-memory zip from a map of name->content strings and
// returns a *zip.Reader over it. Fatals the test on any error.
func makeTestZip(t *testing.T, entries map[string]string) *zip.Reader {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for name, body := range entries {
		addZipEntry(t, zw, name, body)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(b.Bytes()), int64(b.Len()))
	if err != nil {
		t.Fatal(err)
	}
	return zr
}

// TestDocPropsXMLTextExtraction verifies that fromOOXMLDocProps extracts text
// nodes from a minimal docProps/core.xml and emits the DOCPROPS-STRINGS marker.
func TestDocPropsXMLTextExtraction(t *testing.T) {
	want := "http://evil.example/c2"
	coreXML := `<?xml version="1.0"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"><dc:title xmlns:dc="http://purl.org/dc/elements/1.1/">` + want + `</dc:title></cp:coreProperties>`

	zr := makeTestZip(t, map[string]string{
		"docProps/core.xml": coreXML,
	})

	var out [][]byte
	fromOOXMLDocProps(zr, &out, time.Time{})

	if !hasDocPropsMarker(out) {
		t.Fatal("DOCPROPS-STRINGS marker not found in streams")
	}
	found := false
	for _, s := range out {
		if strings.Contains(string(s), want) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected %q in streams, got %v", want, streamsToStrings(out))
	}
}

// TestDocPropsDocVarExtraction verifies that fromOOXMLDocProps extracts
// w:docVar/@w:val attribute values from word/settings.xml.
func TestDocPropsDocVarExtraction(t *testing.T) {
	want := "powershell -nop -enc AAABBBCCC"
	settingsXML := `<?xml version="1.0"?><w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:docVars><w:docVar w:name="payload" w:val="` + want + `"/></w:docVars></w:settings>`

	zr := makeTestZip(t, map[string]string{
		"word/settings.xml": settingsXML,
	})

	var out [][]byte
	fromOOXMLDocProps(zr, &out, time.Time{})

	if !hasDocPropsMarker(out) {
		t.Fatal("DOCPROPS-STRINGS marker not found in streams")
	}
	found := false
	for _, s := range out {
		if strings.Contains(string(s), want) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected %q in streams, got %v", want, streamsToStrings(out))
	}
}

// TestDocPropsOLECarveStrings verifies that carveStrings (reused by
// fromOLEDocProps) correctly extracts printable ASCII runs from binary data
// containing a command-like payload.
func TestDocPropsOLECarveStrings(t *testing.T) {
	payload := "cmd.exe /c powershell -nop"
	raw := []byte{0x00, 0x01, 0x02}
	raw = append(raw, []byte(payload)...)
	raw = append(raw, []byte{0x00, 0x03, 0x04}...)

	runs := carveStrings(raw)
	found := false
	for _, r := range runs {
		if strings.Contains(string(r), payload) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected %q in carved runs, got %v", payload, func() []string {
			ss := make([]string, len(runs))
			for i, r := range runs {
				ss[i] = string(r)
			}
			return ss
		}())
	}
}

// TestDocPropsNoFalsePositiveOnCleanDoc verifies that a zip with no property
// parts does NOT emit the DOCPROPS-STRINGS marker.
func TestDocPropsNoFalsePositiveOnCleanDoc(t *testing.T) {
	zr := makeTestZip(t, map[string]string{
		"word/document.xml": `<?xml version="1.0"?><w:document><w:body><w:p><w:r><w:t>Hello</w:t></w:r></w:p></w:body></w:document>`,
	})

	var out [][]byte
	fromOOXMLDocProps(zr, &out, time.Time{})

	if hasDocPropsMarker(out) {
		t.Error("DOCPROPS-STRINGS marker should NOT appear when there are no property parts")
	}
}

// streamsToStrings converts [][]byte to []string for test error messages.
func streamsToStrings(streams [][]byte) []string {
	ss := make([]string, len(streams))
	for i, s := range streams {
		ss[i] = string(s)
	}
	return ss
}
