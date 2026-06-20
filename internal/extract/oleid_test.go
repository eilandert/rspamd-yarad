package extract

import (
	"testing"
	"time"
)

// TestOLEIDObjectPool: a CFB carrying an ObjectPool storage emits the
// OLEID-OBJECTPOOL marker (oleid indicator, OLEID-1).
func TestOLEIDObjectPool(t *testing.T) {
	buf := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5},
		{name: "ObjectPool", mse: 1},
		{name: "WordDocument", mse: 2, data: []byte("body text, no macros")},
	})
	res := Extract(buf, time.Time{})
	if !streamsContain(res, "OLEID-OBJECTPOOL") {
		t.Fatalf("OLEID-OBJECTPOOL marker not emitted; streams: %v", streamsAsStrings(res))
	}
}

// TestOLEIDFlash: a CFB stream whose head carries SWF magic (CWS) emits the
// OLEID-FLASH marker.
func TestOLEIDFlash(t *testing.T) {
	swf := append([]byte("CWS"), byte(0x0F)) // CWS + version byte
	swf = append(swf, []byte(" compressed flash payload tail")...)
	buf := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5},
		{name: "Contents", mse: 2, data: swf},
	})
	res := Extract(buf, time.Time{})
	if !streamsContain(res, "OLEID-FLASH") {
		t.Fatalf("OLEID-FLASH marker not emitted; streams: %v", streamsAsStrings(res))
	}
}

// TestOLEIDNoFalsePositive: a plain document with neither an ObjectPool nor SWF
// emits no OLEID-* markers.
func TestOLEIDNoFalsePositive(t *testing.T) {
	buf := buildCFB(t, []cfbEntry{
		{name: "Root Entry", mse: 5},
		{name: "WordDocument", mse: 2, data: []byte("ordinary body text")},
	})
	res := Extract(buf, time.Time{})
	for _, s := range streamsAsStrings(res) {
		if len(s) >= 6 && s[:6] == "OLEID-" {
			t.Fatalf("unexpected OLEID marker on clean doc: %q", s)
		}
	}
}
