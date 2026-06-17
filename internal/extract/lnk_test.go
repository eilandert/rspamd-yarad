package extract

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
	"unicode/utf16"
)

// lnkBuilder assembles a minimal .lnk: 76-byte header (magic + flags), optional
// size-prefixed IDList/LinkInfo blobs, then StringData blocks in order.
type lnkBuilder struct {
	flags   uint32
	idList  []byte // raw bytes after the 2-byte size (nil = no IDList block)
	linkInf []byte // raw bytes including the 4-byte size field (nil = none)
	strings [][2]string
	unicode bool
}

func u16le(s string) []byte {
	enc := utf16.Encode([]rune(s))
	b := make([]byte, len(enc)*2)
	for i, c := range enc {
		binary.LittleEndian.PutUint16(b[i*2:], c)
	}
	return b
}

func (lb *lnkBuilder) build() []byte {
	var b bytes.Buffer
	hdr := make([]byte, lnkHeaderSize)
	copy(hdr, lnkMagic)
	binary.LittleEndian.PutUint32(hdr[lnkFlagsOff:], lb.flags)
	b.Write(hdr)

	if lb.flags&lnkHasLinkTargetIDList != 0 {
		var sz [2]byte
		binary.LittleEndian.PutUint16(sz[:], uint16(len(lb.idList)))
		b.Write(sz[:])
		b.Write(lb.idList)
	}
	if lb.flags&lnkHasLinkInfo != 0 {
		b.Write(lb.linkInf)
	}
	for _, kv := range lb.strings {
		s := kv[1]
		var cnt [2]byte
		runes := []rune(s)
		binary.LittleEndian.PutUint16(cnt[:], uint16(len(utf16.Encode(runes))))
		if !lb.unicode {
			binary.LittleEndian.PutUint16(cnt[:], uint16(len(s)))
		}
		b.Write(cnt[:])
		if lb.unicode {
			b.Write(u16le(s))
		} else {
			b.WriteString(s)
		}
	}
	return b.Bytes()
}

// A unicode .lnk with COMMAND_LINE_ARGUMENTS carrying a powershell payload must
// have that string surfaced.
func TestExtractLNKArguments(t *testing.T) {
	lb := &lnkBuilder{
		flags:   lnkHasArguments | lnkIsUnicode,
		unicode: true,
		strings: [][2]string{{"args", "-w hidden -enc SQBFAFgA lnk dropper payload"}},
	}
	res := Extract(lb.build(), time.Time{})
	if !res.IsLNK {
		t.Fatal(".lnk not flagged IsLNK")
	}
	if !streamsContain(res, "lnk dropper payload") {
		t.Errorf("arguments not surfaced; got %d streams", len(res.Streams))
	}
}

// IDList + LinkInfo blocks before StringData must be skipped correctly so the
// arguments after them are still reached.
func TestExtractLNKSkipsTargetAndInfo(t *testing.T) {
	lb := &lnkBuilder{
		flags:   lnkHasLinkTargetIDList | lnkHasLinkInfo | lnkHasArguments | lnkIsUnicode,
		unicode: true,
		idList:  bytes.Repeat([]byte{0xAB}, 20),
		strings: [][2]string{{"args", "cmd /c calc.exe ARGSAFTERBLOBS"}},
	}
	// LinkInfo: 4-byte size (incl itself) + body.
	body := bytes.Repeat([]byte{0xCD}, 12)
	linkInf := make([]byte, 4)
	binary.LittleEndian.PutUint32(linkInf, uint32(4+len(body)))
	lb.linkInf = append(linkInf, body...)

	res := Extract(lb.build(), time.Time{})
	if !streamsContain(res, "ARGSAFTERBLOBS") {
		t.Errorf("arguments after IDList/LinkInfo not reached; got %d streams", len(res.Streams))
	}
}

// An ANSI (non-unicode) .lnk string must decode too.
func TestExtractLNKAnsi(t *testing.T) {
	lb := &lnkBuilder{
		flags:   lnkHasArguments,
		unicode: false,
		strings: [][2]string{{"args", "powershell ansi lnk payload"}},
	}
	res := Extract(lb.build(), time.Time{})
	if !streamsContain(res, "ansi lnk payload") {
		t.Errorf("ansi arguments not surfaced; got %d streams", len(res.Streams))
	}
}

// A truncated .lnk (header says HasArguments but the string is cut) must not
// panic and must surface nothing past the truncation.
func TestExtractLNKTruncated(t *testing.T) {
	hdr := make([]byte, lnkHeaderSize)
	copy(hdr, lnkMagic)
	binary.LittleEndian.PutUint32(hdr[lnkFlagsOff:], lnkHasArguments|lnkIsUnicode)
	// CountChars says 1000 but provide no string bytes.
	buf := append(hdr, 0xE8, 0x03)
	res := Extract(buf, time.Time{})
	if res.Panicked {
		t.Fatal("truncated .lnk panicked")
	}
	if len(res.Streams) != 0 {
		t.Errorf("truncated string should surface nothing, got %d", len(res.Streams))
	}
}

// A header shorter than 76 bytes must be handled without panic.
func TestExtractLNKShortHeader(t *testing.T) {
	res := Extract(append([]byte(nil), lnkMagic...), time.Time{})
	if res.Panicked {
		t.Fatal("short .lnk header panicked")
	}
}

// A non-.lnk buffer must not be flagged IsLNK.
func TestExtractNotLNK(t *testing.T) {
	res := Extract([]byte("not a shell link at all"), time.Time{})
	if res.IsLNK {
		t.Error("plain text wrongly flagged IsLNK")
	}
}
