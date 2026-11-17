package transport

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestFrameBounds(t *testing.T) {
	for _, n := range []int{0, 1, MaxDatagram} {
		var b bytes.Buffer
		payload := bytes.Repeat([]byte{42}, n)
		if e := WriteFrame(&b, payload, MaxDatagram); e != nil {
			t.Fatal(e)
		}
		r, e := ReadFrame(&b, MaxDatagram)
		if e != nil || !bytes.Equal(r, payload) {
			t.Fatal(e)
		}
	}
	var b bytes.Buffer
	if WriteFrame(&b, make([]byte, MaxDatagram+1), MaxDatagram) == nil {
		t.Fatal("oversized write")
	}
	binary.Write(&b, binary.BigEndian, uint16(65535))
	if _, e := ReadFrame(&b, MaxDatagram); e == nil {
		t.Fatal("oversized read")
	}
	if _, e := ReadFrame(bytes.NewReader([]byte{0}), MaxDatagram); e == nil {
		t.Fatal("truncated header")
	}
}
func FuzzReadFrame(f *testing.F) {
	f.Add([]byte{0, 1, 42})
	f.Add([]byte{255, 255})
	f.Fuzz(func(t *testing.T, b []byte) {
		r, e := ReadFrame(bytes.NewReader(b), MaxDatagram)
		if e == nil && len(r) > MaxDatagram {
			t.Fatal("unbounded frame")
		}
	})
}
