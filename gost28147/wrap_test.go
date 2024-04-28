package gost28147

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"
)

func TestWrapSymmetric(t *testing.T) {
	kek := make([]byte, KeySize)
	cek := make([]byte, KeySize)
	ukm := make([]byte, 8)
	for i := 0; i < 1000; i++ {
		if _, err := io.ReadFull(rand.Reader, kek); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(rand.Reader, cek); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(rand.Reader, ukm); err != nil {
			t.Fatal(err)
		}
		data := WrapGost(ukm, kek, cek)
		got := UnwrapGost(kek, data)
		if !bytes.Equal(got, cek) {
			t.FailNow()
		}
	}
}
