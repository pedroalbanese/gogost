//go:build amd64 || 386 || ppc64 || ppc64le || s390x
// +build amd64 386 ppc64 ppc64le s390x

// Fast XOR taken from native crypto/cipher

package gost3412128

import (
	"unsafe"
)

const xorWords = BlockSize / int(unsafe.Sizeof(uintptr(0)))

func xor(dst, a, b []byte) {
	dw := *(*[]uintptr)(unsafe.Pointer(&dst))
	aw := *(*[]uintptr)(unsafe.Pointer(&a))
	bw := *(*[]uintptr)(unsafe.Pointer(&b))
	for i := 0; i < xorWords; i++ {
		dw[i] = aw[i] ^ bw[i]
	}
}
