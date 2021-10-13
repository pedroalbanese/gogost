//go:build !amd64 && !386 && !ppc64 && !ppc64le && !s390x
// +build !amd64,!386,!ppc64,!ppc64le,!s390x

package gost3412128

func xor(dst, src1, src2 []byte) {
	dst[0] = src1[0] ^ src2[0]
	dst[1] = src1[1] ^ src2[1]
	dst[2] = src1[2] ^ src2[2]
	dst[3] = src1[3] ^ src2[3]
	dst[4] = src1[4] ^ src2[4]
	dst[5] = src1[5] ^ src2[5]
	dst[6] = src1[6] ^ src2[6]
	dst[7] = src1[7] ^ src2[7]
	dst[8] = src1[8] ^ src2[8]
	dst[9] = src1[9] ^ src2[9]
	dst[10] = src1[10] ^ src2[10]
	dst[11] = src1[11] ^ src2[11]
	dst[12] = src1[12] ^ src2[12]
	dst[13] = src1[13] ^ src2[13]
	dst[14] = src1[14] ^ src2[14]
	dst[15] = src1[15] ^ src2[15]
}
