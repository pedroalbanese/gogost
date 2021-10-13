// GoGOST -- Pure Go GOST cryptographic functions library
// Copyright (C) 2015-2021 Sergey Matveev <stargrave@stargrave.org>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 3 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// GOST 34.12-2015 128-bit (Кузнечик (Kuznechik)) block cipher.
package gost3412128

const (
	BlockSize = 16
	KeySize   = 32
)

var (
	lc [BlockSize]byte = [BlockSize]byte{
		148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16,
		133, 32, 148, 1,
	}
	pi [256]byte = [256]byte{
		252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250,
		218, 35, 197, 4, 77, 233, 119, 240, 219, 147, 46,
		153, 186, 23, 54, 241, 187, 20, 205, 95, 193, 249,
		24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139,
		1, 142, 79, 5, 132, 2, 174, 227, 106, 143, 160, 6,
		11, 237, 152, 127, 212, 211, 31, 235, 52, 44, 81,
		234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206,
		204, 181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19,
		71, 156, 183, 93, 135, 21, 161, 150, 41, 16, 123,
		154, 199, 243, 145, 120, 111, 157, 158, 178, 177,
		50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198,
		128, 195, 189, 13, 87, 223, 245, 36, 169, 62, 168,
		67, 201, 215, 121, 214, 246, 124, 34, 185, 3, 224,
		15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80,
		78, 51, 10, 74, 167, 151, 96, 115, 30, 0, 98, 68,
		26, 184, 56, 130, 100, 159, 38, 65, 173, 69, 70,
		146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213,
		149, 59, 7, 88, 179, 64, 134, 172, 29, 247, 48, 55,
		107, 228, 136, 217, 231, 137, 225, 27, 131, 73, 76,
		63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97,
		32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208,
		190, 229, 108, 82, 89, 166, 116, 210, 230, 244, 180,
		192, 209, 102, 175, 194, 57, 75, 99, 182,
	}
	piInv   [256]byte
	cBlk    [32]*[BlockSize]byte
	gfCache [256][256]byte
)

func gf(a, b byte) (c byte) {
	for b > 0 {
		if b&1 > 0 {
			c ^= a
		}
		if a&0x80 > 0 {
			a = (a << 1) ^ 0xC3
		} else {
			a <<= 1
		}
		b >>= 1
	}
	return
}

func l(blk *[BlockSize]byte) {
	for n := 0; n < BlockSize; n++ {
		blk[0],
			blk[1],
			blk[2],
			blk[3],
			blk[4],
			blk[5],
			blk[6],
			blk[7],
			blk[8],
			blk[9],
			blk[10],
			blk[11],
			blk[12],
			blk[13],
			blk[14],
			blk[15] = (blk[15] ^
			gfCache[blk[0]][lc[0]] ^
			gfCache[blk[1]][lc[1]] ^
			gfCache[blk[2]][lc[2]] ^
			gfCache[blk[3]][lc[3]] ^
			gfCache[blk[4]][lc[4]] ^
			gfCache[blk[5]][lc[5]] ^
			gfCache[blk[6]][lc[6]] ^
			gfCache[blk[7]][lc[7]] ^
			gfCache[blk[8]][lc[8]] ^
			gfCache[blk[9]][lc[9]] ^
			gfCache[blk[10]][lc[10]] ^
			gfCache[blk[11]][lc[11]] ^
			gfCache[blk[12]][lc[12]] ^
			gfCache[blk[13]][lc[13]] ^
			gfCache[blk[14]][lc[14]]),
			blk[0],
			blk[1],
			blk[2],
			blk[3],
			blk[4],
			blk[5],
			blk[6],
			blk[7],
			blk[8],
			blk[9],
			blk[10],
			blk[11],
			blk[12],
			blk[13],
			blk[14]
	}
}

func lInv(blk *[BlockSize]byte) {
	var t byte
	for n := 0; n < BlockSize; n++ {
		t = blk[0]
		copy(blk[:], blk[1:])
		t ^= gfCache[blk[0]][lc[0]]
		t ^= gfCache[blk[1]][lc[1]]
		t ^= gfCache[blk[2]][lc[2]]
		t ^= gfCache[blk[3]][lc[3]]
		t ^= gfCache[blk[4]][lc[4]]
		t ^= gfCache[blk[5]][lc[5]]
		t ^= gfCache[blk[6]][lc[6]]
		t ^= gfCache[blk[7]][lc[7]]
		t ^= gfCache[blk[8]][lc[8]]
		t ^= gfCache[blk[9]][lc[9]]
		t ^= gfCache[blk[10]][lc[10]]
		t ^= gfCache[blk[11]][lc[11]]
		t ^= gfCache[blk[12]][lc[12]]
		t ^= gfCache[blk[13]][lc[13]]
		t ^= gfCache[blk[14]][lc[14]]
		blk[15] = t
	}
}

func s(blk *[BlockSize]byte) {
	blk[0] = pi[int(blk[0])]
	blk[1] = pi[int(blk[1])]
	blk[2] = pi[int(blk[2])]
	blk[3] = pi[int(blk[3])]
	blk[4] = pi[int(blk[4])]
	blk[5] = pi[int(blk[5])]
	blk[6] = pi[int(blk[6])]
	blk[7] = pi[int(blk[7])]
	blk[8] = pi[int(blk[8])]
	blk[9] = pi[int(blk[9])]
	blk[10] = pi[int(blk[10])]
	blk[11] = pi[int(blk[11])]
	blk[12] = pi[int(blk[12])]
	blk[13] = pi[int(blk[13])]
	blk[14] = pi[int(blk[14])]
	blk[15] = pi[int(blk[15])]
}

func sInv(blk *[BlockSize]byte) {
	for n := 0; n < BlockSize; n++ {
		blk[n] = piInv[int(blk[n])]
	}
}

func init() {
	for a := 0; a < 256; a++ {
		for b := 0; b < 256; b++ {
			gfCache[a][b] = gf(byte(a), byte(b))
		}
	}
	for i := 0; i < 256; i++ {
		piInv[int(pi[i])] = byte(i)
	}
	for i := 0; i < 32; i++ {
		cBlk[i] = new([BlockSize]byte)
		cBlk[i][15] = byte(i) + 1
		l(cBlk[i])
	}
}

type Cipher struct {
	ks [10][BlockSize]byte
}

func (c *Cipher) BlockSize() int {
	return BlockSize
}

func NewCipher(key []byte) *Cipher {
	if len(key) != KeySize {
		panic("invalid key size")
	}
	var ks [10][BlockSize]byte
	var kr0 [BlockSize]byte
	var kr1 [BlockSize]byte
	var krt [BlockSize]byte
	copy(kr0[:], key[:BlockSize])
	copy(kr1[:], key[BlockSize:])
	copy(ks[0][:], kr0[:])
	copy(ks[1][:], kr1[:])
	for i := 0; i < 4; i++ {
		for j := 0; j < 8; j++ {
			xor(krt[:], kr0[:], cBlk[8*i+j][:])
			s(&krt)
			l(&krt)
			xor(krt[:], krt[:], kr1[:])
			copy(kr1[:], kr0[:])
			copy(kr0[:], krt[:])
		}
		copy(ks[2+2*i][:], kr0[:])
		copy(ks[2+2*i+1][:], kr1[:])
	}
	return &Cipher{ks}
}

func (c *Cipher) Encrypt(dst, src []byte) {
	blk := new([BlockSize]byte)
	copy(blk[:], src)
	for i := 0; i < 9; i++ {
		xor(blk[:], blk[:], c.ks[i][:])
		s(blk)
		l(blk)
	}
	xor(blk[:], blk[:], c.ks[9][:])
	copy(dst, blk[:])
}

func (c *Cipher) Decrypt(dst, src []byte) {
	blk := new([BlockSize]byte)
	copy(blk[:], src)
	for i := 9; i > 0; i-- {
		xor(blk[:], blk[:], c.ks[i][:])
		lInv(blk)
		sInv(blk)
	}
	xor(dst, blk[:], c.ks[0][:])
}
