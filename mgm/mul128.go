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

package mgm

import "encoding/binary"

type mul128 struct{ buf [16]byte }

func newMul128() *mul128 {
	return &mul128{}
}

func gf128half(n int, t, x0, x1, z0, z1 uint64) (uint64, uint64, uint64, uint64, uint64) {
	var sign bool
	for i := 0; i < n; i++ {
		if t&1 > 0 {
			z0, z1 = z0^x0, z1^x1
		}
		t >>= 1
		sign = x1>>63 > 0
		x1 = (x1 << 1) ^ (x0 >> 63)
		x0 <<= 1
		if sign {
			x0 ^= 0x87
		}
	}
	return t, x0, x1, z0, z1
}

func (mul *mul128) Mul(x, y []byte) []byte {
	x1 := binary.BigEndian.Uint64(x[:8])
	x0 := binary.BigEndian.Uint64(x[8:])
	y1 := binary.BigEndian.Uint64(y[:8])
	y0 := binary.BigEndian.Uint64(y[8:])
	t, x0, x1, z0, z1 := gf128half(64, y0, x0, x1, 0, 0)
	t, x0, x1, z0, z1 = gf128half(63, y1, x0, x1, z0, z1)
	if t&1 > 0 {
		z0, z1 = z0^x0, z1^x1
	}
	binary.BigEndian.PutUint64(mul.buf[:8], z1)
	binary.BigEndian.PutUint64(mul.buf[8:], z0)
	return mul.buf[:]
}
