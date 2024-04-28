// GoGOST -- Pure Go GOST cryptographic functions library
// Copyright (C) 2015-2024 Sergey Matveev <stargrave@stargrave.org>
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

package prfplus

type PRFForPlus interface {
	BlockSize() int
	Derive(salt []byte) []byte
}

// prf+ function as defined in RFC 7296 (IKEv2)
func PRFPlus(prf PRFForPlus, dst, salt []byte) {
	in := make([]byte, prf.BlockSize()+len(salt)+1)
	in[len(in)-1] = byte(0x01)
	copy(in[prf.BlockSize():], salt)
	copy(in[:prf.BlockSize()], prf.Derive(in[prf.BlockSize():]))
	copy(dst, in[:prf.BlockSize()])
	n := len(dst) / prf.BlockSize()
	if n == 0 {
		return
	}
	if n*prf.BlockSize() != len(dst) {
		n++
	}
	n--
	out := dst[prf.BlockSize():]
	for i := 0; i < n; i++ {
		in[len(in)-1] = byte(i + 2)
		copy(in[:prf.BlockSize()], prf.Derive(in))
		copy(out, in[:prf.BlockSize()])
		if i+1 != n {
			out = out[prf.BlockSize():]
		}
	}
}
