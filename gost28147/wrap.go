// GoGOST -- Pure Go GOST cryptographic functions library
// Copyright (C) 2015-2023 Sergey Matveev <stargrave@stargrave.org>
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

package gost28147

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
)

func WrapGost(ukm, kek, cek []byte) []byte {
	c := NewCipher(kek, &SboxIdGost2814789CryptoProAParamSet)
	mac, err := c.NewMAC(4, ukm)
	if err != nil {
		panic(err)
	}
	_, err = mac.Write(cek)
	if err != nil {
		panic(err)
	}
	cekMac := mac.Sum(nil)
	cekEnc := make([]byte, 32)
	c.NewECBEncrypter().CryptBlocks(cekEnc, cek)
	return bytes.Join([][]byte{ukm, cekEnc, cekMac}, nil)
}

func UnwrapGost(kek, data []byte) []byte {
	ukm, data := data[:8], data[8:]
	cekEnc, cekMac := data[:KeySize], data[KeySize:]
	c := NewCipher(kek, &SboxIdGost2814789CryptoProAParamSet)
	cek := make([]byte, 32)
	c.NewECBDecrypter().CryptBlocks(cek, cekEnc)
	mac, err := c.NewMAC(4, ukm)
	if err != nil {
		panic(err)
	}
	_, err = mac.Write(cek)
	if err != nil {
		panic(err)
	}
	if subtle.ConstantTimeCompare(mac.Sum(nil), cekMac) != 1 {
		return nil
	}
	return cek
}

func DiversifyCryptoPro(kek, ukm []byte) []byte {
	out := kek
	for i := 0; i < 8; i++ {
		var s1, s2 uint64
		for j := 0; j < 8; j++ {
			k := binary.LittleEndian.Uint32(out[j*4 : j*4+4])
			if (ukm[i]>>j)&1 > 0 {
				s1 += uint64(k)
			} else {
				s2 += uint64(k)
			}
		}
		iv := make([]byte, 8)
		binary.LittleEndian.PutUint32(iv[:4], uint32(s1%(1<<32)))
		binary.LittleEndian.PutUint32(iv[4:], uint32(s2%(1<<32)))
		c := NewCipher(out, &SboxIdGost2814789CryptoProAParamSet)
		c.NewCFBEncrypter(iv).XORKeyStream(out, out)
	}
	return out
}

func UnwrapCryptoPro(kek, data []byte) []byte {
	return UnwrapGost(DiversifyCryptoPro(kek, data[:8]), data)
}
