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

// Multilinear Galois Mode (MGM) block cipher mode.
package mgm

import (
	"crypto/cipher"
	"crypto/hmac"
	"encoding/binary"
	"errors"
)

type Mul interface {
	Mul(x, y []byte) []byte
}

type MGM struct {
	MaxSize   uint64
	BlockSize int
	TagSize   int
	cipher    cipher.Block
	icn       []byte
	bufP      []byte
	bufC      []byte
	padded    []byte
	sum       []byte
	mul       Mul
}

func NewMGM(cipher cipher.Block, tagSize int) (cipher.AEAD, error) {
	blockSize := cipher.BlockSize()
	if !(blockSize == 8 || blockSize == 16) {
		return nil, errors.New("gogost/mgm: only 64/128 blocksizes allowed")
	}
	if tagSize < 4 || tagSize > blockSize {
		return nil, errors.New("gogost/mgm: invalid tag size")
	}
	mgm := MGM{
		MaxSize:   uint64(1<<uint(blockSize*8/2) - 1),
		BlockSize: blockSize,
		TagSize:   tagSize,
		cipher:    cipher,
		icn:       make([]byte, blockSize),
		bufP:      make([]byte, blockSize),
		bufC:      make([]byte, blockSize),
		padded:    make([]byte, blockSize),
		sum:       make([]byte, blockSize),
	}
	if blockSize == 8 {
		mgm.mul = newMul64()
	} else {
		mgm.mul = newMul128()
	}
	return &mgm, nil
}

func (mgm *MGM) NonceSize() int {
	return mgm.BlockSize
}

func (mgm *MGM) Overhead() int {
	return mgm.TagSize
}

func incr(data []byte) {
	for i := len(data) - 1; i >= 0; i-- {
		data[i]++
		if data[i] != 0 {
			return
		}
	}
}

func xor(dst, src1, src2 []byte) {
	for i := 0; i < len(src1); i++ {
		dst[i] = src1[i] ^ src2[i]
	}
}

func (mgm *MGM) validateNonce(nonce []byte) {
	if len(nonce) != mgm.BlockSize {
		panic("nonce length must be equal to cipher's blocksize")
	}
	if nonce[0]&0x80 > 0 {
		panic("nonce must not have higher bit set")
	}
}

func (mgm *MGM) validateSizes(text, additionalData []byte) {
	if len(text) == 0 && len(additionalData) == 0 {
		panic("at least either *text or additionalData must be provided")
	}
	if uint64(len(additionalData)) > mgm.MaxSize {
		panic("additionalData is too big")
	}
	if uint64(len(text)+len(additionalData)) > mgm.MaxSize {
		panic("*text with additionalData are too big")
	}
}

func (mgm *MGM) auth(out, text, ad []byte) {
	for i := 0; i < mgm.BlockSize; i++ {
		mgm.sum[i] = 0
	}
	adLen := len(ad) * 8
	textLen := len(text) * 8
	mgm.icn[0] |= 0x80
	mgm.cipher.Encrypt(mgm.bufP, mgm.icn) // Z_1 = E_K(1 || ICN)
	for len(ad) >= mgm.BlockSize {
		mgm.cipher.Encrypt(mgm.bufC, mgm.bufP) // H_i = E_K(Z_i)
		xor(                                   // sum (xor)= H_i (x) A_i
			mgm.sum,
			mgm.sum,
			mgm.mul.Mul(mgm.bufC, ad[:mgm.BlockSize]),
		)
		incr(mgm.bufP[:mgm.BlockSize/2]) // Z_{i+1} = incr_l(Z_i)
		ad = ad[mgm.BlockSize:]
	}
	if len(ad) > 0 {
		copy(mgm.padded, ad)
		for i := len(ad); i < mgm.BlockSize; i++ {
			mgm.padded[i] = 0
		}
		mgm.cipher.Encrypt(mgm.bufC, mgm.bufP)
		xor(mgm.sum, mgm.sum, mgm.mul.Mul(mgm.bufC, mgm.padded))
		incr(mgm.bufP[:mgm.BlockSize/2])
	}

	for len(text) >= mgm.BlockSize {
		mgm.cipher.Encrypt(mgm.bufC, mgm.bufP) // H_{h+j} = E_K(Z_{h+j})
		xor(                                   // sum (xor)= H_{h+j} (x) C_j
			mgm.sum,
			mgm.sum,
			mgm.mul.Mul(mgm.bufC, text[:mgm.BlockSize]),
		)
		incr(mgm.bufP[:mgm.BlockSize/2]) // Z_{h+j+1} = incr_l(Z_{h+j})
		text = text[mgm.BlockSize:]
	}
	if len(text) > 0 {
		copy(mgm.padded, text)
		for i := len(text); i < mgm.BlockSize; i++ {
			mgm.padded[i] = 0
		}
		mgm.cipher.Encrypt(mgm.bufC, mgm.bufP)
		xor(mgm.sum, mgm.sum, mgm.mul.Mul(mgm.bufC, mgm.padded))
		incr(mgm.bufP[:mgm.BlockSize/2])
	}

	mgm.cipher.Encrypt(mgm.bufP, mgm.bufP) // H_{h+q+1} = E_K(Z_{h+q+1})
	// len(A) || len(C)
	if mgm.BlockSize == 8 {
		binary.BigEndian.PutUint32(mgm.bufC, uint32(adLen))
		binary.BigEndian.PutUint32(mgm.bufC[mgm.BlockSize/2:], uint32(textLen))
	} else {
		binary.BigEndian.PutUint64(mgm.bufC, uint64(adLen))
		binary.BigEndian.PutUint64(mgm.bufC[mgm.BlockSize/2:], uint64(textLen))
	}
	// sum (xor)= H_{h+q+1} (x) (len(A) || len(C))
	xor(mgm.sum, mgm.sum, mgm.mul.Mul(mgm.bufC, mgm.bufP))
	mgm.cipher.Encrypt(mgm.bufP, mgm.sum) // E_K(sum)
	copy(out, mgm.bufP[:mgm.TagSize])     // MSB_S(E_K(sum))
}

func (mgm *MGM) crypt(out, in []byte) {
	mgm.icn[0] &= 0x7F
	mgm.cipher.Encrypt(mgm.bufP, mgm.icn) // Y_1 = E_K(0 || ICN)
	for len(in) >= mgm.BlockSize {
		mgm.cipher.Encrypt(mgm.bufC, mgm.bufP) // E_K(Y_i)
		xor(out, mgm.bufC, in)                 // C_i = P_i (xor) E_K(Y_i)
		incr(mgm.bufP[mgm.BlockSize/2:])       // Y_i = incr_r(Y_{i-1})
		out = out[mgm.BlockSize:]
		in = in[mgm.BlockSize:]
	}
	if len(in) > 0 {
		mgm.cipher.Encrypt(mgm.bufC, mgm.bufP)
		xor(out, in, mgm.bufC)
	}
}

func (mgm *MGM) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	mgm.validateNonce(nonce)
	mgm.validateSizes(plaintext, additionalData)
	if uint64(len(plaintext)) > mgm.MaxSize {
		panic("plaintext is too big")
	}
	ret, out := sliceForAppend(dst, len(plaintext)+mgm.TagSize)
	copy(mgm.icn, nonce)
	mgm.crypt(out, plaintext)
	mgm.auth(
		out[len(plaintext):len(plaintext)+mgm.TagSize],
		out[:len(plaintext)],
		additionalData,
	)
	return ret
}

func (mgm *MGM) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	mgm.validateNonce(nonce)
	mgm.validateSizes(ciphertext, additionalData)
	if len(ciphertext) < mgm.TagSize {
		return nil, errors.New("ciphertext is too short")
	}
	if uint64(len(ciphertext)-mgm.TagSize) > mgm.MaxSize {
		panic("ciphertext is too big")
	}
	ret, out := sliceForAppend(dst, len(ciphertext)-mgm.TagSize)
	ct := ciphertext[:len(ciphertext)-mgm.TagSize]
	copy(mgm.icn, nonce)
	mgm.auth(mgm.sum, ct, additionalData)
	if !hmac.Equal(mgm.sum[:mgm.TagSize], ciphertext[len(ciphertext)-mgm.TagSize:]) {
		return nil, errors.New("gogost/mgm: invalid authentication tag")
	}
	mgm.crypt(out, ct)
	return ret, nil
}
