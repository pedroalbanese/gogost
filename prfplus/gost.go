// GoGOST -- Pure Go GOST cryptographic functions library
// Copyright (C) 2015-2020 Sergey Matveev <stargrave@stargrave.org>
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

// PRF_IPSEC_PRFPLUS_GOSTR3411_2012_{256,512} as defined in R 50.1.113-2016.
package prfplus

import (
	"crypto/hmac"
	"hash"

	"go.cypherpunks.ru/gogost/v5/gost34112012256"
	"go.cypherpunks.ru/gogost/v5/gost34112012512"
)

type PRFIPsecPRFPlusGOSTR34112012 struct{ h hash.Hash }

func NewPRFIPsecPRFPlusGOSTR34112012256(key []byte) PRFForPlus {
	return PRFIPsecPRFPlusGOSTR34112012{hmac.New(gost34112012256.New, key)}
}

func NewPRFIPsecPRFPlusGOSTR34112012512(key []byte) PRFForPlus {
	return PRFIPsecPRFPlusGOSTR34112012{hmac.New(gost34112012512.New, key)}
}

func (prf PRFIPsecPRFPlusGOSTR34112012) BlockSize() int {
	return prf.h.Size()
}

func (prf PRFIPsecPRFPlusGOSTR34112012) Derive(salt []byte) []byte {
	if _, err := prf.h.Write(salt); err != nil {
		panic(err)
	}
	sum := prf.h.Sum(nil)
	prf.h.Reset()
	return sum
}
