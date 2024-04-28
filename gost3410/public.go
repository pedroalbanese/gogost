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

package gost3410

import (
	"crypto"
	"fmt"
	"math/big"
)

type PublicKey struct {
	C    *Curve
	X, Y *big.Int
}

// Unmarshal LE(X)||LE(Y) public key. "raw" must be 2*c.PointSize() length.
func NewPublicKeyLE(c *Curve, raw []byte) (*PublicKey, error) {
	pointSize := c.PointSize()
	key := make([]byte, 2*pointSize)
	if len(raw) != len(key) {
		return nil, fmt.Errorf("gogost/gost3410: len(key) != %d", len(key))
	}
	for i := 0; i < len(key); i++ {
		key[i] = raw[len(raw)-i-1]
	}
	return &PublicKey{
		c,
		bytes2big(key[pointSize : 2*pointSize]),
		bytes2big(key[:pointSize]),
	}, nil
}

// Unmarshal BE(X)||BE(Y) public key. "raw" must be 2*c.PointSize() length.
func NewPublicKeyBE(c *Curve, raw []byte) (*PublicKey, error) {
	pointSize := c.PointSize()
	if len(raw) != 2*pointSize {
		return nil, fmt.Errorf("gogost/gost3410: len(key) != %d", 2*pointSize)
	}
	return &PublicKey{
		c,
		bytes2big(raw[:pointSize]),
		bytes2big(raw[pointSize:]),
	}, nil
}

// This is an alias for NewPublicKeyLE().
func NewPublicKey(c *Curve, raw []byte) (*PublicKey, error) {
	return NewPublicKeyLE(c, raw)
}

// Marshal LE(X)||LE(Y) public key. raw will be 2*pub.C.PointSize() length.
func (pub *PublicKey) RawLE() []byte {
	pointSize := pub.C.PointSize()
	raw := append(
		pad(pub.Y.Bytes(), pointSize),
		pad(pub.X.Bytes(), pointSize)...,
	)
	reverse(raw)
	return raw
}

// Marshal BE(X)||BE(Y) public key. raw will be 2*pub.C.PointSize() length.
func (pub *PublicKey) RawBE() []byte {
	pointSize := pub.C.PointSize()
	return append(
		pad(pub.X.Bytes(), pointSize),
		pad(pub.Y.Bytes(), pointSize)...,
	)
}

// This is an alias for RawLE().
func (pub *PublicKey) Raw() []byte {
	return pub.RawLE()
}

func (pub *PublicKey) VerifyDigest(digest, signature []byte) (bool, error) {
	pointSize := pub.C.PointSize()
	if len(signature) != 2*pointSize {
		return false, fmt.Errorf("gogost/gost3410: len(signature)=%d != %d", len(signature), 2*pointSize)
	}
	s := bytes2big(signature[:pointSize])
	r := bytes2big(signature[pointSize:])
	if r.Cmp(zero) <= 0 ||
		r.Cmp(pub.C.Q) >= 0 ||
		s.Cmp(zero) <= 0 ||
		s.Cmp(pub.C.Q) >= 0 {
		return false, nil
	}
	e := bytes2big(digest)
	e.Mod(e, pub.C.Q)
	if e.Cmp(zero) == 0 {
		e = big.NewInt(1)
	}
	v := big.NewInt(0)
	v.ModInverse(e, pub.C.Q)
	z1 := big.NewInt(0)
	z2 := big.NewInt(0)
	z1.Mul(s, v)
	z1.Mod(z1, pub.C.Q)
	z2.Mul(r, v)
	z2.Mod(z2, pub.C.Q)
	z2.Sub(pub.C.Q, z2)
	p1x, p1y, err := pub.C.Exp(z1, pub.C.X, pub.C.Y)
	if err != nil {
		return false, err
	}
	q1x, q1y, err := pub.C.Exp(z2, pub.X, pub.Y)
	if err != nil {
		return false, err
	}
	lm := big.NewInt(0)
	lm.Sub(q1x, p1x)
	if lm.Cmp(zero) < 0 {
		lm.Add(lm, pub.C.P)
	}
	lm.ModInverse(lm, pub.C.P)
	z1.Sub(q1y, p1y)
	lm.Mul(lm, z1)
	lm.Mod(lm, pub.C.P)
	lm.Mul(lm, lm)
	lm.Mod(lm, pub.C.P)
	lm.Sub(lm, p1x)
	lm.Sub(lm, q1x)
	lm.Mod(lm, pub.C.P)
	if lm.Cmp(zero) < 0 {
		lm.Add(lm, pub.C.P)
	}
	lm.Mod(lm, pub.C.Q)
	return lm.Cmp(r) == 0, nil
}

func (our *PublicKey) Equal(theirKey crypto.PublicKey) bool {
	their, ok := theirKey.(*PublicKey)
	if !ok {
		return false
	}
	return our.X.Cmp(their.X) == 0 && our.Y.Cmp(their.Y) == 0 && our.C.Equal(their.C)
}

type PublicKeyReverseDigest struct {
	Pub *PublicKey
}

func (pub PublicKeyReverseDigest) VerifyDigest(
	digest, signature []byte,
) (bool, error) {
	dgst := make([]byte, len(digest))
	for i := 0; i < len(digest); i++ {
		dgst[i] = digest[len(digest)-i-1]
	}
	return pub.Pub.VerifyDigest(dgst, signature)
}

func (pub PublicKeyReverseDigest) Equal(theirKey crypto.PublicKey) bool {
	return pub.Pub.Equal(theirKey)
}

type PublicKeyReverseDigestAndSignature struct {
	Pub *PublicKey
}

func (pub PublicKeyReverseDigestAndSignature) VerifyDigest(
	digest, signature []byte,
) (bool, error) {
	dgst := make([]byte, len(digest))
	for i := 0; i < len(digest); i++ {
		dgst[i] = digest[len(digest)-i-1]
	}
	sign := make([]byte, len(signature))
	for i := 0; i < len(signature); i++ {
		sign[i] = signature[len(signature)-i-1]
	}
	return pub.Pub.VerifyDigest(dgst, sign)
}

func (pub PublicKeyReverseDigestAndSignature) Equal(theirKey crypto.PublicKey) bool {
	return pub.Pub.Equal(theirKey)
}
