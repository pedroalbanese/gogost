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
	"errors"
	"fmt"
	"io"
	"math/big"
)

type PrivateKey struct {
	C   *Curve
	Key *big.Int
}

// Unmarshal little-endian private key. "raw" must be c.PointSize() length.
func NewPrivateKeyLE(c *Curve, raw []byte) (*PrivateKey, error) {
	pointSize := c.PointSize()
	if len(raw) != pointSize {
		return nil, fmt.Errorf("gogost/gost3410: len(key)=%d != %d", len(raw), pointSize)
	}
	key := make([]byte, pointSize)
	for i := 0; i < len(key); i++ {
		key[i] = raw[len(raw)-i-1]
	}
	k := bytes2big(key)
	if k.Cmp(zero) == 0 {
		return nil, errors.New("gogost/gost3410: zero private key")
	}
	return &PrivateKey{c, k.Mod(k, c.Q)}, nil
}

// Unmarshal big-endian private key. "raw" must be c.PointSize() length.
func NewPrivateKeyBE(c *Curve, raw []byte) (*PrivateKey, error) {
	pointSize := c.PointSize()
	if len(raw) != pointSize {
		return nil, fmt.Errorf("gogost/gost3410: len(key)=%d != %d", len(raw), pointSize)
	}
	k := bytes2big(raw)
	if k.Cmp(zero) == 0 {
		return nil, errors.New("gogost/gost3410: zero private key")
	}
	return &PrivateKey{c, k.Mod(k, c.Q)}, nil
}

// This is an alias for NewPrivateKeyLE().
func NewPrivateKey(c *Curve, raw []byte) (*PrivateKey, error) {
	return NewPrivateKeyLE(c, raw)
}

func GenPrivateKey(c *Curve, rand io.Reader) (*PrivateKey, error) {
	raw := make([]byte, c.PointSize())
	if _, err := io.ReadFull(rand, raw); err != nil {
		return nil, fmt.Errorf("gogost/gost3410.GenPrivateKey: %w", err)
	}
	return NewPrivateKey(c, raw)
}

// Marshal little-endian private key. raw will be prv.C.PointSize() length.
func (prv *PrivateKey) RawLE() (raw []byte) {
	raw = pad(prv.Key.Bytes(), prv.C.PointSize())
	reverse(raw)
	return raw
}

// Marshal big-endian private key. raw will be prv.C.PointSize() length.
func (prv *PrivateKey) RawBE() (raw []byte) {
	return pad(prv.Key.Bytes(), prv.C.PointSize())
}

// This is an alias for RawLE().
func (prv *PrivateKey) Raw() []byte {
	return prv.RawLE()
}

func (prv *PrivateKey) PublicKey() (*PublicKey, error) {
	x, y, err := prv.C.Exp(prv.Key, prv.C.X, prv.C.Y)
	if err != nil {
		return nil, fmt.Errorf("gogost/gost3410.PrivateKey.PublicKey: %w", err)
	}
	return &PublicKey{prv.C, x, y}, nil
}

func (prv *PrivateKey) SignDigest(digest []byte, rand io.Reader) ([]byte, error) {
	e := bytes2big(digest)
	e.Mod(e, prv.C.Q)
	if e.Cmp(zero) == 0 {
		e = big.NewInt(1)
	}
	kRaw := make([]byte, prv.C.PointSize())
	var err error
	var k *big.Int
	var r *big.Int
	d := big.NewInt(0)
	s := big.NewInt(0)
Retry:
	if _, err = io.ReadFull(rand, kRaw); err != nil {
		return nil, fmt.Errorf("gogost/gost3410.PrivateKey.SignDigest: %w", err)
	}
	k = bytes2big(kRaw)
	k.Mod(k, prv.C.Q)
	if k.Cmp(zero) == 0 {
		goto Retry
	}
	r, _, err = prv.C.Exp(k, prv.C.X, prv.C.Y)
	if err != nil {
		return nil, fmt.Errorf("gogost/gost3410.PrivateKey.SignDigest: %w", err)
	}
	r.Mod(r, prv.C.Q)
	if r.Cmp(zero) == 0 {
		goto Retry
	}
	d.Mul(prv.Key, r)
	k.Mul(k, e)
	s.Add(d, k)
	s.Mod(s, prv.C.Q)
	if s.Cmp(zero) == 0 {
		goto Retry
	}
	pointSize := prv.C.PointSize()
	return append(
		pad(s.Bytes(), pointSize),
		pad(r.Bytes(), pointSize)...,
	), nil
}

// Sign the digest. opts argument is unused. That is identical to SignDigest,
// but kept to be friendly to crypto.Signer.
func (prv *PrivateKey) Sign(
	rand io.Reader, digest []byte, opts crypto.SignerOpts,
) ([]byte, error) {
	return prv.SignDigest(digest, rand)
}

func (prv *PrivateKey) Public() crypto.PublicKey {
	pub, err := prv.PublicKey()
	if err != nil {
		panic(err)
	}
	return pub
}

type PrivateKeyReverseDigest struct {
	Prv *PrivateKey
}

func (prv *PrivateKeyReverseDigest) Public() crypto.PublicKey {
	return prv.Prv.Public()
}

func (prv *PrivateKeyReverseDigest) Sign(
	rand io.Reader, digest []byte, opts crypto.SignerOpts,
) ([]byte, error) {
	dgst := make([]byte, len(digest))
	for i := 0; i < len(digest); i++ {
		dgst[i] = digest[len(digest)-i-1]
	}
	return prv.Prv.Sign(rand, dgst, opts)
}

type PrivateKeyReverseDigestAndSignature struct {
	Prv *PrivateKey
}

func (prv *PrivateKeyReverseDigestAndSignature) Public() crypto.PublicKey {
	return prv.Prv.Public()
}

func (prv *PrivateKeyReverseDigestAndSignature) Sign(
	rand io.Reader, digest []byte, opts crypto.SignerOpts,
) ([]byte, error) {
	dgst := make([]byte, len(digest))
	for i := 0; i < len(digest); i++ {
		dgst[i] = digest[len(digest)-i-1]
	}
	sign, err := prv.Prv.Sign(rand, dgst, opts)
	if err != nil {
		return sign, err
	}
	reverse(sign)
	return sign, err
}
