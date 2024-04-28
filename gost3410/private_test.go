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
	"crypto/rand"
	"io"
	"testing"
)

func TestSignerInterface(t *testing.T) {
	c := CurveIdGostR34102001TestParamSet()
	prvRaw := make([]byte, c.PointSize())
	_, err := io.ReadFull(rand.Reader, prvRaw)
	if err != nil {
		t.Fatal(err)
	}
	prv, err := NewPrivateKey(c, prvRaw)
	if err != nil {
		t.Fatal(err)
	}
	var _ crypto.Signer = prv
	var _ crypto.Signer = &PrivateKeyReverseDigest{prv}
	var _ crypto.Signer = &PrivateKeyReverseDigestAndSignature{prv}
}

func TestSignerReverseDigest(t *testing.T) {
	dgst := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, dgst)
	if err != nil {
		t.Fatal(err)
	}
	prv0, err := GenPrivateKey(CurveIdGostR34102001TestParamSet(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub0 := prv0.Public().(*PublicKey)
	sign, err := prv0.Sign(rand.Reader, dgst, nil)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := pub0.VerifyDigest(dgst, sign)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.FailNow()
	}
	var _ crypto.PublicKey = pub0

	prv1 := PrivateKeyReverseDigest{prv0}
	pub1 := PublicKeyReverseDigest{prv1.Public().(*PublicKey)}
	sign, err = prv1.Sign(rand.Reader, dgst, nil)
	if err != nil {
		t.Fatal(err)
	}
	valid, err = pub1.VerifyDigest(dgst, sign)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.FailNow()
	}

	prv2 := PrivateKeyReverseDigestAndSignature{prv0}
	pub2 := PublicKeyReverseDigestAndSignature{prv2.Public().(*PublicKey)}
	sign, err = prv2.Sign(rand.Reader, dgst, nil)
	if err != nil {
		t.Fatal(err)
	}
	valid, err = pub2.VerifyDigest(dgst, sign)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.FailNow()
	}
}
