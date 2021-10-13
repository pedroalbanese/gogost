// GoGOST -- Pure Go GOST cryptographic functions library
// Copyright (C) 2015-2020 Sergey Matveev <stargrave@stargrave.org>
// Copyright (C) 2020-2021 Pedro Albanese <pedroalbanese@hotmail.com>
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

// Command-line 34.10-2012 Public key shared key agreement.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"

	"github.com/pedroalbanese/gogost/gost3410"
)

func main() {
	curveName := flag.String("curve", "id-tc26-gost-3410-2012-256-paramSetA", "Curve name")
	pubHex := flag.String("pub", "", "Remote's side public key")
	prvHex := flag.String("prv", "", "Our private key")
	keygen := flag.Bool("gen", false, "Generate keypair")
	flag.Parse()

	var curve *gost3410.Curve
	switch *curveName {
	case "id-tc26-gost-3410-2012-256-paramSetA":
		curve = gost3410.CurveIdtc26gost34102012256paramSetA()
	case "id-tc26-gost-3410-2012-256-paramSetB":
		curve = gost3410.CurveIdtc26gost34102012256paramSetD()
	case "id-tc26-gost-3410-2012-256-paramSetC":
		curve = gost3410.CurveIdtc26gost34102012256paramSetC()
	case "id-tc26-gost-3410-2012-256-paramSetD":
		curve = gost3410.CurveIdtc26gost34102012256paramSetD()
	default:
		panic(errors.New("unknown curve specified"))
	}

	var err error
	var prvRaw []byte
	var pubRaw []byte
	var prv *gost3410.PrivateKey
	var pub *gost3410.PublicKey

	if *keygen {
		prvRaw = make([]byte, 256/8)
		_, err = io.ReadFull(rand.Reader, prvRaw)
		if err != nil {
			panic(err)
		}
		fmt.Fprintln(os.Stderr, "Private:", hex.EncodeToString(prvRaw))
		prv, err = gost3410.NewPrivateKey(curve, prvRaw)
		if err != nil {
			panic(err)
		}

		pub, err = prv.PublicKey()
		if err != nil {
			panic(err)
		}
		pubRaw = pub.Raw()
		fmt.Fprintln(os.Stderr, "Public:", hex.EncodeToString(pubRaw))
		os.Exit(0)
	}

	prvRaw, err = hex.DecodeString(*prvHex)
	if err != nil {
		panic(err)
	}
	if len(prvRaw) != 256/8 {
		panic(errors.New("private key has wrong length"))
	}
	prv, err = gost3410.NewPrivateKey(curve, prvRaw)
	if err != nil {
		panic(err)
	}
	pubRaw, err = hex.DecodeString(*pubHex)
	if err != nil {
		panic(err)
	}
	if len(pubRaw) != 2*256/8 {
		panic(errors.New("public key has wrong length"))
	}
	pub, err = gost3410.NewPublicKey(curve, pubRaw)
	if err != nil {
		panic(err)
	}

	shared, err := prv.KEK2012256(pub, big.NewInt(1))
	if err != nil {
		panic(err)
	}
	fmt.Println("Shared:", hex.EncodeToString(shared))
}
