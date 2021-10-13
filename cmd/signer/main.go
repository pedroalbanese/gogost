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

// Command-line 34.10-2012 Public key algorithm signer.
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/pedroalbanese/gogost/gost3410"
	"github.com/pedroalbanese/gogost/gost34112012256"
)

func main() {
	curveName := flag.String("curve", "id-tc26-gost-3410-2012-256-paramSetA", "Curve name")
	keygen := flag.Bool("gen", false, "Generate keypair")
	sign := flag.Bool("sign", false, "Sign with private key")
	verify := flag.Bool("verify", false, "Verify with public key")
	sig := flag.String("sig", "", "Input signature.")
	key := flag.String("key", "", "Private/Public key, depending on operation.")
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

	if *keygen {
		var err error
		var prvRaw []byte
		var pubRaw []byte
		var prv *gost3410.PrivateKey
		var pub *gost3410.PublicKey
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

	if *sign == true || *verify == true {

		scannerWrite := bufio.NewScanner(os.Stdin)
		if !scannerWrite.Scan() {
			log.Printf("Failed to read: %v", scannerWrite.Err())
			return
		}

		var err error
		var prvRaw []byte
		var pubRaw []byte
		var prv *gost3410.PrivateKey
		var pub *gost3410.PublicKey

		var inputsig []byte
		inputsig, err = hex.DecodeString(*sig)
		if err != nil {
			panic(err)
		}

		if *sign == true {
			hash := scannerWrite.Bytes()
			data := []byte(hash)
			hasher := gost34112012256.New()
			_, err := hasher.Write(data)
			if err != nil {
				log.Fatal(err)
			}
			dgst := hasher.Sum(nil)
			prvRaw, err = hex.DecodeString(*key)
			if err != nil {
				panic(err)
			}
			if len(prvRaw) != 256/8 {
				log.Fatal(err, "private key has wrong length")
			}
			prv, err = gost3410.NewPrivateKey(curve, prvRaw)
			if err != nil {
				panic(err)
			}

			signature, err := prv.Sign(rand.Reader, dgst, nil)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println(hex.EncodeToString(signature))
			os.Exit(0)
		}

		if *verify == true {
			hash := scannerWrite.Bytes()
			data := []byte(hash)
			hasher := gost34112012256.New()
			_, err := hasher.Write(data)
			if err != nil {
				panic(err)
			}
			dgst := hasher.Sum(nil)
			pubRaw, err = hex.DecodeString(*key)
			if err != nil {
				panic(err)
			}
			if len(pubRaw) != 2*256/8 {
				log.Fatal(err, "public key has wrong length")
			}
			pub, err = gost3410.NewPublicKey(curve, pubRaw)
			if err != nil {
				panic(err)
			}
			isValid, err := pub.VerifyDigest(dgst, inputsig)
			if err != nil {
				panic(err)
			}
			if !isValid {
				panic(errors.New("signature is invalid"))
			}
			fmt.Println("Verify correct.")
			os.Exit(0)
		}
	}
}
