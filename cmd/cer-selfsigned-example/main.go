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

// Example X.509 certificate issuing utility.
package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"io"
	"log"
	"math/big"
	"os"
	"time"

	"crypto/go.cypherpunks.ru/gogost/v5/gost3410"
	"crypto/go.cypherpunks.ru/gogost/v5/gost34112012256"
)

const (
	PEMKey = "PRIVATE KEY"
	PEMCer = "CERTIFICATE"
)

func loadKeypair(filename string) (cer *x509.Certificate, prv any, err error) {
	var data []byte
	data, err = os.ReadFile(filename)
	if err != nil {
		return
	}
	var block *pem.Block
	for len(data) > 0 {
		block, data = pem.Decode(data)
		if block == nil {
			continue
		}
		switch block.Type {
		case PEMCer:
			cer, err = x509.ParseCertificate(block.Bytes)
		case PEMKey:
			prv, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		}
		if err != nil {
			return
		}
	}
	return
}

func main() {
	ca := flag.Bool("ca", false, "Enable BasicConstraints.cA")
	cn := flag.String("cn", "", "Subject's CommonName")
	country := flag.String("country", "", "Subject's Country")
	serial := flag.Int64("serial", -1, "Serial number")
	ai := flag.String("ai", "", "Signing algorithm: {256[ABCD],512[ABC]}")
	issueWith := flag.String("issue-with", "", "Path to PEM with CA to issue the child")
	reuseKey := flag.String("reuse-key", "", "Path to PEM with the key to reuse")
	outKey := flag.String("out-key", "", "Path to PEM with the resulting key")
	onlyKey := flag.Bool("only-key", false, "Only generate the key")
	outCer := flag.String("out-cert", "", "Path to PEM with the resulting certificate")
	flag.Parse()
	log.SetFlags(log.Lshortfile)

	if *cn == "" {
		log.Fatal("no CommonName is set")
	}
	var curve *gost3410.Curve
	var sigAlg x509.SignatureAlgorithm
	switch *ai {
	case "256A":
		curve = gost3410.CurveIdtc26gost341012256paramSetA()
		sigAlg = x509.GOST256
	case "256B":
		curve = gost3410.CurveIdtc26gost341012256paramSetB()
		sigAlg = x509.GOST256
	case "256C":
		curve = gost3410.CurveIdtc26gost341012256paramSetC()
		sigAlg = x509.GOST256
	case "256D":
		curve = gost3410.CurveIdtc26gost341012256paramSetD()
		sigAlg = x509.GOST256
	case "512A":
		curve = gost3410.CurveIdtc26gost341012512paramSetA()
		sigAlg = x509.GOST512
	case "512B":
		curve = gost3410.CurveIdtc26gost341012512paramSetB()
		sigAlg = x509.GOST512
	case "512C":
		curve = gost3410.CurveIdtc26gost341012512paramSetC()
		sigAlg = x509.GOST512
	default:
		log.Fatal("unknown curve name")
	}

	var err error
	var caCer *x509.Certificate
	var caPrv any
	if *issueWith != "" {
		caCer, caPrv, err = loadKeypair(*issueWith)
		if err != nil {
			log.Fatal(err)
		}
		sigAlg = caCer.SignatureAlgorithm
	}

	var prv any
	if *reuseKey == "" {
		prvRaw := make([]byte, curve.PointSize())
		if _, err := io.ReadFull(rand.Reader, prvRaw); err != nil {
			log.Fatal(err)
		}
		prv, err = gost3410.NewPrivateKey(curve, prvRaw)
		if err != nil {
			log.Fatal(err)
		}
		data, err := x509.MarshalPKCS8PrivateKey(prv)
		if err != nil {
			log.Fatal(err)
		}
		data = pem.EncodeToMemory(&pem.Block{Type: PEMKey, Bytes: data})
		if *outKey == "" {
			_, err = os.Stdout.Write(data)
		} else {
			err = os.WriteFile(*outKey, data, 0o666)
		}
		if err != nil {
			log.Fatal(err)
		}
		if *onlyKey {
			return
		}
	} else {
		_, prv, err = loadKeypair(*reuseKey)
		if err != nil {
			log.Fatal(err)
		}
	}

	notBefore := time.Now().UTC()
	days := 365 * 24 * time.Hour
	if *ca {
		days *= 10
	}
	notAfter := notBefore.Add(days)

	sn := big.NewInt(0)
	if *serial == -1 {
		data := make([]byte, 16, gost34112012256.Size)
		if _, err = io.ReadFull(rand.Reader, data); err != nil {
			log.Fatal(err)
		}
		hasher := gost34112012256.New()
		if _, err = hasher.Write(data); err != nil {
			log.Fatal(err)
		}
		data = hasher.Sum(data[:0])
		sn = sn.SetBytes(data[:20])
	} else {
		sn = sn.SetInt64(*serial)
	}

	subj := pkix.Name{CommonName: *cn}
	if *country != "" {
		subj.Country = []string{*country}
	}

	pub, err := prv.(*gost3410.PrivateKey).PublicKey()
	if err != nil {
		log.Fatal(err)
	}
	hasher := gost34112012256.New()
	if _, err = hasher.Write(pub.Raw()); err != nil {
		log.Fatal(err)
	}
	spki := hasher.Sum(nil)
	spki = spki[:20]

	cerTmpl := x509.Certificate{
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		SerialNumber:       sn,
		SignatureAlgorithm: sigAlg,
		Subject:            subj,
		SubjectKeyId:       spki,
	}
	if *ca {
		cerTmpl.BasicConstraintsValid = true
		cerTmpl.IsCA = true
		cerTmpl.KeyUsage = x509.KeyUsageCertSign
	} else {
		cerTmpl.DNSNames = []string{*cn}
		cerTmpl.KeyUsage = x509.KeyUsageDigitalSignature
	}

	if caCer == nil {
		caCer = &cerTmpl
		caPrv = prv
	}
	data, err := x509.CreateCertificate(
		rand.Reader,
		&cerTmpl, caCer, pub,
		&gost3410.PrivateKeyReverseDigest{Prv: caPrv.(*gost3410.PrivateKey)},
	)
	if err != nil {
		log.Fatal(err)
	}
	data = pem.EncodeToMemory(&pem.Block{Type: PEMCer, Bytes: data})
	if *outCer == "" {
		_, err = os.Stdout.Write(data)
	} else {
		err = os.WriteFile(*outCer, data, 0o666)
	}
	if err != nil {
		log.Fatal(err)
	}
}
