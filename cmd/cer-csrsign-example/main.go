package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"time"

	"github.com/pedroalbanese/gogost/gost3410"
)

func main() {
	// CA certificate
	data, err := os.ReadFile("/home/stargrave/secure/ca/ee/gost/cagost.cypherpunks.ru/www.cypherpunks.ru/cer.pem")
	if err != nil {
		panic(err)
	}
	b, _ := pem.Decode(data)
	if b == nil || b.Type != "CERTIFICATE" {
		panic("no CERTIFICATE")
	}
	caCert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		panic(err)
	}

	// CA key
	data, err = os.ReadFile("/home/stargrave/secure/ca/ee/gost/cagost.cypherpunks.ru/www.cypherpunks.ru/key.pem")
	if err != nil {
		panic(err)
	}
	b, _ = pem.Decode(data)
	if b == nil || b.Type != "PRIVATE KEY" {
		panic("no PRIVATE KEY")
	}
	caKey, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		panic(err)
	}

	// CSR
	curve := gost3410.CurveIdtc26gost341012256paramSetA()
	eeKeyRaw := make([]byte, curve.PointSize())
	if _, err := io.ReadFull(rand.Reader, eeKeyRaw); err != nil {
		panic(err)
	}
	eeKey, err := gost3410.NewPrivateKey(curve, eeKeyRaw)
	if err != nil {
		panic(err)
	}
	cn := "example.com"
	csrTmpl := x509.CertificateRequest{
		SignatureAlgorithm: x509.GOST256,
		Subject:            pkix.Name{CommonName: cn},
		DNSNames:           []string{cn},
	}
	csrDer, err := x509.CreateCertificateRequest(
		rand.Reader,
		&csrTmpl, &gost3410.PrivateKeyReverseDigest{Prv: eeKey},
	)
	csr, err := x509.ParseCertificateRequest(csrDer)
	if err != nil {
		panic(err)
	}

	// Issue
	cerTmpl := x509.Certificate{
		DNSNames:           csr.DNSNames,
		KeyUsage:           x509.KeyUsageDigitalSignature,
		NotBefore:          time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:           time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		SerialNumber:       big.NewInt(12345),
		SignatureAlgorithm: x509.GOST256,
		Subject:            csr.Subject,
	}
	cerDer, err := x509.CreateCertificate(
		rand.Reader,
		&cerTmpl, caCert, csr.PublicKey,
		&gost3410.PrivateKeyReverseDigest{Prv: caKey.(*gost3410.PrivateKey)},
	)
	if err != nil {
		panic(err)
	}
	cer, err := x509.ParseCertificate(cerDer)
	if err != nil {
		panic(err)
	}
	fmt.Println(cer)
	os.WriteFile("/tmp/cer", cerDer, 0o666)
}
