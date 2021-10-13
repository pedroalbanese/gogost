package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/pedroalbanese/gogost/gost28147"
)

func main() {
	keyHex := flag.String("key", "", "Key")
	flag.Parse()
	if len(*keyHex) != 256/8 {
		fmt.Println("Secret key must have 128-bit.")
        	os.Exit(1)
	}
	c := gost28147.NewCipher([]byte(*keyHex), &gost28147.SboxIdGostR341194CryptoProParamSet)
	var iv [8]byte
	h, _ := c.NewMAC(8, iv[:])
	io.Copy(h, os.Stdin)
	fmt.Println(hex.EncodeToString(h.Sum(nil)))
        os.Exit(0)
}