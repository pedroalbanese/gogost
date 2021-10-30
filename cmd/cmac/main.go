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

// Command-line 28147-89 CMAC function.
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
