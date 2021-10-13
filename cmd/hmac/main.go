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

// Command-line 34.11-2012 256-bit HMAC function.
package main

import (
	"crypto/hmac"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/pedroalbanese/gogost/gost34112012256"
)

func main() {
	keyHex := flag.String("key", "", "Key")
	flag.Parse()
	key, err := hex.DecodeString(*keyHex)
	if err != nil {
		panic(err)
	}
	h := hmac.New(gost34112012256.New, key)
	if _, err = io.Copy(h, os.Stdin); err != nil {
		panic(err)
	}
	fmt.Println("MAC:", hex.EncodeToString(h.Sum(nil)))
}
