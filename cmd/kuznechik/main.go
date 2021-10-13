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

// Command-line 34.12-2015 128-bit Block cipher Kuznyechik crypter.
package main

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/pedroalbanese/gogost/gost3412128"
)

func main() {
	keyHex := flag.String("key", "", "Key")
	flag.Parse()
	var key []byte
	var err error
	if *keyHex == "" {
		key = make([]byte, gost3412128.KeySize)
		_, err = io.ReadFull(rand.Reader, key)
		if err != nil {
			panic(err)
		}
		fmt.Fprintln(os.Stderr, "Key:", hex.EncodeToString(key))
	} else {
		key, err = hex.DecodeString(*keyHex)
		if err != nil {
			panic(err)
		}
		if len(key) != gost3412128.KeySize {
			panic(errors.New("provided key has wrong length"))
		}
	}
	ciph := gost3412128.NewCipher(key)
	iv := make([]byte, gost3412128.BlockSize)
	stream := cipher.NewCTR(ciph, iv)
	buf := make([]byte, 128*1<<10)
	var n int
	for {
		n, err = os.Stdin.Read(buf)
		if err != nil && err != io.EOF {
			panic(err)
		}
		stream.XORKeyStream(buf[:n], buf[:n])
		if _, err := os.Stdout.Write(buf[:n]); err != nil {
			panic(err)
		}
		if err == io.EOF {
			break
		}
	}
}
