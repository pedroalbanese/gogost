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
	"math/big"
)

func (c *Curve) IsEdwards() bool {
	return c.E != nil
}

func (c *Curve) EdwardsST() (*big.Int, *big.Int) {
	if c.edS != nil {
		return c.edS, c.edT
	}
	c.edS = big.NewInt(0)
	c.edS.Set(c.E)
	c.edS.Sub(c.edS, c.D)
	c.pos(c.edS)
	var t big.Int
	t.SetUint64(4)
	t.ModInverse(&t, c.P)
	c.edS.Mul(c.edS, &t)
	c.edS.Mod(c.edS, c.P)
	c.edT = big.NewInt(0)
	c.edT.Set(c.E)
	c.edT.Add(c.edT, c.D)
	t.SetUint64(6)
	t.ModInverse(&t, c.P)
	c.edT.Mul(c.edT, &t)
	c.edT.Mod(c.edT, c.P)
	return c.edS, c.edT
}

// Convert Weierstrass X,Y coordinates to twisted Edwards U,V
func XY2UV(c *Curve, x, y *big.Int) (*big.Int, *big.Int) {
	if !c.IsEdwards() {
		panic("non twisted Edwards curve")
	}
	edS, edT := c.EdwardsST()
	var t big.Int
	t.Sub(x, edT)
	c.pos(&t)
	u := big.NewInt(0)
	u.ModInverse(y, c.P)
	u.Mul(u, &t)
	u.Mod(u, c.P)
	v := big.NewInt(0).Set(&t)
	v.Sub(v, edS)
	c.pos(v)
	t.Add(&t, edS)
	t.ModInverse(&t, c.P)
	v.Mul(v, &t)
	v.Mod(v, c.P)
	return u, v
}

// Convert twisted Edwards U,V coordinates to Weierstrass X,Y
func UV2XY(c *Curve, u, v *big.Int) (*big.Int, *big.Int) {
	if !c.IsEdwards() {
		panic("non twisted Edwards curve")
	}
	edS, edT := c.EdwardsST()
	var tx, ty big.Int
	tx.Add(bigInt1, v)
	tx.Mul(&tx, edS)
	tx.Mod(&tx, c.P)
	ty.Sub(bigInt1, v)
	c.pos(&ty)
	x := big.NewInt(0)
	x.ModInverse(&ty, c.P)
	x.Mul(x, &tx)
	x.Add(x, edT)
	x.Mod(x, c.P)
	y := big.NewInt(0)
	y.Mul(u, &ty)
	y.ModInverse(y, c.P)
	y.Mul(y, &tx)
	y.Mod(y, c.P)
	return x, y
}
