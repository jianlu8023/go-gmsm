package sm2

import (
	"encoding/asn1"
	"math/big"
)

// Decompress 由压缩公钥恢复公钥（y = sqrt(x^3 + ax + b) 按首位取符号）。
// 与归档的 tjfoc 实现等价，曲线运算改为 emmansun 曲线参数（big.Int mod P）。
func Decompress(a []byte) *PublicKey {
	x := new(big.Int).SetBytes(a[1:])
	params := P256Sm2().Params()
	// y^2 = x^3 + a*x + b, a = P - 3
	xx3 := new(big.Int).Mul(x, x)
	xx3.Mul(xx3, x)
	ax := new(big.Int).Sub(params.P, three)
	ax.Mul(ax, x)
	xx3.Add(xx3, ax)
	xx3.Add(xx3, params.B)
	xx3.Mod(xx3, params.P)

	y := new(big.Int).ModSqrt(xx3, params.P)
	if getLastBit(y) != uint(a[0]) {
		y.Sub(params.P, y)
	}
	return &PublicKey{
		Curve: P256Sm2(),
		X:     x,
		Y:     y,
	}
}

func Compress(a *PublicKey) []byte {
	buf := []byte{}
	yp := getLastBit(a.Y)
	buf = append(buf, a.X.Bytes()...)
	if n := len(a.X.Bytes()); n < 32 {
		buf = append(zeroByteSlice()[:(32-n)], buf...)
	}
	buf = append([]byte{byte(yp)}, buf...)
	return buf
}

type sm2Signature struct {
	R, S *big.Int
}

func SignDigitToSignData(r, s *big.Int) ([]byte, error) {
	return asn1.Marshal(sm2Signature{r, s})
}

func SignDataToSignDigit(sign []byte) (*big.Int, *big.Int, error) {
	var sm2Sign sm2Signature

	_, err := asn1.Unmarshal(sign, &sm2Sign)
	if err != nil {
		return nil, nil, err
	}
	return sm2Sign.R, sm2Sign.S, nil
}

func getLastBit(a *big.Int) uint {
	return a.Bit(0)
}
