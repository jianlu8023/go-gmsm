package sm3

import (
	gmsm3 "github.com/emmansun/gmsm/sm3"
)

// Kdf 按 GB/T 35276 从密钥 z 派生 keyLen 字节密钥流：
// KDF(z) = W1 || W2 || ... || Wn，Wi = SM3(Wi-1 || i)。
// 委托 emmansun/gmsm/sm3.Kdf 实现。
func Kdf(z []byte, keyLen int) []byte {
	return gmsm3.Kdf(z, keyLen)
}
