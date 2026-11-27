package sm4

import (
	"crypto/cipher"
	"fmt"

	gmsmcipher "github.com/emmansun/gmsm/cipher"
	gmsm4 "github.com/emmansun/gmsm/sm4"
)

// NewGCM 返回基于 SM4 的 GCM AEAD 实例（crypto/cipher.AEAD 接口，
// 标准 12 字节 nonce，16 字节认证标签），底层走 emmansun 的汇编加速
// GCM 实现（gcmAble 快速路径）。
//
// 与包内旧 Sm4GCM（支持任意长度 IV、C/T 分离返回）并存：本函数面向
// 标准 crypto 接口用法；长 IV 场景仍用 Sm4GCM。
func NewGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != BlockSize {
		return nil, fmt.Errorf("SM4: invalid key size %d", len(key))
	}
	block, err := gmsm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// NewBCEncrypter 返回 GB/T 17964 国标 BC（Block Chaining）模式加密器。
// 上游 emmansun 的 BC 实现与标准 CBC 等价（C1=E(P1 xor IV), Cn=E(Pn xor
// Cn-1)），保留本 API 是为了与 emmansun 上游及国密生态命名对齐；标准
// CBC 场景直接用 crypto/cipher.NewCBCEncrypter 亦可。委托 emmansun 实现。
func NewBCEncrypter(b cipher.Block, iv []byte) cipher.BlockMode {
	return gmsmcipher.NewBCEncrypter(b, iv)
}

// NewBCDecrypter 返回 GB/T 17964 国标 BC 模式解密器（说明同上）。委托 emmansun 实现。
func NewBCDecrypter(b cipher.Block, iv []byte) cipher.BlockMode {
	return gmsmcipher.NewBCDecrypter(b, iv)
}
