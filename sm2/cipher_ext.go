package sm2

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"io"

	gmsm2 "github.com/emmansun/gmsm/sm2"
)

// AdjustCiphertextSplicingOrder 在 C1C3C2 与 C1C2C3 两种拼接顺序间转换
// SM2 普通密文（plain 格式，带 0x04 前缀，支持 0x02/0x03 压缩点头）。
// from/to 使用本包的 C1C3C2/C1C2C3 常量；from==to 时原样返回。
// 委托 emmansun 实现。
func AdjustCiphertextSplicingOrder(ciphertext []byte, from, to ciphertextSplicingOrder) ([]byte, error) {
	for _, o := range []ciphertextSplicingOrder{from, to} {
		if o != C1C3C2 && o != C1C2C3 {
			return nil, fmt.Errorf("sm2: invalid splicing order %d", o)
		}
	}
	gFrom := gmsm2.C1C3C2
	if from == C1C2C3 {
		gFrom = gmsm2.C1C2C3
	}
	gTo := gmsm2.C1C3C2
	if to == C1C2C3 {
		gTo = gmsm2.C1C2C3
	}
	return gmsm2.AdjustCiphertextSplicingOrder(ciphertext, gFrom, gTo)
}

// PlainCiphertext2ASN1 将 plain 格式密文（带 0x04 前缀）转为 ASN.1 DER 编码
// 密文（SEQUENCE{x, y, hash, cipherText}，即 CipherMarshal 的输出）。
func PlainCiphertext2ASN1(ciphertext []byte, from ciphertextSplicingOrder) ([]byte, error) {
	if from != C1C3C2 && from != C1C2C3 {
		return nil, fmt.Errorf("sm2: invalid splicing order %d", from)
	}
	gFrom := gmsm2.C1C3C2
	if from == C1C2C3 {
		gFrom = gmsm2.C1C2C3
	}
	return gmsm2.PlainCiphertext2ASN1(ciphertext, gFrom)
}

// ASN1Ciphertext2Plain 将 ASN.1 DER 编码密文（CipherMarshal 的输出）转为
// plain 格式密文；opts 为 nil 时使用 C1C3C2 拼接顺序。
func ASN1Ciphertext2Plain(ciphertext []byte, opts *EncrypterOpts) ([]byte, error) {
	var gOpts *gmsm2.EncrypterOpts
	if opts != nil {
		if opts.SplicingOrder != C1C3C2 && opts.SplicingOrder != C1C2C3 {
			return nil, fmt.Errorf("sm2: invalid splicing order %d", opts.SplicingOrder)
		}
		gOrder := gmsm2.C1C3C2
		if opts.SplicingOrder == C1C2C3 {
			gOrder = gmsm2.C1C2C3
		}
		gOpts = gmsm2.NewPlainEncrypterOpts(gmsm2.MarshalUncompressed, gOrder)
	}
	return gmsm2.ASN1Ciphertext2Plain(ciphertext, gOpts)
}

// EncrypterOpts 描述密文转换的拼接顺序选项（plain 格式）。
type EncrypterOpts struct {
	SplicingOrder ciphertextSplicingOrder
}

// NewPlainEncrypterOpts 创建 plain 格式密文选项。
func NewPlainEncrypterOpts(splicingOrder ciphertextSplicingOrder) *EncrypterOpts {
	return &EncrypterOpts{SplicingOrder: splicingOrder}
}

// ciphertextSplicingOrder 是密文 C2/C3 拼接顺序类型。
// 注意：本包已有包级常量 C1C3C2 = 0 / C1C2C3 = 1（int），与 emmansun 的
// 同值常量兼容；此别名保持本包既有 API 形态。
type ciphertextSplicingOrder = int

// MarshalEnvelopedPrivateKey 用 SM2 公钥加密（封装）一个待保护的 SM2 私钥，
// 输出 GB/T 35276 封装私钥的 ASN.1 字节（SM4-ECB 保护私钥分量，SM2 保护
// 对称密钥）。rand 不得为 nil（上游不处理 nil，传 nil 会 panic）。
// 委托 emmansun 实现。
func MarshalEnvelopedPrivateKey(randReader io.Reader, pub *PublicKey, tobeEnveloped *PrivateKey) ([]byte, error) {
	if randReader == nil {
		return nil, errors.New("sm2: rand reader is nil")
	}
	if pub == nil {
		return nil, errors.New("sm2: public key is nil")
	}
	if tobeEnveloped == nil {
		return nil, errors.New("sm2: private key to be enveloped is nil")
	}
	d, err := tobeEnveloped.ec()
	if err != nil {
		return nil, err
	}
	return gmsm2.MarshalEnvelopedPrivateKey(randReader, pub.ec(), d)
}

// ParseEnvelopedPrivateKey 用 SM2 私钥解出封装私钥（MarshalEnvelopedPrivateKey
// 的输出）。委托 emmansun 实现。
func ParseEnvelopedPrivateKey(priv *PrivateKey, enveloped []byte) (*PrivateKey, error) {
	if priv == nil {
		return nil, errors.New("sm2: private key is nil")
	}
	d, err := priv.ec()
	if err != nil {
		return nil, err
	}
	ec, err := gmsm2.ParseEnvelopedPrivateKey(d, enveloped)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{
		PublicKey: PublicKey{Curve: P256Sm2(), X: ec.X, Y: ec.Y},
		D:         ec.D,
	}, nil
}

// RecoverPublicKeysFromSM2Signature 从 hash 的 DER 编码签名恢复候选公钥
// （最多 2 个）。注意本函数返回标准库 *ecdsa.PublicKey（与 emmansun 上游
// 返回类型一致），是本包少数直接使用 ecdsa 类型的 API。委托 emmansun 实现。
func RecoverPublicKeysFromSM2Signature(hash, sig []byte) ([]*ecdsa.PublicKey, error) {
	return gmsm2.RecoverPublicKeysFromSM2Signature(hash, sig)
}
