package sm2

import (
	"crypto"
	"crypto/rand"
	"errors"
	"io"
	"math/big"

	gmsm2 "github.com/emmansun/gmsm/sm2"
)

// SM2SignerOption 是 SM2 专用的 crypto.SignerOpts，供 (*PrivateKey).Sign 使用。
// 字段与 emmansun/gmsm 的 SM2SignerOption 对齐：
//   - forceGMSign: true 时 msg 视为原始消息，Sign 内部按 GB/T 32918.2 计算
//     ZA+SM3 摘要后签名（GM 语义）；false 时 msg 视为已算好的摘要值。
//   - uid: forceGMSign=true 时生效；未指定（nil/空）时使用 default_uid。
//
// 注意：本类型是本包的独立类型，不能与 emmansun 的 SM2SignerOption 直接互换；
// (*PrivateKey).Sign 内部完成两者转换。
type SM2SignerOption struct {
	uid         []byte
	forceGMSign bool
}

// NewSM2SignerOption 创建 SM2 签名选项。
// forceGMSign 为 true 且 uid 为空时，uid 取 default_uid。
func NewSM2SignerOption(forceGMSign bool, uid []byte) *SM2SignerOption {
	opt := &SM2SignerOption{
		uid:         uid,
		forceGMSign: forceGMSign,
	}
	if forceGMSign && len(uid) == 0 {
		opt.uid = default_uid
	}
	return opt
}

// DefaultSM2SignerOpts 使用 default_uid 且 forceGMSign=true 的预置选项。
var DefaultSM2SignerOpts = NewSM2SignerOption(true, nil)

// HashFunc 满足 crypto.SignerOpts 接口。
func (*SM2SignerOption) HashFunc() crypto.Hash {
	return crypto.Hash(0) // 等价于 emmansun 的 directSigning：调用方负责摘要语义
}

// NewPrivateKey 用 32 字节小端无关的 D 值（GB/T 32918.1 要求 D ∈ [1, N-2]）
// 构造私钥，并推导对应公钥（X/Y 填充到曲线大小）。委托 emmansun 实现。
func NewPrivateKey(key []byte) (*PrivateKey, error) {
	ec, err := gmsm2.NewPrivateKey(key)
	if err != nil {
		return nil, err
	}
	priv := &PrivateKey{
		PublicKey: PublicKey{Curve: P256Sm2(), X: ec.X, Y: ec.Y},
		D:         ec.D,
	}
	return priv, nil
}

// NewPrivateKeyFromInt 从 *big.Int 私钥分量构造私钥。委托 emmansun 实现。
func NewPrivateKeyFromInt(key *big.Int) (*PrivateKey, error) {
	if key == nil {
		return nil, errors.New("sm2: private key is nil")
	}
	// emmansun 内部会原地 FillBytes，这里复制一份避免修改调用方参数
	k := new(big.Int).Set(key)
	ec, err := gmsm2.NewPrivateKeyFromInt(k)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{
		PublicKey: PublicKey{Curve: P256Sm2(), X: ec.X, Y: ec.Y},
		D:         ec.D,
	}, nil
}

// NewPublicKey 用非压缩格式公钥（0x04 || X(32) || Y(32)）构造公钥，
// 校验点在 SM2 曲线上。委托 emmansun 实现。
func NewPublicKey(key []byte) (*PublicKey, error) {
	ec, err := gmsm2.NewPublicKey(key)
	if err != nil {
		return nil, err
	}
	return &PublicKey{Curve: P256Sm2(), X: ec.X, Y: ec.Y}, nil
}

// SignASN1 对 hash 做 ECDSA 签名（hash 语义，返回 DER 编码 [r, s]），
// 不做 ZA 预处理；opts 传 *SM2SignerOption(forceGMSign=true) 时则对 hash
// 按 GM 语义做 SM2 摘要（uid 取自 opts）后再签名。委托 emmansun 实现。
func SignASN1(randReader io.Reader, priv *PrivateKey, hash []byte, opts crypto.SignerOpts) ([]byte, error) {
	ec, err := priv.ec()
	if err != nil {
		return nil, err
	}
	if randReader == nil {
		randReader = rand.Reader
	}
	return gmsm2.SignASN1(randReader, ec, hash, toGmsmOpts(opts))
}

// VerifyASN1 验证 hash 的 DER 编码 SM2 签名（hash 语义，不做 ZA 预处理）。
// 委托 emmansun 实现。
func VerifyASN1(pub *PublicKey, hash, sig []byte) bool {
	return gmsm2.VerifyASN1(pub.ec(), hash, sig)
}

// toGmsmOpts 将本包的签名选项转换为 emmansun 的类型。
// *SM2SignerOption 透传 forceGMSign/uid 语义（nil uid 时 emmansun 同样回退
// 其 defaultUID，与本包 default_uid 相同）；其余 opts 原样传递
// （emmansun 仅在 *gmsm2.SM2SignerOption 时启用 GM 路径）。
func toGmsmOpts(opts crypto.SignerOpts) crypto.SignerOpts {
	switch o := opts.(type) {
	case *SM2SignerOption:
		return gmsm2.NewSM2SignerOption(o.forceGMSign, o.uid)
	default:
		return opts
	}
}
