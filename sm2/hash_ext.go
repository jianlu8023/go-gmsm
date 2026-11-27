package sm2

import (
	"errors"
	"hash"

	gmsm2 "github.com/emmansun/gmsm/sm2"
)

// NewHash 返回带 SM2 ZA 预处理的 SM3 摘要器（GB/T 32918.2 的 M' = ZA || M），
// 用户 ID 使用 default_uid。用法：Write(msg) 后 Sum 即得 e 值（与
// (*PublicKey).Sm3Digest(msg, nil) 的 32 字节大端数值一致）。
func NewHash(pub *PublicKey) (hash.Hash, error) {
	if pub == nil {
		return nil, errors.New("sm2: public key is nil")
	}
	h, err := gmsm2.NewHash(pub.ec())
	if err != nil {
		return nil, err
	}
	return h, nil
}

// NewHashWithUserID 同 NewHash，但使用指定用户 ID。
func NewHashWithUserID(pub *PublicKey, uid []byte) (hash.Hash, error) {
	if pub == nil {
		return nil, errors.New("sm2: public key is nil")
	}
	if len(uid) == 0 {
		// emmansun 的 NewHashWithUserID 空 uid 不会回退 defaultUID，
		// 这里显式回退以保持与本包 ZA/Sm3Digest 的语义一致。
		uid = default_uid
	}
	h, err := gmsm2.NewHashWithUserID(pub.ec(), uid)
	if err != nil {
		return nil, err
	}
	return h, nil
}
