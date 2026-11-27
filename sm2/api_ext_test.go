package sm2

import (
	"bytes"
	"crypto/rand"
	"encoding/asn1"
	"math/big"
	"testing"
)

// TestNewPrivateKey 验证 32 字节 D 构造私钥与 GenerateKey/ScalarBaseMult 一致。
func TestNewPrivateKey(t *testing.T) {
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// D 填充到 32 字节（与 emmansun/GB/T 32918.1 的字节表示一致）
	d := make([]byte, 32)
	priv.D.FillBytes(d)

	priv2, err := NewPrivateKey(d)
	if err != nil {
		t.Fatal(err)
	}
	if priv2.D.Cmp(priv.D) != 0 {
		t.Fatalf("D mismatch: %v vs %v", priv2.D, priv.D)
	}
	if priv2.X.Cmp(priv.X) != 0 || priv2.Y.Cmp(priv.Y) != 0 {
		t.Fatalf("derived public key mismatch")
	}

	// 错误路径
	if _, err := NewPrivateKey(make([]byte, 31)); err == nil {
		t.Fatal("expected error for 31-byte key")
	}
	if _, err := NewPrivateKey(make([]byte, 33)); err == nil {
		t.Fatal("expected error for 33-byte key")
	}
	if _, err := NewPrivateKey(make([]byte, 32)); err == nil { // D = 0 非法
		t.Fatal("expected error for D = 0")
	}
}

// TestNewPrivateKeyFromInt 验证 *big.Int 构造私钥，且不会修改调用方参数。
func TestNewPrivateKeyFromInt(t *testing.T) {
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	orig := new(big.Int).Set(priv.D)

	priv2, err := NewPrivateKeyFromInt(priv.D)
	if err != nil {
		t.Fatal(err)
	}
	if priv2.D.Cmp(orig) != 0 || priv.X.Cmp(priv2.X) != 0 || priv.Y.Cmp(priv2.Y) != 0 {
		t.Fatal("key mismatch")
	}
	// emmansun 内部 FillBytes 会原地改写，包装层必须复制
	if priv.D.Cmp(orig) != 0 {
		t.Fatal("caller's big.Int was mutated")
	}
	if _, err := NewPrivateKeyFromInt(nil); err == nil {
		t.Fatal("expected error for nil key")
	}
}

// TestNewPublicKey 验证 0x04||X||Y 构造公钥及错误路径。
func TestNewPublicKey(t *testing.T) {
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 0, 65)
	buf = append(buf, 0x04)
	buf = append(buf, make([]byte, 32-len(priv.X.Bytes()))...)
	buf = append(buf, priv.X.Bytes()...)
	buf = append(buf, make([]byte, 32-len(priv.Y.Bytes()))...)
	buf = append(buf, priv.Y.Bytes()...)

	pub, err := NewPublicKey(buf)
	if err != nil {
		t.Fatal(err)
	}
	if pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
		t.Fatal("public key mismatch")
	}

	// 错误路径
	if _, err := NewPublicKey(make([]byte, 64)); err == nil {
		t.Fatal("expected error for 64-byte key")
	}
	if _, err := NewPublicKey(append([]byte{0x02}, buf[1:]...)); err == nil {
		t.Fatal("expected error for compressed key")
	}
	if _, err := NewPublicKey(append([]byte{0x05}, buf[1:]...)); err == nil {
		t.Fatal("expected error for off-curve point")
	}
}

// TestSignWithSM2SignerOption 验证 (*PrivateKey).Sign 对 *SM2SignerOption 的
// 三条路径：GM 默认 uid、GM 指定 uid、hash 语义。
func TestSignWithSM2SignerOption(t *testing.T) {
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := &priv.PublicKey
	msg := []byte("hello sm2 signer option")

	// 1) forceGMSign=true, uid 缺省 → 与原 Sign(msg 版) 语义一致（default_uid）
	sig, err := priv.Sign(rand.Reader, msg, NewSM2SignerOption(true, nil))
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Verify(msg, sig) {
		t.Fatal("verify failed with default uid")
	}

	// 2) forceGMSign=true, 指定 uid → 只能用该 uid 的摘要验签（msg 版
	// Verify 固定 default_uid，不应通过）
	uid := []byte("test-uid-1234")
	sig2, err := priv.Sign(rand.Reader, msg, NewSM2SignerOption(true, uid))
	if err != nil {
		t.Fatal(err)
	}
	var rs struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sig2, &rs); err != nil {
		t.Fatal(err)
	}
	digest, err := pub.Sm3Digest(msg, uid)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(pub, digest, rs.R, rs.S) {
		t.Fatal("verify failed: Sign(uid) does not match Sm3Digest(uid) + Verify(hash)")
	}
	if Sm2Verify(pub, msg, uid, rs.R, rs.S) == false {
		t.Fatal("verify failed: Sign(uid) does not match Sm2Verify(uid)")
	}
	if pub.Verify(msg, sig2) {
		t.Fatal("default-uid Verify should fail for a custom-uid signature")
	}

	// 3) forceGMSign=false → msg 视为已算好的摘要（hash 语义）
	hash := []byte("test")
	sig3, err := priv.Sign(rand.Reader, hash, NewSM2SignerOption(false, nil))
	if err != nil {
		t.Fatal(err)
	}
	var rs3 struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sig3, &rs3); err != nil {
		t.Fatal(err)
	}
	if !Verify(pub, hash, rs3.R, rs3.S) {
		t.Fatal("verify failed in hash semantics")
	}

	// DefaultSM2SignerOpts 与路径 1 等价
	sig4, err := priv.Sign(rand.Reader, msg, DefaultSM2SignerOpts)
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Verify(msg, sig4) {
		t.Fatal("verify failed with DefaultSM2SignerOpts")
	}
}

// TestSignASN1 验证包函数 SignASN1/VerifyASN1 的 hash 语义与 GM 语义。
func TestSignASN1(t *testing.T) {
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := &priv.PublicKey

	// hash 语义：nil opts，digest 为任意摘要
	digest := make([]byte, 32)
	if _, err := rand.Read(digest); err != nil {
		t.Fatal(err)
	}
	sig, err := SignASN1(nil, priv, digest, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyASN1(pub, digest, sig) {
		t.Fatal("VerifyASN1 failed (hash semantics)")
	}
	if VerifyASN1(pub, append([]byte{0x00}, digest...), sig) {
		t.Fatal("VerifyASN1 should fail for a different hash")
	}

	// GM 语义：对原始消息做 ZA+SM3 后签名
	msg := []byte("sm2 asn1 message")
	sig2, err := SignASN1(nil, priv, msg, DefaultSM2SignerOpts)
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Verify(msg, sig2) {
		t.Fatal("VerifyASN1 GM-signature not verifiable by msg-form Verify")
	}

	// 篡改私钥后应验签失败
	priv2, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if VerifyASN1(&priv2.PublicKey, digest, sig) {
		t.Fatal("VerifyASN1 should fail for a different key")
	}
}

// TestNewHash 验证 NewHash/NewHashWithUserID 与本地 Sm3Digest 逐字节一致。
func TestNewHash(t *testing.T) {
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := &priv.PublicKey
	msg := []byte("hash consistency check")

	h, err := NewHash(pub)
	if err != nil {
		t.Fatal(err)
	}
	h.Write(msg)
	got := h.Sum(nil)
	want, err := pub.Sm3Digest(msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Sm3Digest 返回 big.Int.Bytes()（可能缺前导零），统一转定长 32 字节比较
	want32 := make([]byte, 32)
	want32 = append(want32[:32-len(want)], want...)
	if !bytes.Equal(got, want32) {
		t.Fatalf("NewHash = %x, Sm3Digest = %x", got, want32)
	}

	// 指定 uid
	uid := []byte("uid-abc")
	h2, err := NewHashWithUserID(pub, uid)
	if err != nil {
		t.Fatal(err)
	}
	h2.Write(msg)
	got2 := h2.Sum(nil)
	want2, err := pub.Sm3Digest(msg, uid)
	if err != nil {
		t.Fatal(err)
	}
	want32 = make([]byte, 32)
	want32 = append(want32[:32-len(want2)], want2...)
	if !bytes.Equal(got2, want32) {
		t.Fatalf("NewHashWithUserID = %x, Sm3Digest(uid) = %x", got2, want32)
	}

	// 空 uid 回退 default_uid
	h3, err := NewHashWithUserID(pub, nil)
	if err != nil {
		t.Fatal(err)
	}
	h3.Write(msg)
	if !bytes.Equal(h3.Sum(nil), got) {
		t.Fatal("NewHashWithUserID(nil) should equal NewHash (default uid)")
	}

	if _, err := NewHash(nil); err == nil {
		t.Fatal("expected error for nil public key")
	}
}
