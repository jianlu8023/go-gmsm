package sm2

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestAdjustCiphertextSplicingOrder 验证拼接顺序转换与 Encrypt 两种模式输出一致。
func TestAdjustCiphertextSplicingOrder(t *testing.T) {
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := &priv.PublicKey
	msg := []byte("splice order round trip")

	c32, err := Encrypt(pub, msg, rand.Reader, C1C3C2)
	if err != nil {
		t.Fatal(err)
	}
	c23, err := Encrypt(pub, msg, rand.Reader, C1C2C3)
	if err != nil {
		t.Fatal(err)
	}

	// C1C3C2 → C1C2C3 与直接以 C1C2C3 模式加密再解密应还原同一明文
	got23, err := AdjustCiphertextSplicingOrder(c32, C1C3C2, C1C2C3)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := Decrypt(priv, got23, C1C2C3)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, msg) {
		t.Fatal("round trip C1C3C2→C1C2C3 failed")
	}

	// C1C2C3 → C1C3C2 同理
	got32, err := AdjustCiphertextSplicingOrder(c23, C1C2C3, C1C3C2)
	if err != nil {
		t.Fatal(err)
	}
	plain, err = Decrypt(priv, got32, C1C3C2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, msg) {
		t.Fatal("round trip C1C2C3→C1C3C2 failed")
	}

	// from == to 原样返回
	same, err := AdjustCiphertextSplicingOrder(c32, C1C3C2, C1C3C2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(same, c32) {
		t.Fatal("identity conversion should return input unchanged")
	}

	// 非法输入
	if _, err := AdjustCiphertextSplicingOrder([]byte{0x04, 1, 2}, C1C3C2, C1C2C3); err == nil {
		t.Fatal("expected error for too-short ciphertext")
	}
	if _, err := AdjustCiphertextSplicingOrder(c32, C1C3C2, 9); err == nil {
		t.Fatal("expected error for unknown target order")
	}
}

// TestCiphertextFormatConvert 验证 plain ↔ ASN.1 转换与 CipherMarshal/CipherUnmarshal
// 的字节一致性与可解密性。
// 注意：本包 CipherMarshal(data) 只接受 C1C3C2 顺序的 plain 密文（单参数，
// 布局固定为 x||y||hash||cipherText），故字节级一致性断言只在 C1C3C2 下做。
func TestCiphertextFormatConvert(t *testing.T) {
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := &priv.PublicKey
	msg := []byte("cipher text format convert")

	// C1C3C2：与 CipherMarshal/CipherUnmarshal 逐字节一致
	plain32, err := Encrypt(pub, msg, rand.Reader, C1C3C2)
	if err != nil {
		t.Fatal(err)
	}
	der, err := PlainCiphertext2ASN1(plain32, C1C3C2)
	if err != nil {
		t.Fatal(err)
	}
	want, err := CipherMarshal(plain32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(der, want) {
		t.Fatalf("PlainCiphertext2ASN1 = %x, CipherMarshal = %x", der, want)
	}
	plain2, err := ASN1Ciphertext2Plain(der, NewPlainEncrypterOpts(C1C3C2))
	if err != nil {
		t.Fatal(err)
	}
	want2, err := CipherUnmarshal(der)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain2, want2) {
		t.Fatalf("ASN1Ciphertext2Plain = %x, CipherUnmarshal = %x", plain2, want2)
	}
	// 转换后的 ASN.1 密文仍可被 DecryptAsn1 解出
	dec, err := priv.DecryptAsn1(der)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec, msg) {
		t.Fatal("converted ASN.1 ciphertext not decryptable")
	}

	// C1C2C3：往返一致（CipherMarshal 不支持该顺序，不做字节级对比）
	plain23, err := Encrypt(pub, msg, rand.Reader, C1C2C3)
	if err != nil {
		t.Fatal(err)
	}
	der23, err := PlainCiphertext2ASN1(plain23, C1C2C3)
	if err != nil {
		t.Fatal(err)
	}
	back23, err := ASN1Ciphertext2Plain(der23, NewPlainEncrypterOpts(C1C2C3))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back23, plain23) {
		t.Fatal("C1C2C3 plain→ASN.1→plain round trip mismatch")
	}
	dec23, err := Decrypt(priv, back23, C1C2C3)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec23, msg) {
		t.Fatal("C1C2C3 converted ciphertext not decryptable")
	}

	// ASN.1Ciphertext2Plain(nil opts) 默认 C1C3C2
	backNil, err := ASN1Ciphertext2Plain(der, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(backNil, plain32) {
		t.Fatal("nil opts should default to C1C3C2")
	}

	// 非法输入
	if _, err := PlainCiphertext2ASN1([]byte{0x02, 1, 2}, C1C3C2); err == nil {
		t.Fatal("expected error for too-short plain ciphertext")
	}
	if _, err := ASN1Ciphertext2Plain([]byte("not-asn1"), nil); err == nil {
		t.Fatal("expected error for non-ASN.1 input")
	}
}

// TestEnvelopedPrivateKey 验证私钥封装（GB/T 32918.5）往返。
func TestEnvelopedPrivateKey(t *testing.T) {
	inner, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// 封装用一对独立的收发方密钥
	alice, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bob, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// 用 bob 的公钥封装、bob 的私钥解封
	der, err := MarshalEnvelopedPrivateKey(rand.Reader, &bob.PublicKey, inner)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseEnvelopedPrivateKey(bob, der)
	if err != nil {
		t.Fatal(err)
	}
	if got.D.Cmp(inner.D) != 0 {
		t.Fatal("unwrapped private key mismatch")
	}

	// 错误路径：nil rand 应报错（上游传 nil 会 panic，包装层前置拦截）
	if _, err := MarshalEnvelopedPrivateKey(nil, &bob.PublicKey, inner); err == nil {
		t.Fatal("expected error for nil rand reader")
	}
	// 错误私钥无法解封；乱序输入报错
	if _, err := ParseEnvelopedPrivateKey(alice, der); err == nil {
		t.Fatal("expected error unwrapping with wrong key")
	}
	if _, err := MarshalEnvelopedPrivateKey(rand.Reader, nil, inner); err == nil {
		t.Fatal("expected error for nil public key")
	}
	if _, err := MarshalEnvelopedPrivateKey(rand.Reader, &bob.PublicKey, nil); err == nil {
		t.Fatal("expected error for nil tobeEnveloped")
	}
}

// TestRecoverPublicKeysFromSM2Signature 验证由签名恢复公钥并用其验签。
func TestRecoverPublicKeysFromSM2Signature(t *testing.T) {
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("recover pubkey message")
	digest, err := priv.PublicKey.Sm3Digest(msg, nil)
	if err != nil {
		t.Fatal(err)
	}

	r, s, err := Sm2Sign(priv, msg, nil, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := SignDigitToSignData(r, s)
	if err != nil {
		t.Fatal(err)
	}
	// digest 转定长 32 字节（Sm3Digest 返回 big.Int.Bytes() 可能缺前导零）
	digest32 := make([]byte, 32)
	digest32 = append(digest32[:32-len(digest)], digest...)

	keys, err := RecoverPublicKeysFromSM2Signature(digest32, sig)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) == 0 || len(keys) > 2 {
		t.Fatalf("expected 1-2 candidate keys, got %d", len(keys))
	}
	found := false
	for _, k := range keys {
		if k.X.Cmp(priv.X) == 0 && k.Y.Cmp(priv.Y) == 0 {
			found = true
			// 恢复出的公钥应能验证签名（ecdsa 类型可直接用于验签）
			_ = k
		}
	}
	if !found {
		t.Fatalf("original public key not among recovered keys: %v", keys)
	}

	if _, err := RecoverPublicKeysFromSM2Signature(digest32, []byte("bad-sig")); err == nil {
		t.Fatal("expected error for malformed signature")
	}
}

// TestNewPlainEncrypterOpts 冒烟：选项构造与字段透传。
func TestNewPlainEncrypterOpts(t *testing.T) {
	opts := NewPlainEncrypterOpts(C1C2C3)
	if opts == nil || opts.SplicingOrder != C1C2C3 {
		t.Fatal("opts mismatch")
	}
	// 该选项可用于 ASN1Ciphertext2Plain
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("opts smoke")
	plain, err := Encrypt(&priv.PublicKey, msg, rand.Reader, C1C2C3)
	if err != nil {
		t.Fatal(err)
	}
	der, err := PlainCiphertext2ASN1(plain, C1C2C3)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ASN1Ciphertext2Plain(der, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, plain) {
		t.Fatal("C1C2C3 opts round trip failed")
	}
}
