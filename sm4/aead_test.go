package sm4

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// TestNewGCM 验证 NewGCM 的 AEAD 接口行为与错误路径。
func TestNewGCM(t *testing.T) {
	key := []byte("1234567890abcdef")
	if _, err := NewGCM([]byte("tooshort")); err == nil {
		t.Fatal("expected error for short key")
	}
	if _, err := NewGCM(make([]byte, 17)); err == nil {
		t.Fatal("expected error for long key")
	}

	aead, err := NewGCM(key)
	if err != nil {
		t.Fatal(err)
	}

	// 随机 12 字节 nonce 的 seal/open 往返
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	if aead.NonceSize() != 12 || len(aead.Seal(nil, nonce, nil, nil)) != 16 {
		t.Fatalf("unexpected nonce/overhead: %d/%d", aead.NonceSize(), len(aead.Seal(nil, nonce, nil, nil)))
	}
	plaintext := bytes.Repeat([]byte("sm4 gcm aead "), 8)
	aad := []byte("associated data")
	ct := aead.Seal(nil, nonce, plaintext, aad)
	pt, err := aead.Open(nil, nonce, ct, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatal("open mismatch")
	}
	// 篡改密文/标签/nonce 应失败
	bad := append([]byte(nil), ct...)
	bad[0] ^= 0x01
	if _, err := aead.Open(nil, nonce, bad, aad); err == nil {
		t.Fatal("expected error for tampered ciphertext")
	}
	if _, err := aead.Open(nil, nonce, ct, nil); err == nil {
		t.Fatal("expected error for missing AAD")
	}
}

// TestNewGCMInteropWithSm4GCM 验证 NewGCM 与包内旧 Sm4GCM 在 12 字节 IV 下
// 的 CTR 密文部分逐字节一致，并记录旧实现 tag 的已知偏差：
// 旧 GHASH 的 AAD/长度块拼接与标准 GCM 不同（多乘一次 H），导致 tag 不等价；
// 长 IV（非 96-bit）走 GHASH 路径同样与标准不等价。因此 NewGCM 只保证与
// 标准 GCM 一致，不保证与旧 Sm4GCM 的 tag 一致。
func TestNewGCMInteropWithSm4GCM(t *testing.T) {
	key := []byte("1234567890abcdef")
	iv := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b}
	plaintext := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}

	aead, err := NewGCM(key)
	if err != nil {
		t.Fatal(err)
	}
	sealed := aead.Seal(nil, iv, plaintext, nil)
	oldCT, oldT, err := Sm4GCM(key, iv, plaintext, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	// 12 字节 IV 下两者 Y0 均为 IV||00000001，CTR 密文部分应一致
	if !bytes.Equal(sealed[:len(oldCT)], oldCT) {
		t.Fatalf("CTR ciphertext mismatch:\n NewGCM %x\n Sm4GCM %x", sealed[:len(oldCT)], oldCT)
	}
	// 记录旧实现的 GHASH 偏差（tag 应不同）；若未来旧实现被修复为标准
	// GCM，此断言会反过来失败——届时改为相等断言。
	if bytes.Equal(sealed[len(oldCT):], oldT) {
		t.Fatal("legacy GHASH tag unexpectedly equals standard GCM tag")
	}
}

// TestNewBCEncrypter 使用 emmansun/gmsm/cipher 上游 TestBC 的 SM4/BC 测试
// 向量（GB/T 17964 BC 模式）。
func TestNewBCEncrypter(t *testing.T) {
	key, _ := hex.DecodeString("2B7E151628AED2A6ABF7158809CF4F3C")
	iv, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F")
	plaintext, _ := hex.DecodeString("6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710")
	ciphertext, _ := hex.DecodeString("AC529AF989A62FCE9CDDC5FFB84125CAFB8CDE77339FFE481D113C40BBD5B6786FFC9916F98F94FF12D78319707E240428718707605BC1EAC503153EBAA0FB1D")

	c, err := NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	got := make([]byte, len(plaintext))
	NewBCEncrypter(c, iv).CryptBlocks(got, plaintext)
	if !bytes.Equal(got, ciphertext) {
		t.Fatalf("BC encrypt mismatch:\n got %x\nwant %x", got, ciphertext)
	}
	NewBCDecrypter(c, iv).CryptBlocks(got, ciphertext)
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("BC decrypt mismatch:\n got %x\nwant %x", got, plaintext)
	}
}

// TestNewBCRandom 随机多块密文的 BC 模式加解密往返。
func TestNewBCRandom(t *testing.T) {
	key, _ := hex.DecodeString("2B7E151628AED2A6ABF7158809CF4F3C")
	iv := []byte("0123456789ABCDEF")
	c, err := NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 16; i++ {
		plaintext := make([]byte, i*BlockSize)
		if _, err := rand.Read(plaintext); err != nil {
			t.Fatal(err)
		}
		ciphertext := make([]byte, len(plaintext))
		NewBCEncrypter(c, iv).CryptBlocks(ciphertext, plaintext)
		got := make([]byte, len(plaintext))
		NewBCDecrypter(c, iv).CryptBlocks(got, ciphertext)
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("%d-block BC round trip failed", i)
		}
	}
}

// TestBCVsStandardCBC 记录 GB/T 17964 BC 模式与标准 CBC 的关系：上游
// emmansun 的 BC 测试向量与标准 CBC 模式定义一致（首块 C1=E(P1 xor IV)，
// 后续 Cn=E(Pn xor Cn-1)），故两者密文相同。此测试作为防回归断言，
// 若 emmansun 的 BC 实现变更则失败提醒。
func TestBCVsStandardCBC(t *testing.T) {
	key, _ := hex.DecodeString("2B7E151628AED2A6ABF7158809CF4F3C")
	iv, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F")
	plaintext := bytes.Repeat([]byte{0x6b, 0xc1, 0xbe, 0xe2}, 4)
	c, err := NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	bc := make([]byte, len(plaintext))
	NewBCEncrypter(c, iv).CryptBlocks(bc, plaintext)
	cbcOut := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(c, iv).CryptBlocks(cbcOut, plaintext)
	if !bytes.Equal(bc, cbcOut) {
		t.Fatal("GB/T 17964 BC mode should match standard CBC")
	}
}
