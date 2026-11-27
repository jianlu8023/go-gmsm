// 本文件验证新 emmansun 实现与归档的 tjfoc 实现（tjfoc/gmsm/sm2）之间的
// 签名/加解密/密钥协商/公钥压缩互操作性。
package sm2

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/jianlu8023/go-gmsm/sm3"
	tjfoc2 "github.com/jianlu8023/go-gmsm/tjfoc/gmsm/sm2"
	tjfoc3 "github.com/jianlu8023/go-gmsm/tjfoc/gmsm/sm3"
)

// newPrivFromTjfoc 将 tjfoc 私钥转换为新实现类型（共享曲线单例）。
func newPrivFromTjfoc(t *testing.T, p *tjfoc2.PrivateKey) *PrivateKey {
	t.Helper()
	return &PrivateKey{
		PublicKey: PublicKey{Curve: P256Sm2(), X: p.X, Y: p.Y},
		D:         p.D,
	}
}

// tjfocPrivFromNew 将新实现私钥转换为 tjfoc 类型。
func tjfocPrivFromNew(t *testing.T, p *PrivateKey) *tjfoc2.PrivateKey {
	t.Helper()
	return &tjfoc2.PrivateKey{
		PublicKey: tjfoc2.PublicKey{Curve: tjfoc2.P256Sm2(), X: p.X, Y: p.Y},
		D:         p.D,
	}
}

// 新实现签名 → 新旧两侧验签；tjfoc 签名 → 新实现验签
func TestInteropSign(t *testing.T) {
	msg := []byte("1234567812345678")
	uid := []byte("1234567812345678")

	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r, s, err := Sm2Sign(priv, msg, uid, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if !Sm2Verify(&priv.PublicKey, msg, uid, r, s) {
		t.Error("new Sm2Verify rejected new signature")
	}
	oldPriv := tjfocPrivFromNew(t, priv)
	if !tjfoc2.Sm2Verify(&oldPriv.PublicKey, msg, uid, r, s) {
		t.Error("tjfoc Sm2Verify rejected new signature")
	}

	r2, s2, err := tjfoc2.Sm2Sign(oldPriv, msg, uid, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if !Sm2Verify(&priv.PublicKey, msg, uid, r2, s2) {
		t.Error("new Sm2Verify rejected tjfoc signature")
	}

	// 默认 uid 路径
	r3, s3, err := Sm2Sign(priv, msg, nil, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if !tjfoc2.Sm2Verify(&oldPriv.PublicKey, msg, nil, r3, s3) {
		t.Error("tjfoc Sm2Verify rejected new signature with default uid")
	}
}

// 新旧实现互相加解密（含 C1C2C3 模式）
func TestInteropEncrypt(t *testing.T) {
	msg := []byte("hello, interop")
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oldPriv := tjfocPrivFromNew(t, priv)
	oldPub := &oldPriv.PublicKey
	newPub := &priv.PublicKey

	for _, mode := range []int{C1C3C2, C1C2C3} {
		ct, err := Encrypt(newPub, msg, rand.Reader, mode)
		if err != nil {
			t.Fatalf("new Encrypt(%d): %v", mode, err)
		}
		pt, err := tjfoc2.Decrypt(oldPriv, ct, mode)
		if err != nil {
			t.Fatalf("tjfoc Decrypt(%d) of new ciphertext: %v", mode, err)
		}
		if !bytes.Equal(pt, msg) {
			t.Errorf("mode %d: tjfoc decrypted %x, want %x", mode, pt, msg)
		}

		ct2, err := tjfoc2.Encrypt(oldPub, msg, rand.Reader, mode)
		if err != nil {
			t.Fatalf("tjfoc Encrypt(%d): %v", mode, err)
		}
		pt2, err := Decrypt(priv, ct2, mode)
		if err != nil {
			t.Fatalf("new Decrypt(%d) of tjfoc ciphertext: %v", mode, err)
		}
		if !bytes.Equal(pt2, msg) {
			t.Errorf("mode %d: new decrypted %x, want %x", mode, pt2, msg)
		}
	}
}

// 空消息：归档实现 Encrypt(nil) 因 kdf(0) 恒 ok=false 导致无限循环（未终止 bug），
// 新实现按 emmansun 行为返回 (nil, nil)，修复该 bug；空消息签名路径不受影响。
func TestEncryptEmpty(t *testing.T) {
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := Encrypt(&priv.PublicKey, nil, rand.Reader, C1C3C2)
	if err != nil {
		t.Fatalf("Encrypt(nil): %v", err)
	}
	if ct != nil {
		t.Fatalf("Encrypt(nil) returned %d bytes, want nil", len(ct))
	}
	// 空消息签名路径（TestSm2 中 ifile 不存在时的实际路径）仍可正常签名/验签
	sign, err := priv.Sign(rand.Reader, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !priv.PublicKey.Verify(nil, sign) {
		t.Error("Verify of nil-message signature failed")
	}
}

// ZA / Sm3Digest 新旧实现逐字节一致
func TestInteropZA(t *testing.T) {
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oldPriv := tjfocPrivFromNew(t, priv)
	for _, uid := range [][]byte{nil, []byte("1234567812345678"), []byte{0x01, 0x02, 0x03}} {
		za1, err := ZA(&priv.PublicKey, uid)
		if err != nil {
			t.Fatal(err)
		}
		za2, err := tjfoc2.ZA(&oldPriv.PublicKey, uid)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(za1, za2) {
			t.Errorf("ZA mismatch for uid %x: new %x, tjfoc %x", uid, za1, za2)
		}
		d1, err := priv.PublicKey.Sm3Digest([]byte("abc"), uid)
		if err != nil {
			t.Fatal(err)
		}
		d2, err := oldPriv.PublicKey.Sm3Digest([]byte("abc"), uid)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(d1, d2) {
			t.Errorf("Sm3Digest mismatch for uid %x", uid)
		}
	}
}

// 新旧实现跨库密钥协商（B 端 tjfoc / A 端新实现），k 与校验值必须一致
func TestInteropKeyExchange(t *testing.T) {
	ida := []byte("1234567812345678")
	idb := []byte("1234567812345678")

	daBuf := []byte{0x81, 0xEB, 0x26, 0xE9, 0x41, 0xBB, 0x5A, 0xF1,
		0x6D, 0xF1, 0x16, 0x49, 0x5F, 0x90, 0x69, 0x52,
		0x72, 0xAE, 0x2C, 0xD6, 0x3D, 0x6C, 0x4A, 0xE1,
		0x67, 0x84, 0x18, 0xBE, 0x48, 0x23, 0x00, 0x29}
	dbBuf := []byte{0x78, 0x51, 0x29, 0x91, 0x7D, 0x45, 0xA9, 0xEA,
		0x54, 0x37, 0xA5, 0x93, 0x56, 0xB8, 0x23, 0x38,
		0xEA, 0xAD, 0xDA, 0x6C, 0xEB, 0x19, 0x90, 0x88,
		0xF1, 0x4A, 0xE1, 0x0D, 0xEF, 0xA2, 0x29, 0xB5}
	raBuf := []byte{0xD4, 0xDE, 0x15, 0x47, 0x4D, 0xB7, 0x4D, 0x06,
		0x49, 0x1C, 0x44, 0x0D, 0x30, 0x5E, 0x01, 0x24,
		0x00, 0x99, 0x0F, 0x3E, 0x39, 0x0C, 0x7E, 0x87,
		0x15, 0x3C, 0x12, 0xDB, 0x2E, 0xA6, 0x0B, 0xB3}
	rbBuf := []byte{0x7E, 0x07, 0x12, 0x48, 0x14, 0xB3, 0x09, 0x48,
		0x91, 0x25, 0xEA, 0xED, 0x10, 0x11, 0x13, 0x16,
		0x4E, 0xBF, 0x0F, 0x34, 0x58, 0xC5, 0xBD, 0x88,
		0x33, 0x5C, 0x1F, 0x9D, 0x59, 0x62, 0x43, 0xD6}

	oldCurve := tjfoc2.P256Sm2()
	oldDa := &tjfoc2.PrivateKey{PublicKey: tjfoc2.PublicKey{Curve: oldCurve}}
	oldDa.D = newBig(daBuf)
	oldDa.X, oldDa.Y = oldCurve.ScalarBaseMult(daBuf)
	oldDb := &tjfoc2.PrivateKey{PublicKey: tjfoc2.PublicKey{Curve: oldCurve}}
	oldDb.D = newBig(dbBuf)
	oldDb.X, oldDb.Y = oldCurve.ScalarBaseMult(dbBuf)
	oldRa := &tjfoc2.PrivateKey{PublicKey: tjfoc2.PublicKey{Curve: oldCurve}}
	oldRa.D = newBig(raBuf)
	oldRa.X, oldRa.Y = oldCurve.ScalarBaseMult(raBuf)
	oldRb := &tjfoc2.PrivateKey{PublicKey: tjfoc2.PublicKey{Curve: oldCurve}}
	oldRb.D = newBig(rbBuf)
	oldRb.X, oldRb.Y = oldCurve.ScalarBaseMult(rbBuf)

	newCurve := P256Sm2()
	nda := &PrivateKey{PublicKey: PublicKey{Curve: newCurve}}
	nda.D = newBig(daBuf)
	nda.X, nda.Y = newCurve.ScalarBaseMult(daBuf)
	ndb := &PrivateKey{PublicKey: PublicKey{Curve: newCurve}}
	ndb.D = newBig(dbBuf)
	ndb.X, ndb.Y = newCurve.ScalarBaseMult(dbBuf)
	nra := &PrivateKey{PublicKey: PublicKey{Curve: newCurve}}
	nra.D = newBig(raBuf)
	nra.X, nra.Y = newCurve.ScalarBaseMult(raBuf)
	nrb := &PrivateKey{PublicKey: PublicKey{Curve: newCurve}}
	nrb.D = newBig(rbBuf)
	nrb.X, nrb.Y = newCurve.ScalarBaseMult(rbBuf)

	// A 端用新实现，B 端用 tjfoc 实现
	kA, s1, sa, err := KeyExchangeA(16, ida, idb, nda, &ndb.PublicKey, nra, &nrb.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	kB, sb, s2, err := tjfoc2.KeyExchangeB(16, ida, idb, oldDb, &oldDa.PublicKey, oldRb, &oldRa.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(kA, kB) {
		t.Errorf("cross-library key mismatch: new %x, tjfoc %x", kA, kB)
	}
	if !bytes.Equal(s1, sb) {
		t.Error("cross-library s1 mismatch")
	}
	if !bytes.Equal(sa, s2) {
		t.Error("cross-library s2 mismatch")
	}
}

func newBig(b []byte) *big.Int {
	return new(big.Int).SetBytes(b)
}

// Compress/Decompress 新旧实现互操作
func TestInteropCompress(t *testing.T) {
	priv, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oldPriv := tjfocPrivFromNew(t, priv)

	c1 := Compress(&priv.PublicKey)
	c2 := tjfoc2.Compress(&oldPriv.PublicKey)
	if !bytes.Equal(c1, c2) {
		t.Errorf("Compress mismatch: new %x, tjfoc %x", c1, c2)
	}
	d1 := Decompress(c2)
	if d1.X.Cmp(priv.X) != 0 || d1.Y.Cmp(priv.Y) != 0 {
		t.Error("new Decompress(tjfoc Compress) point mismatch")
	}
	d2 := tjfoc2.Decompress(c1)
	if d2.X.Cmp(priv.X) != 0 || d2.Y.Cmp(priv.Y) != 0 {
		t.Error("tjfoc Decompress(new Compress) point mismatch")
	}
}

// 新旧实现 SM3 摘要一致（sm3 兼容层委托 emmansun 的回归校验）
func TestInteropSm3(t *testing.T) {
	data := bytes.Repeat([]byte("1234"), 100)
	if !bytes.Equal(sm3.Sm3Sum(data), tjfoc3.Sm3Sum(data)) {
		t.Fatal("sm3 vs tjfoc sm3 mismatch")
	}
}
